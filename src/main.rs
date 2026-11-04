mod config;
mod files;
mod guard;
mod ipc;
mod mcp;
mod node;
mod wire;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::collections::HashMap;

const USAGE: &str = "agora: secure messaging and file exchange between AI agents (hybrid post-quantum encryption)

Pair two machines (once):
  agora invite <name> [--no-files]      on the machine the other connects to: prints a one-time code (10 min)
  agora join <code> <name> <host:port>  on the other machine: pins the inviter's key and pairs

Inspect and control:
  agora status                          this machine's key, peers, connections, refused handshakes, invites
  agora trusted                         trusted machines and their keys
  agora untrust <name>                  remove a machine immediately
  agora files <name> on|off             allow or block file exchange with a machine
  agora log [N]                         last N audit entries (metadata only)
  agora reload                          re-read config.toml after editing it
  agora owner [display name]            show or set the owner name paired machines see
  agora id                              print this machine's public key
  agora trust <name> <key> [host:port]  add a machine by key (manual alternative to invite/join)
  agora stop                            stop the background node

Agents and scripts:
  agora mcp [--name N] [--about TEXT] [--channel] [--root DIR]
                                        MCP server for one agent session; the default name is
                                        <client>-<project>, e.g. copilot-agora or claude-femsim
  agora send <to> <text|-> [--as N]     send a message (- reads stdin)
  agora send-file <to> <path> [--as N]  send a file from the current folder
  agora recv [--as N] [--wait S]        read messages
  agora node                            run the node in the foreground (normally auto-started)
";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("agora: {e:#}");
        std::process::exit(1);
    }
}

fn parse(args: &[String]) -> Result<(Vec<String>, HashMap<String, String>)> {
    let (mut pos, mut flags) = (vec![], HashMap::new());
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--channel" | "--no-files" => {
                flags.insert(a.trim_start_matches('-').into(), String::new());
            }
            "--name" | "--as" | "--wait" | "--root" | "--about" => {
                let Some(v) = it.next() else { bail!("{a} needs a value") };
                let key = match a.as_str() {
                    "--as" => "name",
                    k => k.trim_start_matches('-'),
                };
                flags.insert(key.into(), v.clone());
            }
            "-" => pos.push(a.clone()),
            f if f.starts_with("--") => bail!("unknown flag {f}"),
            _ => pos.push(a.clone()),
        }
    }
    Ok((pos, flags))
}

fn agent_name(flags: &HashMap<String, String>, default: &str) -> Result<String> {
    let n = flags.get("name").cloned().or_else(|| std::env::var("AGORA_AGENT").ok()).unwrap_or_else(|| default.into());
    if !config::valid_name(&n) {
        bail!("invalid agent name {n:?} (letters, digits, - _ . up to 64)");
    }
    Ok(n)
}

fn cwd() -> Option<String> {
    std::env::current_dir().ok().map(|d| d.to_string_lossy().into_owned())
}

async fn admin(req: Value) -> Result<Value> {
    ipc::Client::connect("cli", "none", cwd().as_deref(), None, None, true).await?.call(req).await
}

fn print(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

async fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (pos, flags) = parse(&args)?;
    let p = |i: usize| pos.get(i).map(String::as_str);
    match p(0) {
        Some("init") | Some("id") => {
            let id = config::identity()?;
            if !config::home().join("config.toml").exists() {
                config::save(&config::load()?)?;
            }
            println!("{}", config::encode_key(&id.public));
        }
        Some("invite") => {
            let Some(name) = p(1) else { bail!("usage: agora invite <name-for-the-other-machine>") };
            let r = admin(json!({"op": "invite", "name": name, "files": !flags.contains_key("no-files")})).await?;
            let code = r["code"].as_str().unwrap_or_default();
            let port = r["listen"].as_str().and_then(|l| l.rsplit_once(':')).map_or("7312", |(_, p)| p).to_string();
            println!("On the other machine, run (valid 10 minutes, works once):\n\n  agora join {code} <name-for-this-machine> <host:port>\n");
            println!("<host:port> is how that machine reaches this one, e.g. 127.0.0.1:{port} through an SSH tunnel.");
            println!("Only paste the code into a channel you trust (your own terminal or SSH session).");
        }
        Some("join") => {
            let (Some(code), Some(name), Some(addr)) = (p(1), p(2), p(3)) else { bail!("usage: agora join <code> <name> <host:port>") };
            let r = admin(json!({"op": "join", "code": code, "name": name, "addr": addr})).await?;
            println!("paired with {name} (key {})", r["key"].as_str().unwrap_or(""));
        }
        Some("status") => print(&admin(json!({"op": "status"})).await?)?,
        Some("trusted") => {
            for p in config::load()?.peer {
                println!("{:<16} {}  {}  files {}", p.name, p.key, p.addr.as_deref().unwrap_or("(connects to us)"), if p.files { "on" } else { "off" });
            }
        }
        Some("trust") => {
            let (Some(name), Some(key)) = (p(1), p(2)) else { bail!("usage: agora trust <name> <key> [host:port]") };
            admin(json!({"op": "trust", "name": name, "key": key, "addr": p(3)})).await?;
            println!("trusted {name}");
        }
        Some("untrust") => {
            let Some(name) = p(1) else { bail!("usage: agora untrust <name>") };
            admin(json!({"op": "untrust", "name": name})).await?;
            println!("removed {name}");
        }
        Some("files") => {
            let (Some(name), Some(v @ ("on" | "off"))) = (p(1), p(2)) else { bail!("usage: agora files <name> on|off") };
            admin(json!({"op": "files", "name": name, "on": v == "on"})).await?;
            println!("file exchange with {name}: {v}");
        }
        Some("reload") => {
            admin(json!({"op": "reload"})).await?;
            println!("configuration reloaded");
        }
        Some("log") => {
            let n: usize = p(1).map(str::parse).transpose()?.unwrap_or(20);
            let s = std::fs::read_to_string(config::home().join("audit.jsonl")).unwrap_or_default();
            let lines: Vec<&str> = s.lines().collect();
            for l in &lines[lines.len().saturating_sub(n)..] {
                println!("{l}");
            }
        }
        Some("stop") => match ipc::Client::connect("cli", "none", None, None, None, false).await {
            Ok(c) => {
                c.call(json!({"op": "stop"})).await?;
                println!("node stopped");
            }
            Err(_) => println!("node not running"),
        },
        Some("node") => node::run().await?,
        Some("mcp") => {
            let root = flags.get("root").cloned().or_else(cwd);
            let name = match flags.get("name").cloned().or_else(|| std::env::var("AGORA_AGENT").ok()) {
                Some(n) if config::valid_name(&n) => Some(n),
                Some(n) => bail!("invalid agent name {n:?} (letters, digits, - _ . up to 64)"),
                None => None,
            };
            mcp::run(name, flags.get("about").cloned(), flags.contains_key("channel"), root).await?
        }
        Some("owner") => match p(1) {
            Some(_) => {
                let owner = pos[1..].join(" ");
                admin(json!({"op": "owner", "owner": owner})).await?;
                println!("paired machines now see this machine's owner as: {owner}");
            }
            None => println!("{}", Some(config::load()?.owner).filter(|o| !o.is_empty()).unwrap_or_else(|| "(not set; your OS user name is shown)".into())),
        },
        Some("send") => {
            let (Some(to), true) = (p(1), pos.len() > 2) else { bail!("usage: agora send <to> <text|->") };
            let text = if p(2) == Some("-") { std::io::read_to_string(std::io::stdin())? } else { pos[2..].join(" ") };
            let c = ipc::Client::connect(&agent_name(&flags, "cli")?, "none", None, None, None, true).await?;
            print(&c.call(json!({"op": "send", "to": to, "text": text})).await?)?;
        }
        Some("send-file") => {
            let (Some(to), Some(path)) = (p(1), p(2)) else { bail!("usage: agora send-file <to> <path>") };
            let c = ipc::Client::connect(&agent_name(&flags, "cli")?, "none", cwd().as_deref(), None, None, true).await?;
            print(&c.call(json!({"op": "send_file", "to": to, "path": path})).await?)?;
        }
        Some("recv") => {
            let want = agent_name(&flags, "cli")?;
            let c = ipc::Client::connect(&want, "pull", None, None, None, true).await?;
            if c.agent != want {
                eprintln!("note: {want} is in use by a running session; reading as {}", c.agent);
            }
            let wait: u64 = flags.get("wait").map(|w| w.parse()).transpose()?.unwrap_or(0);
            print(&c.call(json!({"op": "inbox", "wait": wait})).await?)?;
        }
        Some("peers") => print(&admin(json!({"op": "peers"})).await?)?,
        _ => print!("{USAGE}"),
    }
    Ok(())
}
