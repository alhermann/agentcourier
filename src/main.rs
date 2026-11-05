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

const USAGE: &str = "agentwire: secure messaging and file exchange between AI agents (hybrid post-quantum encryption)

Pair two machines (once):
  agentwire invite <name> [--no-files]      on the machine the other connects to: prints a one-time code (10 min)
  agentwire join <code> <name> <host:port>  on the other machine: pins the inviter's key and pairs

Inspect and control:
  agentwire status                          key, paired machines, connections, agents, refused attempts, invites
  agentwire peers                           who is reachable, including agents seen before
  agentwire trusted                         paired machines and their keys
  agentwire untrust <name>                  remove a machine immediately
  agentwire files <name> on|off             allow or block file exchange with a machine
  agentwire owner [display name]            show or set the owner name paired machines see
  agentwire log [N]                         last N audit entries (metadata only)
  agentwire reload                          re-read config.toml after editing it
  agentwire id                              print this machine's public key
  agentwire trust <name> <key> [host:port]  add a machine by key (manual alternative to invite/join)
  agentwire stop                            stop the background node

Agents and scripts:
  agentwire mcp [--name N] [--about TEXT] [--channel] [--root DIR]
                                            MCP server for one agent session; default name <client>-<project>,
                                            e.g. copilot-agentwire or claude-femsim (or set AGENTWIRE_NAME)
  agentwire send <to> <text|-> [--as N]     send a message (- reads stdin)
  agentwire send-file <to> <path> [--as N]  send a file from the current folder
  agentwire recv [--as N] [--wait S]        read messages
  agentwire node                            run the node in the foreground (normally auto-started)
";

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("agentwire: {e:#}");
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
            "--version" | "-V" => {
                flags.insert("version".into(), String::new());
            }
            "-" => pos.push(a.clone()),
            f if f.starts_with("--") => bail!("unknown flag {f}"),
            _ => pos.push(a.clone()),
        }
    }
    Ok((pos, flags))
}

fn name_flag(flags: &HashMap<String, String>) -> Result<Option<String>> {
    match flags.get("name").cloned().or_else(|| std::env::var("AGENTWIRE_NAME").ok()) {
        Some(n) if config::valid_name(&n) => Ok(Some(n)),
        Some(n) => bail!("invalid agent name {n:?} (letters, digits, - _ . up to 64)"),
        None => Ok(None),
    }
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
    if flags.contains_key("version") {
        println!("agentwire {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
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
            let Some(name) = p(1) else { bail!("usage: agentwire invite <name-for-the-other-machine>") };
            let r = admin(json!({"op": "invite", "name": name, "files": !flags.contains_key("no-files")})).await?;
            let code = r["code"].as_str().unwrap_or_default();
            let port = r["listen"].as_str().and_then(|l| l.rsplit_once(':')).map_or("7312", |(_, p)| p).to_string();
            println!("On the other machine, run (valid 10 minutes, works once):\n\n  agentwire join {code} <name-for-this-machine> <host:port>\n");
            println!("<host:port> is how that machine reaches this one, e.g. 127.0.0.1:{port} through an SSH tunnel.");
            println!("Only paste the code into a channel you trust (your own terminal or SSH session).");
        }
        Some("join") => {
            let (Some(code), Some(name), Some(addr)) = (p(1), p(2), p(3)) else { bail!("usage: agentwire join <code> <name> <host:port>") };
            let r = admin(json!({"op": "join", "code": code, "name": name, "addr": addr})).await?;
            println!("paired with {name} (key {})", r["key"].as_str().unwrap_or(""));
        }
        Some("status") => print(&admin(json!({"op": "status"})).await?)?,
        Some("peers") => print(&admin(json!({"op": "peers"})).await?)?,
        Some("trusted") => {
            for p in config::load()?.peer {
                println!("{:<16} {}  {}  files {}", p.name, p.key, p.addr.as_deref().unwrap_or("(connects to us)"), if p.files { "on" } else { "off" });
            }
        }
        Some("trust") => {
            let (Some(name), Some(key)) = (p(1), p(2)) else { bail!("usage: agentwire trust <name> <key> [host:port]") };
            admin(json!({"op": "trust", "name": name, "key": key, "addr": p(3)})).await?;
            println!("trusted {name}");
        }
        Some("untrust") => {
            let Some(name) = p(1) else { bail!("usage: agentwire untrust <name>") };
            admin(json!({"op": "untrust", "name": name})).await?;
            println!("removed {name}");
        }
        Some("files") => {
            let (Some(name), Some(v @ ("on" | "off"))) = (p(1), p(2)) else { bail!("usage: agentwire files <name> on|off") };
            admin(json!({"op": "files", "name": name, "on": v == "on"})).await?;
            println!("file exchange with {name}: {v}");
        }
        Some("owner") => match p(1) {
            Some(_) => {
                let owner = pos[1..].join(" ");
                admin(json!({"op": "owner", "owner": owner})).await?;
                println!("paired machines now see this machine's owner as: {owner}");
            }
            None => println!("{}", Some(config::load()?.owner).filter(|o| !o.is_empty()).unwrap_or_else(|| "(not set; your OS user name is shown)".into())),
        },
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
        Some("mcp") => mcp::run(name_flag(&flags)?, flags.get("about").cloned(), flags.contains_key("channel"), flags.get("root").cloned()).await?,
        Some("send") => {
            let (Some(to), true) = (p(1), pos.len() > 2) else { bail!("usage: agentwire send <to> <text|->") };
            let text = if p(2) == Some("-") { std::io::read_to_string(std::io::stdin())? } else { pos[2..].join(" ") };
            let me = name_flag(&flags)?.unwrap_or_else(|| "cli".into());
            let c = ipc::Client::connect(&me, "none", None, None, None, true).await?;
            print(&c.call(json!({"op": "send", "to": to, "text": text})).await?)?;
        }
        Some("send-file") => {
            let (Some(to), Some(path)) = (p(1), p(2)) else { bail!("usage: agentwire send-file <to> <path>") };
            let me = name_flag(&flags)?.unwrap_or_else(|| "cli".into());
            let c = ipc::Client::connect(&me, "none", cwd().as_deref(), None, None, true).await?;
            print(&c.call(json!({"op": "send_file", "to": to, "path": path})).await?)?;
        }
        Some("recv") => {
            let want = name_flag(&flags)?.unwrap_or_else(|| "cli".into());
            let c = ipc::Client::connect(&want, "pull", None, None, None, true).await?;
            if c.agent != want {
                eprintln!("note: {want} is in use by a running session; reading as {}", c.agent);
            }
            let wait: u64 = flags.get("wait").map(|w| w.parse()).transpose()?.unwrap_or(0);
            print(&c.call(json!({"op": "inbox", "wait": wait})).await?)?;
        }
        _ => print!("{USAGE}"),
    }
    Ok(())
}
