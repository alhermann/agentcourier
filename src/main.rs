mod config;
mod files;
mod guard;
mod ipc;
mod mcp;
mod node;
mod relay;
mod wire;

use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::collections::HashMap;

const USAGE: &str = "agentcourier: secure messaging and file exchange between AI agents (hybrid post-quantum encryption)

Pair two machines (once):
  agentcourier invite <name> [--no-files]      on the machine the other connects to: prints a one-time code (10 min)
  agentcourier join <code> <name> <host:port>  on the other machine: pins the inviter's key and pairs
                                               (use relay instead of host:port when both machines joined the same relay)

Relay (for machines that cannot reach each other; you run it yourself):
  agentcourier relay [--listen ADDR]           run a relay on a machine both can reach (default 0.0.0.0:7400)
  agentcourier relay invite <name> <host:port> on the relay machine: one-time code for a member (10 min)
  agentcourier relay join <code>               on a member machine: use that relay
  agentcourier relay members | remove <name>   on the relay machine: who may use it
  agentcourier relay leave                     on a member machine: stop using the relay

Inspect and control:
  agentcourier status                          key, paired machines, connections, agents, refused attempts, invites
  agentcourier peers                           who is reachable, including agents seen before
  agentcourier trusted                         paired machines and their keys
  agentcourier untrust <name>                  remove a machine immediately
  agentcourier rename <name> <new-name>        change what this machine calls a paired machine (pairing stays)
  agentcourier files <name> on|off             allow or block file exchange with a machine
  agentcourier owner [display name]            show or set the owner name paired machines see
  agentcourier log [N]                         last N audit entries (metadata only)
  agentcourier reload                          re-read config.toml after editing it
  agentcourier id                              print this machine's public key
  agentcourier trust <name> <key> [host:port]  add a machine by key (manual alternative to invite/join)
  agentcourier stop                            stop the background node

Agents and scripts:
  agentcourier mcp [--name N] [--about TEXT] [--channel] [--root DIR]
                                               MCP server for one agent session; default name <client>-<project>,
                                               e.g. copilot-paper or claude-femsim (or set AGENTCOURIER_NAME)
  agentcourier send <to> <text|-> [--as N]     send a message (- reads stdin)
  agentcourier send-file <to> <path> [--as N]  send a file from the current folder
  agentcourier recv [--as N] [--wait S]        read messages
  agentcourier watch                           stream arrival notices (sender and recipient only, never text)
  agentcourier vscode                          install the VS Code extension that shows new messages
  agentcourier node                            run the node in the foreground (normally auto-started)
";

const VSCODE_PACKAGE: &str = include_str!("../vscode/package.json");
const VSCODE_EXTENSION: &str = include_str!("../vscode/extension.js");

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("agentcourier: {e:#}");
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
            "--name" | "--as" | "--wait" | "--root" | "--about" | "--listen" => {
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
    match flags.get("name").cloned().or_else(|| std::env::var("AGENTCOURIER_NAME").ok()) {
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
        println!("agentcourier {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let p = |i: usize| pos.get(i).map(String::as_str);
    // Move a former installation's folder before anything reads settings from the new one.
    if p(0).is_some() {
        config::ensure_home()?;
    }
    match p(0) {
        Some("init") | Some("id") => {
            let id = config::identity()?;
            if !config::home().join("config.toml").exists() {
                config::save(&config::load()?)?;
            }
            println!("{}", config::encode_key(&id.public));
        }
        Some("invite") => {
            let Some(name) = p(1) else { bail!("usage: agentcourier invite <name-for-the-other-machine>") };
            let r = admin(json!({"op": "invite", "name": name, "files": !flags.contains_key("no-files")})).await?;
            let code = r["code"].as_str().unwrap_or_default();
            let port = r["listen"].as_str().and_then(|l| l.rsplit_once(':')).map_or("7312", |(_, p)| p).to_string();
            println!("On the other machine, run (valid 10 minutes, works once):\n\n  agentcourier join {code} <name-for-this-machine> <host:port>\n");
            if r["relay"] == true {
                println!("If both machines joined the same relay, use relay instead of <host:port>:\n\n  agentcourier join {code} <name-for-this-machine> relay\n");
            }
            println!("<host:port> is how that machine reaches this one, e.g. 127.0.0.1:{port} through an SSH tunnel.");
            println!("Only paste the code into a channel you trust (your own terminal or SSH session).");
        }
        Some("join") => {
            let (Some(code), Some(name), Some(addr)) = (p(1), p(2), p(3)) else { bail!("usage: agentcourier join <code> <name> <host:port>") };
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
            let (Some(name), Some(key)) = (p(1), p(2)) else { bail!("usage: agentcourier trust <name> <key> [host:port]") };
            admin(json!({"op": "trust", "name": name, "key": key, "addr": p(3)})).await?;
            println!("trusted {name}");
        }
        Some("untrust") => {
            let Some(name) = p(1) else { bail!("usage: agentcourier untrust <name>") };
            admin(json!({"op": "untrust", "name": name})).await?;
            println!("removed {name}");
        }
        Some("rename") => {
            let (Some(name), Some(new)) = (p(1), p(2)) else { bail!("usage: agentcourier rename <name> <new-name>") };
            admin(json!({"op": "rename", "name": name, "new": new})).await?;
            println!("{name} is now called {new} on this machine; agents address it as <agent>@{new}");
        }
        Some("files") => {
            let (Some(name), Some(v @ ("on" | "off"))) = (p(1), p(2)) else { bail!("usage: agentcourier files <name> on|off") };
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
        Some("relay") => match p(1) {
            None => relay::serve(flags.get("listen").cloned()).await?,
            Some("invite") => {
                let (Some(name), Some(addr)) = (p(2), p(3)) else { bail!("usage: agentcourier relay invite <name> <host:port members use to reach this relay>") };
                let code = relay::invite(name, addr)?;
                println!("On {name}'s machine, run (valid 10 minutes, works once):\n\n  agentcourier relay join {code}\n");
                println!("Keep the relay running here: agentcourier relay");
            }
            Some("join") => {
                let Some(code) = p(2) else { bail!("usage: agentcourier relay join <code>") };
                let r = admin(json!({"op": "relay_join", "code": code})).await?;
                println!("this machine now uses the relay at {}", r["relay"].as_str().unwrap_or("?"));
            }
            Some("leave") => {
                admin(json!({"op": "relay_leave"})).await?;
                println!("this machine no longer uses a relay");
            }
            Some("members") => {
                for (name, key) in relay::members()? {
                    println!("{name:<16} {key}");
                }
            }
            Some("remove") => {
                let Some(name) = p(2) else { bail!("usage: agentcourier relay remove <name>") };
                println!("{}", if relay::remove(name)? { format!("removed {name}") } else { format!("{name} was not a member") });
            }
            Some(o) => bail!("unknown relay command {o:?}"),
        },
        Some("mcp") => mcp::run(name_flag(&flags)?, flags.get("about").cloned(), flags.contains_key("channel"), flags.get("root").cloned()).await?,
        Some("send") => {
            let (Some(to), true) = (p(1), pos.len() > 2) else { bail!("usage: agentcourier send <to> <text|->") };
            let text = if p(2) == Some("-") { std::io::read_to_string(std::io::stdin())? } else { pos[2..].join(" ") };
            let me = name_flag(&flags)?.unwrap_or_else(|| "cli".into());
            let c = ipc::Client::connect(&me, "none", None, None, None, true).await?;
            print(&c.call(json!({"op": "send", "to": to, "text": text})).await?)?;
        }
        Some("send-file") => {
            let (Some(to), Some(path)) = (p(1), p(2)) else { bail!("usage: agentcourier send-file <to> <path>") };
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
        Some("watch") => {
            use std::io::Write;
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let c = ipc::Client::connect("watch", "watch", None, None, Some(tx), true).await?;
            let mut so = std::io::stdout();
            let u = c.call(json!({"op": "unread"})).await?;
            writeln!(so, "{}", json!({"ev": "unread", "unread": u["unread"]}))?;
            so.flush()?;
            while let Some(ev) = rx.recv().await {
                writeln!(so, "{ev}")?;
                so.flush()?;
            }
            bail!("connection to the node closed");
        }
        Some("vscode") => {
            let base = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).ok_or_else(|| anyhow::anyhow!("no home folder"))?;
            let exts = std::path::PathBuf::from(base).join(".vscode").join("extensions");
            let dir = exts.join("agentcourier.agentcourier");
            std::fs::create_dir_all(&dir)?;
            std::fs::write(dir.join("package.json"), VSCODE_PACKAGE)?;
            std::fs::write(dir.join("extension.js"), VSCODE_EXTENSION)?;
            // The same extension under the project's former name would show every message twice.
            let old = exts.join("agentwire.agentwire");
            if old.join("extension.js").is_file() && std::fs::remove_dir_all(&old).is_ok() {
                println!("removed the old agentwire extension");
            }
            println!("installed to {}\nReload VS Code (Command Palette: Developer: Reload Window) to activate it.", dir.display());
        }
        _ => print!("{USAGE}"),
    }
    Ok(())
}
