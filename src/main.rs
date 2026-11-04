mod config;
mod guard;
mod ipc;
mod mcp;
mod node;
mod wire;

use anyhow::{Result, bail};
use serde_json::json;
use std::collections::HashMap;

const USAGE: &str = "agora: authenticated, end-to-end encrypted (hybrid post-quantum) messaging between AI agents

  agora init                            create this machine's identity and print its key
  agora id                              print this machine's key
  agora trust <name> <key> [host:port]  trust a peer (address only needed on the side that dials)
  agora untrust <name>
  agora mcp [--name N] [--channel]      MCP server for one agent session (--channel: push into Claude Code)
  agora send <to> <text|-> [--as N]     send from the shell (- reads stdin)
  agora recv [--as N] [--wait S]        read messages for agent N from the shell
  agora peers                           show peers and online agents
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
            "--channel" => {
                flags.insert("channel".into(), String::new());
            }
            "--name" | "--as" | "--wait" => {
                let Some(v) = it.next() else { bail!("{a} needs a value") };
                let key = if a == "--wait" { "wait" } else { "name" };
                flags.insert(key.into(), v.clone());
            }
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

async fn reload_node() {
    if let Ok(c) = ipc::Client::connect("cli", "none", None, false).await {
        let _ = c.call(json!({"op": "reload"})).await;
    }
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
            if p(0) == Some("init") {
                eprintln!("Share this key with peers; they run: agora trust <name-for-you> <key> [your-host:port]");
            }
        }
        Some("trust") => {
            let (Some(name), Some(key)) = (p(1), p(2)) else { bail!("usage: agora trust <name> <key> [host:port]") };
            if !config::valid_name(name) {
                bail!("invalid peer name {name:?}");
            }
            let k = config::decode_key(key)?;
            if k == config::identity()?.public {
                bail!("that is this machine's own key");
            }
            let addr = p(3).map(String::from);
            if addr.as_deref().is_some_and(|a| !a.contains(':')) {
                bail!("address must be host:port");
            }
            let mut cfg = config::load()?;
            cfg.peer.retain(|x| x.name != name && config::decode_key(&x.key).ok() != Some(k));
            cfg.peer.push(config::Peer { name: name.into(), key: config::encode_key(&k), addr });
            config::save(&cfg)?;
            reload_node().await;
            println!("trusted {name}");
        }
        Some("untrust") => {
            let Some(name) = p(1) else { bail!("usage: agora untrust <name>") };
            let mut cfg = config::load()?;
            let before = cfg.peer.len();
            cfg.peer.retain(|x| x.name != name);
            if cfg.peer.len() == before {
                bail!("no peer named {name}");
            }
            config::save(&cfg)?;
            reload_node().await;
            println!("removed {name}");
        }
        Some("node") => node::run().await?,
        Some("mcp") => mcp::run(agent_name(&flags, "agent")?, flags.contains_key("channel")).await?,
        Some("send") => {
            let (Some(to), true) = (p(1), pos.len() > 2) else { bail!("usage: agora send <to> <text|->") };
            let text = if p(2) == Some("-") { std::io::read_to_string(std::io::stdin())? } else { pos[2..].join(" ") };
            let c = ipc::Client::connect(&agent_name(&flags, "cli")?, "none", None, true).await?;
            let r = c.call(json!({"op": "send", "to": to, "text": text})).await?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Some("recv") => {
            let want = agent_name(&flags, "cli")?;
            let c = ipc::Client::connect(&want, "pull", None, true).await?;
            if c.agent != want {
                eprintln!("note: {want} is in use by a running session; reading as {}", c.agent);
            }
            let wait: u64 = flags.get("wait").map(|w| w.parse()).transpose()?.unwrap_or(0);
            let r = c.call(json!({"op": "inbox", "wait": wait})).await?;
            println!("{}", serde_json::to_string_pretty(&r)?);
        }
        Some("peers") => {
            let c = ipc::Client::connect("cli", "none", None, true).await?;
            println!("{}", serde_json::to_string_pretty(&c.call(json!({"op": "peers"})).await?)?);
        }
        _ => print!("{USAGE}"),
    }
    Ok(())
}
