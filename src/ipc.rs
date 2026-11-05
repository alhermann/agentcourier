//! Client side of the local control connection (used by `agentwire mcp` and the CLI).
use crate::config;
use crate::node::{ct_eq, mac, read_json};
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

pub struct Client {
    out: mpsc::UnboundedSender<String>,
    pending: Pending,
    rid: AtomicU64,
    dead: Arc<AtomicBool>,
    reader: tokio::task::JoinHandle<()>,
    pub agent: String,
}

impl Drop for Client {
    // Both halves must go for the socket to close and the node to release this session's name.
    fn drop(&mut self) {
        self.reader.abort();
    }
}

#[cfg(unix)]
async fn dial() -> Result<tokio::net::UnixStream> {
    Ok(tokio::net::UnixStream::connect(config::socket_path()).await?)
}

#[cfg(windows)]
async fn dial() -> Result<tokio::net::TcpStream> {
    Ok(tokio::net::TcpStream::connect(("127.0.0.1", config::load()?.ipc_port)).await?)
}

fn spawn_node() -> Result<()> {
    let log = config::open_private_append(&config::ensure_home()?.join("node.log"))?;
    let mut c = std::process::Command::new(std::env::current_exe()?);
    c.arg("node").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(log);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        c.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        unsafe extern "system" {
            fn GetStdHandle(n: u32) -> isize;
            fn SetHandleInformation(h: isize, mask: u32, flags: u32) -> i32;
        }
        // The long-lived node must not inherit our stdio pipes, or the MCP client never sees them close.
        for n in [-10i32, -11, -12] {
            unsafe {
                let h = GetStdHandle(n as u32);
                if h != 0 && h != -1 {
                    SetHandleInformation(h, 1, 0);
                }
            }
        }
        const NO_WINDOW: u32 = 0x0800_0000;
        const NEW_GROUP: u32 = 0x0000_0200;
        const BREAKAWAY: u32 = 0x0100_0000;
        // Leave the client's job object so closing the editor does not kill the node.
        if c.creation_flags(NO_WINDOW | NEW_GROUP | BREAKAWAY).spawn().is_ok() {
            return Ok(());
        }
        c.creation_flags(NO_WINDOW | NEW_GROUP);
    }
    c.spawn()?;
    Ok(())
}

impl Client {
    /// `mode`: "push" (events streamed), "pull" (read via inbox), "none" (send only, not registered).
    /// Client and node prove knowledge of the local token to each other without sending it.
    pub async fn connect(
        agent: &str,
        mode: &str,
        root: Option<&str>,
        about: Option<&str>,
        events: Option<mpsc::UnboundedSender<Value>>,
        autostart: bool,
    ) -> Result<Client> {
        let mut s = dial().await;
        if s.is_err() {
            if let Some(h) = config::node_elsewhere() {
                bail!("agentwire runs on {h}, which shares this home folder with {}; start this agent on {h} (e.g. ssh {h})", config::hostname());
            }
        }
        if s.is_err() && autostart {
            spawn_node()?;
            for _ in 0..50 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                s = dial().await;
                if s.is_ok() {
                    break;
                }
            }
        }
        let s = s.map_err(|e| anyhow!("agentwire node not reachable ({e}); see {}", config::home().join("node.log").display()))?;
        let token = std::fs::read_to_string(config::home().join("ipc.token"))?.trim().to_string();
        let (r, mut w) = tokio::io::split(s);
        let mut r = BufReader::new(r);
        let challenge = match tokio::time::timeout(Duration::from_secs(10), read_json(&mut r)).await {
            Ok(Ok(Some(v))) => v["challenge"].as_str().unwrap_or("").to_string(),
            _ => bail!("agentwire node did not answer"),
        };
        if challenge.len() != 32 {
            bail!("agentwire node sent an invalid challenge");
        }
        let nonce = config::random_hex(16);
        let (out, mut out_rx) = mpsc::unbounded_channel::<String>();
        let pending: Pending = Arc::default();
        let dead = Arc::new(AtomicBool::new(false));
        tokio::spawn(async move {
            while let Some(l) = out_rx.recv().await {
                if w.write_all(l.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let (p, d) = (pending.clone(), dead.clone());
        let reader = tokio::spawn(async move {
            while let Ok(Some(v)) = read_json(&mut r).await {
                if v.get("ev").is_some() {
                    if let Some(e) = &events {
                        let _ = e.send(v);
                    }
                } else if let Some(tx) = v["rid"].as_u64().and_then(|rid| p.lock().unwrap().remove(&rid)) {
                    let _ = tx.send(v);
                }
            }
            d.store(true, Ordering::Relaxed);
            p.lock().unwrap().clear();
        });
        let mut c = Client { out, pending, rid: AtomicU64::new(1), dead, reader, agent: String::new() };
        let proof = mac(&token, &["client", &challenge, &nonce]);
        let hello = c.call(json!({"op": "hello", "agent": agent, "mode": mode, "root": root, "about": about, "nonce": nonce, "proof": proof})).await?;
        // Reject an impostor that grabbed the port: only the real node knows the token.
        if !hello["proof"].as_str().is_some_and(|p| ct_eq(p, &mac(&token, &["node", &challenge, &nonce]))) {
            bail!("the process on the agentwire port is not your node");
        }
        c.agent = hello["agent"].as_str().unwrap_or(agent).to_string();
        Ok(c)
    }

    pub fn alive(&self) -> bool {
        !self.dead.load(Ordering::Relaxed) && !self.out.is_closed()
    }

    pub async fn call(&self, mut req: Value) -> Result<Value> {
        let rid = self.rid.fetch_add(1, Ordering::Relaxed);
        req["rid"] = rid.into();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(rid, tx);
        self.out.send(format!("{req}\n")).map_err(|_| anyhow!("node connection closed"))?;
        let mut v = rx.await.map_err(|_| anyhow!("node connection closed"))?;
        if v["ok"].as_bool() != Some(true) {
            bail!("{}", v["error"].as_str().unwrap_or("request failed"));
        }
        if let Some(o) = v.as_object_mut() {
            o.remove("rid");
            o.remove("ok");
        }
        Ok(v)
    }
}
