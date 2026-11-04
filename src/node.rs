//! The per-machine node: holds identity, encrypted peer links, per-agent queues and the local control socket.
use crate::config::{self, Config, Identity, valid_name};
use crate::guard::Guard;
use crate::wire;
use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};
use tokio::time::{sleep, timeout};

const HANDSHAKE: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(25);
const IDLE: Duration = Duration::from_secs(75);
const ACK_WAIT: Duration = Duration::from_secs(10);
const QUEUE_MAX: usize = 1000;
const QUEUES_MAX: usize = 256;
const SEEN_MAX: usize = 8192;
const LINE_MAX: u64 = 4 << 20;
const WAKE_EVERY: Duration = Duration::from_secs(60);

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "t", rename_all = "lowercase")]
enum P2p {
    Msg(Msg),
    Ack { id: String, ok: bool, status: String },
    Presence { agents: Vec<String> },
    Ping,
}

#[derive(Serialize, Deserialize, Clone)]
struct Msg {
    id: String,
    from: String,
    to: String,
    #[serde(default)]
    thread: Option<String>,
    body: String,
    ts: u64,
}

#[derive(Serialize, Clone)]
struct Event {
    id: String,
    from: String,
    to: String,
    thread: Option<String>,
    body: String,
    ts: u64,
    redacted: Vec<&'static str>,
}

struct Link {
    tx: mpsc::UnboundedSender<P2p>,
    id: u64,
    key: [u8; 32],
    i_initiated: bool,
    since: Instant,
}

struct Session {
    sid: u64,
    notify: Arc<Notify>,
}

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    queues: HashMap<String, VecDeque<Event>>,
    links: HashMap<String, Link>,
    outbox: HashMap<String, VecDeque<Msg>>,
    unacked: HashMap<String, (String, Msg)>,
    waiters: HashMap<String, oneshot::Sender<(bool, String)>>,
    remote_agents: HashMap<String, Vec<String>>,
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
    buckets: HashMap<String, (f64, Instant)>,
    woken: HashMap<String, Instant>,
    dialing: HashSet<String>,
}

pub struct Node {
    me: Identity,
    cfg: RwLock<Arc<Config>>,
    guard: RwLock<Arc<Guard>>,
    st: Mutex<State>,
    token: String,
    ids: AtomicU64,
    audit: Mutex<Option<std::fs::File>>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn valid_thread(t: &Option<String>) -> bool {
    t.as_deref().is_none_or(valid_name)
}

/// "agent@peer" → (agent, Some(peer)); "agent" → local. "*" addresses every agent.
fn split_addr(to: &str) -> Result<(String, Option<String>)> {
    let (a, p) = match to.rsplit_once('@') {
        Some((a, p)) => (a, Some(p.to_string())),
        None => (to, None),
    };
    if !(a == "*" || valid_name(a)) || p.as_deref().is_some_and(|p| !valid_name(p)) {
        bail!("invalid address {to:?}; use agent, agent@peer or *@peer");
    }
    Ok((a.to_string(), p))
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub async fn run() -> Result<()> {
    let me = config::identity()?;
    let cfg = config::load()?;
    let token = config::ipc_token()?;
    let ipc = ipc_bind(&cfg).await?;
    let p2p = TcpListener::bind(&cfg.listen).await.map_err(|e| anyhow!("bind {}: {e}", cfg.listen))?;
    let audit = std::fs::OpenOptions::new().create(true).append(true).open(config::home().join("audit.jsonl")).ok();
    eprintln!("agora node {} listening on {}", config::encode_key(&me.public), cfg.listen);
    let node = Arc::new(Node {
        me,
        guard: RwLock::new(Arc::new(Guard::new(cfg.guard.clone()))),
        cfg: RwLock::new(Arc::new(cfg)),
        st: Mutex::new(State::default()),
        token,
        ids: AtomicU64::new(1),
        audit: Mutex::new(audit),
    });
    node.spawn_dialers();
    let n = node.clone();
    tokio::spawn(async move { n.accept_p2p(p2p).await });
    node.accept_ipc(ipc).await
}

#[cfg(unix)]
type IpcListener = tokio::net::UnixListener;
#[cfg(windows)]
type IpcListener = TcpListener;

#[cfg(unix)]
async fn ipc_bind(_: &Config) -> Result<IpcListener> {
    use std::os::unix::fs::PermissionsExt;
    let path = config::ensure_home()?.join("node.sock");
    if path.exists() {
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            bail!("a node is already running");
        }
        std::fs::remove_file(&path)?;
    }
    let l = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

#[cfg(windows)]
async fn ipc_bind(cfg: &Config) -> Result<IpcListener> {
    TcpListener::bind(("127.0.0.1", cfg.ipc_port)).await.map_err(|e| anyhow!("a node is already running or port {} is taken: {e}", cfg.ipc_port))
}

impl Node {
    fn cfg(&self) -> Arc<Config> {
        self.cfg.read().unwrap().clone()
    }
    fn guard(&self) -> Arc<Guard> {
        self.guard.read().unwrap().clone()
    }

    fn audit(&self, v: Value) {
        if let Some(f) = self.audit.lock().unwrap().as_mut() {
            let _ = writeln!(f, "{v}");
        }
    }

    async fn accept_ipc(self: &Arc<Self>, l: IpcListener) -> Result<()> {
        loop {
            let (s, _) = l.accept().await?;
            tokio::spawn(self.clone().serve_ipc(s));
        }
    }

    async fn accept_p2p(self: Arc<Self>, l: TcpListener) {
        let gate = Arc::new(Semaphore::new(64));
        loop {
            let Ok((s, _)) = l.accept().await else { continue };
            let Ok(permit) = gate.clone().try_acquire_owned() else { continue };
            let n = self.clone();
            tokio::spawn(async move {
                let _ = s.set_nodelay(true);
                let hs = timeout(HANDSHAKE, wire::respond(s, &n.me, |k| n.cfg().peer_by_key(k).is_some())).await;
                drop(permit);
                if let Ok(Ok((key, r, w))) = hs {
                    if let Some(p) = n.cfg().peer_by_key(&key).map(|p| p.name.clone()) {
                        n.run_link(p, key, r, w, false).await;
                    }
                }
            });
        }
    }

    fn spawn_dialers(self: &Arc<Self>) {
        for p in self.cfg().peer.iter().filter(|p| p.addr.is_some()) {
            self.spawn_dialer(p.name.clone());
        }
    }

    fn spawn_dialer(self: &Arc<Self>, name: String) {
        if !self.st.lock().unwrap().dialing.insert(name.clone()) {
            return;
        }
        let n = self.clone();
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                let cfg = n.cfg();
                let Some(p) = cfg.peer(&name) else { break };
                let (Some(addr), Ok(key)) = (p.addr.clone(), config::decode_key(&p.key)) else { break };
                let connected = n.st.lock().unwrap().links.contains_key(&name);
                if connected {
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                let dial = async {
                    let s = TcpStream::connect(&addr).await?;
                    s.set_nodelay(true)?;
                    wire::initiate(s, &n.me, &key).await
                };
                match timeout(HANDSHAKE, dial).await {
                    Ok(Ok((r, w))) => {
                        backoff = 1;
                        n.run_link(name.clone(), key, r, w, true).await;
                        sleep(Duration::from_secs(1)).await;
                    }
                    Ok(Err(e)) => {
                        if backoff == 1 {
                            eprintln!("peer {name} ({addr}): {e}");
                        }
                        sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(60);
                    }
                    Err(_) => {
                        sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(60);
                    }
                }
            }
            n.st.lock().unwrap().dialing.remove(&name);
        });
    }

    async fn run_link(self: &Arc<Self>, peer: String, key: [u8; 32], mut r: wire::Reader, mut w: wire::Writer, i_initiated: bool) {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        {
            let mut st = self.st.lock().unwrap();
            if let Some(old) = st.links.get(&peer) {
                // Simultaneous dials: both sides keep the link opened by the lower key. Otherwise newest wins.
                let preferred = |mine: bool| mine == (self.me.public < key);
                if old.since.elapsed() < Duration::from_secs(3) && preferred(old.i_initiated) && !preferred(i_initiated) {
                    return;
                }
            }
            st.links.insert(peer.clone(), Link { tx: tx.clone(), id, key, i_initiated, since: Instant::now() });
            let agents: Vec<String> = st.sessions.keys().cloned().collect();
            let _ = tx.send(P2p::Presence { agents });
            let mut pending: Vec<Msg> = st.unacked.values().filter(|(p, _)| p == &peer).map(|(_, m)| m.clone()).collect();
            pending.extend(st.outbox.remove(&peer).unwrap_or_default());
            for m in pending {
                st.unacked.insert(m.id.clone(), (peer.clone(), m.clone()));
                let _ = tx.send(P2p::Msg(m));
            }
        }
        drop(tx);
        eprintln!("peer {peer} connected");
        let writer = async {
            let mut ping = tokio::time::interval(PING);
            loop {
                let m = tokio::select! {
                    m = rx.recv() => match m { Some(m) => m, None => break },
                    _ = ping.tick() => P2p::Ping,
                };
                if w.send(&serde_json::to_vec(&m).unwrap()).await.is_err() {
                    break;
                }
            }
        };
        let reader = async {
            while let Ok(Ok(b)) = timeout(IDLE, r.recv()).await {
                let Ok(m) = serde_json::from_slice::<P2p>(&b) else { break };
                self.on_p2p(&peer, m);
            }
        };
        tokio::select! { _ = writer => {}, _ = reader => {} }
        let mut st = self.st.lock().unwrap();
        if st.links.get(&peer).is_some_and(|l| l.id == id) {
            st.links.remove(&peer);
            st.remote_agents.remove(&peer);
            eprintln!("peer {peer} disconnected");
        }
    }

    fn on_p2p(self: &Arc<Self>, peer: &str, m: P2p) {
        match m {
            P2p::Ping => {}
            P2p::Presence { agents } => {
                let a = agents.into_iter().filter(|a| valid_name(a)).take(256).collect();
                self.st.lock().unwrap().remote_agents.insert(peer.to_string(), a);
            }
            P2p::Ack { id, ok, status } => {
                let mut st = self.st.lock().unwrap();
                if st.unacked.get(&id).is_some_and(|(p, _)| p == peer) {
                    st.unacked.remove(&id);
                    if let Some(w) = st.waiters.remove(&id) {
                        let _ = w.send((ok, status.chars().take(200).collect()));
                    }
                }
            }
            P2p::Msg(m) => {
                let id = m.id.clone();
                let (ok, status) = match self.inbound(peer, m) {
                    Ok(s) => (true, s),
                    Err(e) => (false, e.to_string()),
                };
                if let Some(l) = self.st.lock().unwrap().links.get(peer) {
                    let _ = l.tx.send(P2p::Ack { id, ok, status });
                }
            }
        }
    }

    fn inbound(self: &Arc<Self>, peer: &str, m: Msg) -> Result<String> {
        let guard = self.guard();
        if !valid_name(&m.from) || !(m.to == "*" || valid_name(&m.to)) || !valid_thread(&m.thread) || m.id.is_empty() || m.id.len() > 64 {
            bail!("invalid message");
        }
        if m.body.len() > guard.cfg.max_bytes {
            bail!("message larger than {} bytes", guard.cfg.max_bytes);
        }
        {
            let mut st = self.st.lock().unwrap();
            let rate = guard.cfg.per_minute.max(1) as f64;
            let b = st.buckets.entry(peer.to_string()).or_insert((rate, Instant::now()));
            b.0 = (b.0 + b.1.elapsed().as_secs_f64() * rate / 60.0).min(rate);
            b.1 = Instant::now();
            if b.0 < 1.0 {
                bail!("rate limited");
            }
            b.0 -= 1.0;
            if !st.seen_set.insert(m.id.clone()) {
                return Ok("duplicate".into());
            }
            st.seen.push_back(m.id.clone());
            if st.seen.len() > SEEN_MAX {
                let old = st.seen.pop_front().unwrap();
                st.seen_set.remove(&old);
            }
        }
        let (body, redacted) = guard.clean(&m.body);
        let ev = Event { id: m.id, from: format!("{}@{peer}", m.from), to: m.to, thread: m.thread, body, ts: m.ts, redacted };
        self.audit(json!({"ts": now(), "dir": "in", "peer": peer, "id": ev.id, "from": ev.from, "to": ev.to, "bytes": ev.body.len(), "redacted": ev.redacted}));
        self.deliver(ev)
    }

    /// Queues an event for local agents and wakes their sessions.
    fn deliver(self: &Arc<Self>, ev: Event) -> Result<String> {
        let mut st = self.st.lock().unwrap();
        let targets: Vec<String> = if ev.to == "*" {
            st.sessions.keys().cloned().collect()
        } else {
            vec![ev.to.clone()]
        };
        let targets = if targets.is_empty() { vec!["*".to_string()] } else { targets };
        let mut live = false;
        for t in &targets {
            if !st.queues.contains_key(t) && st.queues.len() >= QUEUES_MAX {
                bail!("too many waiting queues");
            }
            let q = st.queues.entry(t.clone()).or_default();
            if q.len() >= QUEUE_MAX {
                q.pop_front();
            }
            q.push_back(Event { to: t.clone(), ..ev.clone() });
            if let Some(s) = st.sessions.get(t) {
                s.notify.notify_one();
                live = true;
            }
        }
        if live {
            return Ok("delivered".into());
        }
        let wake = &self.cfg().wake;
        let due = |k: &str, every: Duration| st.woken.get(k).is_none_or(|t| t.elapsed() > every);
        if !wake.is_empty() && ev.to != "*" && due(&ev.to, WAKE_EVERY) && due("", Duration::from_secs(5)) {
            st.woken.insert(ev.to.clone(), Instant::now());
            st.woken.insert(String::new(), Instant::now());
            let mut cmd = tokio::process::Command::new(&wake[0]);
            cmd.args(&wake[1..]).env("AGORA_AGENT", &ev.to).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            match cmd.spawn() {
                Ok(mut c) => {
                    tokio::spawn(async move { let _ = c.wait().await; });
                    return Ok("held; waking agent".into());
                }
                Err(e) => eprintln!("wake {}: {e}", wake[0]),
            }
        }
        Ok("held until the agent connects".into())
    }

    fn broadcast_presence(&self, st: &State) {
        let agents: Vec<String> = st.sessions.keys().cloned().collect();
        for l in st.links.values() {
            let _ = l.tx.send(P2p::Presence { agents: agents.clone() });
        }
    }

    async fn send(self: &Arc<Self>, from: &str, to: &str, text: &str, thread: Option<String>) -> Result<Value> {
        let guard = self.guard();
        if text.len() > guard.cfg.max_bytes {
            bail!("message larger than {} bytes", guard.cfg.max_bytes);
        }
        if !valid_thread(&thread) {
            bail!("invalid thread id (letters, digits, - _ . up to 64)");
        }
        let (agent, peer) = split_addr(to)?;
        let (body, redacted) = guard.clean(text);
        let id = config::random_hex(16);
        let ts = now();
        let status = match &peer {
            None => self.deliver(Event { id: id.clone(), from: from.into(), to: agent.clone(), thread, body, ts, redacted: redacted.clone() })?,
            Some(p) => {
                if self.cfg().peer(p).is_none() {
                    bail!("unknown peer {p:?}; see agora_peers");
                }
                let m = Msg { id: id.clone(), from: from.into(), to: agent.clone(), thread, body, ts };
                let (wtx, wrx) = oneshot::channel();
                {
                    let mut st = self.st.lock().unwrap();
                    if let Some(l) = st.links.get(p) {
                        let tx = l.tx.clone();
                        st.unacked.insert(id.clone(), (p.clone(), m.clone()));
                        let _ = tx.send(P2p::Msg(m));
                    } else {
                        let q = st.outbox.entry(p.clone()).or_default();
                        if q.len() >= QUEUE_MAX {
                            bail!("outbox for {p} is full");
                        }
                        q.push_back(m);
                    }
                    st.waiters.insert(id.clone(), wtx);
                }
                match timeout(ACK_WAIT, wrx).await {
                    Ok(Ok((true, s))) => s,
                    Ok(Ok((false, s))) => bail!("rejected by {p}: {s}"),
                    _ => {
                        self.st.lock().unwrap().waiters.remove(&id);
                        "queued; will be sent when the peer is reachable".into()
                    }
                }
            }
        };
        self.audit(json!({"ts": ts, "dir": "out", "peer": peer, "id": id, "from": from, "to": to, "bytes": text.len(), "redacted": redacted, "status": status}));
        Ok(json!({"id": id, "status": status, "redacted": redacted}))
    }

    fn peers(&self, me: &str) -> Value {
        let cfg = self.cfg();
        let st = self.st.lock().unwrap();
        let peers: Vec<Value> = cfg
            .peer
            .iter()
            .map(|p| {
                json!({
                    "name": p.name,
                    "online": st.links.contains_key(&p.name),
                    "agents": st.remote_agents.get(&p.name).cloned().unwrap_or_default(),
                    "queued": st.outbox.get(&p.name).map_or(0, |q| q.len()),
                })
            })
            .collect();
        let local: Vec<&String> = st.sessions.keys().collect();
        json!({"you": me, "node_key": config::encode_key(&self.me.public), "local_agents": local, "peers": peers})
    }

    async fn inbox(&self, me: &str, notify: &Notify, wait: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(wait.min(600));
        loop {
            let msgs: Vec<Event> = self.st.lock().unwrap().queues.remove(me).map(Vec::from).unwrap_or_default();
            let left = deadline.saturating_duration_since(Instant::now());
            if !msgs.is_empty() || left.is_zero() {
                return json!({"messages": msgs});
            }
            let _ = timeout(left, notify.notified()).await;
        }
    }

    fn reload(self: &Arc<Self>) -> Result<Value> {
        let cfg = config::load()?;
        *self.guard.write().unwrap() = Arc::new(Guard::new(cfg.guard.clone()));
        *self.cfg.write().unwrap() = Arc::new(cfg.clone());
        {
            let mut st = self.st.lock().unwrap();
            st.links.retain(|name, l| cfg.peer(name).is_some_and(|p| config::decode_key(&p.key).is_ok_and(|k| k == l.key)));
            st.outbox.retain(|name, _| cfg.peer(name).is_some());
        }
        self.spawn_dialers();
        Ok(json!({"peers": cfg.peer.len()}))
    }

    fn register(&self, want: &str) -> (String, u64, Arc<Notify>) {
        let mut st = self.st.lock().unwrap();
        let mut name = want.to_string();
        let mut i = 2;
        while st.sessions.contains_key(&name) {
            name = format!("{want}-{i}");
            i += 1;
        }
        let sid = self.ids.fetch_add(1, Ordering::Relaxed);
        let notify = Arc::new(Notify::new());
        if let Some(any) = st.queues.remove("*") {
            for ev in any {
                st.queues.entry(name.clone()).or_default().push_back(Event { to: name.clone(), ..ev });
            }
        }
        notify.notify_one();
        st.sessions.insert(name.clone(), Session { sid, notify: notify.clone() });
        self.broadcast_presence(&st);
        (name, sid, notify)
    }

    fn unregister(&self, name: &str, sid: u64) {
        let mut st = self.st.lock().unwrap();
        if st.sessions.get(name).is_some_and(|s| s.sid == sid) {
            st.sessions.remove(name);
            self.broadcast_presence(&st);
        }
    }

    async fn serve_ipc<S: AsyncRead + AsyncWrite + Send + 'static>(self: Arc<Self>, s: S) {
        let (r, mut w) = tokio::io::split(s);
        let mut r = BufReader::new(r);
        let (out, mut out_rx) = mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(l) = out_rx.recv().await {
                if w.write_all(l.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        let reply = |v: Value| {
            let _ = out.send(format!("{v}\n"));
        };
        let Ok(Some(hello)) = read_json(&mut r).await else { return writer.abort() };
        if !hello["token"].as_str().is_some_and(|t| ct_eq(t, &self.token)) {
            reply(json!({"rid": hello["rid"], "ok": false, "error": "bad token"}));
            return;
        }
        let want = hello["agent"].as_str().filter(|a| valid_name(a)).unwrap_or("agent");
        let mode = hello["mode"].as_str().unwrap_or("pull");
        let (pull, push, none) = (mode == "pull", mode == "push", mode == "none");
        let (name, sid, notify) = if none { (want.to_string(), 0, Arc::new(Notify::new())) } else { self.register(want) };
        reply(json!({"rid": hello["rid"], "ok": true, "agent": name, "node_key": config::encode_key(&self.me.public)}));
        let pusher = push.then(|| {
            let (n, name, notify, out) = (self.clone(), name.clone(), notify.clone(), out.clone());
            tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    let msgs = n.st.lock().unwrap().queues.remove(&name).unwrap_or_default();
                    for ev in msgs {
                        if out.send(format!("{}\n", json!({"ev": "msg", "msg": ev}))).is_err() {
                            return;
                        }
                    }
                }
            })
        });
        while let Ok(Some(req)) = read_json(&mut r).await {
            let (n, name, notify, out) = (self.clone(), name.clone(), notify.clone(), out.clone());
            tokio::spawn(async move {
                let res = match req["op"].as_str().unwrap_or("") {
                    "send" => {
                        let thread = req["thread"].as_str().map(String::from);
                        n.send(&name, req["to"].as_str().unwrap_or(""), req["text"].as_str().unwrap_or(""), thread).await
                    }
                    "inbox" if pull => Ok(n.inbox(&name, &notify, req["wait"].as_u64().unwrap_or(0)).await),
                    "peers" => Ok(n.peers(&name)),
                    "reload" => n.reload(),
                    op => Err(anyhow!("unsupported op {op:?}")),
                };
                let v = match res {
                    Ok(mut v) => {
                        v["rid"] = req["rid"].clone();
                        v["ok"] = true.into();
                        v
                    }
                    Err(e) => json!({"rid": req["rid"], "ok": false, "error": e.to_string()}),
                };
                let _ = out.send(format!("{v}\n"));
            });
        }
        if !none {
            self.unregister(&name, sid);
        }
        if let Some(p) = pusher {
            p.abort();
        }
        writer.abort();
    }
}

pub async fn read_json<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<Option<Value>> {
    let mut buf = Vec::new();
    let n = (&mut *r).take(LINE_MAX).read_until(b'\n', &mut buf).await?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') && n as u64 >= LINE_MAX {
        bail!("line too long");
    }
    Ok(Some(serde_json::from_slice(&buf)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(split_addr("claude@laptop").unwrap(), ("claude".into(), Some("laptop".into())));
        assert_eq!(split_addr("copilot").unwrap(), ("copilot".into(), None));
        assert_eq!(split_addr("*@hpc").unwrap(), ("*".into(), Some("hpc".into())));
        for bad in ["", "a@", "@p", "a b@p", "a@p q", "../x"] {
            assert!(split_addr(bad).is_err(), "{bad}");
        }
    }
}
