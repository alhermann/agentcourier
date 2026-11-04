//! The per-machine node: identity, encrypted peer links, pairing, per-agent queues, file transfer
//! and the authenticated local control socket.
use crate::config::{self, Config, Identity, Peer, valid_name};
use crate::files::{self, Kind};
use crate::guard::Guard;
use crate::wire;
use anyhow::{Result, anyhow, bail};
use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac256, Digest};
use data_encoding::{BASE32_NOPAD, BASE64, HEXLOWER};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
const FILE_WAIT: Duration = Duration::from_secs(330);
const INVITE_TTL: Duration = Duration::from_secs(600);
const WAKE_EVERY: Duration = Duration::from_secs(60);
const QUEUE_MAX: usize = 1000;
const QUEUES_MAX: usize = 256;
const SEEN_MAX: usize = 8192;
const REFUSED_MAX: usize = 20;
const FILES_INFLIGHT: usize = 4;
const CHUNK: usize = 256 * 1024;
const LINE_MAX: u64 = 4 << 20;
const AUDIT_MAX: u64 = 10 << 20;
const INVITE_PREFIX: &str = "agora-";

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "t", rename_all = "snake_case")]
enum P2p {
    Msg(Msg),
    Ack { id: String, ok: bool, status: String },
    Presence { agents: Vec<String> },
    Ping,
    Join { secret: String },
    Joined,
    FileStart(FileMeta),
    FileChunk { id: String, seq: u64, data: String },
    FileEnd { id: String },
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

#[derive(Serialize, Deserialize, Clone)]
struct FileMeta {
    id: String,
    from: String,
    to: String,
    name: String,
    size: u64,
    hash: String,
    #[serde(default)]
    note: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    file: Option<Value>,
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

struct Invite {
    secret: [u8; 16],
    name: String,
    files: bool,
    expires: Instant,
}

struct Incoming {
    meta: FileMeta,
    peer: String,
    file: std::fs::File,
    path: PathBuf,
    got: u64,
    seq: u64,
    hasher: Blake2s256,
}

type Waiter = (String, oneshot::Sender<(bool, String)>);

#[derive(Default)]
struct State {
    sessions: HashMap<String, Session>,
    queues: HashMap<String, VecDeque<Event>>,
    links: HashMap<String, Link>,
    outbox: HashMap<String, VecDeque<Msg>>,
    unacked: HashMap<String, (String, Msg)>,
    waiters: HashMap<String, Waiter>,
    remote_agents: HashMap<String, Vec<String>>,
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
    buckets: HashMap<String, (f64, Instant)>,
    woken: HashMap<String, Instant>,
    dialing: HashSet<String>,
    invites: Vec<Invite>,
    refused: VecDeque<(String, String, SystemTime)>,
    incoming: HashMap<String, Incoming>,
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

pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Keyed BLAKE2s over length-prefixed parts; proves knowledge of the local token without revealing it.
pub fn mac(token: &str, parts: &[&str]) -> String {
    let key = HEXLOWER.decode(token.as_bytes()).unwrap_or_default();
    let mut m = <Blake2sMac256 as KeyInit>::new_from_slice(&key).expect("token is 32 bytes");
    for p in parts {
        Mac::update(&mut m, &(p.len() as u32).to_be_bytes());
        Mac::update(&mut m, p.as_bytes());
    }
    HEXLOWER.encode(&m.finalize().into_bytes())
}

pub fn encode_invite(key: &[u8; 32], secret: &[u8; 16]) -> String {
    let mut b = key.to_vec();
    b.extend_from_slice(secret);
    format!("{INVITE_PREFIX}{}", BASE32_NOPAD.encode(&b).to_ascii_lowercase())
}

pub fn decode_invite(code: &str) -> Result<([u8; 32], [u8; 16])> {
    let body = code.trim().strip_prefix(INVITE_PREFIX).ok_or_else(|| anyhow!("not an agora invite code"))?;
    let b = BASE32_NOPAD.decode(body.to_ascii_uppercase().as_bytes()).map_err(|_| anyhow!("malformed invite code"))?;
    if b.len() != 48 {
        bail!("malformed invite code");
    }
    Ok((b[..32].try_into()?, b[32..].try_into()?))
}

fn dir_size(p: &Path) -> u64 {
    std::fs::read_dir(p)
        .map(|rd| {
            rd.flatten()
                .map(|e| match e.file_type() {
                    Ok(t) if t.is_dir() => dir_size(&e.path()),
                    Ok(_) => e.metadata().map(|m| m.len()).unwrap_or(0),
                    Err(_) => 0,
                })
                .sum()
        })
        .unwrap_or(0)
}

fn files_dir() -> PathBuf {
    config::home().join("files")
}

pub async fn run() -> Result<()> {
    config::ensure_home()?;
    config::harden_home();
    let me = config::identity()?;
    let cfg = config::load()?;
    let token = config::ipc_token()?;
    let ipc = ipc_bind(&cfg).await?;
    let p2p = TcpListener::bind(&cfg.listen).await.map_err(|e| anyhow!("bind {}: {e}", cfg.listen))?;
    let _ = std::fs::remove_dir_all(files_dir().join(".partial"));
    let audit = open_audit();
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

fn open_audit() -> Option<std::fs::File> {
    config::open_private_append(&config::home().join("audit.jsonl")).ok()
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
        let mut a = self.audit.lock().unwrap();
        if a.as_ref().and_then(|f| f.metadata().ok()).is_some_and(|m| m.len() > AUDIT_MAX) {
            let p = config::home().join("audit.jsonl");
            let _ = std::fs::rename(&p, p.with_extension("jsonl.1"));
            *a = open_audit();
        }
        if let Some(f) = a.as_mut() {
            let _ = writeln!(f, "{v}");
        }
    }

    /// Persists and applies a new configuration; drops links to peers that are no longer trusted.
    fn apply(self: &Arc<Self>, cfg: Config) -> Result<()> {
        config::save(&cfg)?;
        *self.guard.write().unwrap() = Arc::new(Guard::new(cfg.guard.clone()));
        *self.cfg.write().unwrap() = Arc::new(cfg.clone());
        {
            let mut st = self.st.lock().unwrap();
            st.links.retain(|name, l| cfg.peer(name).is_some_and(|p| config::decode_key(&p.key).is_ok_and(|k| k == l.key)));
            st.outbox.retain(|name, _| cfg.peer(name).is_some());
            st.remote_agents.retain(|name, _| cfg.peer(name).is_some());
        }
        self.spawn_dialers();
        Ok(())
    }

    async fn accept_ipc(self: &Arc<Self>, l: IpcListener) -> Result<()> {
        loop {
            let (s, _) = l.accept().await?;
            tokio::spawn(self.clone().serve_ipc(s));
        }
    }

    fn invites_open(&self) -> bool {
        let mut st = self.st.lock().unwrap();
        st.invites.retain(|i| i.expires > Instant::now());
        !st.invites.is_empty()
    }

    fn note_refused(&self, key: &[u8; 32], addr: SocketAddr) {
        let k = config::encode_key(key);
        eprintln!("refused handshake from {addr} (key {k})");
        let mut st = self.st.lock().unwrap();
        st.refused.retain(|(rk, _, _)| rk != &k);
        st.refused.push_back((k, addr.to_string(), SystemTime::now()));
        if st.refused.len() > REFUSED_MAX {
            st.refused.pop_front();
        }
    }

    async fn accept_p2p(self: Arc<Self>, l: TcpListener) {
        let gate = Arc::new(Semaphore::new(64));
        loop {
            let Ok((s, addr)) = l.accept().await else { continue };
            let Ok(permit) = gate.clone().try_acquire_owned() else { continue };
            let n = self.clone();
            tokio::spawn(async move {
                let _ = s.set_nodelay(true);
                let allowed = |k: &[u8; 32]| n.cfg().peer_by_key(k).is_some() || n.invites_open();
                let hs = timeout(HANDSHAKE, wire::respond(s, &n.me, allowed)).await;
                drop(permit);
                match hs {
                    Ok(Ok((key, Some((r, w))))) => match n.cfg().peer_by_key(&key).map(|p| p.name.clone()) {
                        Some(p) => n.run_link(p, key, r, w, false, false).await,
                        None => n.pairing(key, addr, r, w).await,
                    },
                    Ok(Ok((key, None))) => n.note_refused(&key, addr),
                    _ => {}
                }
            });
        }
    }

    /// An unknown key may only present a valid one-time invite secret, then becomes a trusted peer.
    async fn pairing(self: &Arc<Self>, key: [u8; 32], addr: SocketAddr, mut r: wire::Reader, mut w: wire::Writer) {
        let secret = match timeout(HANDSHAKE, r.recv()).await {
            Ok(Ok(b)) => match serde_json::from_slice::<P2p>(&b) {
                Ok(P2p::Join { secret }) => secret,
                _ => return self.note_refused(&key, addr),
            },
            _ => return,
        };
        let invite = {
            let mut st = self.st.lock().unwrap();
            st.invites.retain(|i| i.expires > Instant::now());
            match st.invites.iter().position(|i| ct_eq(&HEXLOWER.encode(&i.secret), &secret)) {
                Some(i) => Some(st.invites.remove(i)),
                None => None,
            }
        };
        let Some(inv) = invite else {
            // 128-bit secrets cannot be guessed; slowing failures just keeps probing cheap for us.
            sleep(Duration::from_secs(1)).await;
            return self.note_refused(&key, addr);
        };
        let mut cfg = (*self.cfg()).clone();
        if cfg.peer(&inv.name).is_some() || cfg.peer_by_key(&key).is_some() {
            return;
        }
        cfg.peer.push(Peer { name: inv.name.clone(), key: config::encode_key(&key), addr: None, files: inv.files });
        if let Err(e) = self.apply(cfg) {
            eprintln!("pairing {}: {e}", inv.name);
            return;
        }
        self.audit(json!({"ts": now(), "dir": "pair", "peer": inv.name, "key": config::encode_key(&key), "from": addr.to_string()}));
        eprintln!("paired with {} ({addr})", inv.name);
        if w.send(&serde_json::to_vec(&P2p::Joined).unwrap()).await.is_ok() {
            self.run_link(inv.name, key, r, w, false, true).await;
        }
    }

    async fn join(self: &Arc<Self>, code: &str, name: &str, addr: &str) -> Result<Value> {
        if !valid_name(name) || !addr.contains(':') {
            bail!("usage: agora join <code> <name> <host:port>");
        }
        let (key, secret) = decode_invite(code)?;
        let cfg = self.cfg();
        if key == self.me.public {
            bail!("that invite is from this machine");
        }
        if let Some(p) = cfg.peer_by_key(&key) {
            bail!("already paired with this machine as {}", p.name);
        }
        if cfg.peer(name).is_some() {
            bail!("the name {name} is already used");
        }
        let s = timeout(HANDSHAKE, TcpStream::connect(addr)).await.map_err(|_| anyhow!("timeout connecting to {addr}"))??;
        s.set_nodelay(true)?;
        let (mut r, mut w) = timeout(HANDSHAKE, wire::initiate(s, &self.me, &key))
            .await
            .map_err(|_| anyhow!("no answer: the code is wrong, used or expired, or {addr} is not that machine"))?
            .map_err(|_| anyhow!("refused: the code is wrong, used or expired, or {addr} is not that machine"))?;
        w.send(&serde_json::to_vec(&P2p::Join { secret: HEXLOWER.encode(&secret) })?).await?;
        match timeout(HANDSHAKE, r.recv()).await {
            Ok(Ok(b)) if matches!(serde_json::from_slice(&b), Ok(P2p::Joined)) => {}
            _ => bail!("refused: the code is wrong, used or expired"),
        }
        let mut cfg = (*cfg).clone();
        cfg.peer.push(Peer { name: name.into(), key: config::encode_key(&key), addr: Some(addr.into()), files: true });
        self.apply(cfg)?;
        self.audit(json!({"ts": now(), "dir": "pair", "peer": name, "key": config::encode_key(&key), "addr": addr}));
        let (n, nm) = (self.clone(), name.to_string());
        tokio::spawn(async move { n.run_link(nm, key, r, w, true, true).await });
        Ok(json!({"paired": name, "key": config::encode_key(&key)}))
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
                        n.run_link(name.clone(), key, r, w, true, false).await;
                        sleep(Duration::from_secs(1)).await;
                    }
                    res => {
                        if backoff == 1 {
                            let why = match res {
                                Ok(Err(e)) => e.to_string(),
                                _ => "timeout".into(),
                            };
                            eprintln!("peer {name} ({addr}): {why}");
                        }
                        sleep(Duration::from_secs(backoff)).await;
                        backoff = (backoff * 2).min(60);
                    }
                }
            }
            n.st.lock().unwrap().dialing.remove(&name);
        });
    }

    /// `fresh`: the peer already proved it holds the live session keys (pairing). Otherwise an inbound
    /// link counts only after its first valid message, so a replayed handshake cannot displace a live link.
    async fn run_link(self: &Arc<Self>, peer: String, key: [u8; 32], mut r: wire::Reader, mut w: wire::Writer, i_initiated: bool, fresh: bool) {
        let mut first = None;
        if !i_initiated && !fresh {
            match timeout(HANDSHAKE, r.recv()).await {
                Ok(Ok(b)) => match serde_json::from_slice::<P2p>(&b) {
                    Ok(m) => first = Some(m),
                    Err(_) => return,
                },
                _ => return,
            }
        }
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
            pending.sort_by_key(|m| m.ts);
            pending.extend(st.outbox.remove(&peer).unwrap_or_default());
            for m in pending {
                st.unacked.insert(m.id.clone(), (peer.clone(), m.clone()));
                let _ = tx.send(P2p::Msg(m));
            }
        }
        drop(tx);
        eprintln!("peer {peer} connected ({})", if i_initiated { "outbound" } else { "inbound" });
        if let Some(m) = first {
            self.on_p2p(&peer, m);
        }
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
            let stale: Vec<String> = st.incoming.iter().filter(|(_, i)| i.peer == peer).map(|(k, _)| k.clone()).collect();
            for k in stale {
                if let Some(i) = st.incoming.remove(&k) {
                    let _ = std::fs::remove_file(i.path);
                }
            }
            eprintln!("peer {peer} disconnected");
        }
    }

    fn reply(&self, peer: &str, id: String, res: Result<String>) {
        let (ok, status) = match res {
            Ok(s) => (true, s),
            Err(e) => (false, e.to_string()),
        };
        if let Some(l) = self.st.lock().unwrap().links.get(peer) {
            let _ = l.tx.send(P2p::Ack { id, ok, status });
        }
    }

    fn on_p2p(self: &Arc<Self>, peer: &str, m: P2p) {
        match m {
            P2p::Ping | P2p::Join { .. } | P2p::Joined => {}
            P2p::Presence { agents } => {
                let a = agents.into_iter().filter(|a| valid_name(a)).take(256).collect();
                self.st.lock().unwrap().remote_agents.insert(peer.to_string(), a);
            }
            P2p::Ack { id, ok, status } => {
                let mut st = self.st.lock().unwrap();
                if st.unacked.get(&id).is_some_and(|(p, _)| p == peer) {
                    st.unacked.remove(&id);
                }
                if st.waiters.get(&id).is_some_and(|(p, _)| p == peer) {
                    let (_, w) = st.waiters.remove(&id).unwrap();
                    let _ = w.send((ok, status.chars().take(300).collect()));
                }
            }
            P2p::Msg(m) => {
                let id = m.id.clone();
                let res = self.inbound(peer, m);
                self.reply(peer, id, res);
            }
            P2p::FileStart(meta) => {
                let id = meta.id.clone();
                if let Err(e) = self.file_start(peer, meta) {
                    self.reply(peer, id, Err(e));
                }
            }
            P2p::FileChunk { id, seq, data } => {
                if let Err(e) = self.file_chunk(peer, &id, seq, &data) {
                    self.drop_incoming(&id);
                    self.reply(peer, id, Err(e));
                }
            }
            P2p::FileEnd { id } => {
                let inc = {
                    let mut st = self.st.lock().unwrap();
                    if st.incoming.get(&id).is_some_and(|i| i.peer == peer) { st.incoming.remove(&id) } else { None }
                };
                let Some(inc) = inc else { return };
                let (n, p) = (self.clone(), peer.to_string());
                tokio::spawn(async move {
                    let path = inc.path.clone();
                    let res = n.file_finish(&p, inc).await;
                    if res.is_err() {
                        let _ = std::fs::remove_file(path);
                    }
                    if let Err(e) = &res {
                        n.audit(json!({"ts": now(), "dir": "in", "peer": p, "id": id, "file": true, "status": e.to_string()}));
                    }
                    n.reply(&p, id, res);
                });
            }
        }
    }

    fn admit(&self, peer: &str, id: &str) -> Result<bool> {
        let guard = self.guard();
        let mut st = self.st.lock().unwrap();
        let rate = guard.cfg.per_minute.max(1) as f64;
        let b = st.buckets.entry(peer.to_string()).or_insert((rate, Instant::now()));
        b.0 = (b.0 + b.1.elapsed().as_secs_f64() * rate / 60.0).min(rate);
        b.1 = Instant::now();
        if b.0 < 1.0 {
            bail!("rate limited");
        }
        b.0 -= 1.0;
        let key = format!("{peer}/{id}");
        if !st.seen_set.insert(key.clone()) {
            return Ok(false);
        }
        st.seen.push_back(key);
        if st.seen.len() > SEEN_MAX {
            let old = st.seen.pop_front().unwrap();
            st.seen_set.remove(&old);
        }
        Ok(true)
    }

    fn inbound(self: &Arc<Self>, peer: &str, m: Msg) -> Result<String> {
        let guard = self.guard();
        if !valid_name(&m.from) || !(m.to == "*" || valid_name(&m.to)) || !valid_thread(&m.thread) || !valid_name(&m.id) {
            bail!("invalid message");
        }
        if m.body.len() > guard.cfg.max_bytes {
            bail!("message larger than {} bytes", guard.cfg.max_bytes);
        }
        if !self.admit(peer, &m.id)? {
            return Ok("duplicate".into());
        }
        let (body, redacted) = guard.clean(&m.body);
        let ev = Event { id: m.id, from: format!("{}@{peer}", m.from), to: m.to, thread: m.thread, body, ts: m.ts, redacted, file: None };
        self.audit(json!({"ts": now(), "dir": "in", "peer": peer, "id": ev.id, "from": ev.from, "to": ev.to, "bytes": ev.body.len(), "redacted": ev.redacted}));
        self.deliver(ev)
    }

    fn drop_incoming(&self, id: &str) {
        if let Some(i) = self.st.lock().unwrap().incoming.remove(id) {
            let _ = std::fs::remove_file(i.path);
        }
    }

    fn file_start(&self, peer: &str, meta: FileMeta) -> Result<()> {
        let cfg = self.cfg();
        if !cfg.files.enabled || !cfg.peer(peer).is_some_and(|p| p.files) {
            bail!("file exchange with this machine is turned off");
        }
        if !valid_name(&meta.id) || !valid_name(&meta.from) || !valid_name(&meta.to) || meta.name.is_empty() || meta.name.len() > 255 {
            bail!("invalid file header");
        }
        if meta.hash.len() != 64 || HEXLOWER.decode(meta.hash.as_bytes()).is_err() || meta.note.as_ref().is_some_and(|n| n.len() > 4096) {
            bail!("invalid file header");
        }
        if meta.size > cfg.files.max_bytes {
            bail!("file larger than {} bytes", cfg.files.max_bytes);
        }
        if !self.admit(peer, &meta.id)? {
            bail!("duplicate file id");
        }
        if dir_size(&files_dir()) + meta.size > cfg.files.quota_bytes {
            bail!("receiver storage quota is full");
        }
        let mut st = self.st.lock().unwrap();
        if st.incoming.values().filter(|i| i.peer == peer).count() >= FILES_INFLIGHT {
            bail!("too many files in transit");
        }
        let dir = files_dir().join(".partial");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(&meta.id);
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        st.incoming.insert(meta.id.clone(), Incoming { meta, peer: peer.into(), file, path, got: 0, seq: 0, hasher: Blake2s256::new() });
        Ok(())
    }

    fn file_chunk(&self, peer: &str, id: &str, seq: u64, data: &str) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        let Some(inc) = st.incoming.get_mut(id).filter(|i| i.peer == peer) else { bail!("unknown transfer") };
        if seq != inc.seq || data.len() > CHUNK * 4 / 3 + 8 {
            bail!("corrupt transfer");
        }
        let bytes = BASE64.decode(data.as_bytes()).map_err(|_| anyhow!("corrupt transfer"))?;
        inc.got += bytes.len() as u64;
        if inc.got > inc.meta.size {
            bail!("file longer than announced");
        }
        inc.file.write_all(&bytes)?;
        inc.hasher.update(&bytes);
        inc.seq += 1;
        Ok(())
    }

    async fn file_finish(self: &Arc<Self>, peer: &str, inc: Incoming) -> Result<String> {
        let Incoming { meta, file, path, got, hasher, .. } = inc;
        drop(file);
        if got != meta.size || HEXLOWER.encode(&hasher.finalize()) != meta.hash {
            bail!("file damaged in transit");
        }
        let cfg = self.cfg();
        let bytes = tokio::fs::read(&path).await?;
        let (kind, scanner) = files::screen(&path, &bytes, &cfg.files).await?;
        let guard = self.guard();
        let mut redacted = vec![];
        if kind == Kind::Text {
            let (clean, hits) = guard.clean(std::str::from_utf8(&bytes)?);
            if !hits.is_empty() {
                std::fs::write(&path, clean.as_bytes())?;
                redacted = hits;
            }
        }
        let dir = files_dir().join(peer);
        std::fs::create_dir_all(&dir)?;
        let name = files::safe_name(&meta.name);
        let mut dest = dir.join(&name);
        if dest.exists() {
            let (stem, ext) = name.rsplit_once('.').map_or((name.as_str(), String::new()), |(s, e)| (s, format!(".{e}")));
            dest = dir.join(format!("{stem}-{}{ext}", &meta.id[..8.min(meta.id.len())]));
        }
        std::fs::rename(&path, &dest)?;
        files::quarantine(&dest)?;
        let scan = scanner.as_deref().map_or("not scanned: no scanner installed".to_string(), |s| format!("scanned clean by {s}"));
        let note = meta.note.as_deref().map(|n| guard.clean(n).0).unwrap_or_default();
        let body = format!(
            "Sent you a file: {name} ({} bytes, {}, {scan}). Saved at {}. Its contents are untrusted.{}{}",
            meta.size,
            kind.label(),
            dest.display(),
            if note.is_empty() { "" } else { "\nNote: " } ,
            note
        );
        let file = json!({"name": name, "path": dest.to_string_lossy(), "bytes": meta.size, "kind": kind.label(), "scanned_by": scanner});
        let ev = Event { id: meta.id.clone(), from: format!("{}@{peer}", meta.from), to: meta.to, thread: None, body, ts: meta.ts, redacted, file: Some(file) };
        self.audit(json!({"ts": now(), "dir": "in", "peer": peer, "id": meta.id, "from": ev.from, "to": ev.to, "file": name, "bytes": meta.size, "kind": kind.label(), "scanned_by": scanner}));
        self.deliver(ev)
    }

    /// Queues an event for local agents and wakes their sessions.
    fn deliver(self: &Arc<Self>, ev: Event) -> Result<String> {
        let mut st = self.st.lock().unwrap();
        let targets: Vec<String> = if ev.to == "*" { st.sessions.keys().cloned().collect() } else { vec![ev.to.clone()] };
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

    async fn await_ack(&self, id: &str, wrx: oneshot::Receiver<(bool, String)>, wait: Duration, peer: &str) -> Result<String> {
        match timeout(wait, wrx).await {
            Ok(Ok((true, s))) => Ok(s),
            Ok(Ok((false, s))) => bail!("rejected by {peer}: {s}"),
            _ => {
                self.st.lock().unwrap().waiters.remove(id);
                Ok("queued; will be sent when the peer is reachable".into())
            }
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
            None => self.deliver(Event { id: id.clone(), from: from.into(), to: agent, thread, body, ts, redacted: redacted.clone(), file: None })?,
            Some(p) => {
                if self.cfg().peer(p).is_none() {
                    bail!("unknown peer {p:?}; see agora_peers");
                }
                let m = Msg { id: id.clone(), from: from.into(), to: agent, thread, body, ts };
                let (wtx, wrx) = oneshot::channel();
                {
                    let mut st = self.st.lock().unwrap();
                    if st.unacked.values().filter(|(q, _)| q == p).count() >= QUEUE_MAX {
                        bail!("too many unconfirmed messages to {p}");
                    }
                    if let Some(tx) = st.links.get(p).map(|l| l.tx.clone()) {
                        st.unacked.insert(id.clone(), (p.clone(), m.clone()));
                        let _ = tx.send(P2p::Msg(m));
                    } else {
                        let q = st.outbox.entry(p.clone()).or_default();
                        if q.len() >= QUEUE_MAX {
                            bail!("outbox for {p} is full");
                        }
                        q.push_back(m);
                    }
                    st.waiters.insert(id.clone(), (p.clone(), wtx));
                }
                self.await_ack(&id, wrx, ACK_WAIT, p).await?
            }
        };
        self.audit(json!({"ts": ts, "dir": "out", "peer": peer, "id": id, "from": from, "to": to, "bytes": text.len(), "redacted": redacted, "status": status}));
        Ok(json!({"id": id, "status": status, "redacted": redacted}))
    }

    async fn send_file(self: &Arc<Self>, from: &str, root: Option<&Path>, to: &str, path: &str, note: Option<&str>) -> Result<Value> {
        let cfg = self.cfg();
        if !cfg.files.enabled {
            bail!("file exchange is turned off on this machine");
        }
        let (agent, peer) = split_addr(to)?;
        let Some(p) = peer else { bail!("files go to agents on other machines; sessions on this machine can open the path directly") };
        if agent == "*" {
            bail!("send files to one agent, not *");
        }
        if !cfg.peer(&p).ok_or_else(|| anyhow!("unknown peer {p:?}"))?.files {
            bail!("file exchange with {p} is turned off (agora files {p} on)");
        }
        let root = root.ok_or_else(|| anyhow!("no project folder known; start agora mcp inside the project or pass --root"))?;
        let shown = root.display().to_string();
        let root = std::fs::canonicalize(root)?;
        let full = std::fs::canonicalize(root.join(path)).map_err(|e| anyhow!("{path}: {e}"))?;
        if !full.starts_with(&root) {
            bail!("only files inside {shown} can be sent");
        }
        if files::sensitive(&full) {
            bail!("refused: {path} looks like a credential or key file");
        }
        let meta = std::fs::metadata(&full)?;
        if !meta.is_file() {
            bail!("{path} is not a regular file");
        }
        if meta.len() > cfg.files.max_bytes {
            bail!("file larger than {} bytes", cfg.files.max_bytes);
        }
        let bytes = tokio::fs::read(&full).await?;
        let kind = files::classify(&bytes);
        if kind == Kind::Executable && !cfg.files.allow_executables {
            bail!("refused: executable content");
        }
        if kind == Kind::Text {
            let (_, hits) = self.guard().redact(std::str::from_utf8(&bytes)?);
            if hits.iter().any(|h| ["private_key", "token", "secret", "credentials"].contains(h)) {
                bail!("refused: the file contains secrets ({})", hits.join(", "));
            }
            if cfg.files.block_pii && !hits.is_empty() {
                bail!("refused: the file contains personal data ({})", hits.join(", "));
            }
        }
        let note = note.map(|n| self.guard().clean(&n.chars().take(4096).collect::<String>()).0);
        let id = config::random_hex(16);
        let name = files::safe_name(&full.file_name().unwrap_or_default().to_string_lossy());
        let hash = HEXLOWER.encode(&Blake2s256::digest(&bytes));
        let fm = FileMeta { id: id.clone(), from: from.into(), to: agent, name: name.clone(), size: bytes.len() as u64, hash, note, ts: now() };
        let (wtx, wrx) = oneshot::channel();
        {
            let mut st = self.st.lock().unwrap();
            let Some(tx) = st.links.get(&p).map(|l| l.tx.clone()) else { bail!("{p} is offline; files are only sent to connected machines") };
            st.waiters.insert(id.clone(), (p.clone(), wtx));
            let _ = tx.send(P2p::FileStart(fm));
            for (seq, c) in bytes.chunks(CHUNK).enumerate() {
                let _ = tx.send(P2p::FileChunk { id: id.clone(), seq: seq as u64, data: BASE64.encode(c) });
            }
            let _ = tx.send(P2p::FileEnd { id: id.clone() });
        }
        let status = match timeout(FILE_WAIT, wrx).await {
            Ok(Ok((true, s))) => s,
            Ok(Ok((false, s))) => bail!("rejected by {p}: {s}"),
            _ => {
                self.st.lock().unwrap().waiters.remove(&id);
                bail!("no confirmation from {p}; the transfer may have been interrupted")
            }
        };
        self.audit(json!({"ts": now(), "dir": "out", "peer": p, "id": id, "from": from, "to": to, "file": name, "bytes": bytes.len(), "status": status}));
        Ok(json!({"id": id, "file": name, "bytes": bytes.len(), "status": status}))
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
                    "files": p.files && cfg.files.enabled,
                    "queued": st.outbox.get(&p.name).map_or(0, |q| q.len()),
                })
            })
            .collect();
        let local: Vec<&String> = st.sessions.keys().collect();
        json!({"you": me, "local_agents": local, "peers": peers})
    }

    fn status(&self) -> Value {
        let cfg = self.cfg();
        let st = self.st.lock().unwrap();
        let peers: Vec<Value> = cfg
            .peer
            .iter()
            .map(|p| {
                let l = st.links.get(&p.name);
                json!({
                    "name": p.name,
                    "key": p.key,
                    "addr": p.addr,
                    "online": l.is_some(),
                    "direction": l.map(|l| if l.i_initiated { "outbound" } else { "inbound" }),
                    "connected_secs": l.map(|l| l.since.elapsed().as_secs()),
                    "agents": st.remote_agents.get(&p.name).cloned().unwrap_or_default(),
                    "files": p.files,
                    "queued": st.outbox.get(&p.name).map_or(0, |q| q.len()),
                })
            })
            .collect();
        let refused: Vec<Value> = st
            .refused
            .iter()
            .rev()
            .map(|(k, a, t)| json!({"key": k, "from": a, "secs_ago": t.elapsed().map(|d| d.as_secs()).unwrap_or(0)}))
            .collect();
        let invites: Vec<Value> = st
            .invites
            .iter()
            .filter(|i| i.expires > Instant::now())
            .map(|i| json!({"for": i.name, "expires_in_secs": i.expires.saturating_duration_since(Instant::now()).as_secs()}))
            .collect();
        json!({
            "key": config::encode_key(&self.me.public),
            "listen": cfg.listen,
            "encryption": "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s + ML-KEM-768",
            "local_agents": st.sessions.keys().collect::<Vec<_>>(),
            "peers": peers,
            "open_invites": invites,
            "refused_handshakes": refused,
            "files": {"enabled": cfg.files.enabled, "scanner": files::scanner_name(&cfg.files), "inbox": files_dir().to_string_lossy()},
        })
    }

    fn invite(&self, name: &str, files: bool) -> Result<Value> {
        if !valid_name(name) {
            bail!("invalid name {name:?}");
        }
        if self.cfg().peer(name).is_some() {
            bail!("{name} is already a trusted peer");
        }
        let mut secret = [0u8; 16];
        getrandom::fill(&mut secret).map_err(|e| anyhow!("random: {e}"))?;
        let mut st = self.st.lock().unwrap();
        st.invites.retain(|i| i.expires > Instant::now() && i.name != name);
        if st.invites.len() >= 16 {
            bail!("too many open invites");
        }
        st.invites.push(Invite { secret, name: name.into(), files, expires: Instant::now() + INVITE_TTL });
        Ok(json!({"code": encode_invite(&self.me.public, &secret), "for": name, "expires_in_secs": INVITE_TTL.as_secs(), "listen": self.cfg().listen}))
    }

    fn admin(self: &Arc<Self>, op: &str, req: &Value) -> Result<Value> {
        let s = |k: &str| req[k].as_str().unwrap_or("");
        let mut cfg = (*self.cfg()).clone();
        match op {
            "trust" => {
                let (name, key) = (s("name"), config::decode_key(s("key"))?);
                if !valid_name(name) {
                    bail!("invalid peer name {name:?}");
                }
                if key == self.me.public {
                    bail!("that is this machine's own key");
                }
                let addr = req["addr"].as_str().map(String::from);
                if addr.as_deref().is_some_and(|a| !a.contains(':')) {
                    bail!("address must be host:port");
                }
                cfg.peer.retain(|x| x.name != name && config::decode_key(&x.key).ok() != Some(key));
                cfg.peer.push(Peer { name: name.into(), key: config::encode_key(&key), addr, files: true });
            }
            "untrust" => {
                let before = cfg.peer.len();
                cfg.peer.retain(|x| x.name != s("name"));
                if cfg.peer.len() == before {
                    bail!("no peer named {}", s("name"));
                }
            }
            "files" => {
                let on = req["on"].as_bool().unwrap_or(false);
                cfg.peer.iter_mut().find(|p| p.name == s("name")).ok_or_else(|| anyhow!("no peer named {}", s("name")))?.files = on;
            }
            "reload" => cfg = config::load()?,
            _ => bail!("unsupported op"),
        }
        self.apply(cfg)?;
        self.audit(json!({"ts": now(), "dir": "admin", "op": op, "peer": req["name"]}));
        Ok(json!({"done": op}))
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
        let challenge = config::random_hex(16);
        let _ = out.send(format!("{}\n", json!({"challenge": challenge})));
        let Ok(Ok(Some(hello))) = timeout(HANDSHAKE, read_json(&mut r)).await else { return writer.abort() };
        let nonce = hello["nonce"].as_str().unwrap_or("");
        let proof = hello["proof"].as_str().unwrap_or("");
        if hello["op"] != "hello" || nonce.len() != 32 || !ct_eq(proof, &mac(&self.token, &["client", &challenge, nonce])) {
            let _ = out.send(format!("{}\n", json!({"rid": hello["rid"], "ok": false, "error": "authentication failed"})));
            sleep(Duration::from_millis(200)).await;
            return writer.abort();
        }
        let want = hello["agent"].as_str().filter(|a| valid_name(a)).unwrap_or("agent");
        let mode = hello["mode"].as_str().unwrap_or("pull");
        let (pull, push, none) = (mode == "pull", mode == "push", mode == "none");
        let root: Option<PathBuf> = hello["root"].as_str().filter(|r| !r.is_empty()).map(PathBuf::from);
        let (name, sid, notify) = if none { (want.to_string(), 0, Arc::new(Notify::new())) } else { self.register(want) };
        let _ = out.send(format!(
            "{}\n",
            json!({"rid": hello["rid"], "ok": true, "agent": name, "proof": mac(&self.token, &["node", &challenge, nonce])})
        ));
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
            let (n, name, notify, out, root) = (self.clone(), name.clone(), notify.clone(), out.clone(), root.clone());
            tokio::spawn(async move {
                let op = req["op"].as_str().unwrap_or("").to_string();
                let s = |k: &str| req[k].as_str().unwrap_or("").to_string();
                let res = match op.as_str() {
                    "send" => n.send(&name, &s("to"), &s("text"), req["thread"].as_str().map(String::from)).await,
                    "send_file" => n.send_file(&name, root.as_deref(), &s("to"), &s("path"), req["note"].as_str()).await,
                    "inbox" if pull => Ok(n.inbox(&name, &notify, req["wait"].as_u64().unwrap_or(0)).await),
                    "peers" => Ok(n.peers(&name)),
                    "status" => Ok(n.status()),
                    "invite" => n.invite(&s("name"), req["files"].as_bool().unwrap_or(true)),
                    "join" => n.join(&s("code"), &s("name"), &s("addr")).await,
                    "trust" | "untrust" | "files" | "reload" => n.admin(&op, &req),
                    "stop" => {
                        tokio::spawn(async {
                            sleep(Duration::from_millis(200)).await;
                            std::process::exit(0);
                        });
                        Ok(json!({"stopping": true}))
                    }
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

    #[test]
    fn invite_roundtrip_and_rejects_garbage() {
        let (k, s) = ([7u8; 32], [9u8; 16]);
        let code = encode_invite(&k, &s);
        assert_eq!(decode_invite(&code).unwrap(), (k, s));
        assert_eq!(decode_invite(&code.to_uppercase().replace("AGORA-", "agora-")).unwrap(), (k, s));
        assert!(decode_invite("agora-abc").is_err());
        assert!(decode_invite(&code[6..]).is_err());
    }

    #[test]
    fn mac_binds_role_and_nonces() {
        let t = "11".repeat(32);
        let a = mac(&t, &["client", "n1", "n2"]);
        assert_ne!(a, mac(&t, &["node", "n1", "n2"]));
        assert_ne!(a, mac(&t, &["client", "n1n", "2"]));
        assert_ne!(a, mac(&"22".repeat(32), &["client", "n1", "n2"]));
        assert_eq!(a, mac(&t, &["client", "n1", "n2"]));
    }
}
