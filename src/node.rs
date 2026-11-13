//! The per-machine node: identity, encrypted peer links, pairing, per-agent queues, file transfer
//! and the authenticated local control socket.
use crate::config::{self, Config, Identity, Peer, valid_name};
use crate::files::{self, Kind};
use crate::guard::Guard;
use crate::relay;
use crate::wire;
use anyhow::{Result, anyhow, bail};
use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac256, Digest};
use data_encoding::{BASE32_NOPAD, BASE64, HEXLOWER};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::time::{sleep, timeout};

const HANDSHAKE: Duration = Duration::from_secs(10);
const PING: Duration = Duration::from_secs(25);
const IDLE: Duration = Duration::from_secs(75);
const ACK_WAIT: Duration = Duration::from_secs(10);
/// How long courier_send_file waits before the transfer continues in the background.
const FILE_SYNC_WAIT: Duration = Duration::from_secs(20);
const FILE_ACCEPT_WAIT: Duration = Duration::from_secs(60);
/// From the last byte to the receiver's verdict: hashing, malware scan and masking of a large file.
const FILE_FINISH_WAIT: Duration = Duration::from_secs(1800);
/// How long a sender waits for a lost connection to come back before giving up.
const RESUME_WAIT: Duration = Duration::from_secs(600);
const RESUME_ATTEMPTS: u32 = 50;
/// Sender name of the node's own notices to local agents; no agent can take it.
const NOTICE_FROM: &str = "agentcourier";
/// How long a receiver keeps a half-received file for the sender to resume.
const RESUME_KEEP: Duration = Duration::from_secs(3600);
/// A transfer on a live connection that delivers no data for this long is dropped, freeing its space.
const STALL: Duration = Duration::from_secs(600);
/// File data waiting for the connection; bounds the sender's memory whatever the file size.
const DATA_QUEUE: usize = 8;
const DONE_MAX: usize = 1024;
/// Announced in presence: this node streams files as raw chunks and resumes them.
const CAP_FILES2: &str = "files2";
const INVITE_TTL: Duration = Duration::from_secs(600);
const WAKE_EVERY: Duration = Duration::from_secs(60);
const QUEUE_MAX: usize = 1000;
const QUEUES_MAX: usize = 256;
const QUEUED_BYTES_MAX: usize = 64 << 20;
const ACK_BACKLOG: usize = 4096;
const SEEN_MAX: usize = 8192;
const REFUSED_MAX: usize = 20;
const FILES_INFLIGHT: usize = 4;
const CHUNK: usize = 256 * 1024;
const LINE_MAX: u64 = 4 << 20;
const AUDIT_MAX: u64 = 10 << 20;
const INVITE_PREFIX: &str = "agentcourier-";
const SEEN_DAYS: u64 = 30;
const KNOWN_MAX: usize = 100;

#[derive(Serialize, Deserialize, Clone)]
#[serde(tag = "t", rename_all = "snake_case")]
enum P2p {
    Msg(Msg),
    Ack { id: String, ok: bool, status: String },
    Presence {
        agents: Vec<String>,
        #[serde(default)]
        owner: Option<String>,
        #[serde(default)]
        about: HashMap<String, String>,
        #[serde(default)]
        caps: Vec<String>,
    },
    Ping,
    Join { secret: String },
    Joined,
    FileStart(FileMeta),
    FileChunk { id: String, seq: u64, data: String },
    FileEnd { id: String },
    // Only sent to machines that announce CAP_FILES2; the data then travels as raw frames (see file_frame).
    FileOffer(FileMeta),
    FileAccept { id: String, offset: u64 },
    FileDone { id: String },
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

#[derive(Serialize, Deserialize, Clone)]
struct Event {
    id: String,
    from: String,
    to: String,
    thread: Option<String>,
    body: String,
    ts: u64,
    redacted: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<Value>,
}

/// An agent seen on a paired machine, remembered so it can be found while offline.
#[derive(Serialize, Deserialize, Clone)]
struct Known {
    #[serde(default)]
    about: Option<String>,
    last_seen: u64,
}

/// What survives a node restart: undelivered messages and agents seen before.
#[derive(Deserialize, Default)]
struct Saved {
    #[serde(default)]
    queues: HashMap<String, VecDeque<Event>>,
    #[serde(default)]
    outbox: HashMap<String, VecDeque<Msg>>,
    #[serde(default)]
    known: HashMap<String, HashMap<String, Known>>,
}

#[derive(Serialize)]
struct SavedRef<'a> {
    queues: &'a HashMap<String, VecDeque<Event>>,
    outbox: HashMap<&'a str, Vec<&'a Msg>>,
    known: &'a HashMap<String, HashMap<String, Known>>,
}

fn strs(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn ago(secs: u64) -> String {
    match secs {
        0..120 => "just now".into(),
        120..7200 => format!("{} min ago", secs / 60),
        7200..172800 => format!("{} h ago", secs / 3600),
        _ => format!("{} days ago", secs / 86400),
    }
}

struct Link {
    tx: mpsc::UnboundedSender<P2p>,
    /// File data, already encoded. Bounded, and written only when no message is waiting.
    data: mpsc::Sender<Vec<u8>>,
    /// Replies queued but not yet written to the peer.
    acks: Arc<AtomicUsize>,
    /// Ends the connection at once, even while data is still queued for it.
    close: Arc<Notify>,
    id: u64,
    key: [u8; 32],
    i_initiated: bool,
    since: Instant,
}

struct Session {
    sid: u64,
    notify: Arc<Notify>,
    about: Option<String>,
}

/// What a peer says about itself. Self-declared and unverified; the trusted name is our own petname.
#[derive(Default)]
struct Remote {
    agents: Vec<String>,
    about: HashMap<String, String>,
    owner: Option<String>,
    caps: Vec<String>,
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
    /// The connection that carries it; a transfer that cannot resume ends with that connection.
    link: u64,
    /// None while a resumable transfer waits for its sender to reconnect.
    file: Option<std::fs::File>,
    path: PathBuf,
    got: u64,
    seq: u64,
    resumable: bool,
    detached: Option<Instant>,
    /// Last time data arrived; a transfer that stalls on a live connection is dropped after STALL.
    last: Instant,
}

struct Outgoing {
    peer: String,
    name: String,
    size: u64,
    sent: Arc<AtomicU64>,
}

enum Start {
    Accept(u64),
    AlreadyDone,
}

/// Where a received piece belongs: a byte offset (raw frames) or a chunk number (older protocol).
enum At {
    Offset(u64),
    Seq(u64),
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
    remote: HashMap<String, Remote>,
    known: HashMap<String, HashMap<String, Known>>,
    notified: HashMap<String, Instant>,
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
    buckets: HashMap<String, (f64, Instant)>,
    woken: HashMap<String, Instant>,
    dialing: HashSet<String>,
    relay_running: bool,
    relay_up: bool,
    invites: Vec<Invite>,
    refused: VecDeque<(String, String, SystemTime)>,
    incoming: HashMap<String, Incoming>,
    outgoing: HashMap<String, Outgoing>,
    accepts: HashMap<String, (String, oneshot::Sender<u64>)>,
    /// Recently completed incoming files ("peer/id"), so a resumed offer of one is answered, not repeated.
    done_files: VecDeque<String>,
    /// Incoming files fully received and now being checked.
    finishing: HashSet<String>,
}

pub struct Node {
    me: Identity,
    cfg: RwLock<Arc<Config>>,
    guard: RwLock<Arc<Guard>>,
    st: Mutex<State>,
    token: String,
    ids: AtomicU64,
    audit: Mutex<Option<std::fs::File>>,
    /// Metadata-only arrival/read notices for watchers such as the VS Code extension; never message text.
    watch: tokio::sync::broadcast::Sender<String>,
    /// Bumped when the relay setting changes; ends everything that ran through the old relay.
    relay_gen: tokio::sync::watch::Sender<u64>,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn valid_thread(t: &Option<String>) -> bool {
    t.as_deref().is_none_or(valid_name)
}

/// "agent@peer" → (agent, Some(peer)); "agent" → local. "*" means whichever single agent is running.
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
    let c = code.trim();
    // Machines that still run the former version hand out agentwire- codes.
    let body = c.strip_prefix(INVITE_PREFIX).or_else(|| c.strip_prefix("agentwire-")).ok_or_else(|| anyhow!("not an agentcourier invite code"))?;
    let b = BASE32_NOPAD.decode(body.to_ascii_uppercase().as_bytes()).map_err(|_| anyhow!("malformed invite code"))?;
    if b.len() != 48 {
        bail!("malformed invite code");
    }
    Ok((b[..32].try_into()?, b[32..].try_into()?))
}

fn verdict(peer: &str, r: std::result::Result<(bool, String), oneshot::error::RecvError>) -> Result<Option<String>> {
    match r {
        Ok((true, s)) => Ok(Some(s)),
        Ok((false, s)) => Err(anyhow!("rejected by {peer}: {s}")),
        Err(_) => Ok(None),
    }
}

async fn read_full(f: &mut tokio::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        let k = f.read(&mut buf[n..]).await?;
        if k == 0 {
            break;
        }
        n += k;
    }
    Ok(n)
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

/// Private copies of text files while they are being sent.
fn outgoing_dir() -> PathBuf {
    config::home().join("outgoing")
}

fn agents_of(r: Option<&Remote>) -> Vec<Value> {
    r.map(|r| r.agents.iter().map(|a| json!({"name": a, "about": r.about.get(a)})).collect()).unwrap_or_default()
}

fn seen_before(st: &State, peer: &str) -> Vec<Value> {
    let online: HashSet<&String> = st.remote.get(peer).map(|r| r.agents.iter().collect()).unwrap_or_default();
    let mut v: Vec<(&String, &Known)> = st.known.get(peer).map(|k| k.iter().filter(|(n, _)| !online.contains(n)).collect()).unwrap_or_default();
    v.sort_by_key(|(_, k)| std::cmp::Reverse(k.last_seen));
    v.into_iter().map(|(n, k)| json!({"name": n, "about": k.about, "last_seen": ago(now().saturating_sub(k.last_seen))})).collect()
}

/// Platform notifier; the text travels in an environment variable, never in a command line.
fn notifier(text: &str) -> Option<tokio::process::Command> {
    let mut c;
    if cfg!(windows) {
        const PS: &str = "[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;\
            $x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);\
            $t=$x.GetElementsByTagName('text');$t.Item(0).AppendChild($x.CreateTextNode('agentcourier'))|Out-Null;\
            $t.Item(1).AppendChild($x.CreateTextNode($env:AGENTCOURIER_NOTE))|Out-Null;\
            [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe').Show([Windows.UI.Notifications.ToastNotification]::new($x))";
        c = tokio::process::Command::new("powershell.exe");
        c.args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", PS]);
        #[cfg(windows)]
        c.creation_flags(0x0800_0000);
    } else if cfg!(target_os = "macos") {
        c = tokio::process::Command::new("osascript");
        c.args(["-e", "display notification (system attribute \"AGENTCOURIER_NOTE\") with title \"agentcourier\""]);
    } else if std::env::var_os("DISPLAY").is_some() || std::env::var_os("WAYLAND_DISPLAY").is_some() {
        c = tokio::process::Command::new("notify-send");
        c.args(["agentcourier", text]);
    } else {
        return None;
    }
    c.env("AGENTCOURIER_NOTE", text);
    Some(c)
}

pub async fn run() -> Result<()> {
    config::ensure_home()?;
    config::harden_home();
    if let Some(h) = config::node_elsewhere() {
        bail!("agentcourier already runs on {h}, which shares this home folder; start your agents on {h}");
    }
    let me = config::identity()?;
    let cfg = config::load()?;
    let token = config::ipc_token()?;
    let ipc = ipc_bind(&cfg).await?;
    #[cfg(unix)]
    crate::ipc::Client::stop_outdated_node().await;
    config::write_lock();
    let p2p = TcpListener::bind(&cfg.listen).await.map_err(|e| anyhow!("port {} is already in use, possibly by an older agentcourier or agentwire node; stop that process ({e})", cfg.listen))?;
    let _ = std::fs::remove_dir_all(files_dir().join(".partial"));
    let _ = std::fs::remove_dir_all(outgoing_dir());
    let audit = open_audit();
    eprintln!("agentcourier node {} listening on {}", config::encode_key(&me.public), cfg.listen);
    let saved: Saved = std::fs::read_to_string(state_file()).ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let st = State {
        queues: saved.queues,
        outbox: saved.outbox.into_iter().filter(|(p, _)| cfg.peer(p).is_some()).collect(),
        known: saved.known.into_iter().filter(|(p, _)| cfg.peer(p).is_some()).collect(),
        ..State::default()
    };
    let node = Arc::new(Node {
        me,
        guard: RwLock::new(Arc::new(Guard::new(cfg.guard.clone()))),
        cfg: RwLock::new(Arc::new(cfg)),
        st: Mutex::new(st),
        token,
        ids: AtomicU64::new(1),
        audit: Mutex::new(audit),
        watch: tokio::sync::broadcast::channel(256).0,
        relay_gen: tokio::sync::watch::channel(0).0,
    });
    node.spawn_dialers();
    node.spawn_relay();
    let n = node.clone();
    tokio::spawn(async move { n.accept_p2p(p2p).await });
    let n = node.clone();
    tokio::spawn(async move {
        let mut last = String::new();
        let mut beat = 0u32;
        loop {
            sleep(Duration::from_secs(2)).await;
            n.persist(&mut last);
            beat += 1;
            if beat % 5 == 0 {
                config::write_lock();
            }
            if beat % 30 == 0 {
                n.prune_partials();
            }
        }
    });
    node.accept_ipc(ipc).await
}

fn state_file() -> PathBuf {
    config::home().join("state.json")
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
    config::ensure_home()?;
    let path = config::socket_path();
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
        let relay_changed = self.cfg().relay != cfg.relay;
        *self.guard.write().unwrap() = Arc::new(Guard::new(cfg.guard.clone()));
        *self.cfg.write().unwrap() = Arc::new(cfg.clone());
        if relay_changed {
            self.relay_gen.send_modify(|g| *g += 1);
        }
        {
            let mut st = self.st.lock().unwrap();
            st.links.retain(|name, l| {
                let keep = cfg.peer(name).is_some_and(|p| config::decode_key(&p.key).is_ok_and(|k| k == l.key));
                if !keep {
                    l.close.notify_one();
                }
                keep
            });
            st.outbox.retain(|name, _| cfg.peer(name).is_some());
            st.remote.retain(|name, _| cfg.peer(name).is_some());
            st.known.retain(|name, _| cfg.peer(name).is_some());
            // Half-received files from a machine that was removed or may no longer send files go at once.
            st.incoming.retain(|_, i| {
                let keep = cfg.files.enabled && cfg.peer(&i.peer).is_some_and(|p| p.files);
                if !keep {
                    let _ = std::fs::remove_file(&i.path);
                }
                keep
            });
            self.broadcast_presence(&st);
        }
        self.spawn_dialers();
        self.spawn_relay();
        Ok(())
    }

    async fn accept_ipc(self: &Arc<Self>, l: IpcListener) -> Result<()> {
        loop {
            match l.accept().await {
                Ok((s, _)) => {
                    tokio::spawn(self.clone().serve_ipc(s));
                }
                Err(e) => {
                    eprintln!("local connection failed: {e}");
                    sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn invites_open(&self) -> bool {
        let mut st = self.st.lock().unwrap();
        st.invites.retain(|i| i.expires > Instant::now());
        !st.invites.is_empty()
    }

    fn note_refused(&self, key: &[u8; 32], from: &str) {
        let k = config::encode_key(key);
        eprintln!("refused handshake from {from} (key {k})");
        let mut st = self.st.lock().unwrap();
        st.refused.retain(|(rk, _, _)| rk != &k);
        st.refused.push_back((k, from.to_string(), SystemTime::now()));
        if st.refused.len() > REFUSED_MAX {
            st.refused.pop_front();
        }
    }

    async fn accept_p2p(self: Arc<Self>, l: TcpListener) {
        let gate = Arc::new(Semaphore::new(64));
        loop {
            let Ok((s, addr)) = l.accept().await else { continue };
            let Ok(permit) = gate.clone().try_acquire_owned() else { continue };
            let _ = s.set_nodelay(true);
            tokio::spawn(self.clone().incoming_conn(s, addr.to_string(), Some(permit)));
        }
    }

    /// One incoming connection, direct or through the relay: the same trust rules apply to both.
    async fn incoming_conn<S: wire::Stream>(self: Arc<Self>, s: S, from: String, permit: Option<OwnedSemaphorePermit>) {
        let allowed = |k: &[u8; 32]| self.cfg().peer_by_key(k).is_some() || self.invites_open();
        let hs = timeout(HANDSHAKE, wire::respond(s, &self.me, allowed)).await;
        drop(permit);
        match hs {
            Ok(Ok((key, Some((r, w))))) => match self.cfg().peer_by_key(&key).map(|p| p.name.clone()) {
                Some(p) => self.run_link(p, key, r, w, false, false).await,
                None => self.pairing(key, &from, r, w).await,
            },
            Ok(Ok((key, None))) => self.note_refused(&key, &from),
            _ => {}
        }
    }

    /// Keeps this machine reachable through its relay and takes the connections other members open to it.
    fn spawn_relay(self: &Arc<Self>) {
        {
            let mut st = self.st.lock().unwrap();
            if st.relay_running || self.cfg().relay.is_none() {
                return;
            }
            st.relay_running = true;
        }
        let n = self.clone();
        tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                let mut stop = n.relay_gen.subscribe();
                let link = {
                    let mut st = n.st.lock().unwrap();
                    match n.cfg().relay.clone() {
                        Some(l) => l,
                        None => {
                            st.relay_running = false;
                            break;
                        }
                    }
                };
                let started = Instant::now();
                let (n2, l2, n4) = (n.clone(), link.clone(), n.clone());
                let ready = move || n4.st.lock().unwrap().relay_up = true;
                // A relay can ask for connections, but never more at once than this.
                let gate = Arc::new(Semaphore::new(16));
                let listen = relay::listen(&link, &n.me, PING, ready, move |token, from| {
                    let Ok(permit) = gate.clone().try_acquire_owned() else { return };
                    let (n3, l3) = (n2.clone(), l2.clone());
                    let stop = n3.relay_gen.subscribe();
                    tokio::spawn(async move {
                        match relay::accept(&l3, &n3.me, &token, stop).await {
                            Ok(s) => n3.incoming_conn(s, format!("relay ({from})"), Some(permit)).await,
                            Err(e) => eprintln!("relay: incoming connection failed: {e}"),
                        }
                    });
                });
                let res = tokio::select! {
                    r = listen => r,
                    _ = stop.changed() => continue,
                };
                n.st.lock().unwrap().relay_up = false;
                if started.elapsed() > Duration::from_secs(60) {
                    backoff = 1;
                }
                if backoff == 1 {
                    eprintln!("relay {}: {}", link.addr, res.err().map_or("closed".to_string(), |e| e.to_string()));
                }
                tokio::select! {
                    _ = sleep(Duration::from_secs(backoff)) => {}
                    _ = stop.changed() => {
                        backoff = 1;
                        continue;
                    }
                }
                backoff = (backoff * 2).min(60);
            }
        });
    }

    /// Opens a byte stream to a peer: directly, or through the relay when its address is "relay".
    async fn connect_to(&self, addr: &str, key: &[u8; 32]) -> Result<(wire::Reader, wire::Writer)> {
        if addr == "relay" {
            let stop = self.relay_gen.subscribe();
            let link = self.cfg().relay.clone().ok_or_else(|| anyhow!("no relay configured (agentcourier relay join <code>)"))?;
            let s = relay::dial(&link, &self.me, key, stop).await?;
            return wire::initiate(s, &self.me, key).await;
        }
        let s = TcpStream::connect(addr).await?;
        s.set_nodelay(true)?;
        wire::initiate(s, &self.me, key).await
    }

    async fn relay_join(self: &Arc<Self>, code: &str) -> Result<Value> {
        let link = relay::join(code, &self.me).await?;
        let mut cfg = (*self.cfg()).clone();
        cfg.relay = Some(link.clone());
        self.apply(cfg)?;
        self.audit(json!({"ts": now(), "dir": "relay", "addr": link.addr, "key": link.key}));
        Ok(json!({"relay": link.addr}))
    }

    /// An unknown key may only present a valid one-time invite secret, then becomes a trusted peer.
    async fn pairing(self: &Arc<Self>, key: [u8; 32], from: &str, mut r: wire::Reader, mut w: wire::Writer) {
        let secret = match timeout(HANDSHAKE, r.recv()).await {
            Ok(Ok(b)) => match serde_json::from_slice::<P2p>(&b) {
                Ok(P2p::Join { secret }) => secret,
                _ => return self.note_refused(&key, from),
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
            return self.note_refused(&key, from);
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
        self.audit(json!({"ts": now(), "dir": "pair", "peer": inv.name, "key": config::encode_key(&key), "from": from}));
        eprintln!("paired with {} ({from})", inv.name);
        if w.send(&serde_json::to_vec(&P2p::Joined).unwrap()).await.is_ok() {
            self.run_link(inv.name, key, r, w, false, true).await;
        }
    }

    async fn join(self: &Arc<Self>, code: &str, name: &str, addr: &str) -> Result<Value> {
        if !valid_name(name) || !(addr == "relay" || addr.contains(':')) {
            bail!("usage: agentcourier join <code> <name> <host:port|relay>");
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
        let (mut r, mut w) = timeout(HANDSHAKE, self.connect_to(addr, &key))
            .await
            .map_err(|_| anyhow!("no answer: the code is wrong, used or expired, or {addr} is not that machine"))?
            .map_err(|e| anyhow!("refused: the code is wrong, used or expired, or {addr} is not that machine ({e})"))?;
        w.send(&serde_json::to_vec(&P2p::Join { secret: HEXLOWER.encode(&secret) })?).await?;
        match timeout(HANDSHAKE, r.recv()).await {
            Ok(Ok(b)) if matches!(serde_json::from_slice(&b), Ok(P2p::Joined)) => {}
            _ => bail!("refused: the code is wrong, used or expired"),
        }
        // The trust list may have changed while the network round trip ran; never write back an old copy.
        let mut cfg = (*self.cfg()).clone();
        if cfg.peer(name).is_some() || cfg.peer_by_key(&key).is_some() {
            bail!("{name} or this machine was added in the meantime");
        }
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
                let dial = n.connect_to(&addr, &key);
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
        let (dtx, mut drx) = mpsc::channel::<Vec<u8>>(DATA_QUEUE);
        let acks = Arc::new(AtomicUsize::new(0));
        let close = Arc::new(Notify::new());
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        {
            let mut st = self.st.lock().unwrap();
            // The machine may have been removed while this link waited for its first message.
            if !self.cfg().peer(&peer).is_some_and(|p| config::decode_key(&p.key).is_ok_and(|k| k == key)) {
                return;
            }
            if let Some(old) = st.links.get(&peer) {
                // Simultaneous dials: both sides keep the link opened by the lower key. Otherwise newest wins.
                let preferred = |mine: bool| mine == (self.me.public < key);
                if old.since.elapsed() < Duration::from_secs(3) && preferred(old.i_initiated) && !preferred(i_initiated) {
                    return;
                }
            }
            let link = Link { tx: tx.clone(), data: dtx, acks: acks.clone(), close: close.clone(), id, key, i_initiated, since: Instant::now() };
            if let Some(old) = st.links.insert(peer.clone(), link) {
                old.close.notify_one();
            }
            let _ = tx.send(self.presence(&st));
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
            self.on_p2p(&peer, id, m);
        }
        let writer = async {
            let mut ping = tokio::time::interval(PING);
            loop {
                // Messages and replies first, so a large file never holds them up.
                let (bytes, is_ack) = tokio::select! {
                    biased;
                    m = rx.recv() => match m {
                        Some(m) => (serde_json::to_vec(&m).unwrap(), matches!(m, P2p::Ack { .. } | P2p::FileAccept { .. })),
                        None => break,
                    },
                    _ = ping.tick() => (serde_json::to_vec(&P2p::Ping).unwrap(), false),
                    d = drx.recv() => match d { Some(d) => (d, false), None => break },
                };
                if !matches!(timeout(IDLE, w.send(&bytes)).await, Ok(Ok(_))) {
                    break;
                }
                if is_ack {
                    acks.fetch_sub(1, Ordering::Relaxed);
                }
            }
        };
        let reader = async {
            while let Ok(Ok(b)) = timeout(IDLE, r.recv()).await {
                if b.first() == Some(&0) {
                    self.file_frame(&peer, id, &b);
                    continue;
                }
                let Ok(m) = serde_json::from_slice::<P2p>(&b) else { break };
                self.on_p2p(&peer, id, m);
            }
        };
        tokio::select! { _ = writer => {}, _ = reader => {}, _ = close.notified() => {} }
        let mut st = self.st.lock().unwrap();
        st.incoming.retain(|_, i| {
            if i.link != id {
                return true;
            }
            if i.resumable {
                i.file = None;
                i.detached = Some(Instant::now());
                return true;
            }
            let _ = std::fs::remove_file(&i.path);
            false
        });
        if st.links.get(&peer).is_some_and(|l| l.id == id) {
            st.links.remove(&peer);
            if let Some(r) = st.remote.remove(&peer) {
                let t = now();
                let k = st.known.entry(peer.clone()).or_default();
                for a in r.agents {
                    k.entry(a).or_insert(Known { about: None, last_seen: t }).last_seen = t;
                }
            }
            eprintln!("peer {peer} disconnected");
        }
    }

    fn reply(&self, peer: &str, link: u64, id: String, res: Result<String>) {
        // Echoing an id we rejected would let a peer make our replies as large as it likes.
        if !valid_name(&id) {
            return;
        }
        let (ok, status) = match res {
            Ok(s) => (true, s),
            Err(e) => (false, e.to_string()),
        };
        self.answer(peer, link, P2p::Ack { id, ok, status });
    }

    /// Sends a reply on the connection the request came on, never on a newer one.
    fn answer(&self, peer: &str, link: u64, m: P2p) {
        let mut st = self.st.lock().unwrap();
        let Some(l) = st.links.get(peer).filter(|l| l.id == link) else { return };
        // A peer that keeps sending but never reads our replies would otherwise fill memory.
        if l.acks.fetch_add(1, Ordering::Relaxed) >= ACK_BACKLOG {
            l.close.notify_one();
            st.links.remove(peer);
            eprintln!("peer {peer} stopped reading replies; link closed");
            return;
        }
        let _ = l.tx.send(m);
    }

    fn on_p2p(self: &Arc<Self>, peer: &str, link: u64, m: P2p) {
        match m {
            P2p::Ping | P2p::Join { .. } | P2p::Joined => {}
            P2p::Presence { agents, owner, about, caps } => {
                let guard = self.guard();
                let label = |s: &str, n: usize| -> String { guard.sanitize(s).replace(['\n', '\t'], " ").trim().chars().take(n).collect() };
                let agents: Vec<String> = agents.into_iter().filter(|a| valid_name(a)).take(256).collect();
                let about: HashMap<String, String> = about.into_iter().filter(|(k, _)| agents.contains(k)).map(|(k, v)| (k, label(&v, 200))).collect();
                let owner = owner.map(|o| label(&o, 80)).filter(|o| !o.is_empty());
                let t = now();
                let mut st = self.st.lock().unwrap();
                let k = st.known.entry(peer.to_string()).or_default();
                for a in &agents {
                    k.insert(a.clone(), Known { about: about.get(a).cloned(), last_seen: t });
                }
                k.retain(|_, v| t.saturating_sub(v.last_seen) < SEEN_DAYS * 86400);
                while k.len() > KNOWN_MAX {
                    let oldest = k.iter().min_by_key(|(_, v)| v.last_seen).map(|(n, _)| n.clone()).unwrap();
                    k.remove(&oldest);
                }
                let caps: Vec<String> = caps.into_iter().filter(|c| valid_name(c)).take(16).collect();
                st.remote.insert(peer.to_string(), Remote { agents, about, owner, caps });
            }
            P2p::Ack { id, ok, status } => {
                // The other side writes this text; it reaches agents and terminals as a delivery status.
                let status: String = status.chars().take(300).collect();
                let status = self.guard().sanitize(&status).replace(['\n', '\r', '\t'], " ");
                let mut st = self.st.lock().unwrap();
                if st.unacked.get(&id).is_some_and(|(p, _)| p == peer) {
                    st.unacked.remove(&id);
                }
                if st.waiters.get(&id).is_some_and(|(p, _)| p == peer) {
                    let (_, w) = st.waiters.remove(&id).unwrap();
                    let _ = w.send((ok, status));
                }
            }
            P2p::Msg(m) => {
                let id = m.id.clone();
                let res = self.inbound(peer, m);
                self.reply(peer, link, id, res);
            }
            P2p::FileStart(meta) => {
                let id = meta.id.clone();
                if let Err(e) = self.file_start(peer, link, meta, false) {
                    self.reply(peer, link, id, Err(e));
                }
            }
            P2p::FileOffer(meta) => {
                let id = meta.id.clone();
                match self.file_start(peer, link, meta, true) {
                    Ok(Start::Accept(offset)) => self.answer(peer, link, P2p::FileAccept { id, offset }),
                    Ok(Start::AlreadyDone) => self.reply(peer, link, id, Ok("already delivered".into())),
                    Err(e) => self.reply(peer, link, id, Err(e)),
                }
            }
            P2p::FileAccept { id, offset } => {
                let mut st = self.st.lock().unwrap();
                if st.accepts.get(&id).is_some_and(|(p, _)| p == peer) {
                    let (_, tx) = st.accepts.remove(&id).unwrap();
                    let _ = tx.send(offset);
                }
            }
            P2p::FileChunk { id, seq, data } => {
                if data.len() > CHUNK * 4 / 3 + 8 {
                    if self.drop_incoming(peer, link, &id) {
                        self.reply(peer, link, id, Err(anyhow!("corrupt transfer")));
                    }
                    return;
                }
                let res = BASE64.decode(data.as_bytes()).map_err(|_| anyhow!("corrupt transfer")).and_then(|b| self.file_write(peer, link, &id, At::Seq(seq), &b));
                if let Err(e) = res {
                    // One error reply per failed transfer, not one per remaining chunk.
                    if self.drop_incoming(peer, link, &id) {
                        self.reply(peer, link, id, Err(e));
                    }
                }
            }
            P2p::FileEnd { id } | P2p::FileDone { id } => {
                let inc = {
                    let mut st = self.st.lock().unwrap();
                    let k = format!("{peer}/{id}");
                    let inc = if st.incoming.get(&k).is_some_and(|i| i.link == link && i.file.is_some()) { st.incoming.remove(&k) } else { None };
                    if inc.is_some() {
                        st.finishing.insert(format!("{peer}/{id}"));
                    }
                    inc
                };
                let Some(inc) = inc else { return };
                let (n, p) = (self.clone(), peer.to_string());
                tokio::spawn(async move {
                    let path = inc.path.clone();
                    let res = n.file_finish(&p, inc).await;
                    if res.is_err() {
                        let _ = std::fs::remove_file(path);
                    }
                    let key = format!("{p}/{id}");
                    match &res {
                        Err(e) => n.audit(json!({"ts": now(), "dir": "in", "peer": p, "id": id, "file": true, "status": e.to_string()})),
                        Ok(_) => {
                            let mut st = n.st.lock().unwrap();
                            st.done_files.push_back(key.clone());
                            if st.done_files.len() > DONE_MAX {
                                st.done_files.pop_front();
                            }
                        }
                    }
                    n.st.lock().unwrap().finishing.remove(&key);
                    // The check can take minutes; if the connection was replaced meanwhile, the verdict takes the new one.
                    let now_link = n.st.lock().unwrap().links.get(&p).map(|l| l.id);
                    n.reply(&p, now_link.unwrap_or(link), id, res);
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
        let ev = Event { id: m.id, from: format!("{}@{peer}", m.from), to: m.to, thread: m.thread, body, ts: m.ts, redacted: strs(&redacted), file: None };
        self.audit(json!({"ts": now(), "dir": "in", "peer": peer, "id": ev.id, "from": ev.from, "to": ev.to, "bytes": ev.body.len(), "redacted": ev.redacted}));
        let (from, to) = (ev.from.clone(), ev.to.clone());
        let r = self.deliver(ev);
        if r.is_ok() {
            self.alert(&from, &to, "Message");
        }
        r
    }

    /// Ends a transfer after an error on the connection that carries it; frames from an older connection change nothing.
    fn drop_incoming(&self, peer: &str, link: u64, id: &str) -> bool {
        let mut st = self.st.lock().unwrap();
        let k = format!("{peer}/{id}");
        if !st.incoming.get(&k).is_some_and(|i| i.link == link) {
            return false;
        }
        if let Some(i) = st.incoming.remove(&k) {
            let _ = std::fs::remove_file(i.path);
        }
        true
    }

    fn file_start(&self, peer: &str, link: u64, meta: FileMeta, resumable: bool) -> Result<Start> {
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
        // Raw frames carry the id in 32 bytes.
        if resumable && !(meta.id.len() == 32 && meta.id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))) {
            bail!("invalid file header");
        }
        if meta.size > cfg.files.max_bytes {
            bail!("file larger than {} bytes", cfg.files.max_bytes);
        }
        if resumable {
            self.prune_partials();
            let mut st = self.st.lock().unwrap();
            if let Some(inc) = st.incoming.get_mut(&format!("{peer}/{}", meta.id)).filter(|i| i.resumable) {
                if inc.meta.hash != meta.hash || inc.meta.size != meta.size {
                    bail!("a different file with this id is in transit");
                }
                inc.file = Some(std::fs::OpenOptions::new().append(true).open(&inc.path)?);
                inc.link = link;
                inc.detached = None;
                return Ok(Start::Accept(inc.got));
            }
            if st.done_files.contains(&format!("{peer}/{}", meta.id)) {
                return Ok(Start::AlreadyDone);
            }
            if st.finishing.contains(&format!("{peer}/{}", meta.id)) {
                // Everything arrived; the verdict follows once the check is done.
                return Ok(Start::Accept(meta.size));
            }
        }
        if !self.admit(peer, &meta.id)? {
            bail!("duplicate file id");
        }
        let used = dir_size(&files_dir());
        let mut st = self.st.lock().unwrap();
        let in_flight: u64 = st.incoming.values().map(|i| i.meta.size.saturating_sub(i.got)).sum();
        if used + in_flight + meta.size > cfg.files.quota_bytes {
            bail!("receiver storage quota is full");
        }
        if st.incoming.values().filter(|i| i.peer == peer).count() >= FILES_INFLIGHT {
            bail!("too many files in transit");
        }
        let dir = files_dir().join(".partial");
        std::fs::create_dir_all(&dir)?;
        // Named from peer and id, so ids chosen by different peers (or by older versions) can never meet on disk.
        let path = dir.join(HEXLOWER.encode(&Blake2s256::digest(format!("{peer}/{}", meta.id).as_bytes())[..16]));
        let file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?;
        st.incoming.insert(format!("{peer}/{}", meta.id), Incoming { meta, peer: peer.into(), link, file: Some(file), path, got: 0, seq: 0, resumable, detached: None, last: Instant::now() });
        Ok(Start::Accept(0))
    }

    /// Drops half-received files whose sender did not come back in time, or that made no progress for too long.
    fn prune_partials(&self) {
        let mut st = self.st.lock().unwrap();
        st.incoming.retain(|_, i| {
            let stale = i.detached.is_some_and(|t| t.elapsed() > RESUME_KEEP) || (i.detached.is_none() && i.last.elapsed() > STALL);
            if stale {
                let _ = std::fs::remove_file(&i.path);
            }
            !stale
        });
    }

    /// Appends received bytes in order. Under the state lock, so a resume can never interleave with a write in progress.
    fn file_write(&self, peer: &str, link: u64, id: &str, at: At, bytes: &[u8]) -> Result<()> {
        let mut st = self.st.lock().unwrap();
        let Some(inc) = st.incoming.get_mut(&format!("{peer}/{id}")).filter(|i| i.link == link) else { bail!("unknown transfer") };
        let in_order = match at {
            At::Offset(o) => inc.resumable && o == inc.got && !bytes.is_empty(),
            At::Seq(s) => !inc.resumable && s == inc.seq && !bytes.is_empty(),
        };
        if !in_order {
            bail!("corrupt transfer");
        }
        if inc.got + bytes.len() as u64 > inc.meta.size {
            bail!("file longer than announced");
        }
        let Some(file) = inc.file.as_mut() else { bail!("unknown transfer") };
        file.write_all(bytes)?;
        inc.got += bytes.len() as u64;
        inc.seq += 1;
        inc.last = Instant::now();
        Ok(())
    }

    /// A raw file frame: a zero byte, the transfer id (32 hex characters), the byte offset (8 bytes, big-endian), the data.
    fn file_frame(&self, peer: &str, link: u64, b: &[u8]) {
        let Some(id) = b.get(1..33).and_then(|s| std::str::from_utf8(s).ok()) else { return };
        let res = match b.get(33..41) {
            Some(o) if b.len() <= 41 + CHUNK => self.file_write(peer, link, id, At::Offset(u64::from_be_bytes(o.try_into().unwrap())), &b[41..]),
            _ => Err(anyhow!("corrupt transfer")),
        };
        if let Err(e) = res {
            if self.drop_incoming(peer, link, id) {
                self.reply(peer, link, id.to_string(), Err(e));
            }
        }
    }

    async fn file_finish(self: &Arc<Self>, peer: &str, inc: Incoming) -> Result<String> {
        let Incoming { meta, file, path, got, .. } = inc;
        drop(file);
        if got != meta.size {
            bail!("file damaged in transit");
        }
        let cfg = self.cfg();
        let guard = self.guard();
        let p = path.clone();
        let (hash, kind) = tokio::task::spawn_blocking(move || -> Result<(String, Kind)> { Ok((files::hash_file(&p)?, files::inspect(&p)?)) }).await??;
        if hash != meta.hash {
            bail!("file damaged in transit");
        }
        let scanner = files::screen(&path, kind, &cfg.files).await?;
        let mut redacted = vec![];
        if kind == Kind::Text {
            let (p, g) = (path.clone(), guard.clone());
            redacted = tokio::task::spawn_blocking(move || files::clean_text_file(&p, |s| g.clean(s))).await??;
        }
        // The machine may have been removed, or file exchange turned off, while the file was being checked.
        let cfg = self.cfg();
        if !cfg.files.enabled || !cfg.peer(peer).is_some_and(|p| p.files) {
            bail!("file exchange with this machine is turned off");
        }
        let dir = files_dir().join(peer);
        std::fs::create_dir_all(&dir)?;
        let name = files::safe_name(&meta.name);
        let (stem, ext) = name.rsplit_once('.').map_or((name.as_str(), String::new()), |(s, e)| (s, format!(".{e}")));
        // Reserve the name atomically, so a file the user may already have looked at is never replaced.
        let mut n = 1;
        let dest = loop {
            let cand = if n == 1 { dir.join(&name) } else { dir.join(format!("{stem}-{n}{ext}")) };
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&cand) {
                Ok(_) => break cand,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => n += 1,
                Err(e) => return Err(e.into()),
            }
        };
        if let Err(e) = std::fs::rename(&path, &dest) {
            let _ = std::fs::remove_file(&dest);
            return Err(e.into());
        }
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
        let ev = Event { id: meta.id.clone(), from: format!("{}@{peer}", meta.from), to: meta.to, thread: None, body, ts: meta.ts, redacted: strs(&redacted), file: Some(file) };
        self.audit(json!({"ts": now(), "dir": "in", "peer": peer, "id": meta.id, "from": ev.from, "to": ev.to, "file": name, "bytes": meta.size, "kind": kind.label(), "scanned_by": scanner}));
        let (from, to) = (ev.from.clone(), ev.to.clone());
        let r = self.deliver(ev);
        if r.is_ok() {
            self.alert(&from, &to, "File");
        }
        r
    }

    /// Queues an event for local agents and wakes their sessions.
    fn deliver(self: &Arc<Self>, ev: Event) -> Result<String> {
        let mut st = self.st.lock().unwrap();
        let targets: Vec<String> = if ev.to == "*" {
            let mut names: Vec<String> = st.sessions.keys().cloned().collect();
            // Copying one message into every session would leak it into unrelated projects.
            if names.len() > 1 {
                names.sort();
                bail!("several agents are running here; address one of them by name: {}", names.join(", "));
            }
            names
        } else {
            vec![ev.to.clone()]
        };
        let targets = if targets.is_empty() { vec!["*".to_string()] } else { targets };
        if targets.iter().any(|t| !st.queues.contains_key(t)) && st.queues.len() >= QUEUES_MAX {
            bail!("too many waiting queues");
        }
        // Bound the total like each queue: drop the oldest waiting messages of the largest queue first.
        let need = ev.body.len() * targets.len();
        let mut queued: usize = st.queues.values().flatten().map(|e| e.body.len()).sum();
        while queued + need > QUEUED_BYTES_MAX {
            let largest = st.queues.iter().max_by_key(|(_, q)| q.iter().map(|e| e.body.len()).sum::<usize>()).map(|(k, _)| k.clone());
            match largest.and_then(|k| st.queues.get_mut(&k).and_then(VecDeque::pop_front)) {
                Some(e) => queued -= e.body.len(),
                None => break,
            }
        }
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
            let about = st.sessions.get(t).and_then(|s| s.about.clone());
            let _ = self.watch.send(json!({"ev": "arrived", "to": t, "about": about, "from": ev.from, "file": ev.file.is_some()}).to_string());
            if let Some(s) = st.sessions.get(t) {
                // Both the channel pusher and a waiting courier_inbox must wake; the stored permit covers a pusher that is busy.
                s.notify.notify_waiters();
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
            cmd.args(&wake[1..]).env("AGENTCOURIER_NAME", &ev.to).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
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

    fn presence(&self, st: &State) -> P2p {
        let cfg = self.cfg();
        let owner = Some(cfg.owner.clone()).filter(|o| !o.is_empty()).or_else(|| std::env::var("USER").or_else(|_| std::env::var("USERNAME")).ok());
        let about = st.sessions.iter().filter_map(|(k, s)| s.about.clone().map(|a| (k.clone(), a))).collect();
        P2p::Presence { agents: st.sessions.keys().cloned().collect(), owner, about, caps: vec![CAP_FILES2.into()] }
    }

    fn broadcast_presence(&self, st: &State) {
        let p = self.presence(st);
        for l in st.links.values() {
            let _ = l.tx.send(p.clone());
        }
    }

    /// Desktop notice that names only the sender; message text never reaches the notifier.
    fn alert(&self, from: &str, to: &str, what: &str) {
        if !self.cfg().notify {
            return;
        }
        {
            let mut st = self.st.lock().unwrap();
            if st.notified.get(from).is_some_and(|t| t.elapsed() < Duration::from_secs(10)) {
                return;
            }
            if st.notified.len() > 1024 {
                st.notified.clear();
            }
            st.notified.insert(from.to_string(), Instant::now());
        }
        if let Some(mut cmd) = notifier(&format!("{what} from {from} for {to}")) {
            cmd.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
            if let Ok(mut c) = cmd.spawn() {
                tokio::spawn(async move { let _ = c.wait().await; });
            }
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
            None => self.deliver(Event { id: id.clone(), from: from.into(), to: agent, thread, body, ts, redacted: strs(&redacted), file: None })?,
            Some(p) => {
                if self.cfg().peer(p).is_none() {
                    bail!("unknown peer {p:?}; see courier_peers");
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
            bail!("file exchange with {p} is turned off (agentcourier files {p} on)");
        }
        let root = root.ok_or_else(|| anyhow!("no project folder known; start agentcourier mcp inside the project or pass --root"))?;
        let shown = root.display().to_string();
        let root = std::fs::canonicalize(root)?;
        // With the home folder as "project", a manipulated agent could reach every personal file.
        let homes = ["HOME", "USERPROFILE"].into_iter().filter_map(std::env::var_os).filter_map(|h| std::fs::canonicalize(h).ok());
        if homes.into_iter().any(|h| h.starts_with(&root)) {
            bail!("refused: {shown} is your home folder or contains it; open a project folder instead");
        }
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
        let size = meta.len();
        let note = note.map(|n| self.guard().clean(&n.chars().take(4096).collect::<String>()).0);
        let id = config::random_hex(16);
        let name = files::safe_name(&full.file_name().unwrap_or_default().to_string_lossy());
        let sent = Arc::new(AtomicU64::new(0));
        {
            let mut st = self.st.lock().unwrap();
            if !st.links.contains_key(&p) {
                bail!("{p} is offline; files are only sent to connected machines");
            }
            st.outgoing.insert(id.clone(), Outgoing { peer: p.clone(), name: name.clone(), size, sent: sent.clone() });
        }
        let (done_tx, done_rx) = oneshot::channel::<std::result::Result<String, String>>();
        let (n, from, to, fid, fname) = (self.clone(), from.to_string(), to.to_string(), id.clone(), name.clone());
        tokio::spawn(async move {
            let snap = outgoing_dir().join(&fid);
            let res = async {
                std::fs::create_dir_all(outgoing_dir())?;
                // Checking, hashing and copying happen in one pass, so what is sent is exactly what was checked.
                let (src, s2, guard, fcfg) = (full.clone(), snap.clone(), n.guard(), n.cfg().files.clone());
                let prep = tokio::task::spawn_blocking(move || files::prepare(&src, size, &s2, |b| guard.redact(b).1)).await??;
                if prep.kind == Kind::Executable && !fcfg.allow_executables {
                    bail!("refused: executable content");
                }
                if prep.hits.iter().any(|h| ["private_key", "token", "secret", "credentials"].contains(h)) {
                    bail!("refused: the file contains secrets ({})", prep.hits.join(", "));
                }
                if fcfg.block_pii && !prep.hits.is_empty() {
                    bail!("refused: the file contains personal data ({})", prep.hits.join(", "));
                }
                if prep.kind == Kind::Text && prep.uncertain {
                    bail!("refused: this text file could not be checked for secrets reliably (very long runs of lines ending in ':' or '='); compress it and send the archive");
                }
                let fm = FileMeta { id: fid.clone(), from: from.clone(), to: agent, name: fname.clone(), size, hash: prep.hash, note, ts: now() };
                n.push_file(&p, &fm, prep.snapshot.as_deref().unwrap_or(&full), &sent).await
            }
            .await
            .map_err(|e| e.to_string());
            let _ = std::fs::remove_file(&snap);
            n.st.lock().unwrap().outgoing.remove(&fid);
            let status = match &res {
                Ok(s) | Err(s) => s.clone(),
            };
            n.audit(json!({"ts": now(), "dir": "out", "peer": p, "id": fid, "from": from, "to": to, "file": fname, "bytes": size, "status": status}));
            if let Err(res) = done_tx.send(res) {
                // The agent stopped waiting; tell it how the transfer ended. The receiver wrote the status, so it is quoted.
                let body = match res {
                    Ok(s) => format!("Your file {fname} ({size} bytes) has arrived at {to}. The receiving machine reports: \"{s}\"."),
                    Err(e) => format!("Your file {fname} could not be sent to {to}: {e}"),
                };
                let _ = n.deliver(Event { id: config::random_hex(16), from: NOTICE_FROM.into(), to: from, thread: None, body, ts: now(), redacted: vec![], file: None });
            }
        });
        match timeout(FILE_SYNC_WAIT, done_rx).await {
            Ok(Ok(Ok(status))) => Ok(json!({"id": id, "file": name, "bytes": size, "status": status})),
            Ok(Ok(Err(e))) => Err(anyhow!(e)),
            _ => Ok(json!({"id": id, "file": name, "bytes": size, "status": "still sending in the background; you will get a message when it has arrived"})),
        }
    }

    fn link_is(&self, p: &str, lid: u64) -> bool {
        self.st.lock().unwrap().links.get(p).is_some_and(|l| l.id == lid)
    }

    /// Streams a file to a peer and returns its verdict. After a lost connection it resumes where it stopped,
    /// if the peer supports that; older peers get the file the old way and cannot resume.
    async fn push_file(self: &Arc<Self>, p: &str, fm: &FileMeta, path: &Path, sent: &AtomicU64) -> Result<String> {
        let (mut lost, mut attempts): (Option<Instant>, u32) = (None, 0);
        loop {
            let link = {
                let st = self.st.lock().unwrap();
                st.links.get(p).zip(st.remote.get(p)).map(|(l, r)| (l.id, l.tx.clone(), l.data.clone(), r.caps.iter().any(|c| c == CAP_FILES2)))
            };
            let Some((lid, tx, data, v2)) = link else {
                if lost.get_or_insert_with(Instant::now).elapsed() > RESUME_WAIT {
                    bail!("{p} went offline; the transfer stopped");
                }
                sleep(Duration::from_millis(500)).await;
                continue;
            };
            attempts += 1;
            if attempts > RESUME_ATTEMPTS {
                bail!("the connection to {p} kept breaking; the transfer stopped");
            }
            let (wtx, mut wrx) = oneshot::channel();
            self.st.lock().unwrap().waiters.insert(fm.id.clone(), (p.to_string(), wtx));
            let res = if v2 { self.push_raw(p, lid, &tx, &data, fm, path, sent, &mut wrx).await } else { self.push_json(p, lid, &data, fm, path, sent, &mut wrx).await };
            {
                let mut st = self.st.lock().unwrap();
                st.waiters.remove(&fm.id);
                st.accepts.remove(&fm.id);
            }
            match res {
                Ok(Some(s)) => return Ok(s),
                Ok(None) if v2 => lost = Some(Instant::now()),
                Ok(None) => bail!("the connection to {p} was lost; send the file again"),
                Err(e) => return Err(e),
            }
        }
    }

    /// Offers the file, then streams raw frames from where the receiver says it stands. None: the connection went away.
    #[allow(clippy::too_many_arguments)]
    async fn push_raw(
        &self,
        p: &str,
        lid: u64,
        tx: &mpsc::UnboundedSender<P2p>,
        data: &mpsc::Sender<Vec<u8>>,
        fm: &FileMeta,
        path: &Path,
        sent: &AtomicU64,
        wrx: &mut oneshot::Receiver<(bool, String)>,
    ) -> Result<Option<String>> {
        let (atx, mut arx) = oneshot::channel();
        self.st.lock().unwrap().accepts.insert(fm.id.clone(), (p.to_string(), atx));
        if tx.send(P2p::FileOffer(fm.clone())).is_err() {
            return Ok(None);
        }
        let offset = tokio::select! {
            a = &mut arx => match a { Ok(o) => o, Err(_) => return Ok(None) },
            r = &mut *wrx => return verdict(p, r),
            _ = sleep(FILE_ACCEPT_WAIT) => return if self.link_is(p, lid) { Err(anyhow!("{p} did not answer the file offer")) } else { Ok(None) },
        };
        if offset > fm.size {
            bail!("{p} reported an impossible resume position");
        }
        let mut f = tokio::fs::File::open(path).await?;
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        let (mut pos, mut buf) = (offset, vec![0u8; CHUNK]);
        while pos < fm.size {
            if let Ok(r) = wrx.try_recv() {
                return verdict(p, Ok(r));
            }
            let n = read_full(&mut f, &mut buf[..CHUNK.min((fm.size - pos) as usize)]).await?;
            if n == 0 {
                bail!("the file got shorter while it was being sent");
            }
            let mut frame = Vec::with_capacity(41 + n);
            frame.push(0);
            frame.extend_from_slice(fm.id.as_bytes());
            frame.extend_from_slice(&pos.to_be_bytes());
            frame.extend_from_slice(&buf[..n]);
            if data.send(frame).await.is_err() {
                return Ok(None);
            }
            pos += n as u64;
            sent.store(pos, Ordering::Relaxed);
        }
        if data.send(serde_json::to_vec(&P2p::FileDone { id: fm.id.clone() })?).await.is_err() {
            return Ok(None);
        }
        self.wait_verdict(p, lid, fm.size, wrx).await
    }

    /// The protocol older versions understand: start, base64 chunks, end. Streamed, but cannot resume.
    #[allow(clippy::too_many_arguments)]
    async fn push_json(
        &self,
        p: &str,
        lid: u64,
        data: &mpsc::Sender<Vec<u8>>,
        fm: &FileMeta,
        path: &Path,
        sent: &AtomicU64,
        wrx: &mut oneshot::Receiver<(bool, String)>,
    ) -> Result<Option<String>> {
        if data.send(serde_json::to_vec(&P2p::FileStart(fm.clone()))?).await.is_err() {
            return Ok(None);
        }
        let mut f = tokio::fs::File::open(path).await?;
        let (mut pos, mut seq, mut buf) = (0u64, 0u64, vec![0u8; CHUNK]);
        while pos < fm.size {
            // An older receiver may refuse the file at the start; stop sending then.
            if let Ok(r) = wrx.try_recv() {
                return verdict(p, Ok(r));
            }
            let n = read_full(&mut f, &mut buf[..CHUNK.min((fm.size - pos) as usize)]).await?;
            if n == 0 {
                bail!("the file got shorter while it was being sent");
            }
            let m = P2p::FileChunk { id: fm.id.clone(), seq, data: BASE64.encode(&buf[..n]) };
            if data.send(serde_json::to_vec(&m)?).await.is_err() {
                return Ok(None);
            }
            pos += n as u64;
            seq += 1;
            sent.store(pos, Ordering::Relaxed);
        }
        if data.send(serde_json::to_vec(&P2p::FileEnd { id: fm.id.clone() })?).await.is_err() {
            return Ok(None);
        }
        self.wait_verdict(p, lid, fm.size, wrx).await
    }

    /// The receiver's verdict after the last byte; None if the connection went away first.
    /// Hashing and the malware scan take longer for large files, so the wait grows with the size.
    async fn wait_verdict(&self, p: &str, lid: u64, size: u64, wrx: &mut oneshot::Receiver<(bool, String)>) -> Result<Option<String>> {
        let limit = FILE_FINISH_WAIT + Duration::from_secs(120 * (size >> 30));
        let started = Instant::now();
        loop {
            tokio::select! {
                r = &mut *wrx => return verdict(p, r),
                _ = sleep(Duration::from_secs(1)) => {
                    if !self.link_is(p, lid) {
                        return Ok(None);
                    }
                    if started.elapsed() > limit {
                        bail!("no confirmation from {p}; the transfer may have been interrupted");
                    }
                }
            }
        }
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
                    "owner_says": st.remote.get(&p.name).and_then(|r| r.owner.clone()),
                    "online": st.links.contains_key(&p.name),
                    "agents": agents_of(st.remote.get(&p.name)),
                    "seen_before": seen_before(&st, &p.name),
                    "files": p.files && cfg.files.enabled,
                    "queued": st.outbox.get(&p.name).map_or(0, |q| q.len()),
                })
            })
            .collect();
        let local: Vec<Value> = st.sessions.iter().map(|(k, s)| json!({"name": k, "about": s.about})).collect();
        json!({"you": me, "local_agents": local, "peers": peers,
               "note": "name is the trusted name your user gave each machine; owner_says and about are self-declared by the peer and unverified"})
    }

    /// Writes undelivered messages and known agents to disk when they changed.
    fn persist(&self, last: &mut String) {
        let s = {
            let st = self.st.lock().unwrap();
            let mut outbox: HashMap<&str, Vec<&Msg>> = HashMap::new();
            for (p, m) in st.unacked.values() {
                outbox.entry(p.as_str()).or_default().push(m);
            }
            for (p, q) in &st.outbox {
                outbox.entry(p.as_str()).or_default().extend(q.iter());
            }
            serde_json::to_string(&SavedRef { queues: &st.queues, outbox, known: &st.known }).unwrap_or_default()
        };
        if s != *last {
            let tmp = state_file().with_extension("json.tmp");
            if config::write_private(&tmp, s.as_bytes()).is_ok() && std::fs::rename(&tmp, state_file()).is_ok() {
                *last = s;
            }
        }
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
                    "owner_says": st.remote.get(&p.name).and_then(|r| r.owner.clone()),
                    "agents": agents_of(st.remote.get(&p.name)),
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
        let transfers: Vec<Value> = st
            .outgoing
            .iter()
            .map(|(id, o)| json!({"id": id, "direction": "out", "peer": o.peer, "file": o.name, "bytes": o.size, "done": o.sent.load(Ordering::Relaxed)}))
            .chain(st.incoming.values().map(|i| {
                json!({"id": i.meta.id, "direction": "in", "peer": i.peer, "file": files::safe_name(&i.meta.name), "bytes": i.meta.size, "done": i.got, "waiting_to_resume": i.detached.is_some()})
            }))
            .collect();
        json!({
            "key": config::encode_key(&self.me.public),
            "listen": cfg.listen,
            "relay": cfg.relay.as_ref().map(|l| json!({"addr": l.addr, "connected": st.relay_up})),
            "encryption": "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s + ML-KEM-768",
            "local_agents": st.sessions.keys().collect::<Vec<_>>(),
            "peers": peers,
            "open_invites": invites,
            "transfers": transfers,
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
        Ok(json!({"code": encode_invite(&self.me.public, &secret), "for": name, "expires_in_secs": INVITE_TTL.as_secs(), "listen": self.cfg().listen, "relay": self.cfg().relay.is_some()}))
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
            "owner" => {
                let o: String = self.guard().sanitize(s("owner")).replace(['\n', '\t'], " ").trim().chars().take(80).collect();
                cfg.owner = o;
            }
            "rename" => {
                let (old, new) = (s("name"), s("new"));
                if !valid_name(new) {
                    bail!("invalid name {new:?} (letters, digits, - _ . up to 64)");
                }
                if cfg.peer(new).is_some() {
                    bail!("the name {new} is already used");
                }
                cfg.peer.iter_mut().find(|p| p.name == old).ok_or_else(|| anyhow!("no peer named {old}"))?.name = new.into();
                // The live link closes (its name is gone) and reconnects under the new name; queued state moves along.
                let mut st = self.st.lock().unwrap();
                if let Some(q) = st.outbox.remove(old) {
                    st.outbox.insert(new.into(), q);
                }
                if let Some(k) = st.known.remove(old) {
                    st.known.insert(new.into(), k);
                }
                if let Some(b) = st.buckets.remove(old) {
                    st.buckets.insert(new.into(), b);
                }
                for (p, _) in st.unacked.values_mut() {
                    if p == old {
                        *p = new.into();
                    }
                }
                for (p, _) in st.waiters.values_mut() {
                    if p == old {
                        *p = new.into();
                    }
                }
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
            let woken = notify.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            let msgs: Vec<Event> = self.st.lock().unwrap().queues.remove(me).map(Vec::from).unwrap_or_default();
            let left = deadline.saturating_duration_since(Instant::now());
            if !msgs.is_empty() || left.is_zero() {
                if !msgs.is_empty() {
                    let _ = self.watch.send(json!({"ev": "read", "to": me}).to_string());
                }
                return json!({"messages": msgs});
            }
            let _ = timeout(left, woken).await;
        }
    }

    fn unread(&self) -> Value {
        let st = self.st.lock().unwrap();
        let u: serde_json::Map<String, Value> = st
            .queues
            .iter()
            .filter(|(_, q)| !q.is_empty())
            .map(|(k, q)| (k.clone(), json!({"count": q.len(), "about": st.sessions.get(k).and_then(|s| s.about.clone())})))
            .collect();
        json!({"unread": u})
    }

    /// The agent acted after these were pushed to it, so they count as read.
    fn ack(&self, me: &str, pushed: &Mutex<HashSet<String>>) {
        let ids: HashSet<String> = std::mem::take(&mut *pushed.lock().unwrap());
        if ids.is_empty() {
            return;
        }
        let mut st = self.st.lock().unwrap();
        if let Some(q) = st.queues.get_mut(me) {
            q.retain(|e| !ids.contains(&e.id));
            if q.is_empty() {
                st.queues.remove(me);
            }
        }
        drop(st);
        let _ = self.watch.send(json!({"ev": "read", "to": me}).to_string());
    }

    fn register(&self, want: &str, about: Option<String>) -> (String, u64, Arc<Notify>) {
        let mut st = self.st.lock().unwrap();
        let mut name = want.to_string();
        let mut i = 2;
        while st.sessions.contains_key(&name) || name == NOTICE_FROM {
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
        st.sessions.insert(name.clone(), Session { sid, notify: notify.clone(), about });
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
        let want = hello["agent"].as_str().filter(|a| valid_name(a) && *a != NOTICE_FROM).unwrap_or("agent");
        let mode = hello["mode"].as_str().unwrap_or("pull");
        let (pull, push, none) = (mode == "pull", mode == "push", mode == "none" || mode == "watch");
        let root: Option<PathBuf> = hello["root"].as_str().filter(|r| !r.is_empty()).map(PathBuf::from);
        let about = hello["about"]
            .as_str()
            .map(|a| self.guard().clean(a).0.replace(['\n', '\t'], " ").trim().chars().take(200).collect::<String>())
            .filter(|a| !a.is_empty());
        let (name, sid, notify) = if none { (want.to_string(), 0, Arc::new(Notify::new())) } else { self.register(want, about) };
        let _ = out.send(format!(
            "{}\n",
            json!({"rid": hello["rid"], "ok": true, "agent": name, "proof": mac(&self.token, &["node", &challenge, nonce])})
        ));
        // Push sessions: messages stay queued until the agent replies or reads its inbox, so a dropped push loses nothing.
        let pushed: Arc<Mutex<HashSet<String>>> = Arc::default();
        let pusher = push.then(|| {
            let (n, name, notify, out, pushed) = (self.clone(), name.clone(), notify.clone(), out.clone(), pushed.clone());
            tokio::spawn(async move {
                loop {
                    notify.notified().await;
                    let fresh: Vec<Event> = {
                        let st = n.st.lock().unwrap();
                        let mut p = pushed.lock().unwrap();
                        st.queues.get(&name).map(|q| q.iter().filter(|e| p.insert(e.id.clone())).cloned().collect()).unwrap_or_default()
                    };
                    for ev in fresh {
                        if out.send(format!("{}\n", json!({"ev": "msg", "msg": ev}))).is_err() {
                            return;
                        }
                    }
                }
            })
        });
        let watcher = (mode == "watch").then(|| {
            let (mut rx, out) = (self.watch.subscribe(), out.clone());
            tokio::spawn(async move {
                loop {
                    match rx.recv().await {
                        Ok(e) => {
                            if out.send(format!("{e}\n")).is_err() {
                                return;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => return,
                    }
                }
            })
        });
        while let Ok(Some(req)) = read_json(&mut r).await {
            let (n, name, notify, out, root, pushed) = (self.clone(), name.clone(), notify.clone(), out.clone(), root.clone(), pushed.clone());
            tokio::spawn(async move {
                let op = req["op"].as_str().unwrap_or("").to_string();
                let s = |k: &str| req[k].as_str().unwrap_or("").to_string();
                if push && (op == "send" || op == "send_file") {
                    n.ack(&name, &pushed);
                }
                if op == "inbox" {
                    pushed.lock().unwrap().clear();
                }
                let res = match op.as_str() {
                    "send" => n.send(&name, &s("to"), &s("text"), req["thread"].as_str().map(String::from)).await,
                    "send_file" => n.send_file(&name, root.as_deref(), &s("to"), &s("path"), req["note"].as_str()).await,
                    "inbox" if pull || push => Ok(n.inbox(&name, &notify, req["wait"].as_u64().unwrap_or(0)).await),
                    "peers" => Ok(n.peers(&name)),
                    "unread" => Ok(n.unread()),
                    "status" => Ok(n.status()),
                    "invite" => n.invite(&s("name"), req["files"].as_bool().unwrap_or(true)),
                    "join" => n.join(&s("code"), &s("name"), &s("addr")).await,
                    "relay_join" => n.relay_join(&s("code")).await,
                    "relay_leave" => {
                        let mut cfg = (*n.cfg()).clone();
                        cfg.relay = None;
                        n.apply(cfg).map(|_| json!({"relay": null}))
                    }
                    "trust" | "untrust" | "files" | "owner" | "rename" | "reload" => n.admin(&op, &req),
                    "stop" => {
                        n.persist(&mut String::new());
                        let _ = std::fs::remove_file(config::home().join("node.lock"));
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
        if let Some(w) = watcher {
            w.abort();
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
        assert_eq!(decode_invite(&code.to_uppercase().replace("AGENTCOURIER-", "agentcourier-")).unwrap(), (k, s));
        assert_eq!(decode_invite(&code.replace("agentcourier-", "agentwire-")).unwrap(), (k, s));
        assert!(decode_invite("agentcourier-abc").is_err());
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
