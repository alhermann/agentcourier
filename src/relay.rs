//! A relay you run yourself, for machines that cannot reach each other directly.
//! Both connect out to it; it forwards end-to-end encrypted bytes between its members only and
//! never sees message content. It learns who talks to whom, when, and how much.
use crate::config::{self, Identity, valid_name};
use crate::node::ct_eq;
use crate::wire;
use anyhow::{Result, anyhow, bail};
use blake2::{Blake2s256, Digest};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc, oneshot};
use tokio::time::{sleep, timeout};

const CODE_PREFIX: &str = "agentcourier-relay-";
const INVITE_SECS: u64 = 600;
const HANDSHAKE: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(300);
const MEMBER_CHECK: Duration = Duration::from_secs(30);
const TUNNELS_PER_MEMBER: usize = 32;
const PENDING_MAX: usize = 256;
const CONNECTIONS_MAX: usize = 512;

/// How a node reaches its relay (stored in the node's config.toml).
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RelayLink {
    pub addr: String,
    pub key: String,
}

#[derive(Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RelayFile {
    listen: String,
    member: Vec<Member>,
    invite: Vec<Invite>,
}

impl Default for RelayFile {
    fn default() -> Self {
        Self { listen: "0.0.0.0:7400".into(), member: vec![], invite: vec![] }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Member {
    name: String,
    key: String,
}

/// Only a hash of the secret is stored, so reading relay.toml does not let anyone join.
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Invite {
    name: String,
    hash: String,
    expires: u64,
}

fn path() -> PathBuf {
    config::home().join("relay.toml")
}

fn load() -> Result<RelayFile> {
    match std::fs::read_to_string(path()) {
        Ok(s) => Ok(toml::from_str(&s)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RelayFile::default()),
        Err(e) => Err(e.into()),
    }
}

fn save(f: &RelayFile) -> Result<()> {
    let dir = config::ensure_home()?;
    let tmp = dir.join("relay.toml.tmp");
    config::write_private(&tmp, format!("# agentcourier relay: who may use it (rewritten by agentcourier relay commands)\n{}", toml::to_string(f)?).as_bytes())?;
    std::fs::rename(&tmp, path())?;
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn hash(secret: &[u8]) -> String {
    HEXLOWER.encode(&Blake2s256::digest(secret))
}

fn member_name(f: &RelayFile, key: &[u8; 32]) -> Option<String> {
    f.member.iter().find(|m| config::decode_key(&m.key).is_ok_and(|k| &k == key)).map(|m| m.name.clone())
}

/// Creates a one-time code that lets one machine join this relay; `addr` is how members reach it.
pub fn invite(name: &str, addr: &str) -> Result<String> {
    if !valid_name(name) {
        bail!("invalid name {name:?}");
    }
    if !addr.contains(':') {
        bail!("give the address members use to reach this relay, as host:port");
    }
    let me = config::identity()?;
    let mut secret = [0u8; 16];
    getrandom::fill(&mut secret).map_err(|e| anyhow!("random: {e}"))?;
    let mut f = load()?;
    let t = now();
    f.invite.retain(|i| i.expires > t && i.name != name);
    f.invite.push(Invite { name: name.into(), hash: hash(&secret), expires: t + INVITE_SECS });
    save(&f)?;
    let mut b = me.public.to_vec();
    b.extend_from_slice(&secret);
    Ok(format!("{CODE_PREFIX}{}@{addr}", BASE32_NOPAD.encode(&b).to_ascii_lowercase()))
}

pub fn members() -> Result<Vec<(String, String)>> {
    Ok(load()?.member.into_iter().map(|m| (m.name, m.key)).collect())
}

pub fn remove(name: &str) -> Result<bool> {
    let mut f = load()?;
    let before = f.member.len();
    f.member.retain(|m| m.name != name);
    save(&f)?;
    Ok(f.member.len() < before)
}

fn decode_code(code: &str) -> Result<(String, [u8; 32], [u8; 16])> {
    let rest = code.trim().strip_prefix(CODE_PREFIX).ok_or_else(|| anyhow!("not an agentcourier relay code"))?;
    let (body, addr) = rest.split_once('@').ok_or_else(|| anyhow!("malformed relay code"))?;
    let b = BASE32_NOPAD.decode(body.to_ascii_uppercase().as_bytes()).map_err(|_| anyhow!("malformed relay code"))?;
    if b.len() != 48 || !addr.contains(':') {
        bail!("malformed relay code");
    }
    Ok((addr.to_string(), b[..32].try_into()?, b[32..].try_into()?))
}

// ---------- node side ----------

/// Opens an encrypted, authenticated channel to the relay and states what it is for.
async fn open(link: &RelayLink, me: &Identity, first: Value) -> Result<(wire::Reader, wire::Writer)> {
    let key = config::decode_key(&link.key)?;
    let s = timeout(HANDSHAKE, TcpStream::connect(&link.addr)).await.map_err(|_| anyhow!("relay {} not reachable", link.addr))??;
    s.set_nodelay(true)?;
    let (r, mut w) = timeout(HANDSHAKE, wire::initiate(s, me, &key)).await.map_err(|_| anyhow!("relay {} did not answer", link.addr))??;
    w.send(first.to_string().as_bytes()).await?;
    Ok((r, w))
}

async fn expect_ok(r: &mut wire::Reader) -> Result<Value> {
    let v: Value = serde_json::from_slice(&timeout(Duration::from_secs(15), r.recv()).await.map_err(|_| anyhow!("relay timeout"))??)?;
    if v["ok"] != true {
        let why: String = v["error"].as_str().unwrap_or("refused").chars().filter(|c| !c.is_control()).take(200).collect();
        bail!("relay: {why}");
    }
    Ok(v)
}

/// Turns a relay channel into a plain byte stream for the end-to-end handshake between the two machines.
pub fn tunnel(mut r: wire::Reader, mut w: wire::Writer) -> DuplexStream {
    let (local, remote) = tokio::io::duplex(1 << 18);
    let (mut rr, mut rw) = tokio::io::split(remote);
    let down = tokio::spawn(async move {
        while let Ok(m) = r.recv().await {
            if rw.write_all(&m).await.is_err() {
                break;
            }
        }
        let _ = rw.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match rr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if w.send(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Dropping both halves closes the relay connection.
        down.abort();
    });
    local
}

pub async fn dial(link: &RelayLink, me: &Identity, to: &[u8; 32]) -> Result<DuplexStream> {
    let (mut r, w) = open(link, me, json!({"op": "connect", "to": config::encode_key(to)})).await?;
    expect_ok(&mut r).await?;
    Ok(tunnel(r, w))
}

pub async fn accept(link: &RelayLink, me: &Identity, token: &str) -> Result<DuplexStream> {
    let (mut r, w) = open(link, me, json!({"op": "accept", "token": token})).await?;
    expect_ok(&mut r).await?;
    Ok(tunnel(r, w))
}

/// Keeps this machine reachable through the relay; `incoming` gets a token for each machine that wants to connect.
pub async fn listen(link: &RelayLink, me: &Identity, ping: Duration, ready: impl FnOnce(), mut incoming: impl FnMut(String, String)) -> Result<()> {
    let (mut r, mut w) = open(link, me, json!({"op": "listen"})).await?;
    expect_ok(&mut r).await?;
    ready();
    let mut tick = tokio::time::interval(ping);
    loop {
        tokio::select! {
            m = timeout(ping * 3, r.recv()) => {
                let v: Value = serde_json::from_slice(&m.map_err(|_| anyhow!("relay went quiet"))??)?;
                if v["op"] == "incoming" {
                    if let (Some(t), Some(f)) = (v["token"].as_str(), v["from"].as_str()) {
                        incoming(t.to_string(), f.to_string());
                    }
                }
            }
            _ = tick.tick() => w.send(br#"{"op":"ping"}"#).await?,
        }
    }
}

pub async fn join(code: &str, me: &Identity) -> Result<RelayLink> {
    let (addr, key, secret) = decode_code(code)?;
    let link = RelayLink { addr, key: config::encode_key(&key) };
    let (mut r, _w) = open(&link, me, json!({"op": "join", "secret": HEXLOWER.encode(&secret)}))
        .await
        .map_err(|e| anyhow!("{e} (or the code was wrong, used or expired)"))?;
    expect_ok(&mut r).await.map_err(|_| anyhow!("refused: the code is wrong, used or expired"))?;
    Ok(link)
}

// ---------- relay side ----------

struct Pending {
    to: [u8; 32],
    tx: oneshot::Sender<(wire::Reader, wire::Writer)>,
}

struct Relay {
    me: Identity,
    listening: Mutex<HashMap<[u8; 32], (u64, mpsc::UnboundedSender<String>)>>,
    pending: Mutex<HashMap<String, Pending>>,
    tunnels: Mutex<HashMap<[u8; 32], usize>>,
    ids: AtomicU64,
}

/// Counts one open tunnel of a member and frees the slot when dropped.
struct Slot<'a>(&'a Relay, [u8; 32]);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        if let Some(c) = self.0.tunnels.lock().unwrap().get_mut(&self.1) {
            *c = c.saturating_sub(1);
        }
    }
}

pub async fn serve(listen: Option<String>) -> Result<()> {
    let me = config::identity()?;
    let mut f = load()?;
    if let Some(l) = listen {
        f.listen = l;
    }
    save(&f)?;
    let l = TcpListener::bind(&f.listen).await.map_err(|e| anyhow!("relay cannot listen on {}: {e}", f.listen))?;
    eprintln!("agentcourier relay {} listening on {} ({} members)", config::encode_key(&me.public), f.listen, f.member.len());
    run(l, me).await
}

async fn run(l: TcpListener, me: Identity) -> Result<()> {
    let relay = Arc::new(Relay { me, listening: Mutex::default(), pending: Mutex::default(), tunnels: Mutex::default(), ids: AtomicU64::new(1) });
    let gate = Arc::new(Semaphore::new(CONNECTIONS_MAX));
    loop {
        let Ok((s, _)) = l.accept().await else { continue };
        let Ok(permit) = gate.clone().try_acquire_owned() else { continue };
        let r = relay.clone();
        tokio::spawn(async move {
            let _ = s.set_nodelay(true);
            let _ = r.conn(s).await;
            drop(permit);
        });
    }
}

async fn reply(w: &mut wire::Writer, v: Value) -> Result<()> {
    w.send(v.to_string().as_bytes()).await
}

impl Relay {
    async fn conn(self: Arc<Self>, s: TcpStream) -> Result<()> {
        let file = load()?;
        let invites_open = file.invite.iter().any(|i| i.expires > now());
        let allowed = |k: &[u8; 32]| member_name(&file, k).is_some() || invites_open;
        let (key, link) = timeout(HANDSHAKE, wire::respond(s, &self.me, allowed)).await??;
        let Some((mut r, mut w)) = link else { return Ok(()) };
        let first: Value = serde_json::from_slice(&timeout(HANDSHAKE, r.recv()).await??)?;
        let member = member_name(&load()?, &key);
        match (first["op"].as_str().unwrap_or(""), member) {
            ("join", None) => self.join(key, &first, &mut w).await,
            ("listen", Some(name)) => self.listen(key, name, r, w).await,
            ("connect", Some(name)) => self.connect(key, name, &first, r, w).await,
            ("accept", Some(_)) => self.accept(key, &first, r, w).await,
            _ => Ok(()),
        }
    }

    async fn join(&self, key: [u8; 32], first: &Value, w: &mut wire::Writer) -> Result<()> {
        let raw = HEXLOWER.decode(first["secret"].as_str().unwrap_or("").as_bytes()).unwrap_or_default();
        let h = hash(&raw);
        let mut f = load()?;
        let t = now();
        f.invite.retain(|i| i.expires > t);
        let Some(i) = f.invite.iter().position(|i| ct_eq(&i.hash, &h)) else {
            sleep(Duration::from_secs(1)).await;
            return Ok(());
        };
        let inv = f.invite.remove(i);
        f.member.retain(|m| m.name != inv.name);
        f.member.push(Member { name: inv.name.clone(), key: config::encode_key(&key) });
        save(&f)?;
        eprintln!("relay: {} joined", inv.name);
        reply(w, json!({"ok": true, "name": inv.name})).await
    }

    async fn listen(&self, key: [u8; 32], name: String, mut r: wire::Reader, mut w: wire::Writer) -> Result<()> {
        let id = self.ids.fetch_add(1, Ordering::Relaxed);
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        self.listening.lock().unwrap().insert(key, (id, tx));
        eprintln!("relay: {name} online");
        let _ = reply(&mut w, json!({"ok": true})).await;
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => if w.send(m.as_bytes()).await.is_err() { break },
                    None => break,
                },
                m = timeout(IDLE, r.recv()) => match m {
                    // A removed member loses its place at the next ping.
                    Ok(Ok(_)) if member_name(&load()?, &key).is_some() => {
                        if reply(&mut w, json!({"op": "pong"})).await.is_err() {
                            break;
                        }
                    }
                    _ => break,
                },
            }
        }
        let mut l = self.listening.lock().unwrap();
        if l.get(&key).is_some_and(|(i, _)| *i == id) {
            l.remove(&key);
        }
        eprintln!("relay: {name} offline");
        Ok(())
    }

    async fn connect(&self, key: [u8; 32], name: String, first: &Value, r: wire::Reader, mut w: wire::Writer) -> Result<()> {
        let Some(to) = first["to"].as_str().and_then(|k| config::decode_key(k).ok()) else { return Ok(()) };
        let Some(to_name) = member_name(&load()?, &to) else {
            return reply(&mut w, json!({"error": "that machine is not a member of this relay"})).await;
        };
        let full = {
            let mut t = self.tunnels.lock().unwrap();
            let c = t.entry(key).or_default();
            let full = *c >= TUNNELS_PER_MEMBER;
            if !full {
                *c += 1;
            }
            full
        };
        if full {
            return reply(&mut w, json!({"error": "too many open connections"})).await;
        }
        let _slot = Slot(self, key);
        let ctl = self.listening.lock().unwrap().get(&to).map(|(_, tx)| tx.clone());
        let Some(ctl) = ctl else {
            return reply(&mut w, json!({"error": "that machine is not connected to the relay"})).await;
        };
        let token = config::random_hex(16);
        let (tx, rx) = oneshot::channel();
        let busy = {
            let mut p = self.pending.lock().unwrap();
            let busy = p.len() >= PENDING_MAX;
            if !busy {
                p.insert(token.clone(), Pending { to, tx });
            }
            busy
        };
        if busy {
            return reply(&mut w, json!({"error": "relay busy"})).await;
        }
        let _ = ctl.send(json!({"op": "incoming", "token": token, "from": config::encode_key(&key)}).to_string());
        let other = timeout(HANDSHAKE, rx).await;
        self.pending.lock().unwrap().remove(&token);
        let Ok(Ok((br, bw))) = other else {
            return reply(&mut w, json!({"error": "that machine did not answer"})).await;
        };
        reply(&mut w, json!({"ok": true})).await?;
        eprintln!("relay: {name} -> {to_name} connected");
        splice(r, w, br, bw, [key, to]).await;
        eprintln!("relay: {name} -> {to_name} closed");
        Ok(())
    }

    async fn accept(&self, key: [u8; 32], first: &Value, r: wire::Reader, mut w: wire::Writer) -> Result<()> {
        let token = first["token"].as_str().unwrap_or("");
        let p = self.pending.lock().unwrap().remove(token);
        // Only the machine the token was sent to may take the connection.
        let Some(p) = p.filter(|p| p.to == key) else { return Ok(()) };
        reply(&mut w, json!({"ok": true})).await?;
        let _ = p.tx.send((r, w));
        Ok(())
    }
}

async fn splice(mut ar: wire::Reader, mut aw: wire::Writer, mut br: wire::Reader, mut bw: wire::Writer, ends: [[u8; 32]; 2]) {
    let a2b = async {
        while let Ok(Ok(m)) = timeout(IDLE, ar.recv()).await {
            if bw.send(&m).await.is_err() {
                break;
            }
        }
    };
    let b2a = async {
        while let Ok(Ok(m)) = timeout(IDLE, br.recv()).await {
            if aw.send(&m).await.is_err() {
                break;
            }
        }
    };
    // A removed member also loses its open connections.
    let still_members = async {
        loop {
            sleep(MEMBER_CHECK).await;
            match load() {
                Ok(f) if ends.iter().all(|k| member_name(&f, k).is_some()) => {}
                _ => break,
            }
        }
    };
    tokio::select! { _ = a2b => {}, _ = b2a => {}, _ = still_members => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ident() -> Identity {
        let kp = snow::Builder::new(wire::PATTERN.parse().unwrap()).generate_keypair().unwrap();
        Identity { secret: kp.private.try_into().unwrap(), public: kp.public.try_into().unwrap() }
    }

    #[tokio::test]
    async fn members_reach_each_other_strangers_do_not() {
        let home = std::env::temp_dir().join(format!("agentcourier-relay-test-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        // SAFETY: the only test that reads the home folder.
        unsafe { std::env::set_var("AGENTCOURIER_HOME", &home) };
        let (relay, a, b, c) = (ident(), ident(), ident(), ident());
        save(&RelayFile {
            member: vec![Member { name: "a".into(), key: config::encode_key(&a.public) }, Member { name: "b".into(), key: config::encode_key(&b.public) }],
            ..RelayFile::default()
        })
        .unwrap();
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let link = RelayLink { addr: l.local_addr().unwrap().to_string(), key: config::encode_key(&relay.public) };
        tokio::spawn(run(l, ident_copy(&relay)));

        // a listens; b connects to a through the relay; the end-to-end handshake runs inside the tunnel.
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (la, a2) = (link.clone(), ident_copy(&a));
        tokio::spawn(async move { listen(&la, &a2, Duration::from_secs(5), || {}, move |t, f| { let _ = tx.send((t, f)); }).await });
        sleep(Duration::from_millis(300)).await;
        let (lb, b2, a_pub, b_pub) = (link.clone(), ident_copy(&b), a.public, b.public);
        let dialer = tokio::spawn(async move {
            let s = dial(&lb, &b2, &a_pub).await?;
            let (mut r, mut w) = wire::initiate(s, &b2, &a_pub).await?;
            w.send(b"hello through the relay").await?;
            anyhow::Ok(r.recv().await?)
        });
        let (token, from) = rx.recv().await.unwrap();
        assert_eq!(from, config::encode_key(&b_pub));
        let s = accept(&link, &a, &token).await.unwrap();
        let (k, chan) = wire::respond(s, &a, |k| *k == b_pub).await.unwrap();
        assert_eq!(k, b_pub);
        let (mut r, mut w) = chan.unwrap();
        let m = r.recv().await.unwrap();
        w.send(&m).await.unwrap();
        assert_eq!(dialer.await.unwrap().unwrap(), b"hello through the relay");

        // A stranger gets no answer, and cannot reach members.
        assert!(dial(&link, &c, &a.public).await.is_err());

        // With a one-time code the stranger can join, once. (invite() signs with the home key; the test relay has its own.)
        let (_, _, secret) = decode_code(&invite("c", &link.addr).unwrap()).unwrap();
        let fixed = format!("{CODE_PREFIX}{}@{}", BASE32_NOPAD.encode(&[relay.public.as_slice(), &secret].concat()).to_ascii_lowercase(), link.addr);
        assert!(join(&fixed, &c).await.is_ok());
        assert!(join(&fixed, &ident()).await.is_err());
        assert!(members().unwrap().iter().any(|(n, k)| n == "c" && k == &config::encode_key(&c.public)));
        let _ = std::fs::remove_dir_all(&home);
    }

    fn ident_copy(i: &Identity) -> Identity {
        Identity { secret: i.secret, public: i.public }
    }
}
