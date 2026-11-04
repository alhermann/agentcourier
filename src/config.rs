use anyhow::{Context, Result, anyhow, bail};
use data_encoding::{BASE32_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub fn valid_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

pub fn home() -> PathBuf {
    if let Some(h) = std::env::var_os("AGORA_HOME") {
        return h.into();
    }
    let base = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).unwrap_or_else(|| ".".into());
    PathBuf::from(base).join(".agora")
}

pub fn ensure_home() -> Result<PathBuf> {
    let h = home();
    fs::create_dir_all(&h).with_context(|| format!("create {}", h.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&h, fs::Permissions::from_mode(0o700))?;
    }
    Ok(h)
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Address for encrypted peer connections.
    pub listen: String,
    /// Local control port (Windows only; Unix uses a socket in the agora home).
    pub ipc_port: u16,
    /// Optional command started when a message waits for an agent that is not running. Never receives message text.
    pub wake: Vec<String>,
    pub guard: GuardCfg,
    pub peer: Vec<Peer>,
}

impl Default for Config {
    fn default() -> Self {
        Self { listen: "127.0.0.1:7312".into(), ipc_port: 7313, wake: vec![], guard: GuardCfg::default(), peer: vec![] }
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub name: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct GuardCfg {
    pub redact: bool,
    pub redact_ip: bool,
    pub max_bytes: usize,
    pub per_minute: u32,
}

impl Default for GuardCfg {
    fn default() -> Self {
        Self { redact: true, redact_ip: false, max_bytes: 128 * 1024, per_minute: 120 }
    }
}

impl Config {
    pub fn peer_by_key(&self, key: &[u8; 32]) -> Option<&Peer> {
        self.peer.iter().find(|p| decode_key(&p.key).is_ok_and(|k| &k == key))
    }
    pub fn peer(&self, name: &str) -> Option<&Peer> {
        self.peer.iter().find(|p| p.name == name)
    }
}

pub fn load() -> Result<Config> {
    let path = home().join("config.toml");
    match fs::read_to_string(&path) {
        Ok(s) => {
            let c: Config = toml::from_str(&s).with_context(|| format!("parse {}", path.display()))?;
            for p in &c.peer {
                if !valid_name(&p.name) {
                    bail!("invalid peer name {:?}", p.name);
                }
                decode_key(&p.key).with_context(|| format!("peer {}", p.name))?;
            }
            Ok(c)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
        Err(e) => Err(e.into()),
    }
}

pub fn save(c: &Config) -> Result<()> {
    let dir = ensure_home()?;
    let body = toml::to_string(c)?;
    let tmp = dir.join("config.toml.tmp");
    fs::write(&tmp, format!("# agora configuration (rewritten by `agora trust`/`untrust`)\n{body}"))?;
    fs::rename(&tmp, dir.join("config.toml"))?;
    Ok(())
}

pub fn encode_key(k: &[u8]) -> String {
    BASE32_NOPAD.encode(k).to_ascii_lowercase()
}

pub fn decode_key(s: &str) -> Result<[u8; 32]> {
    let v = BASE32_NOPAD.decode(s.trim().to_ascii_uppercase().as_bytes()).map_err(|_| anyhow!("malformed key"))?;
    v.try_into().map_err(|_| anyhow!("key must be 32 bytes"))
}

pub struct Identity {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

pub fn identity() -> Result<Identity> {
    let path = ensure_home()?.join("key");
    if let Ok(s) = fs::read_to_string(&path) {
        let mut it = s.lines().map(|l| HEXLOWER.decode(l.trim().as_bytes()));
        let (Some(Ok(sk)), Some(Ok(pk))) = (it.next(), it.next()) else { bail!("corrupt key file {}", path.display()) };
        return Ok(Identity {
            secret: sk.try_into().map_err(|_| anyhow!("corrupt key"))?,
            public: pk.try_into().map_err(|_| anyhow!("corrupt key"))?,
        });
    }
    let kp = snow::Builder::new(crate::wire::PATTERN.parse()?).generate_keypair().map_err(|e| anyhow!("keygen: {e:?}"))?;
    write_private(&path, format!("{}\n{}\n", HEXLOWER.encode(&kp.private), HEXLOWER.encode(&kp.public)).as_bytes())?;
    identity()
}

pub fn ipc_token() -> Result<String> {
    let path = ensure_home()?.join("ipc.token");
    if let Ok(t) = fs::read_to_string(&path) {
        if t.trim().len() == 64 {
            return Ok(t.trim().to_string());
        }
    }
    let t = random_hex(32);
    write_private(&path, t.as_bytes())?;
    Ok(t)
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("OS random generator unavailable");
    HEXLOWER.encode(&b)
}

fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut o = fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    o.open(path)?.write_all(data)?;
    Ok(())
}
