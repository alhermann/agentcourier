//! File screening: content sniffing, safe names, sensitive-path refusal and an external malware scan.
use crate::config::FilesCfg;
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Kind {
    Text,
    Data,
    Container,
    Executable,
    Unknown,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Text => "text",
            Kind::Data => "data",
            Kind::Container => "document/archive",
            Kind::Executable => "executable",
            Kind::Unknown => "unknown binary",
        }
    }
}

pub fn classify(b: &[u8]) -> Kind {
    let has = |m: &[u8]| b.starts_with(m);
    let exe: [&[u8]; 9] = [
        b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
        b"\x4c\x00\x00\x00\x01\x14\x02\x00", b"\0asm",
    ];
    let container: [&[u8]; 12] = [
        b"%PDF", b"PK\x03\x04", b"PK\x05\x06", b"\xd0\xcf\x11\xe0", b"\x1f\x8b", b"7z\xbc\xaf\x27\x1c", b"Rar!", b"BZh",
        b"\xfd7zXZ", b"\x28\xb5\x2f\xfd", b"{\\rtf", b"MSCF",
    ];
    let data: [&[u8]; 11] = [
        b"\x89PNG", b"\xff\xd8\xff", b"GIF87a", b"GIF89a", b"\x89HDF\r\n\x1a\n", b"CDF\x01", b"CDF\x02", b"\x93NUMPY", b"II*\0",
        b"MM\0*", b"%!PS",
    ];
    if exe.iter().any(|m| has(m)) {
        Kind::Executable
    } else if container.iter().any(|m| has(m)) || b.get(257..262) == Some(b"ustar") {
        Kind::Container
    } else if data.iter().any(|m| has(m)) || (has(b"RIFF") && b.get(8..12) == Some(b"WEBP")) {
        Kind::Data
    } else if !b.contains(&0) && std::str::from_utf8(b).is_ok() {
        Kind::Text
    } else {
        Kind::Unknown
    }
}

const RESERVED: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4",
    "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Extensions a desktop may run or interpret on double-click.
const RISKY_EXT: [&str; 37] = [
    "exe", "com", "scr", "bat", "cmd", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "cpl", "msc", "msi", "msp", "lnk", "url",
    "scf", "reg", "ps1", "psm1", "jar", "application", "gadget", "desktop", "library-ms", "settingcontent-ms", "appref-ms", "iso",
    "img", "vhd", "vhdx", "chm", "inf", "command",
];

pub fn safe_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let s: String = base.chars().map(|c| if c.is_ascii_alphanumeric() || "._-".contains(c) { c } else { '_' }).collect();
    let mut s = s.trim_start_matches('.').trim_end_matches('.').to_string();
    s.truncate(100);
    if s.is_empty() {
        s = "file".into();
    }
    if RESERVED.contains(&s.split('.').next().unwrap_or("").to_ascii_uppercase().as_str()) {
        s.insert(0, '_');
    }
    if s.rsplit_once('.').is_some_and(|(_, e)| RISKY_EXT.contains(&e.to_ascii_lowercase().as_str())) {
        s.push_str(".txt");
    }
    s
}

/// Credentials and keys that must never leave the machine, whatever an agent is told.
pub fn sensitive(p: &Path) -> bool {
    const DIRS: [&str; 12] = [".ssh", ".gnupg", ".aws", ".azure", ".kube", ".agora", ".docker", "gcloud", ".password-store", ".vault-token", ".terraform.d", ".config/gh"];
    const FILES: [&str; 8] = [".netrc", ".pgpass", ".git-credentials", ".npmrc", ".pypirc", "credentials", "credentials.json", "secrets.json"];
    const EXT: [&str; 9] = ["pem", "key", "p12", "pfx", "keystore", "jks", "kdbx", "ppk", "gpg"];
    let lower = p.to_string_lossy().replace('\\', "/").to_ascii_lowercase();
    let comps: Vec<&str> = lower.split('/').collect();
    let name = comps.last().copied().unwrap_or("");
    comps.iter().any(|c| DIRS.contains(c))
        || DIRS.iter().any(|d| d.contains('/') && lower.contains(d))
        || FILES.contains(&name)
        || name == ".env"
        || name.starts_with(".env.")
        || ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"].iter().any(|k| name.starts_with(k))
        || name.rsplit_once('.').is_some_and(|(_, e)| EXT.contains(&e))
}

fn which(cmd: &str) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) { &[".exe", ".bat", ".cmd"] } else { &[""] };
    std::env::split_paths(&std::env::var_os("PATH")?).flat_map(|d| exts.iter().map(move |e| d.join(format!("{cmd}{e}")))).find(|p| p.is_file())
}

/// MpCmdRun exits 2 both for "threat found" and "Defender disabled", so only use it while the service runs.
fn defender_running() -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        return std::process::Command::new("sc.exe")
            .args(["query", "WinDefend"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(0x0800_0000)
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"));
    }
    #[allow(unreachable_code)]
    false
}

fn scanner(cfg: &FilesCfg) -> Option<Vec<String>> {
    if cfg.scanner.first().is_some_and(|s| s == "off") {
        return None;
    }
    if !cfg.scanner.is_empty() {
        return Some(cfg.scanner.clone());
    }
    if cfg!(windows) {
        let pf = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| "C:\\Program Files".into());
        let mp = pf.join("Windows Defender").join("MpCmdRun.exe");
        if mp.is_file() && defender_running() {
            return Some([mp.to_string_lossy().as_ref(), "-Scan", "-ScanType", "3", "-File", "{}", "-DisableRemediation"].map(String::from).to_vec());
        }
        return None;
    }
    if let Some(p) = which("clamdscan") {
        return Some(vec![p.to_string_lossy().into(), "--no-summary".into(), "--fdpass".into(), "{}".into()]);
    }
    which("clamscan").map(|p| vec![p.to_string_lossy().into(), "--no-summary".into(), "{}".into()])
}

pub fn scanner_name(cfg: &FilesCfg) -> Option<String> {
    scanner(cfg).map(|a| Path::new(&a[0]).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default())
}

/// Returns the scanner's name if it ran and found nothing; errors if it found something or failed.
async fn scan(path: &Path, cfg: &FilesCfg) -> Result<Option<String>> {
    let Some(argv) = scanner(cfg) else { return Ok(None) };
    let name = Path::new(&argv[0]).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let args = argv[1..].iter().map(|a| if a == "{}" { path.to_string_lossy().into_owned() } else { a.clone() });
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(args).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).kill_on_drop(true);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => bail!("malware scanner {name} could not start: {e}"),
    };
    match tokio::time::timeout(Duration::from_secs(300), child.wait_with_output()).await {
        Ok(Ok(o)) if o.status.success() => Ok(Some(name)),
        Ok(Ok(o)) => bail!("blocked: {name} reported a threat or could not scan (exit {})", o.status.code().unwrap_or(-1)),
        Ok(Err(e)) => bail!("malware scan failed: {e}"),
        Err(_) => bail!("malware scan timed out"),
    }
}

/// Decides whether a received file may be kept. Fails closed.
pub async fn screen(path: &Path, bytes: &[u8], cfg: &FilesCfg) -> Result<(Kind, Option<String>)> {
    let kind = classify(bytes);
    if kind == Kind::Executable && !cfg.allow_executables {
        bail!("blocked: executable content");
    }
    let scanned = scan(path, cfg).await?;
    let needs_scan = cfg.require_scan || matches!(kind, Kind::Container | Kind::Unknown | Kind::Executable);
    if needs_scan && scanned.is_none() {
        bail!("blocked: {} files are accepted only after a malware scan, and no scanner is available", kind.label());
    }
    Ok((kind, scanned))
}

/// Stops the stored file from being executed or trusted by the desktop.
pub fn quarantine(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let mut ads = path.as_os_str().to_owned();
        ads.push(":Zone.Identifier");
        std::fs::write(ads, "[ZoneTransfer]\r\nZoneId=3\r\n")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_content_not_names() {
        assert_eq!(classify(b"MZ\x90\0"), Kind::Executable);
        assert_eq!(classify(b"\x7fELF\x02"), Kind::Executable);
        assert_eq!(classify(b"%PDF-1.7"), Kind::Container);
        assert_eq!(classify(b"PK\x03\x04rest"), Kind::Container);
        assert_eq!(classify(b"\x89HDF\r\n\x1a\nxx"), Kind::Data);
        assert_eq!(classify("#!/bin/sh\necho hi ü\n".as_bytes()), Kind::Text);
        assert_eq!(classify(b""), Kind::Text);
        assert_eq!(classify(b"\x00\x01\x02\xff"), Kind::Unknown);
    }

    #[test]
    fn names_cannot_escape_or_run() {
        assert_eq!(safe_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_name("..\\..\\x.txt"), "x.txt");
        assert_eq!(safe_name("CON.txt"), "_CON.txt");
        assert_eq!(safe_name("run me.bat"), "run_me.bat.txt");
        assert_eq!(safe_name("evil.PS1"), "evil.PS1.txt");
        assert_eq!(safe_name("..."), "file");
        assert_eq!(safe_name("résumé\u{202e}fdp.exe"), "r_sum__fdp.exe.txt");
        assert_eq!(safe_name("results.h5"), "results.h5");
    }

    #[test]
    fn refuses_credentials() {
        for p in ["/home/u/.ssh/config", "C:\\Users\\u\\.aws\\credentials", "proj/.env", "proj/.env.local", "k/id_ed25519", "a/server.pem", "/u/.config/gh/hosts.yml"] {
            assert!(sensitive(Path::new(p)), "{p}");
        }
        for p in ["proj/src/main.rs", "proj/data/run.h5", "proj/environment.yml", "proj/keys.md"] {
            assert!(!sensitive(Path::new(p)), "{p}");
        }
    }

    #[tokio::test]
    async fn screening_fails_closed_without_scanner() {
        let cfg = FilesCfg { scanner: vec!["off".into()], ..FilesCfg::default() };
        let p = Path::new("unused");
        assert!(screen(p, b"MZ\x90", &cfg).await.is_err());
        assert!(screen(p, b"%PDF-1.7", &cfg).await.is_err());
        assert_eq!(screen(p, b"plain text", &cfg).await.unwrap(), (Kind::Text, None));
        let strict = FilesCfg { require_scan: true, ..cfg };
        assert!(screen(p, b"plain text", &strict).await.is_err());
    }
}
