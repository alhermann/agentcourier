//! Content guard: strips invisible/control characters and masks PII and secrets.
use crate::config::GuardCfg;
use regex::{Captures, Regex};
use std::sync::LazyLock;

type Rep = fn(&Captures, &str) -> Option<String>;

struct Rule {
    kind: &'static str,
    re: Regex,
    rep: Rep,
}

pub struct Guard {
    pub cfg: GuardCfg,
    ansi: Regex,
    rules: Vec<Rule>,
}

fn mask(k: &str) -> String {
    format!("[REDACTED:{k}]")
}
fn whole(_: &Captures, k: &str) -> Option<String> {
    Some(mask(k))
}
fn value(c: &Captures, k: &str) -> Option<String> {
    Some(format!("{}{}{}", &c[1], &c[2], mask(k)))
}
/// Like `value`, but leaves code that only names a secret alone (`settings.SECRET_KEY`, `get_token()`, `$TOKEN`, `true`).
fn secret_value(c: &Captures, k: &str) -> Option<String> {
    static CALL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][\w.]*\((?:\)|$)").unwrap());
    static VAR: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\$(?:[A-Za-z_]\w*|\{[A-Za-z_]\w*\})$").unwrap());
    static ATTR: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^(?:os|settings|config|cfg|conf|env|process|self|this|args|options|app|request|ctx|secrets)(?:\.[A-Za-z_]\w*)+$").unwrap());
    let v = &c[3];
    let reference = CALL.is_match(v) || VAR.is_match(v) || ATTR.is_match(v) || ["true", "false", "null", "none"].contains(&v.to_ascii_lowercase().as_str());
    (!reference).then(|| value(c, k)).flatten()
}
fn url_cred(c: &Captures, k: &str) -> Option<String> {
    Some(format!("{}{}@", &c[1], mask(k)))
}
fn email(c: &Captures, k: &str) -> Option<String> {
    // git@host:org/repo is an address, not a person
    (!c[0].starts_with("git@")).then(|| mask(k))
}
fn digits(s: &str) -> Vec<u32> {
    s.chars().filter_map(|c| c.to_digit(10)).collect()
}
fn phone(c: &Captures, k: &str) -> Option<String> {
    (8..=15).contains(&digits(&c[0]).len()).then(|| mask(k))
}
fn card(c: &Captures, k: &str) -> Option<String> {
    let d = digits(&c[0]);
    let sum: u32 = d.iter().rev().enumerate().map(|(i, &x)| if i % 2 == 1 { if x * 2 > 9 { x * 2 - 9 } else { x * 2 } } else { x }).sum();
    ((13..=19).contains(&d.len()) && sum % 10 == 0 && d.iter().any(|&x| x != d[0])).then(|| mask(k))
}
fn iban(c: &Captures, k: &str) -> Option<String> {
    let s: String = c[0].chars().filter(|c| !c.is_whitespace()).collect();
    if !(15..=34).contains(&s.len()) {
        return None;
    }
    let rearranged = s[4..].chars().chain(s[..4].chars());
    let mut rem = 0u64;
    for ch in rearranged {
        let v = ch.to_digit(36)? as u64;
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    (rem == 1).then(|| mask(k))
}

fn keep(c: char) -> bool {
    if c == '\n' || c == '\t' {
        return true;
    }
    !c.is_control()
        && !matches!(c as u32,
            0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x180B..=0x180F | 0x200B..=0x200F | 0x2028..=0x202E | 0x2060..=0x2064
            | 0x2066..=0x206F | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0 | 0xFFF9..=0xFFFB | 0x1D173..=0x1D17A | 0xE0000..=0xE007F
            | 0xE0100..=0xE01EF)
}

impl Guard {
    pub fn new(cfg: GuardCfg) -> Self {
        let r = |kind, re: &str, rep: Rep| Rule { kind, re: Regex::new(re).unwrap(), rep };
        let rules = vec![
            r("private_key", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----", whole),
            r("token", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", whole),
            r(
                "token",
                r"\b(?:sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,})",
                whole,
            ),
            r(
                "secret",
                r#"(?i)\b(password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|auth[_-]?token|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)(["']?\s*[:=]\s*)("[^"\n]{4,}"|'[^'\n]{4,}'|[^\s"',;]{4,})"#,
                secret_value,
            ),
            // Environment-style names such as DB_PASSWORD or AWS_SECRET_ACCESS_KEY (upper case only, to spare code like pad_token).
            r(
                "secret",
                r#"\b((?:[A-Z][A-Z0-9_]*_)?(?:PASSWORD|PASSWD|SECRET|SECRET_KEY|TOKEN|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET))(["']?\s*[:=]\s*)("[^"\n]{4,}"|'[^'\n]{4,}'|[^\s"',;]{4,})"#,
                secret_value,
            ),
            r("credentials", r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/:@]+:[^\s/@]+@", url_cred),
            r("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b", email),
            r("iban", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b", iban),
            r("card", r"\b\d(?:[ -]?\d){12,18}\b", card),
            r("phone", r"\+\d[\d ()./-]{6,20}\d", phone),
            r("ip", r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", whole),
        ];
        let ansi = Regex::new(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|.)").unwrap();
        Self { cfg, ansi, rules }
    }

    pub fn sanitize(&self, s: &str) -> String {
        self.ansi.replace_all(s, "").chars().filter(|&c| keep(c)).collect()
    }

    pub fn redact(&self, s: &str) -> (String, Vec<&'static str>) {
        let mut out = s.to_string();
        let mut hits = vec![];
        if !self.cfg.redact {
            return (out, hits);
        }
        for rule in &self.rules {
            if rule.kind == "ip" && !self.cfg.redact_ip {
                continue;
            }
            let mut hit = false;
            let new = rule.re.replace_all(&out, |c: &Captures| match (rule.rep)(c, rule.kind) {
                Some(m) => {
                    hit = true;
                    m
                }
                None => c[0].to_string(),
            });
            if hit {
                out = new.into_owned();
                if !hits.contains(&rule.kind) {
                    hits.push(rule.kind);
                }
            }
        }
        (out, hits)
    }

    pub fn clean(&self, s: &str) -> (String, Vec<&'static str>) {
        self.redact(&self.sanitize(s))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> Guard {
        Guard::new(GuardCfg::default())
    }

    #[test]
    fn strips_invisible_and_control() {
        let s = "a\u{202E}b\u{200B}c\u{E0041}d\x1b[31me\x07f\r\n\tg";
        assert_eq!(g().sanitize(s), "abcdef\n\tg");
    }

    #[test]
    fn masks_pii_and_secrets() {
        let (o, h) = g().clean(
            "mail jane.doe@hereon.de, call +49 40 1234 5678, card 4111 1111 1111 1111, \
             iban DE89 3704 0044 0532 0130 00, key ghp_abcdefghijklmnopqrstuvwxyz0123456789, \
             password=hunter22, url https://bob:pw123@host/x",
        );
        for leak in ["jane", "5678", "4111", "DE89", "ghp_", "hunter22", "pw123"] {
            assert!(!o.contains(leak), "{leak} leaked in {o}");
        }
        assert!(o.contains("password=[REDACTED:secret]"));
        assert!(o.contains("https://[REDACTED:credentials]@host/x"));
        for k in ["email", "phone", "card", "iban", "token", "secret", "credentials"] {
            assert!(h.contains(&k), "{k} missing in {h:?}");
        }
    }

    #[test]
    fn masks_secrets_in_prefixed_names() {
        let s = "DB_PASSWORD=hunter22\nAWS_SECRET_ACCESS_KEY=abcd1234wxyz\nSECRET_KEY = 'django-xyz9'\n\"access_token\": \"ya29.abcdef\"\n\"DB_PASSWORD\": \"quoted99\"\nPASSWORD=correct.horse\nPASSWORD=ab(cd)ef\nPASSWORD=$tr0ngP@ss";
        let (o, h) = g().clean(s);
        for leak in ["hunter22", "abcd1234wxyz", "django-xyz9", "ya29.abcdef", "quoted99", "correct.horse", "ab(cd)ef", "tr0ngP@ss"] {
            assert!(!o.contains(leak), "{leak} leaked in {o}");
        }
        assert!(o.contains("DB_PASSWORD=[REDACTED:secret]"), "{o}");
        assert!(h.contains(&"secret"));
    }

    #[test]
    fn strips_invisible_format_characters() {
        assert_eq!(g().sanitize("a\u{00AD}b\u{2028}c\u{3164}d\u{180B}e"), "abcde");
    }

    #[test]
    fn leaves_code_that_only_names_secrets() {
        let s = "\"eos_token\": \"</s>\", self.pad_token = pad_token, SECRET_KEY = settings.SECRET_KEY, use_token: true, OLD_PWD=/home/u, API_KEY=$API_KEY, token = get_token()";
        let (o, h) = g().clean(s);
        assert_eq!(o, s);
        assert!(h.is_empty(), "{h:?}");
    }

    #[test]
    fn leaves_ordinary_content_alone() {
        let s = "git@github.com:org/repo, claude@strand, Vec<String>, 1e-9, step 1234567, sigma_xx = 250 MPa, 10.0.0.1";
        let (o, h) = g().clean(s);
        assert_eq!(o, s);
        assert!(h.is_empty());
    }

    #[test]
    fn private_key_block() {
        let (o, _) = g().clean("x\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\ny");
        assert_eq!(o, "x\n[REDACTED:private_key]\ny");
    }
}
