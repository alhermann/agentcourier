//! Hybrid post-quantum Noise over TCP.
//! Noise IKpsk2 (X25519) authenticates both static keys; a fresh ML-KEM-768 exchange per connection
//! supplies the PSK, so session keys stay secret unless both X25519 and ML-KEM are broken.
use crate::config::Identity;
use anyhow::{Result, anyhow, bail};
use ml_kem::kem::{Decapsulate, Encapsulate, Kem, KeyExport, TryKeyInit};
use ml_kem::{EncapsulationKey768, MlKem768};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

pub const PATTERN: &str = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
// Kept from the project's former name so installations of either version can still talk.
const PROLOGUE: &[u8] = b"agentwire/1 hybrid ML-KEM-768";
const EK_LEN: usize = 1184;
const CT_LEN: usize = 1088;
const HS_MAX: usize = 4096;
const FRAME: usize = 65535;
const TAG: usize = 16;
pub const MAX_MSG: usize = 1 << 20;

type Ts = Arc<Mutex<snow::TransportState>>;

pub struct Reader {
    r: OwnedReadHalf,
    ts: Ts,
    frame: Vec<u8>,
    plain: Vec<u8>,
}

pub struct Writer {
    w: OwnedWriteHalf,
    ts: Ts,
}

fn noise(e: snow::Error) -> anyhow::Error {
    anyhow!("noise: {e:?}")
}

async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut Vec<u8>) -> Result<()> {
    let n = r.read_u16().await? as usize;
    buf.resize(n, 0);
    r.read_exact(buf).await?;
    Ok(())
}

async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    let mut v = Vec::with_capacity(2 + data.len());
    v.extend_from_slice(&(data.len() as u16).to_be_bytes());
    v.extend_from_slice(data);
    w.write_all(&v).await?;
    Ok(())
}

fn builder(me: &Identity) -> Result<snow::Builder<'_>> {
    Ok(snow::Builder::new(PATTERN.parse()?).local_private_key(&me.secret).map_err(noise)?.prologue(PROLOGUE).map_err(noise)?)
}

fn split(s: TcpStream, hs: snow::HandshakeState) -> Result<(Reader, Writer)> {
    let ts = Arc::new(Mutex::new(hs.into_transport_mode().map_err(noise)?));
    let (r, w) = s.into_split();
    Ok((Reader { r, ts: ts.clone(), frame: vec![], plain: vec![] }, Writer { w, ts }))
}

// -> e, es, s, ss  [payload: ML-KEM encapsulation key]
// <- ML-KEM ciphertext || e, ee, se, psk
pub async fn initiate(mut s: TcpStream, me: &Identity, peer: &[u8; 32]) -> Result<(Reader, Writer)> {
    let mut hs = builder(me)?.remote_public_key(peer).map_err(noise)?.build_initiator().map_err(noise)?;
    let (dk, ek) = MlKem768::generate_keypair();
    let mut buf = vec![0u8; HS_MAX];
    let n = hs.write_message(&ek.to_bytes(), &mut buf).map_err(noise)?;
    write_frame(&mut s, &buf[..n]).await?;
    let mut f = Vec::new();
    read_frame(&mut s, &mut f).await?;
    if f.len() <= CT_LEN || f.len() > HS_MAX {
        bail!("bad handshake");
    }
    let (ct, rest) = f.split_at(CT_LEN);
    let ss = dk.decapsulate_slice(ct).map_err(|_| anyhow!("bad ciphertext"))?;
    hs.set_psk(2, ss.as_slice()).map_err(noise)?;
    hs.read_message(rest, &mut buf).map_err(noise)?;
    split(s, hs)
}

/// Completes the handshake only for initiators whose static key passes `allowed`; others get no reply.
/// Returns the initiator's key either way so refusals can be reported.
pub async fn respond(mut s: TcpStream, me: &Identity, allowed: impl Fn(&[u8; 32]) -> bool) -> Result<([u8; 32], Option<(Reader, Writer)>)> {
    let mut hs = builder(me)?.build_responder().map_err(noise)?;
    let mut f = Vec::new();
    read_frame(&mut s, &mut f).await?;
    if f.len() > HS_MAX {
        bail!("bad handshake");
    }
    let mut payload = vec![0u8; HS_MAX];
    let n = hs.read_message(&f, &mut payload).map_err(noise)?;
    let key: [u8; 32] = hs.get_remote_static().ok_or_else(|| anyhow!("no static key"))?.try_into()?;
    if !allowed(&key) {
        return Ok((key, None));
    }
    if n != EK_LEN {
        bail!("bad handshake");
    }
    let ek = EncapsulationKey768::new_from_slice(&payload[..n]).map_err(|_| anyhow!("bad encapsulation key"))?;
    let (ct, ss) = ek.encapsulate();
    hs.set_psk(2, ss.as_slice()).map_err(noise)?;
    let mut out = ct.to_vec();
    let mut buf = vec![0u8; 256];
    let m = hs.write_message(&[], &mut buf).map_err(noise)?;
    out.extend_from_slice(&buf[..m]);
    write_frame(&mut s, &out).await?;
    let (r, w) = split(s, hs)?;
    Ok((key, Some((r, w))))
}

impl Reader {
    pub async fn recv(&mut self) -> Result<Vec<u8>> {
        loop {
            if self.plain.len() >= 4 {
                let n = u32::from_be_bytes(self.plain[..4].try_into()?) as usize;
                if n > MAX_MSG {
                    bail!("message too large");
                }
                if self.plain.len() >= 4 + n {
                    let msg = self.plain[4..4 + n].to_vec();
                    self.plain.drain(..4 + n);
                    return Ok(msg);
                }
            }
            read_frame(&mut self.r, &mut self.frame).await?;
            let mut out = vec![0u8; self.frame.len()];
            let k = self.ts.lock().unwrap().read_message(&self.frame, &mut out).map_err(noise)?;
            self.plain.extend_from_slice(&out[..k]);
        }
    }
}

impl Writer {
    pub async fn send(&mut self, msg: &[u8]) -> Result<()> {
        if msg.len() > MAX_MSG {
            bail!("message too large");
        }
        let mut plain = Vec::with_capacity(4 + msg.len());
        plain.extend_from_slice(&(msg.len() as u32).to_be_bytes());
        plain.extend_from_slice(msg);
        let mut out = vec![0u8; FRAME];
        for chunk in plain.chunks(FRAME - TAG) {
            let k = self.ts.lock().unwrap().write_message(chunk, &mut out).map_err(noise)?;
            write_frame(&mut self.w, &out[..k]).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn ident() -> Identity {
        let kp = snow::Builder::new(PATTERN.parse().unwrap()).generate_keypair().unwrap();
        Identity { secret: kp.private.try_into().unwrap(), public: kp.public.try_into().unwrap() }
    }

    async fn pair(trusted: bool) -> Result<Vec<u8>> {
        let (a, b) = (ident(), ident());
        let (a_pub, b_pub) = (a.public, b.public);
        let l = TcpListener::bind("127.0.0.1:0").await?;
        let addr = l.local_addr()?;
        let srv = tokio::spawn(async move {
            let (s, _) = l.accept().await?;
            let (k, link) = respond(s, &b, |k| trusted && *k == a_pub).await?;
            assert_eq!(k, a_pub);
            let (mut r, mut w) = link.ok_or_else(|| anyhow!("refused"))?;
            let m = r.recv().await?;
            w.send(&m).await?;
            anyhow::Ok(())
        });
        let (mut r, mut w) = initiate(TcpStream::connect(addr).await?, &a, &b_pub).await?;
        let big: Vec<u8> = (0..300_000u32).map(|i| i as u8).collect();
        w.send(&big).await?;
        let echo = r.recv().await?;
        srv.await??;
        Ok(echo)
    }

    #[tokio::test]
    async fn trusted_peer_roundtrip_multi_frame() {
        let echo = pair(true).await.unwrap();
        assert_eq!(echo.len(), 300_000);
        assert!(echo.iter().enumerate().all(|(i, b)| *b == i as u8));
    }

    #[tokio::test]
    async fn untrusted_peer_gets_nothing() {
        assert!(pair(false).await.is_err());
    }

    #[tokio::test]
    async fn wrong_responder_key_fails() {
        let (a, b, c) = (ident(), ident(), ident());
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = l.accept().await.unwrap();
            let _ = respond(s, &b, |_| true).await;
        });
        // Initiator expects c's key but talks to b: must fail.
        assert!(initiate(TcpStream::connect(addr).await.unwrap(), &a, &c.public).await.is_err());
    }

    #[tokio::test]
    async fn tampered_mlkem_ciphertext_breaks_handshake() {
        let (a, b) = (ident(), ident());
        let (a_pub, b_pub) = (a.public, b.public);
        let real = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let real_addr = real.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = real.accept().await.unwrap();
            let _ = respond(s, &b, |k| *k == a_pub).await;
        });
        let mitm = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mitm_addr = mitm.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut c, _) = mitm.accept().await.unwrap();
            let mut s = TcpStream::connect(real_addr).await.unwrap();
            let mut f = Vec::new();
            read_frame(&mut c, &mut f).await.unwrap();
            write_frame(&mut s, &f).await.unwrap();
            read_frame(&mut s, &mut f).await.unwrap();
            f[100] ^= 1; // inside the ML-KEM ciphertext
            write_frame(&mut c, &f).await.unwrap();
        });
        assert!(initiate(TcpStream::connect(mitm_addr).await.unwrap(), &a, &b_pub).await.is_err());
    }
}
