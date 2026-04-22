//! Noise NX session wrapping a [`TcpStream`] (or any
//! `AsyncRead + AsyncWrite + Unpin`).
//!
//! Handshake pattern: `Noise_NX_25519_ChaChaPoly_BLAKE2s`.
//!
//! NX means:
//! - **Initiator** (the miner) has no static key — anonymous to the TP.
//! - **Responder** (the TP) has a static key; it's transmitted to the
//!   initiator encrypted under the handshake's hash, so the initiator
//!   can optionally pin it (TOFU + pin model).
//!
//! Handshake messages (2 total — NX is a two-message pattern):
//!   1. `i -> r`: `-> e`                 (32-byte ephemeral)
//!   2. `r -> i`: `<- e, ee, s, es`       (ephemeral + encrypted static + MAC)
//!
//! Post-handshake framing:
//! ```text
//! | 2 bytes: ciphertext_len LE | ciphertext (plaintext + 16-byte MAC) |
//! ```
//!
//! Each plaintext carries our existing inner framing:
//! ```text
//! | 1 byte: msg_type | 2 bytes: payload_len LE | payload |
//! ```

use anyhow::{anyhow, bail, Context, Result};
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::keys::StaticKeys;

const PARAMS: &str = "Noise_NX_25519_ChaChaPoly_BLAKE2s";

/// Noise's hard ceiling on a single transport message (see the Noise spec).
/// We don't allow any plaintext larger than this; caller must chunk.
pub const NOISE_MAX_PAYLOAD: usize = 65_535 - 16; // minus ChaChaPoly tag

/// Active, handshake-completed Noise session on top of `S`.
pub struct NoiseSession<S> {
    stream: S,
    transport: TransportState,
    peer_static: [u8; 32],
}

impl<S: AsyncRead + AsyncWrite + Unpin> NoiseSession<S> {
    /// Perform a Noise NX handshake as the **responder** (TP side).
    pub async fn accept_nx(mut stream: S, keys: &StaticKeys) -> Result<Self> {
        let params: NoiseParams = PARAMS.parse().expect("static noise params");
        let mut handshake = Builder::new(params)
            .local_private_key(&keys.private)
            .build_responder()
            .context("snow build_responder")?;

        let mut scratch = vec![0u8; 1024];

        // Read msg1 (-> e)
        let msg1 = read_length_prefixed(&mut stream).await?;
        handshake
            .read_message(&msg1, &mut scratch)
            .context("handshake read_message msg1")?;

        // Write msg2 (<- e, ee, s, es) — completes the NX handshake.
        let mut out = vec![0u8; 1024];
        let n = handshake
            .write_message(&[], &mut out)
            .context("handshake write_message msg2")?;
        write_length_prefixed(&mut stream, &out[..n]).await?;

        // NX is two messages. Handshake is now complete on this side.
        // Initiator has no static key in NX — peer_static stays zero.
        let peer_static = [0u8; 32];

        let transport = handshake
            .into_transport_mode()
            .context("into_transport_mode (responder)")?;
        Ok(Self {
            stream,
            transport,
            peer_static,
        })
    }

    /// Perform a Noise NX handshake as the **initiator** (miner side).
    ///
    /// If `expected_server_key` is set, the handshake aborts unless the
    /// responder's transmitted static key matches.
    pub async fn initiate_nx(
        mut stream: S,
        expected_server_key: Option<&[u8; 32]>,
    ) -> Result<Self> {
        let params: NoiseParams = PARAMS.parse().expect("static noise params");
        let mut handshake = Builder::new(params)
            .build_initiator()
            .context("snow build_initiator")?;

        let mut scratch = vec![0u8; 1024];

        // Write msg1 (-> e)
        let mut out = vec![0u8; 1024];
        let n = handshake
            .write_message(&[], &mut out)
            .context("handshake write_message msg1")?;
        write_length_prefixed(&mut stream, &out[..n]).await?;

        // Read msg2 — responder sends its static key here (encrypted).
        let msg2 = read_length_prefixed(&mut stream).await?;
        handshake
            .read_message(&msg2, &mut scratch)
            .context("handshake read_message msg2")?;

        // We now have the responder's static pubkey. Pin it if requested.
        let rs = handshake
            .get_remote_static()
            .ok_or_else(|| anyhow!("no remote static after NX msg2"))?;
        if rs.len() != 32 {
            bail!("responder static key len {} (expected 32)", rs.len());
        }
        let mut peer_static = [0u8; 32];
        peer_static.copy_from_slice(rs);
        if let Some(expected) = expected_server_key {
            if &peer_static != expected {
                bail!(
                    "responder static key mismatch: got {}, expected {}",
                    hex::encode(peer_static),
                    hex::encode(expected)
                );
            }
        }

        // NX is two messages — handshake is complete after reading msg2.
        let transport = handshake
            .into_transport_mode()
            .context("into_transport_mode (initiator)")?;
        Ok(Self {
            stream,
            transport,
            peer_static,
        })
    }

    /// Send an encrypted frame: `(msg_type, payload)` gets wrapped in the
    /// inner framing and encrypted as a single Noise transport message.
    pub async fn write_frame(&mut self, msg_type: u8, payload: &[u8]) -> Result<()> {
        let inner_len = 3 + payload.len();
        if inner_len > NOISE_MAX_PAYLOAD {
            bail!("frame too large: {inner_len} > {NOISE_MAX_PAYLOAD}");
        }
        let mut plain = Vec::with_capacity(inner_len);
        plain.push(msg_type);
        plain.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        plain.extend_from_slice(payload);

        let mut cipher = vec![0u8; inner_len + 16];
        let n = self
            .transport
            .write_message(&plain, &mut cipher)
            .context("transport write_message")?;
        write_length_prefixed(&mut self.stream, &cipher[..n]).await?;
        Ok(())
    }

    /// Receive one encrypted frame. Returns `Ok(None)` on clean EOF.
    pub async fn read_frame(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        let cipher = match read_length_prefixed_opt(&mut self.stream).await? {
            Some(c) => c,
            None => return Ok(None),
        };
        let mut plain = vec![0u8; cipher.len()];
        let n = self
            .transport
            .read_message(&cipher, &mut plain)
            .context("transport read_message")?;
        if n < 3 {
            bail!("inner plaintext too short: {n}");
        }
        let msg_type = plain[0];
        let len = u16::from_le_bytes([plain[1], plain[2]]) as usize;
        if 3 + len != n {
            bail!("inner frame length {len} != body length {}", n - 3);
        }
        let payload = plain[3..3 + len].to_vec();
        Ok(Some((msg_type, payload)))
    }

    /// Responder's static public key (as learned during the handshake).
    pub fn peer_static_key(&self) -> [u8; 32] {
        self.peer_static
    }
}

async fn write_length_prefixed<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    let len: u16 = data
        .len()
        .try_into()
        .map_err(|_| anyhow!("message too long: {}", data.len()))?;
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

async fn read_length_prefixed<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut lb = [0u8; 2];
    r.read_exact(&mut lb).await?;
    let len = u16::from_le_bytes(lb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_length_prefixed_opt<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut lb = [0u8; 2];
    match r.read_exact(&mut lb).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u16::from_le_bytes(lb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn nx_handshake_and_frame_roundtrip() {
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let (a, b) = duplex(8192);

        let keys_clone = keys.clone();
        let server = tokio::spawn(async move {
            let mut sess = NoiseSession::accept_nx(a, &keys_clone).await.unwrap();
            // Echo whatever we receive.
            while let Some((mtype, payload)) = sess.read_frame().await.unwrap() {
                sess.write_frame(mtype, &payload).await.unwrap();
            }
        });

        let mut client = NoiseSession::initiate_nx(b, Some(&server_pub))
            .await
            .unwrap();
        assert_eq!(client.peer_static_key(), server_pub);

        client.write_frame(0x42, b"ping").await.unwrap();
        let (mt, pl) = client.read_frame().await.unwrap().unwrap();
        assert_eq!(mt, 0x42);
        assert_eq!(pl, b"ping");

        // Big-ish payload to confirm framing + crypto survive larger messages.
        let big = vec![0x5A; 4000];
        client.write_frame(0x43, &big).await.unwrap();
        let (mt, pl) = client.read_frame().await.unwrap().unwrap();
        assert_eq!(mt, 0x43);
        assert_eq!(pl, big);

        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn pinned_key_mismatch_is_rejected() {
        let keys = StaticKeys::generate().unwrap();
        let wrong_pub = [0u8; 32];

        let (a, b) = duplex(4096);

        let keys_clone = keys.clone();
        let server = tokio::spawn(async move {
            // Responder may error out on the handshake if the initiator
            // drops before msg3 — that's fine.
            let _ = NoiseSession::accept_nx(a, &keys_clone).await;
        });

        let err = match NoiseSession::initiate_nx(b, Some(&wrong_pub)).await {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("static key mismatch"), "err was: {err}");
        let _ = server.await;
    }
}
