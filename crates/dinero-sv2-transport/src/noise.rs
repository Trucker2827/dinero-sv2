//! Noise NX session wrapping a [`TcpStream`] (or any
//! `AsyncRead + AsyncWrite + Unpin`), Pass-A wire format.
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
//! Outer length prefix (both phases): `u24 LE` — aligns with Stratum
//! V2's message length encoding. Post-handshake transport frames wrap
//! a single Noise transport message:
//!
//! ```text
//! | 3 bytes: u24 LE ciphertext_len | Noise ciphertext (plaintext + 16-byte tag) |
//! ```
//!
//! The inner plaintext follows the SV2 message header:
//!
//! ```text
//! | 2 bytes: u16 LE ext_type | 1 byte: msg_type | 3 bytes: u24 LE msg_length | payload |
//! ```

use anyhow::{anyhow, bail, Context, Result};
use snow::params::NoiseParams;
use snow::{Builder, TransportState};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::keys::StaticKeys;

const PARAMS: &str = "Noise_NX_25519_ChaChaPoly_BLAKE2s";

/// SV2 inner-header size in bytes.
///   ext_type (u16 LE) + msg_type (u8) + msg_length (u24 LE) = 6
const SV2_HEADER_LEN: usize = 6;

/// Maximum outer-frame length representable in a `u24 LE` prefix.
const U24_MAX: usize = 0x00FF_FFFF;

/// Noise's hard ceiling on a single transport message (65 535 bytes
/// including the 16-byte ChaChaPoly tag per the Noise spec).
const NOISE_TRANSPORT_MAX: usize = 65_535;

/// Maximum plaintext payload `write_frame` will accept. Equal to
/// `NOISE_TRANSPORT_MAX - 16 (tag) - SV2_HEADER_LEN (6)`.
pub const NOISE_MAX_PAYLOAD: usize = NOISE_TRANSPORT_MAX - 16 - SV2_HEADER_LEN;

/// Default extension_type for basic (non-extension) SV2 messages.
pub const EXT_BASIC: u16 = 0x0000;

/// A decoded SV2 inner frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// SV2 extension type. `0x0000` for basic (default) messages.
    pub ext_type: u16,
    /// SV2 message type.
    pub msg_type: u8,
    /// Decoded payload (exact length per `msg_length` in the header).
    pub payload: Vec<u8>,
}

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
        let msg1 = read_u24_prefixed(&mut stream).await?;
        handshake
            .read_message(&msg1, &mut scratch)
            .context("handshake read_message msg1")?;

        // Write msg2 (<- e, ee, s, es) — completes the NX handshake.
        let mut out = vec![0u8; 1024];
        let n = handshake
            .write_message(&[], &mut out)
            .context("handshake write_message msg2")?;
        write_u24_prefixed(&mut stream, &out[..n]).await?;

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
        write_u24_prefixed(&mut stream, &out[..n]).await?;

        // Read msg2 — responder sends its static key here (encrypted).
        let msg2 = read_u24_prefixed(&mut stream).await?;
        handshake
            .read_message(&msg2, &mut scratch)
            .context("handshake read_message msg2")?;

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

        let transport = handshake
            .into_transport_mode()
            .context("into_transport_mode (initiator)")?;
        Ok(Self {
            stream,
            transport,
            peer_static,
        })
    }

    /// Send an SV2 frame over Noise with `ext_type = EXT_BASIC`.
    pub async fn write_frame(&mut self, msg_type: u8, payload: &[u8]) -> Result<()> {
        self.write_frame_ext(EXT_BASIC, msg_type, payload).await
    }

    /// Send an SV2 frame over Noise with an explicit extension type.
    pub async fn write_frame_ext(
        &mut self,
        ext_type: u16,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<()> {
        if payload.len() > NOISE_MAX_PAYLOAD {
            bail!("payload too large: {} > {NOISE_MAX_PAYLOAD}", payload.len());
        }
        let inner_len = SV2_HEADER_LEN + payload.len();

        // Build SV2 header + payload as one plaintext buffer.
        let mut plain = Vec::with_capacity(inner_len);
        plain.extend_from_slice(&ext_type.to_le_bytes());
        plain.push(msg_type);
        plain.extend_from_slice(&u24_le(payload.len() as u32));
        plain.extend_from_slice(payload);

        let mut cipher = vec![0u8; inner_len + 16];
        let n = self
            .transport
            .write_message(&plain, &mut cipher)
            .context("transport write_message")?;
        write_u24_prefixed(&mut self.stream, &cipher[..n]).await?;
        Ok(())
    }

    /// Receive one encrypted SV2 frame. Returns `Ok(None)` on clean EOF.
    pub async fn read_frame(&mut self) -> Result<Option<Frame>> {
        let cipher = match read_u24_prefixed_opt(&mut self.stream).await? {
            Some(c) => c,
            None => return Ok(None),
        };
        let mut plain = vec![0u8; cipher.len()];
        let n = self
            .transport
            .read_message(&cipher, &mut plain)
            .context("transport read_message")?;
        if n < SV2_HEADER_LEN {
            bail!("inner plaintext shorter than SV2 header: {n} < {SV2_HEADER_LEN}");
        }
        let ext_type = u16::from_le_bytes([plain[0], plain[1]]);
        let msg_type = plain[2];
        let msg_length = u24_from_le(&plain[3..6]) as usize;
        if SV2_HEADER_LEN + msg_length != n {
            bail!(
                "sv2 header msg_length {msg_length} disagrees with body length {}",
                n - SV2_HEADER_LEN
            );
        }
        let payload = plain[SV2_HEADER_LEN..SV2_HEADER_LEN + msg_length].to_vec();
        Ok(Some(Frame {
            ext_type,
            msg_type,
            payload,
        }))
    }

    /// Responder's static public key (as learned during the handshake).
    pub fn peer_static_key(&self) -> [u8; 32] {
        self.peer_static
    }

    /// Test-only: encrypt and send arbitrary plaintext bytes (bypassing
    /// the SV2 inner header). Used to craft malformed frames for the
    /// decoder's robustness tests.
    #[cfg(test)]
    pub(crate) async fn write_raw_plaintext_for_test(&mut self, plaintext: &[u8]) -> Result<()> {
        let mut cipher = vec![0u8; plaintext.len() + 16];
        let n = self
            .transport
            .write_message(plaintext, &mut cipher)
            .context("transport write_message")?;
        write_u24_prefixed(&mut self.stream, &cipher[..n]).await
    }
}

// ---------------------------------------------------------------------
// u24 LE helpers
// ---------------------------------------------------------------------

/// Encode `n` as 3 little-endian bytes. Panics in debug if `n > 2^24-1`.
fn u24_le(n: u32) -> [u8; 3] {
    debug_assert!(n as usize <= U24_MAX);
    [
        (n & 0xFF) as u8,
        ((n >> 8) & 0xFF) as u8,
        ((n >> 16) & 0xFF) as u8,
    ]
}

/// Decode 3 little-endian bytes to `u32`.
fn u24_from_le(b: &[u8]) -> u32 {
    debug_assert!(b.len() == 3);
    (b[0] as u32) | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

async fn write_u24_prefixed<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > U24_MAX {
        bail!("message too long for u24 prefix: {}", data.len());
    }
    w.write_all(&u24_le(data.len() as u32)).await?;
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}

async fn read_u24_prefixed<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut lb = [0u8; 3];
    r.read_exact(&mut lb).await?;
    let len = u24_from_le(&lb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn read_u24_prefixed_opt<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut lb = [0u8; 3];
    match r.read_exact(&mut lb).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u24_from_le(&lb) as usize;
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[test]
    fn u24_roundtrip_known_values() {
        for v in [0u32, 1, 0xFF, 0x100, 0x1234, 0x80_0000, U24_MAX as u32] {
            let enc = u24_le(v);
            let dec = u24_from_le(&enc);
            assert_eq!(dec, v, "u24 roundtrip failed for {v:#x}");
        }
        // Little-endian byte order: 0x123456 → [0x56, 0x34, 0x12]
        assert_eq!(u24_le(0x123456), [0x56, 0x34, 0x12]);
    }

    #[tokio::test]
    async fn nx_handshake_and_frame_roundtrip() {
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let (a, b) = duplex(8192);

        let keys_clone = keys.clone();
        let server = tokio::spawn(async move {
            let mut sess = NoiseSession::accept_nx(a, &keys_clone).await.unwrap();
            while let Some(f) = sess.read_frame().await.unwrap() {
                // Echo with the same ext_type + msg_type.
                sess.write_frame_ext(f.ext_type, f.msg_type, &f.payload)
                    .await
                    .unwrap();
            }
        });

        let mut client = NoiseSession::initiate_nx(b, Some(&server_pub))
            .await
            .unwrap();
        assert_eq!(client.peer_static_key(), server_pub);

        client.write_frame(0x42, b"ping").await.unwrap();
        let f = client.read_frame().await.unwrap().unwrap();
        assert_eq!(f.ext_type, EXT_BASIC);
        assert_eq!(f.msg_type, 0x42);
        assert_eq!(f.payload, b"ping");

        // Larger payload.
        let big = vec![0x5A; 4000];
        client.write_frame(0x43, &big).await.unwrap();
        let f = client.read_frame().await.unwrap().unwrap();
        assert_eq!(f.msg_type, 0x43);
        assert_eq!(f.payload, big);

        // Non-default extension.
        client.write_frame_ext(0x8001, 0x71, b"tp").await.unwrap();
        let f = client.read_frame().await.unwrap().unwrap();
        assert_eq!(f.ext_type, 0x8001);
        assert_eq!(f.msg_type, 0x71);
        assert_eq!(f.payload, b"tp");

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
            let _ = NoiseSession::accept_nx(a, &keys_clone).await;
        });

        let err = match NoiseSession::initiate_nx(b, Some(&wrong_pub)).await {
            Ok(_) => panic!("expected error"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("static key mismatch"), "err was: {err}");
        let _ = server.await;
    }

    #[tokio::test]
    async fn rejects_plaintext_shorter_than_sv2_header() {
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let (a, b) = duplex(4096);
        let keys_clone = keys.clone();
        tokio::spawn(async move {
            // Server: peek for one frame. Should error.
            let mut sess = NoiseSession::accept_nx(a, &keys_clone).await.unwrap();
            let err = match sess.read_frame().await {
                Ok(_) => panic!("expected error for short inner plaintext"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("shorter than SV2 header"), "err was: {err}");
        });

        let mut client = NoiseSession::initiate_nx(b, Some(&server_pub))
            .await
            .unwrap();
        // Send plaintext that's only 3 bytes — shorter than the 6-byte
        // SV2 header.
        client
            .write_raw_plaintext_for_test(&[0x00, 0x00, 0x00])
            .await
            .unwrap();
        // Give the server task a chance to observe and panic or assert.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn rejects_inner_header_length_mismatch() {
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let (a, b) = duplex(4096);
        let keys_clone = keys.clone();
        tokio::spawn(async move {
            let mut sess = NoiseSession::accept_nx(a, &keys_clone).await.unwrap();
            let err = match sess.read_frame().await {
                Ok(_) => panic!("expected error for msg_length mismatch"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("msg_length"), "err was: {err}");
        });

        let mut client = NoiseSession::initiate_nx(b, Some(&server_pub))
            .await
            .unwrap();
        // SV2 header declares 100-byte payload, but we only send 10 bytes.
        let mut bad = Vec::new();
        bad.extend_from_slice(&0u16.to_le_bytes()); // ext_type
        bad.push(0x99); // msg_type
        bad.extend_from_slice(&u24_le(100)); // claimed payload len
        bad.extend_from_slice(&[0xAA; 10]); // actual payload, 10 bytes
        client.write_raw_plaintext_for_test(&bad).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn empty_payload_is_legal() {
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let (a, b) = duplex(4096);
        let keys_clone = keys.clone();
        tokio::spawn(async move {
            let mut sess = NoiseSession::accept_nx(a, &keys_clone).await.unwrap();
            while let Some(f) = sess.read_frame().await.unwrap() {
                sess.write_frame(f.msg_type, &f.payload).await.unwrap();
            }
        });

        let mut client = NoiseSession::initiate_nx(b, Some(&server_pub))
            .await
            .unwrap();
        client.write_frame(0xAA, &[]).await.unwrap();
        let f = client.read_frame().await.unwrap().unwrap();
        assert_eq!(f.msg_type, 0xAA);
        assert!(f.payload.is_empty());
    }
}
