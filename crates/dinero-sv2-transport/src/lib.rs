//! Dinero Stratum V2 — transport layer.
//!
//! Phase 2.1: clear-text length-delimited framing for the `dinero-tp`
//! simulator / pool protocol. Framing:
//!
//! ```text
//! | 1 byte: msg_type | 2 bytes: payload_len LE | payload (payload_len bytes) |
//! ```
//!
//! Phase 2.2 will add a Noise NX wrapper around this framing (using the
//! `snow` crate). The public API here deliberately returns and accepts
//! `(msg_type, payload)` pairs so the inner semantics survive unchanged
//! when Noise is slipped under the hood.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Message type: server → client, a new [`NewTemplateDinero`] payload.
///
/// [`NewTemplateDinero`]: dinero-sv2-common
pub const MSG_NEW_TEMPLATE: u8 = 0x01;

/// Message type: client → server, a [`SubmitSharesDinero`] payload.
///
/// [`SubmitSharesDinero`]: dinero-sv2-common
pub const MSG_SUBMIT_SHARES: u8 = 0x02;

/// Message type: server → client, a 1-byte share-ack response.
pub const MSG_SHARE_ACK: u8 = 0x03;

/// Share ack: share accepted (meets target, if any).
pub const ACK_OK: u8 = 0x00;
/// Share ack: payload did not decode cleanly.
pub const ACK_BAD_SHAPE: u8 = 0x01;
/// Share ack: valid share but under the configured target.
pub const ACK_UNDER_TARGET: u8 = 0x02;

/// Transport framing errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// Underlying socket I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Payload length field exceeded `u16::MAX`.
    #[error("payload too large: {0} > {max}", max = u16::MAX as usize)]
    PayloadTooLarge(usize),
}

/// Read one frame from `sock`. Returns `Ok(None)` on clean EOF.
pub async fn read_frame<R: AsyncRead + Unpin>(
    sock: &mut R,
) -> Result<Option<(u8, Vec<u8>)>, TransportError> {
    let mut header = [0u8; 3];
    match sock.read_exact(&mut header).await {
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let msg_type = header[0];
    let len = u16::from_le_bytes([header[1], header[2]]) as usize;
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).await?;
    Ok(Some((msg_type, payload)))
}

/// Write one frame to `sock`.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    sock: &mut W,
    msg_type: u8,
    payload: &[u8],
) -> Result<(), TransportError> {
    let len: u16 = payload
        .len()
        .try_into()
        .map_err(|_| TransportError::PayloadTooLarge(payload.len()))?;
    let mut hdr = [0u8; 3];
    hdr[0] = msg_type;
    hdr[1..3].copy_from_slice(&len.to_le_bytes());
    sock.write_all(&hdr).await?;
    sock.write_all(payload).await?;
    sock.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn frame_roundtrip() {
        let (mut a, mut b) = duplex(1024);
        let writer = async move {
            write_frame(&mut a, MSG_NEW_TEMPLATE, b"hello")
                .await
                .unwrap();
            write_frame(&mut a, MSG_SHARE_ACK, &[ACK_OK]).await.unwrap();
            drop(a);
        };
        let reader = async {
            let f1 = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(f1, (MSG_NEW_TEMPLATE, b"hello".to_vec()));
            let f2 = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(f2, (MSG_SHARE_ACK, vec![ACK_OK]));
            let eof = read_frame(&mut b).await.unwrap();
            assert!(eof.is_none());
        };
        tokio::join!(writer, reader);
    }

    #[tokio::test]
    async fn empty_payload_is_legal() {
        let (mut a, mut b) = duplex(64);
        let writer = async move {
            write_frame(&mut a, 0xAA, &[]).await.unwrap();
            drop(a);
        };
        let reader = async {
            let f = read_frame(&mut b).await.unwrap().unwrap();
            assert_eq!(f, (0xAA, vec![]));
        };
        tokio::join!(writer, reader);
    }
}
