//! Dinero Stratum V2 — fixed-size wire codec.
//!
//! Phase 1 is intentionally minimal: both Phase-1 messages are
//! fixed-size records, so the codec is a byte-pasting job with strict
//! length checks. No framing, no Noise, no variable-length fields.
//!
//! The codec owns the exact bytes-on-the-wire layout and rejects any
//! short/over-long input rather than silently padding or truncating.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod sv2;

pub use sv2::{
    decode_coinbase_context, decode_open_standard_mining_channel,
    decode_open_standard_mining_channel_error, decode_open_standard_mining_channel_success,
    decode_set_new_prev_hash, decode_set_target, decode_setup_connection,
    decode_setup_connection_error, decode_setup_connection_success, decode_submit_shares_error,
    decode_submit_shares_extended, decode_submit_shares_success, encode_coinbase_context,
    encode_open_standard_mining_channel, encode_open_standard_mining_channel_error,
    encode_open_standard_mining_channel_success, encode_set_new_prev_hash, encode_set_target,
    encode_setup_connection, encode_setup_connection_error, encode_setup_connection_success,
    encode_submit_shares_error, encode_submit_shares_extended, encode_submit_shares_success,
    Sv2CodecError,
};

use dinero_sv2_common::{NewTemplateDinero, SubmitSharesDinero};

/// Wire size (bytes) of a [`NewTemplateDinero`] frame.
///
/// u64 + u8 + u32 + 32 + 32 + 32 + u64 + u32 + 32 =
///   8 + 1 + 4 + 32 + 32 + 32 + 8 + 4 + 32 = 153.
pub const NEW_TEMPLATE_DINERO_SIZE: usize = 153;

/// Wire size (bytes) of a [`SubmitSharesDinero`] frame.
///
/// u32 + u32 + u32 + u32 + u64 + u32 = 4*5 + 8 = 28.
pub const SUBMIT_SHARES_DINERO_SIZE: usize = 28;

/// Codec errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CodecError {
    /// Buffer shorter than expected for this message type.
    #[error("short frame: expected {expected} bytes, got {got}")]
    ShortFrame {
        /// Required length.
        expected: usize,
        /// Actual input length.
        got: usize,
    },
    /// Buffer longer than expected (no trailing bytes permitted).
    #[error("trailing bytes: expected {expected} bytes, got {got}")]
    TrailingBytes {
        /// Required length.
        expected: usize,
        /// Actual input length.
        got: usize,
    },
    /// A boolean byte was neither 0x00 nor 0x01.
    #[error("invalid boolean byte: 0x{0:02x}")]
    InvalidBool(u8),
}

// ------------------------------ NewTemplateDinero ------------------------------

/// Encode a [`NewTemplateDinero`] to its fixed-size wire form.
pub fn encode_new_template(msg: &NewTemplateDinero) -> [u8; NEW_TEMPLATE_DINERO_SIZE] {
    let mut buf = [0u8; NEW_TEMPLATE_DINERO_SIZE];
    let mut off = 0;

    buf[off..off + 8].copy_from_slice(&msg.template_id.to_le_bytes());
    off += 8;

    buf[off] = u8::from(msg.future_template);
    off += 1;

    buf[off..off + 4].copy_from_slice(&msg.version.to_le_bytes());
    off += 4;

    buf[off..off + 32].copy_from_slice(&msg.prev_block_hash);
    off += 32;

    buf[off..off + 32].copy_from_slice(&msg.merkle_root);
    off += 32;

    buf[off..off + 32].copy_from_slice(&msg.utreexo_root);
    off += 32;

    buf[off..off + 8].copy_from_slice(&msg.timestamp.to_le_bytes());
    off += 8;

    buf[off..off + 4].copy_from_slice(&msg.difficulty.to_le_bytes());
    off += 4;

    buf[off..off + 32].copy_from_slice(&msg.coinbase_outputs_commitment);
    off += 32;

    debug_assert_eq!(off, NEW_TEMPLATE_DINERO_SIZE);
    buf
}

/// Decode a [`NewTemplateDinero`] from its fixed-size wire form.
///
/// Strictly rejects buffers that aren't exactly
/// [`NEW_TEMPLATE_DINERO_SIZE`] bytes.
pub fn decode_new_template(buf: &[u8]) -> Result<NewTemplateDinero, CodecError> {
    if buf.len() < NEW_TEMPLATE_DINERO_SIZE {
        return Err(CodecError::ShortFrame {
            expected: NEW_TEMPLATE_DINERO_SIZE,
            got: buf.len(),
        });
    }
    if buf.len() > NEW_TEMPLATE_DINERO_SIZE {
        return Err(CodecError::TrailingBytes {
            expected: NEW_TEMPLATE_DINERO_SIZE,
            got: buf.len(),
        });
    }

    let mut off = 0;

    let template_id = read_u64(buf, &mut off);
    let future_template = match buf[off] {
        0 => false,
        1 => true,
        b => return Err(CodecError::InvalidBool(b)),
    };
    off += 1;
    let version = read_u32(buf, &mut off);
    let prev_block_hash = read_array32(buf, &mut off);
    let merkle_root = read_array32(buf, &mut off);
    let utreexo_root = read_array32(buf, &mut off);
    let timestamp = read_u64(buf, &mut off);
    let difficulty = read_u32(buf, &mut off);
    let coinbase_outputs_commitment = read_array32(buf, &mut off);

    debug_assert_eq!(off, NEW_TEMPLATE_DINERO_SIZE);

    Ok(NewTemplateDinero {
        template_id,
        future_template,
        version,
        prev_block_hash,
        merkle_root,
        utreexo_root,
        timestamp,
        difficulty,
        coinbase_outputs_commitment,
    })
}

// ------------------------------ SubmitSharesDinero ------------------------------

/// Encode a [`SubmitSharesDinero`] to its fixed-size wire form.
pub fn encode_submit_shares(msg: &SubmitSharesDinero) -> [u8; SUBMIT_SHARES_DINERO_SIZE] {
    let mut buf = [0u8; SUBMIT_SHARES_DINERO_SIZE];
    let mut off = 0;

    buf[off..off + 4].copy_from_slice(&msg.channel_id.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&msg.sequence_number.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&msg.job_id.to_le_bytes());
    off += 4;
    buf[off..off + 4].copy_from_slice(&msg.nonce.to_le_bytes());
    off += 4;
    buf[off..off + 8].copy_from_slice(&msg.timestamp.to_le_bytes());
    off += 8;
    buf[off..off + 4].copy_from_slice(&msg.version.to_le_bytes());
    off += 4;

    debug_assert_eq!(off, SUBMIT_SHARES_DINERO_SIZE);
    buf
}

/// Decode a [`SubmitSharesDinero`] from its fixed-size wire form.
pub fn decode_submit_shares(buf: &[u8]) -> Result<SubmitSharesDinero, CodecError> {
    if buf.len() < SUBMIT_SHARES_DINERO_SIZE {
        return Err(CodecError::ShortFrame {
            expected: SUBMIT_SHARES_DINERO_SIZE,
            got: buf.len(),
        });
    }
    if buf.len() > SUBMIT_SHARES_DINERO_SIZE {
        return Err(CodecError::TrailingBytes {
            expected: SUBMIT_SHARES_DINERO_SIZE,
            got: buf.len(),
        });
    }

    let mut off = 0;
    let channel_id = read_u32(buf, &mut off);
    let sequence_number = read_u32(buf, &mut off);
    let job_id = read_u32(buf, &mut off);
    let nonce = read_u32(buf, &mut off);
    let timestamp = read_u64(buf, &mut off);
    let version = read_u32(buf, &mut off);

    debug_assert_eq!(off, SUBMIT_SHARES_DINERO_SIZE);

    Ok(SubmitSharesDinero {
        channel_id,
        sequence_number,
        job_id,
        nonce,
        timestamp,
        version,
    })
}

// ------------------------------ internal helpers ------------------------------

fn read_u32(buf: &[u8], off: &mut usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[*off..*off + 4]);
    *off += 4;
    u32::from_le_bytes(b)
}

fn read_u64(buf: &[u8], off: &mut usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[*off..*off + 8]);
    *off += 8;
    u64::from_le_bytes(b)
}

fn read_array32(buf: &[u8], off: &mut usize) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&buf[*off..*off + 32]);
    *off += 32;
    a
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample_tmpl() -> NewTemplateDinero {
        NewTemplateDinero {
            template_id: 0xDEAD_BEEF_CAFE_0001,
            future_template: true,
            version: 1,
            prev_block_hash: [0x11; 32],
            merkle_root: [0x22; 32],
            utreexo_root: [0x33; 32],
            timestamp: 1_776_384_000,
            difficulty: 0x1d_31_ff_ce,
            coinbase_outputs_commitment: [0x44; 32],
        }
    }

    fn sample_share() -> SubmitSharesDinero {
        SubmitSharesDinero {
            channel_id: 7,
            sequence_number: 42,
            job_id: 9,
            nonce: 813_915_426,
            timestamp: 1_776_384_000,
            version: 1,
        }
    }

    #[test]
    fn new_template_roundtrip() {
        let msg = sample_tmpl();
        let buf = encode_new_template(&msg);
        let back = decode_new_template(&buf).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn submit_shares_roundtrip() {
        let msg = sample_share();
        let buf = encode_submit_shares(&msg);
        let back = decode_submit_shares(&buf).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn new_template_rejects_short_frame() {
        let buf = encode_new_template(&sample_tmpl());
        let err = decode_new_template(&buf[..buf.len() - 1]).unwrap_err();
        assert!(matches!(err, CodecError::ShortFrame { .. }));
    }

    #[test]
    fn new_template_rejects_trailing_bytes() {
        let mut buf = encode_new_template(&sample_tmpl()).to_vec();
        buf.push(0x00);
        let err = decode_new_template(&buf).unwrap_err();
        assert!(matches!(err, CodecError::TrailingBytes { .. }));
    }

    #[test]
    fn new_template_rejects_invalid_bool() {
        let mut buf = encode_new_template(&sample_tmpl());
        // future_template is at offset 8 (after template_id u64).
        buf[8] = 2;
        let err = decode_new_template(&buf).unwrap_err();
        assert_eq!(err, CodecError::InvalidBool(2));
    }

    #[test]
    fn submit_shares_rejects_short_frame() {
        let buf = encode_submit_shares(&sample_share());
        let err = decode_submit_shares(&buf[..buf.len() - 1]).unwrap_err();
        assert!(matches!(err, CodecError::ShortFrame { .. }));
    }

    #[test]
    fn submit_shares_rejects_trailing_bytes() {
        let mut buf = encode_submit_shares(&sample_share()).to_vec();
        buf.push(0xFF);
        let err = decode_submit_shares(&buf).unwrap_err();
        assert!(matches!(err, CodecError::TrailingBytes { .. }));
    }

    // Proptest fuzz — arbitrary structs survive a round trip.
    proptest! {
        #[test]
        fn fuzz_new_template_roundtrip(
            template_id in any::<u64>(),
            future_template in any::<bool>(),
            version in any::<u32>(),
            prev_block_hash in any::<[u8; 32]>(),
            merkle_root in any::<[u8; 32]>(),
            utreexo_root in any::<[u8; 32]>(),
            timestamp in any::<u64>(),
            difficulty in any::<u32>(),
            coinbase_outputs_commitment in any::<[u8; 32]>(),
        ) {
            let m = NewTemplateDinero {
                template_id,
                future_template,
                version,
                prev_block_hash,
                merkle_root,
                utreexo_root,
                timestamp,
                difficulty,
                coinbase_outputs_commitment,
            };
            let back = decode_new_template(&encode_new_template(&m)).unwrap();
            prop_assert_eq!(m, back);
        }

        #[test]
        fn fuzz_submit_shares_roundtrip(
            channel_id in any::<u32>(),
            sequence_number in any::<u32>(),
            job_id in any::<u32>(),
            nonce in any::<u32>(),
            timestamp in any::<u64>(),
            version in any::<u32>(),
        ) {
            let m = SubmitSharesDinero {
                channel_id,
                sequence_number,
                job_id,
                nonce,
                timestamp,
                version,
            };
            let back = decode_submit_shares(&encode_submit_shares(&m)).unwrap();
            prop_assert_eq!(m, back);
        }
    }
}
