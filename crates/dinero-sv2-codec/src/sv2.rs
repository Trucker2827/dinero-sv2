//! Pass-B codec: wire encoding for the handshake / channel / share-result
//! message family.
//!
//! These messages have variable-length fields (STR0_255 strings for
//! user-agent / user-identity / error-code), so the codec is a cursor
//! walker rather than a fixed-size byte paste. All multi-byte
//! integers are little-endian; STR0_255 is encoded as one length byte
//! followed by `len` raw bytes (so the max string length is 255).

use dinero_sv2_common::{
    OpenStandardMiningChannel, OpenStandardMiningChannelError, OpenStandardMiningChannelSuccess,
    SetNewPrevHash, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
    SubmitSharesError, SubmitSharesSuccess,
};

/// Hard cap on a STR0_255 length byte.
const STR0_255_MAX: usize = 255;

/// Pass-B codec errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Sv2CodecError {
    /// Not enough input bytes to finish decoding.
    #[error("short frame at offset {at}, need {need} more bytes")]
    Short {
        /// Offset into the input at which decoding stalled.
        at: usize,
        /// Bytes required beyond the end of the input.
        need: usize,
    },
    /// Unused bytes at the tail of the input.
    #[error("trailing bytes: {extra}")]
    Trailing {
        /// Number of trailing bytes.
        extra: usize,
    },
    /// A STR0_255 length exceeded the 255-byte cap (unreachable today,
    /// since the length is a `u8`, but useful if we ever widen).
    #[error("string too long: {0} > {STR0_255_MAX}")]
    StringTooLong(usize),
}

// ----------------------------- SetupConnection -----------------------------

/// Encode a [`SetupConnection`] message.
pub fn encode_setup_connection(msg: &SetupConnection) -> Result<Vec<u8>, Sv2CodecError> {
    let mut out = Vec::with_capacity(1 + 2 + 2 + 4 + 1 + msg.user_agent.len());
    out.push(msg.protocol);
    out.extend_from_slice(&msg.min_version.to_le_bytes());
    out.extend_from_slice(&msg.max_version.to_le_bytes());
    out.extend_from_slice(&msg.flags.to_le_bytes());
    write_str0_255(&mut out, &msg.user_agent)?;
    Ok(out)
}

/// Decode a [`SetupConnection`] message.
pub fn decode_setup_connection(buf: &[u8]) -> Result<SetupConnection, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let protocol = cur.read_u8()?;
    let min_version = cur.read_u16()?;
    let max_version = cur.read_u16()?;
    let flags = cur.read_u32()?;
    let user_agent = cur.read_str0_255()?.to_vec();
    cur.finish()?;
    Ok(SetupConnection {
        protocol,
        min_version,
        max_version,
        flags,
        user_agent,
    })
}

/// Encode a [`SetupConnectionSuccess`] message.
pub fn encode_setup_connection_success(msg: &SetupConnectionSuccess) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 4);
    out.extend_from_slice(&msg.used_version.to_le_bytes());
    out.extend_from_slice(&msg.flags.to_le_bytes());
    out
}

/// Decode a [`SetupConnectionSuccess`] message.
pub fn decode_setup_connection_success(
    buf: &[u8],
) -> Result<SetupConnectionSuccess, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let used_version = cur.read_u16()?;
    let flags = cur.read_u32()?;
    cur.finish()?;
    Ok(SetupConnectionSuccess {
        used_version,
        flags,
    })
}

/// Encode a [`SetupConnectionError`] message.
pub fn encode_setup_connection_error(msg: &SetupConnectionError) -> Result<Vec<u8>, Sv2CodecError> {
    let mut out = Vec::with_capacity(4 + 1 + msg.error_code.len());
    out.extend_from_slice(&msg.flags.to_le_bytes());
    write_str0_255(&mut out, &msg.error_code)?;
    Ok(out)
}

/// Decode a [`SetupConnectionError`] message.
pub fn decode_setup_connection_error(buf: &[u8]) -> Result<SetupConnectionError, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let flags = cur.read_u32()?;
    let error_code = cur.read_str0_255()?.to_vec();
    cur.finish()?;
    Ok(SetupConnectionError { flags, error_code })
}

// ------------------------- OpenStandardMiningChannel -------------------------

/// Encode an [`OpenStandardMiningChannel`] message.
pub fn encode_open_standard_mining_channel(
    msg: &OpenStandardMiningChannel,
) -> Result<Vec<u8>, Sv2CodecError> {
    let mut out = Vec::with_capacity(4 + 1 + msg.user_identity.len() + 4 + 32);
    out.extend_from_slice(&msg.request_id.to_le_bytes());
    write_str0_255(&mut out, &msg.user_identity)?;
    out.extend_from_slice(&msg.nominal_hash_rate_bits.to_le_bytes());
    out.extend_from_slice(&msg.max_target);
    Ok(out)
}

/// Decode an [`OpenStandardMiningChannel`] message.
pub fn decode_open_standard_mining_channel(
    buf: &[u8],
) -> Result<OpenStandardMiningChannel, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let request_id = cur.read_u32()?;
    let user_identity = cur.read_str0_255()?.to_vec();
    let nominal_hash_rate_bits = cur.read_u32()?;
    let max_target = cur.read_array32()?;
    cur.finish()?;
    Ok(OpenStandardMiningChannel {
        request_id,
        user_identity,
        nominal_hash_rate_bits,
        max_target,
    })
}

/// Encode an [`OpenStandardMiningChannelSuccess`] message.
pub fn encode_open_standard_mining_channel_success(
    msg: &OpenStandardMiningChannelSuccess,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 + 32);
    out.extend_from_slice(&msg.request_id.to_le_bytes());
    out.extend_from_slice(&msg.channel_id.to_le_bytes());
    out.extend_from_slice(&msg.target);
    out
}

/// Decode an [`OpenStandardMiningChannelSuccess`] message.
pub fn decode_open_standard_mining_channel_success(
    buf: &[u8],
) -> Result<OpenStandardMiningChannelSuccess, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let request_id = cur.read_u32()?;
    let channel_id = cur.read_u32()?;
    let target = cur.read_array32()?;
    cur.finish()?;
    Ok(OpenStandardMiningChannelSuccess {
        request_id,
        channel_id,
        target,
    })
}

/// Encode an [`OpenStandardMiningChannelError`] message.
pub fn encode_open_standard_mining_channel_error(
    msg: &OpenStandardMiningChannelError,
) -> Result<Vec<u8>, Sv2CodecError> {
    let mut out = Vec::with_capacity(4 + 1 + msg.error_code.len());
    out.extend_from_slice(&msg.request_id.to_le_bytes());
    write_str0_255(&mut out, &msg.error_code)?;
    Ok(out)
}

/// Decode an [`OpenStandardMiningChannelError`] message.
pub fn decode_open_standard_mining_channel_error(
    buf: &[u8],
) -> Result<OpenStandardMiningChannelError, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let request_id = cur.read_u32()?;
    let error_code = cur.read_str0_255()?.to_vec();
    cur.finish()?;
    Ok(OpenStandardMiningChannelError {
        request_id,
        error_code,
    })
}

// ------------------------------ SetNewPrevHash ------------------------------

/// Encode a [`SetNewPrevHash`] message.
pub fn encode_set_new_prev_hash(msg: &SetNewPrevHash) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32 + 8 + 4);
    out.extend_from_slice(&msg.channel_id.to_le_bytes());
    out.extend_from_slice(&msg.prev_hash);
    out.extend_from_slice(&msg.min_ntime.to_le_bytes());
    out.extend_from_slice(&msg.nbits.to_le_bytes());
    out
}

/// Decode a [`SetNewPrevHash`] message.
pub fn decode_set_new_prev_hash(buf: &[u8]) -> Result<SetNewPrevHash, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let channel_id = cur.read_u32()?;
    let prev_hash = cur.read_array32()?;
    let min_ntime = cur.read_u64()?;
    let nbits = cur.read_u32()?;
    cur.finish()?;
    Ok(SetNewPrevHash {
        channel_id,
        prev_hash,
        min_ntime,
        nbits,
    })
}

// ------------------------- SubmitSharesSuccess / Error -------------------------

/// Encode a [`SubmitSharesSuccess`] message.
pub fn encode_submit_shares_success(msg: &SubmitSharesSuccess) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 4 + 4 + 8);
    out.extend_from_slice(&msg.channel_id.to_le_bytes());
    out.extend_from_slice(&msg.last_sequence_number.to_le_bytes());
    out.extend_from_slice(&msg.new_submits_accepted_count.to_le_bytes());
    out.extend_from_slice(&msg.new_shares_sum.to_le_bytes());
    out
}

/// Decode a [`SubmitSharesSuccess`] message.
pub fn decode_submit_shares_success(buf: &[u8]) -> Result<SubmitSharesSuccess, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let channel_id = cur.read_u32()?;
    let last_sequence_number = cur.read_u32()?;
    let new_submits_accepted_count = cur.read_u32()?;
    let new_shares_sum = cur.read_u64()?;
    cur.finish()?;
    Ok(SubmitSharesSuccess {
        channel_id,
        last_sequence_number,
        new_submits_accepted_count,
        new_shares_sum,
    })
}

/// Encode a [`SubmitSharesError`] message.
pub fn encode_submit_shares_error(msg: &SubmitSharesError) -> Result<Vec<u8>, Sv2CodecError> {
    let mut out = Vec::with_capacity(4 + 4 + 1 + msg.error_code.len());
    out.extend_from_slice(&msg.channel_id.to_le_bytes());
    out.extend_from_slice(&msg.sequence_number.to_le_bytes());
    write_str0_255(&mut out, &msg.error_code)?;
    Ok(out)
}

/// Decode a [`SubmitSharesError`] message.
pub fn decode_submit_shares_error(buf: &[u8]) -> Result<SubmitSharesError, Sv2CodecError> {
    let mut cur = Cursor::new(buf);
    let channel_id = cur.read_u32()?;
    let sequence_number = cur.read_u32()?;
    let error_code = cur.read_str0_255()?.to_vec();
    cur.finish()?;
    Ok(SubmitSharesError {
        channel_id,
        sequence_number,
        error_code,
    })
}

// ------------------------------ helpers ------------------------------

fn write_str0_255(buf: &mut Vec<u8>, s: &[u8]) -> Result<(), Sv2CodecError> {
    if s.len() > STR0_255_MAX {
        return Err(Sv2CodecError::StringTooLong(s.len()));
    }
    buf.push(s.len() as u8);
    buf.extend_from_slice(s);
    Ok(())
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Sv2CodecError> {
        if self.remaining() < n {
            return Err(Sv2CodecError::Short {
                at: self.pos,
                need: n - self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> Result<u8, Sv2CodecError> {
        Ok(self.take(1)?[0])
    }
    fn read_u16(&mut self) -> Result<u16, Sv2CodecError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn read_u32(&mut self) -> Result<u32, Sv2CodecError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn read_u64(&mut self) -> Result<u64, Sv2CodecError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn read_array32(&mut self) -> Result<[u8; 32], Sv2CodecError> {
        let s = self.take(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
    fn read_str0_255(&mut self) -> Result<&'a [u8], Sv2CodecError> {
        let n = self.read_u8()? as usize;
        self.take(n)
    }
    fn finish(self) -> Result<(), Sv2CodecError> {
        if self.remaining() > 0 {
            Err(Sv2CodecError::Trailing {
                extra: self.remaining(),
            })
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dinero_sv2_common::{PROTOCOL_MINING, PROTOCOL_VERSION};
    use proptest::prelude::*;

    #[test]
    fn setup_connection_roundtrip() {
        let m = SetupConnection {
            protocol: PROTOCOL_MINING,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: b"dinero-testclient/0.1".to_vec(),
        };
        let bytes = encode_setup_connection(&m).unwrap();
        let back = decode_setup_connection(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn setup_connection_rejects_trailing() {
        let m = SetupConnection {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: vec![],
        };
        let mut bytes = encode_setup_connection(&m).unwrap();
        bytes.push(0xFF);
        let err = decode_setup_connection(&bytes).unwrap_err();
        assert!(matches!(err, Sv2CodecError::Trailing { .. }));
    }

    #[test]
    fn setup_connection_rejects_short() {
        let m = SetupConnection {
            protocol: 0,
            min_version: 2,
            max_version: 2,
            flags: 0,
            user_agent: b"hi".to_vec(),
        };
        let bytes = encode_setup_connection(&m).unwrap();
        let err = decode_setup_connection(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(matches!(err, Sv2CodecError::Short { .. }));
    }

    #[test]
    fn setup_connection_success_roundtrip() {
        let m = SetupConnectionSuccess {
            used_version: PROTOCOL_VERSION,
            flags: 0,
        };
        let bytes = encode_setup_connection_success(&m);
        assert_eq!(m, decode_setup_connection_success(&bytes).unwrap());
    }

    #[test]
    fn setup_connection_error_roundtrip() {
        let m = SetupConnectionError {
            flags: 0,
            error_code: b"unsupported-protocol".to_vec(),
        };
        let bytes = encode_setup_connection_error(&m).unwrap();
        assert_eq!(m, decode_setup_connection_error(&bytes).unwrap());
    }

    #[test]
    fn open_standard_mining_channel_roundtrip() {
        let m = OpenStandardMiningChannel {
            request_id: 42,
            user_identity: b"worker-1".to_vec(),
            nominal_hash_rate_bits: f32::to_bits(1_000_000.0),
            max_target: [0xFFu8; 32],
        };
        let bytes = encode_open_standard_mining_channel(&m).unwrap();
        assert_eq!(m, decode_open_standard_mining_channel(&bytes).unwrap());
    }

    #[test]
    fn open_standard_mining_channel_success_roundtrip() {
        let m = OpenStandardMiningChannelSuccess {
            request_id: 42,
            channel_id: 1,
            target: [0x12u8; 32],
        };
        let bytes = encode_open_standard_mining_channel_success(&m);
        assert_eq!(
            m,
            decode_open_standard_mining_channel_success(&bytes).unwrap()
        );
    }

    #[test]
    fn open_standard_mining_channel_error_roundtrip() {
        let m = OpenStandardMiningChannelError {
            request_id: 42,
            error_code: b"max-target-too-high".to_vec(),
        };
        let bytes = encode_open_standard_mining_channel_error(&m).unwrap();
        assert_eq!(
            m,
            decode_open_standard_mining_channel_error(&bytes).unwrap()
        );
    }

    #[test]
    fn set_new_prev_hash_roundtrip() {
        let m = SetNewPrevHash {
            channel_id: 1,
            prev_hash: [0xAB; 32],
            min_ntime: 1_776_384_000,
            nbits: 0x1d_31_ff_ce,
        };
        let bytes = encode_set_new_prev_hash(&m);
        assert_eq!(bytes.len(), 4 + 32 + 8 + 4);
        assert_eq!(m, decode_set_new_prev_hash(&bytes).unwrap());
    }

    #[test]
    fn set_new_prev_hash_rejects_trailing() {
        let m = SetNewPrevHash {
            channel_id: 1,
            prev_hash: [0; 32],
            min_ntime: 0,
            nbits: 0,
        };
        let mut bytes = encode_set_new_prev_hash(&m);
        bytes.push(0xFF);
        let err = decode_set_new_prev_hash(&bytes).unwrap_err();
        assert!(matches!(err, Sv2CodecError::Trailing { .. }));
    }

    #[test]
    fn submit_shares_success_roundtrip() {
        let m = SubmitSharesSuccess {
            channel_id: 1,
            last_sequence_number: 100,
            new_submits_accepted_count: 1,
            new_shares_sum: 1,
        };
        let bytes = encode_submit_shares_success(&m);
        assert_eq!(m, decode_submit_shares_success(&bytes).unwrap());
    }

    #[test]
    fn submit_shares_error_roundtrip() {
        let m = SubmitSharesError {
            channel_id: 1,
            sequence_number: 100,
            error_code: b"stale-share".to_vec(),
        };
        let bytes = encode_submit_shares_error(&m).unwrap();
        assert_eq!(m, decode_submit_shares_error(&bytes).unwrap());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn fuzz_setup_connection(
            protocol in any::<u8>(),
            min_v in any::<u16>(),
            max_v in any::<u16>(),
            flags in any::<u32>(),
            ua in proptest::collection::vec(any::<u8>(), 0..=255),
        ) {
            let m = SetupConnection {
                protocol,
                min_version: min_v,
                max_version: max_v,
                flags,
                user_agent: ua,
            };
            let bytes = encode_setup_connection(&m).unwrap();
            prop_assert_eq!(m, decode_setup_connection(&bytes).unwrap());
        }

        #[test]
        fn fuzz_open_channel(
            request_id in any::<u32>(),
            identity in proptest::collection::vec(any::<u8>(), 0..=255),
            rate in any::<u32>(),
            target in any::<[u8; 32]>(),
        ) {
            let m = OpenStandardMiningChannel {
                request_id,
                user_identity: identity,
                nominal_hash_rate_bits: rate,
                max_target: target,
            };
            let bytes = encode_open_standard_mining_channel(&m).unwrap();
            prop_assert_eq!(m, decode_open_standard_mining_channel(&bytes).unwrap());
        }

        #[test]
        fn fuzz_submit_shares_error(
            channel_id in any::<u32>(),
            sequence_number in any::<u32>(),
            error_code in proptest::collection::vec(any::<u8>(), 0..=255),
        ) {
            let m = SubmitSharesError {
                channel_id,
                sequence_number,
                error_code,
            };
            let bytes = encode_submit_shares_error(&m).unwrap();
            prop_assert_eq!(m, decode_submit_shares_error(&bytes).unwrap());
        }
    }
}
