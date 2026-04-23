//! Wire codec for [`NewTemplateDineroJD`].
//!
//! Unlike Phase 1's fixed-size codec, JD templates have variable-length
//! fields (`coinbase_prefix`, `coinbase_suffix`, `merkle_path`). The
//! framing uses explicit `u32 LE` length prefixes for every bytes blob
//! and a `u16 LE` count + 32-byte entries for `merkle_path`. All
//! multi-byte integers are little-endian.
//!
//! Wire layout:
//!
//! ```text
//! template_id            u64 LE
//! future_template        u8  (0 or 1; any other value rejected)
//! version                u32 LE
//! prev_block_hash        32
//! utreexo_root           32
//! timestamp              u64 LE
//! difficulty             u32 LE
//! coinbase_prefix_len    u32 LE
//! coinbase_prefix        N bytes
//! coinbase_suffix_len    u32 LE
//! coinbase_suffix        N bytes
//! merkle_path_len        u16 LE
//! merkle_path            merkle_path_len * 32 bytes
//! ```
//!
//! Caller limits: `coinbase_prefix` / `coinbase_suffix` capped at 1 MiB
//! each, `merkle_path` capped at 64 entries (covers up to 2^64 tx trees,
//! obviously enough for any real block).

use crate::messages::NewTemplateDineroJD;

const MAX_COINBASE_BLOB: usize = 1_048_576;
const MAX_MERKLE_ENTRIES: usize = 64;

/// Codec errors for JD messages.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JdCodecError {
    /// Not enough bytes to finish decoding.
    #[error("short frame: need {need} more bytes at offset {at}")]
    Short {
        /// Offset into the input where decoding failed.
        at: usize,
        /// Bytes required beyond the end of the input.
        need: usize,
    },
    /// Unused bytes at the tail of the input.
    #[error("trailing bytes: {extra} bytes past the declared payload")]
    Trailing {
        /// Number of trailing bytes.
        extra: usize,
    },
    /// `future_template` was not `0` or `1`.
    #[error("invalid boolean byte: 0x{0:02x}")]
    InvalidBool(u8),
    /// A length prefix exceeded the crate-level cap.
    #[error("length {got} exceeds cap {cap} for {field}")]
    TooLarge {
        /// Field name.
        field: &'static str,
        /// Value we got.
        got: usize,
        /// Upper bound enforced by the codec.
        cap: usize,
    },
}

/// Encode a [`NewTemplateDineroJD`] to its variable-size wire form.
pub fn encode_new_template_jd(msg: &NewTemplateDineroJD) -> Result<Vec<u8>, JdCodecError> {
    if msg.coinbase_prefix.len() > MAX_COINBASE_BLOB {
        return Err(JdCodecError::TooLarge {
            field: "coinbase_prefix",
            got: msg.coinbase_prefix.len(),
            cap: MAX_COINBASE_BLOB,
        });
    }
    if msg.coinbase_suffix.len() > MAX_COINBASE_BLOB {
        return Err(JdCodecError::TooLarge {
            field: "coinbase_suffix",
            got: msg.coinbase_suffix.len(),
            cap: MAX_COINBASE_BLOB,
        });
    }
    if msg.merkle_path.len() > MAX_MERKLE_ENTRIES {
        return Err(JdCodecError::TooLarge {
            field: "merkle_path",
            got: msg.merkle_path.len(),
            cap: MAX_MERKLE_ENTRIES,
        });
    }

    let cap = 8
        + 1
        + 4
        + 32
        + 32
        + 8
        + 4
        + 4
        + msg.coinbase_prefix.len()
        + 4
        + msg.coinbase_suffix.len()
        + 2
        + msg.merkle_path.len() * 32;
    let mut out = Vec::with_capacity(cap);

    out.extend_from_slice(&msg.template_id.to_le_bytes());
    out.push(u8::from(msg.future_template));
    out.extend_from_slice(&msg.version.to_le_bytes());
    out.extend_from_slice(&msg.prev_block_hash);
    out.extend_from_slice(&msg.utreexo_root);
    out.extend_from_slice(&msg.timestamp.to_le_bytes());
    out.extend_from_slice(&msg.difficulty.to_le_bytes());

    out.extend_from_slice(&(msg.coinbase_prefix.len() as u32).to_le_bytes());
    out.extend_from_slice(&msg.coinbase_prefix);

    out.extend_from_slice(&(msg.coinbase_suffix.len() as u32).to_le_bytes());
    out.extend_from_slice(&msg.coinbase_suffix);

    out.extend_from_slice(&(msg.merkle_path.len() as u16).to_le_bytes());
    for h in &msg.merkle_path {
        out.extend_from_slice(h);
    }

    debug_assert_eq!(out.len(), cap);
    Ok(out)
}

/// Decode a [`NewTemplateDineroJD`] from the wire form produced by
/// [`encode_new_template_jd`].
pub fn decode_new_template_jd(buf: &[u8]) -> Result<NewTemplateDineroJD, JdCodecError> {
    let mut cur = Cursor::new(buf);

    let template_id = cur.read_u64()?;
    let future_template = match cur.read_u8()? {
        0 => false,
        1 => true,
        b => return Err(JdCodecError::InvalidBool(b)),
    };
    let version = cur.read_u32()?;
    let prev_block_hash = cur.read_array32()?;
    let utreexo_root = cur.read_array32()?;
    let timestamp = cur.read_u64()?;
    let difficulty = cur.read_u32()?;

    let prefix_len = cur.read_u32()? as usize;
    if prefix_len > MAX_COINBASE_BLOB {
        return Err(JdCodecError::TooLarge {
            field: "coinbase_prefix",
            got: prefix_len,
            cap: MAX_COINBASE_BLOB,
        });
    }
    let coinbase_prefix = cur.read_bytes(prefix_len)?.to_vec();

    let suffix_len = cur.read_u32()? as usize;
    if suffix_len > MAX_COINBASE_BLOB {
        return Err(JdCodecError::TooLarge {
            field: "coinbase_suffix",
            got: suffix_len,
            cap: MAX_COINBASE_BLOB,
        });
    }
    let coinbase_suffix = cur.read_bytes(suffix_len)?.to_vec();

    let path_len = cur.read_u16()? as usize;
    if path_len > MAX_MERKLE_ENTRIES {
        return Err(JdCodecError::TooLarge {
            field: "merkle_path",
            got: path_len,
            cap: MAX_MERKLE_ENTRIES,
        });
    }
    let mut merkle_path = Vec::with_capacity(path_len);
    for _ in 0..path_len {
        merkle_path.push(cur.read_array32()?);
    }

    if cur.remaining() > 0 {
        return Err(JdCodecError::Trailing {
            extra: cur.remaining(),
        });
    }

    Ok(NewTemplateDineroJD {
        template_id,
        future_template,
        version,
        prev_block_hash,
        utreexo_root,
        timestamp,
        difficulty,
        coinbase_prefix,
        coinbase_suffix,
        merkle_path,
    })
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

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], JdCodecError> {
        if self.remaining() < n {
            return Err(JdCodecError::Short {
                at: self.pos,
                need: n - self.remaining(),
            });
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, JdCodecError> {
        let s = self.read_bytes(1)?;
        Ok(s[0])
    }
    fn read_u16(&mut self) -> Result<u16, JdCodecError> {
        let s = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn read_u32(&mut self) -> Result<u32, JdCodecError> {
        let s = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn read_u64(&mut self) -> Result<u64, JdCodecError> {
        let s = self.read_bytes(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn read_array32(&mut self) -> Result<[u8; 32], JdCodecError> {
        let s = self.read_bytes(32)?;
        let mut a = [0u8; 32];
        a.copy_from_slice(s);
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn sample() -> NewTemplateDineroJD {
        NewTemplateDineroJD {
            template_id: 0xCAFE_BABE_DEAD_0001,
            future_template: true,
            version: 1,
            prev_block_hash: [0x11; 32],
            utreexo_root: [0x22; 32],
            timestamp: 1_776_384_000,
            difficulty: 0x1d_31_ff_ce,
            coinbase_prefix: vec![0x03, 0x3c, 0x14, 0x00, 0xAA],
            coinbase_suffix: vec![0x00, 0x00, 0x00, 0x00],
            merkle_path: vec![[0x44; 32], [0x55; 32]],
        }
    }

    #[test]
    fn roundtrip() {
        let m = sample();
        let bytes = encode_new_template_jd(&m).unwrap();
        let back = decode_new_template_jd(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn roundtrip_empty_merkle_path() {
        let mut m = sample();
        m.merkle_path.clear();
        let bytes = encode_new_template_jd(&m).unwrap();
        let back = decode_new_template_jd(&bytes).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut bytes = encode_new_template_jd(&sample()).unwrap();
        bytes.push(0xFF);
        let err = decode_new_template_jd(&bytes).unwrap_err();
        assert!(matches!(err, JdCodecError::Trailing { .. }));
    }

    #[test]
    fn rejects_short() {
        let bytes = encode_new_template_jd(&sample()).unwrap();
        let err = decode_new_template_jd(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(matches!(err, JdCodecError::Short { .. }));
    }

    #[test]
    fn rejects_invalid_bool() {
        let mut bytes = encode_new_template_jd(&sample()).unwrap();
        bytes[8] = 2; // future_template byte
        let err = decode_new_template_jd(&bytes).unwrap_err();
        assert_eq!(err, JdCodecError::InvalidBool(2));
    }

    #[test]
    fn rejects_merkle_path_overflow() {
        let mut m = sample();
        m.merkle_path = vec![[0u8; 32]; MAX_MERKLE_ENTRIES + 1];
        let err = encode_new_template_jd(&m).unwrap_err();
        assert!(matches!(err, JdCodecError::TooLarge { .. }));
    }

    // Fuzz: random structs with bounded blob sizes round-trip cleanly.
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn fuzz_roundtrip(
            template_id in any::<u64>(),
            future_template in any::<bool>(),
            version in any::<u32>(),
            prev_block_hash in any::<[u8; 32]>(),
            utreexo_root in any::<[u8; 32]>(),
            timestamp in any::<u64>(),
            difficulty in any::<u32>(),
            coinbase_prefix in proptest::collection::vec(any::<u8>(), 0..512),
            coinbase_suffix in proptest::collection::vec(any::<u8>(), 0..512),
            path_len in 0usize..20,
            path_seed in any::<u8>(),
        ) {
            let merkle_path: Vec<[u8; 32]> = (0..path_len)
                .map(|i| [path_seed.wrapping_add(i as u8); 32])
                .collect();
            let m = NewTemplateDineroJD {
                template_id,
                future_template,
                version,
                prev_block_hash,
                utreexo_root,
                timestamp,
                difficulty,
                coinbase_prefix,
                coinbase_suffix,
                merkle_path,
            };
            let bytes = encode_new_template_jd(&m).unwrap();
            let back = decode_new_template_jd(&bytes).unwrap();
            prop_assert_eq!(m, back);
        }
    }
}
