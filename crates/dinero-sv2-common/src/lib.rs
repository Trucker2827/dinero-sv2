//! Dinero Stratum V2 — profile message types.
//!
//! This crate owns the wire-level message structs that make Stratum V2 work
//! for Dinero's 128-byte header. It intentionally does NOT fork the Stratum
//! Reference Implementation (SRI) — the message types here mirror SRI's shape
//! but carry Dinero-specific fields (`utreexo_root`, `timestamp: u64`) and
//! enforce Dinero consensus invariants (`reserved[12] == 0`).
//!
//! The encode/decode layer lives in `dinero-sv2-codec`. This crate is
//! codec-agnostic: the structs are plain data, and [`HeaderAssembly`] is a
//! pure function from message pair to 128 raw header bytes.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod sv2_messages;

pub use sv2_messages::{
    CoinbaseContext, CoinbaseOutputWire, OpenStandardMiningChannel, OpenStandardMiningChannelError,
    OpenStandardMiningChannelSuccess, SetNewPrevHash, SetTarget, SetupConnection,
    SetupConnectionError, SetupConnectionSuccess, SubmitSharesError, SubmitSharesExtendedDinero,
    SubmitSharesSuccess, PROTOCOL_MINING, PROTOCOL_VERSION,
};

use sha2::{Digest, Sha256};

/// The fixed serialized size of a Dinero block header, in bytes.
///
/// This is consensus-locked (see `dinero/include/primitives/block.h`). Any
/// `HeaderAssembly` output that is not exactly this size is a bug.
pub const HEADER_SIZE: usize = 128;

/// Length of the consensus-locked zero-reserved tail of the block header.
///
/// These 12 bytes are **not** extranonce, **not** pool scratch, and **not**
/// miner entropy — they are required to be zero for the block to validate.
pub const RESERVED_LEN: usize = 12;

/// Error type for header assembly and invariant checks.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvariantError {
    /// A wire frame carried non-zero bytes in the 12-byte reserved header
    /// tail. Rejected at decode time.
    #[error("reserved[12] must be zero (got bytes at positions {positions:?})")]
    NonZeroReserved {
        /// Positions inside the 12-byte reserved slice that were non-zero.
        positions: Vec<usize>,
    },
    /// Template timestamp mismatched the share's claimed timestamp.
    ///
    /// The share's timestamp is what goes into the header; the template
    /// timestamp is advisory (the point in time the template was emitted).
    /// Implementations may not silently pick one — the caller must choose
    /// explicitly by passing the value they intend to hash.
    #[error("timestamp mismatch: template={template} share={share}")]
    TimestampMismatch {
        /// Timestamp on the template message.
        template: u64,
        /// Timestamp on the share submission.
        share: u64,
    },
}

/// Stratum V2 profile message: a new block template for Dinero.
///
/// In Phase 1, the coinbase is pool-constructed; `merkle_root` is final.
/// A future [`NewTemplateDineroJD`] will carry coinbase fragments and a
/// merkle path to let miners assemble the coinbase themselves (Job
/// Declaration). That is not implemented in this crate.
///
/// [`NewTemplateDineroJD`]: crate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTemplateDinero {
    /// Monotonic per-session template id. Pool sets.
    pub template_id: u64,
    /// If true, this template applies to the *next* tip (future work).
    /// If false, apply immediately (`SetNewPrevHash` semantics).
    pub future_template: bool,
    /// Header field: block version (offset 0x00, 4 bytes LE).
    pub version: u32,
    /// Header field: previous block hash (offset 0x04, 32 bytes LE).
    pub prev_block_hash: [u8; 32],
    /// Header field: merkle root of transactions (offset 0x24, 32 bytes LE).
    ///
    /// In Phase 1 this is the final merkle root; the miner does not touch it.
    pub merkle_root: [u8; 32],
    /// Header field: Utreexo accumulator root (offset 0x44, 32 bytes LE).
    ///
    /// This is a first-class Dinero consensus field, not auxiliary metadata.
    /// Pool-supplied; miners MUST hash the header exactly as given.
    pub utreexo_root: [u8; 32],
    /// Header field: block timestamp (offset 0x64, 8 bytes LE, `u64`).
    ///
    /// Note `u64`, not `u32` — Dinero dodged 2038.
    pub timestamp: u64,
    /// Header field: compact difficulty target (offset 0x6C, 4 bytes LE).
    pub difficulty: u32,
    /// Commitment to the template's transaction-output set.
    ///
    /// Currently `sha256d` of the serialized coinbase outputs + mempool tx
    /// list. Used by pool + client to prove they agree on the full tx set
    /// without shipping all mempool txs over the wire. Not part of the
    /// 128-byte header.
    pub coinbase_outputs_commitment: [u8; 32],
}

/// Stratum V2 profile message: a miner-found share for Dinero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSharesDinero {
    /// Mining channel on which the share was found.
    pub channel_id: u32,
    /// Monotonic share counter; replay prevention.
    pub sequence_number: u32,
    /// Which job on that channel.
    pub job_id: u32,
    /// Header field: miner nonce (offset 0x70, 4 bytes LE).
    pub nonce: u32,
    /// Header field: header timestamp (offset 0x64, 8 bytes LE, `u64`).
    ///
    /// Miners MAY roll this within consensus bounds; pool must verify.
    pub timestamp: u64,
    /// Header field: block version for share (offset 0x00, 4 bytes LE).
    ///
    /// Version rolling is permitted where consensus allows.
    pub version: u32,
}

/// Deterministically assemble a 128-byte Dinero header from a template
/// and a share submission.
///
/// This is the single source of truth for header layout. It enforces:
///
/// - Exact 128-byte output.
/// - `reserved[12]` written as zero.
/// - `timestamp` serialized as little-endian `u64`.
/// - `utreexo_root` at offset 0x44.
///
/// The returned hash is `sha256d(header_bytes)` — matches
/// `BlockHeader::GetHash` in dinerod.
#[derive(Debug)]
pub struct HeaderAssembly;

impl HeaderAssembly {
    /// Build the raw 128 header bytes.
    pub fn bytes(template: &NewTemplateDinero, share: &SubmitSharesDinero) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        // 0x00 version (u32 LE)
        out[0x00..0x04].copy_from_slice(&share.version.to_le_bytes());
        // 0x04 prev_block_hash (32 LE — stored as-is)
        out[0x04..0x24].copy_from_slice(&template.prev_block_hash);
        // 0x24 merkle_root
        out[0x24..0x44].copy_from_slice(&template.merkle_root);
        // 0x44 utreexo_root
        out[0x44..0x64].copy_from_slice(&template.utreexo_root);
        // 0x64 timestamp (u64 LE)
        out[0x64..0x6C].copy_from_slice(&share.timestamp.to_le_bytes());
        // 0x6C difficulty (u32 LE)
        out[0x6C..0x70].copy_from_slice(&template.difficulty.to_le_bytes());
        // 0x70 nonce (u32 LE)
        out[0x70..0x74].copy_from_slice(&share.nonce.to_le_bytes());
        // 0x74..0x80 reserved[12] — already zero-initialized above.
        out
    }

    /// Compute the block hash: `sha256d(bytes)`.
    pub fn hash(template: &NewTemplateDinero, share: &SubmitSharesDinero) -> [u8; 32] {
        let bytes = Self::bytes(template, share);
        sha256d(&bytes)
    }

    /// Check the invariant that the trailing 12 reserved bytes of a
    /// supposedly-Dinero header are zero. Intended for decoders that
    /// receive a raw 128-byte header on the wire.
    pub fn check_reserved_zero(header: &[u8; HEADER_SIZE]) -> Result<(), InvariantError> {
        let tail = &header[0x74..0x80];
        let bad: Vec<usize> = tail
            .iter()
            .enumerate()
            .filter_map(|(i, b)| if *b != 0 { Some(i) } else { None })
            .collect();
        if bad.is_empty() {
            Ok(())
        } else {
            Err(InvariantError::NonZeroReserved { positions: bad })
        }
    }
}

/// Dinero consensus hash: `SHA-256(SHA-256(data))`.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn tmpl() -> NewTemplateDinero {
        NewTemplateDinero {
            template_id: 1,
            future_template: false,
            version: 1,
            prev_block_hash: [0x11; 32],
            merkle_root: [0x22; 32],
            utreexo_root: [0x33; 32],
            timestamp: 1_776_384_000,
            difficulty: 0x1d_31_ff_ce,
            coinbase_outputs_commitment: [0x44; 32],
        }
    }

    fn share() -> SubmitSharesDinero {
        SubmitSharesDinero {
            channel_id: 7,
            sequence_number: 42,
            job_id: 1,
            nonce: 813_915_426,
            timestamp: 1_776_384_000,
            version: 1,
        }
    }

    #[test]
    fn assembly_is_exactly_128_bytes() {
        let bytes = HeaderAssembly::bytes(&tmpl(), &share());
        assert_eq!(bytes.len(), HEADER_SIZE);
    }

    #[test]
    fn reserved_tail_is_zero() {
        let bytes = HeaderAssembly::bytes(&tmpl(), &share());
        assert_eq!(&bytes[0x74..0x80], &[0u8; 12]);
    }

    #[test]
    fn layout_matches_dinero_block_header_v1() {
        // Matches include/primitives/block.h offsets exactly.
        let bytes = HeaderAssembly::bytes(&tmpl(), &share());

        assert_eq!(&bytes[0x00..0x04], &1u32.to_le_bytes(), "version");
        assert_eq!(&bytes[0x04..0x24], &[0x11; 32], "prev_block_hash");
        assert_eq!(&bytes[0x24..0x44], &[0x22; 32], "merkle_root");
        assert_eq!(&bytes[0x44..0x64], &[0x33; 32], "utreexo_root");
        assert_eq!(
            &bytes[0x64..0x6C],
            &1_776_384_000u64.to_le_bytes(),
            "timestamp (u64, not u32)"
        );
        assert_eq!(
            &bytes[0x6C..0x70],
            &0x1d_31_ff_ceu32.to_le_bytes(),
            "difficulty"
        );
        assert_eq!(&bytes[0x70..0x74], &813_915_426u32.to_le_bytes(), "nonce");
        assert_eq!(&bytes[0x74..0x80], &[0u8; 12], "reserved must be zero");
    }

    #[test]
    fn timestamp_is_u64_full_range() {
        // If timestamp were accidentally serialized as u32, values above
        // u32::MAX would collide. This test would catch that regression.
        let large = (u32::MAX as u64) + 1;
        let mut s = share();
        s.timestamp = large;
        let bytes = HeaderAssembly::bytes(&tmpl(), &s);
        let mut ts = [0u8; 8];
        ts.copy_from_slice(&bytes[0x64..0x6C]);
        assert_eq!(u64::from_le_bytes(ts), large);
    }

    #[test]
    fn check_reserved_zero_accepts_zero() {
        let header = HeaderAssembly::bytes(&tmpl(), &share());
        assert!(HeaderAssembly::check_reserved_zero(&header).is_ok());
    }

    #[test]
    fn check_reserved_zero_rejects_any_nonzero_byte() {
        let mut header = HeaderAssembly::bytes(&tmpl(), &share());
        header[0x7A] = 0x01;
        match HeaderAssembly::check_reserved_zero(&header) {
            Err(InvariantError::NonZeroReserved { positions }) => {
                assert_eq!(positions, vec![0x7A - 0x74]);
            }
            other => panic!("expected NonZeroReserved, got {other:?}"),
        }
    }

    #[test]
    fn hash_is_sha256d_of_header() {
        let tmpl = tmpl();
        let share = share();
        let bytes = HeaderAssembly::bytes(&tmpl, &share);
        let expected = sha256d(&bytes);
        let actual = HeaderAssembly::hash(&tmpl, &share);
        assert_eq!(actual, expected);
    }

    // -------- proptest fuzz: invariant preservation --------

    proptest! {
        /// Reserved tail is zero for *any* structurally-valid template/share.
        #[test]
        fn fuzz_reserved_always_zero(
            ver in any::<u32>(),
            nonce in any::<u32>(),
            ts in any::<u64>(),
            diff in any::<u32>(),
            pb in any::<[u8; 32]>(),
            mr in any::<[u8; 32]>(),
            ur in any::<[u8; 32]>(),
        ) {
            let t = NewTemplateDinero {
                template_id: 0,
                future_template: false,
                version: ver,
                prev_block_hash: pb,
                merkle_root: mr,
                utreexo_root: ur,
                timestamp: ts,
                difficulty: diff,
                coinbase_outputs_commitment: [0; 32],
            };
            let s = SubmitSharesDinero {
                channel_id: 0,
                sequence_number: 0,
                job_id: 0,
                nonce,
                timestamp: ts,
                version: ver,
            };
            let bytes = HeaderAssembly::bytes(&t, &s);
            prop_assert_eq!(&bytes[0x74..0x80], &[0u8; 12][..]);
        }

        /// Header length is always exactly 128.
        #[test]
        fn fuzz_length_is_128(
            nonce in any::<u32>(),
            ts in any::<u64>(),
        ) {
            let mut t = tmpl();
            t.timestamp = ts;
            let mut s = share();
            s.nonce = nonce;
            s.timestamp = ts;
            prop_assert_eq!(HeaderAssembly::bytes(&t, &s).len(), HEADER_SIZE);
        }
    }
}
