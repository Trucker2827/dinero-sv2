//! DNRF filter commitment script builder.
//!
//! Mirrors `BuildFilterCommitmentScript` in
//! `src/consensus/filter_commitment.cpp`. The coinbase of every
//! block at or above [`ACTIVATION_HEIGHT`] must contain an
//! OP_RETURN output whose script is exactly 39 bytes:
//!
//! ```text
//! [0]    = 0x6a             (OP_RETURN)
//! [1]    = 0x25             (push 37 bytes)
//! [2..6] = 0x44 0x4E 0x52 0x46   ("DNRF" magic)
//! [6]    = 0x01             (version)
//! [7..39]= filter_hash (raw LE bytes of SHA256d(encoded))
//! ```
//!
//! The 32 bytes at `[7..39]` are the *raw* double-SHA256 output —
//! i.e. [`crate::block_filter::gcs_filter_hash`] — not a
//! display-reversed hex decode.

/// Height at which the DNRF commitment becomes mandatory. Matches
/// `FilterCommitment::ACTIVATION_HEIGHT` in
/// `include/consensus/filter_commitment.h`.
pub const ACTIVATION_HEIGHT: u64 = 1;

/// The 4-byte magic `"DNRF"`.
pub const DNRF_MAGIC: [u8; 4] = [0x44, 0x4E, 0x52, 0x46];

/// Commitment version (currently `0x01`).
pub const DNRF_VERSION: u8 = 0x01;

/// Total length of the DNRF OP_RETURN script body (magic + version
/// + hash), i.e. what appears after the push-length byte.
pub const DNRF_DATA_SIZE: u8 = 37;

/// Returns `true` if a block at `height` must carry a DNRF
/// commitment in its coinbase.
pub fn requires_filter_commitment(height: u64) -> bool {
    height >= ACTIVATION_HEIGHT
}

/// Recognise a DNRF commitment script by its fixed prefix shape:
/// `OP_RETURN` (0x6a), push 37 (0x25), `"DNRF"` magic, version 0x01,
/// then 32 bytes of filter hash. Used by the pool to validate
/// miner-supplied coinbase outputs before submitblock — a coinbase
/// past activation that lacks a DNRF output would be rejected by
/// dinerod and burn a found block.
pub fn is_dnrf_script(script: &[u8]) -> bool {
    script.len() == 2 + DNRF_DATA_SIZE as usize
        && script[0] == 0x6a
        && script[1] == DNRF_DATA_SIZE
        && script[2..6] == DNRF_MAGIC
        && script[6] == DNRF_VERSION
}

/// Build the 39-byte OP_RETURN scriptPubKey that the miner appends
/// to the coinbase. `filter_hash` is the raw LE output of
/// `SHA256d(encoded_filter_data)`.
pub fn build_dnrf_script(filter_hash: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(2 + DNRF_DATA_SIZE as usize);
    s.push(0x6a);
    s.push(DNRF_DATA_SIZE);
    s.extend_from_slice(&DNRF_MAGIC);
    s.push(DNRF_VERSION);
    s.extend_from_slice(filter_hash);
    debug_assert_eq!(s.len(), 39);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn script_shape_matches_cpp() {
        let fh = [0xAB; 32];
        let s = build_dnrf_script(&fh);
        assert_eq!(s.len(), 39);
        assert_eq!(s[0], 0x6a);
        assert_eq!(s[1], 37);
        assert_eq!(&s[2..6], b"DNRF");
        assert_eq!(s[6], 0x01);
        assert_eq!(&s[7..], &fh);
    }

    #[test]
    fn is_dnrf_script_accepts_built_script() {
        let fh = [0xCD; 32];
        let s = build_dnrf_script(&fh);
        assert!(is_dnrf_script(&s));
    }

    #[test]
    fn is_dnrf_script_rejects_taproot_output() {
        // Standard Taproot scriptPubKey: OP_1 (0x51) + push32 (0x20) + 32 bytes
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xAA; 32]);
        assert!(!is_dnrf_script(&s));
    }

    #[test]
    fn is_dnrf_script_rejects_short_op_return() {
        // OP_RETURN with only 5 bytes of data — wrong length, wrong magic
        let s = vec![0x6a, 0x05, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        assert!(!is_dnrf_script(&s));
    }

    #[test]
    fn is_dnrf_script_rejects_wrong_version() {
        let mut s = build_dnrf_script(&[0xEF; 32]);
        s[6] = 0x02;
        assert!(!is_dnrf_script(&s));
    }

    /// DNRF output from regtest block 1 (same golden used in
    /// [`crate::block_filter`] tests).
    #[test]
    fn matches_regtest_block1_dnrf_output() {
        let fh = hex::decode(
            "dc86cb44925d230d276c79987a7207482bb6555a0a562388123bdc22f9a85500",
        )
        .unwrap();
        let mut fh32 = [0u8; 32];
        fh32.copy_from_slice(&fh);
        let s = build_dnrf_script(&fh32);
        assert_eq!(
            hex::encode(s),
            "6a25444e524601dc86cb44925d230d276c79987a7207482bb6555a0a562388123bdc22f9a85500"
        );
    }
}
