//! Compact difficulty (`nBits`) → 256-bit target, plus hash-vs-target
//! comparison.
//!
//! Dinero uses Bitcoin's compact encoding verbatim:
//!   `target = mantissa * 2^(8 * (size - 3))`
//! where `size = bits >> 24` and `mantissa = bits & 0x00FFFFFF`.
//!
//! Targets are represented as 32-byte **big-endian** u256 arrays. Hashes
//! from [`dinero_sv2_common::HeaderAssembly::hash`] are likewise raw
//! `sha256d` bytes (Dinero's hash-display convention is "raw = display",
//! no Bitcoin-style reversal), so a plain `hash < target` lexicographic
//! comparison IS the correct big-endian u256 comparison.

/// Convert Bitcoin-style compact nBits to a 32-byte big-endian target.
pub fn compact_to_target(bits: u32) -> [u8; 32] {
    let size = (bits >> 24) as usize;
    let mantissa = bits & 0x00_FFFFFF;
    let mut target = [0u8; 32];

    if size == 0 || size > 32 {
        return target;
    }

    if size <= 3 {
        // Target fits in `size` bytes; mantissa is truncated from the top.
        let shift = (3 - size) * 8;
        let m = mantissa >> shift;
        let be = m.to_be_bytes(); // 4 bytes
        target[32 - size..].copy_from_slice(&be[4 - size..]);
    } else {
        // Mantissa is 3 bytes placed at offset (32 - size); trailing
        // positions stay zero.
        let offset = 32 - size;
        target[offset] = ((mantissa >> 16) & 0xFF) as u8;
        target[offset + 1] = ((mantissa >> 8) & 0xFF) as u8;
        target[offset + 2] = (mantissa & 0xFF) as u8;
    }

    target
}

/// Strict `hash < target` comparison (big-endian u256 semantics).
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    hash < target
}

/// Size a share target so a miner running at `hashrate_hps` produces
/// approximately one accepted share every `target_share_interval_secs`.
///
/// Math: P(hash ≤ T) = T / 2²⁵⁶, so expected hashes-per-share is
/// 2²⁵⁶ / T. We want hashes-per-share = hashrate × interval, so
/// T = 2²⁵⁶ / (hashrate × interval). Rather than build a 256-bit
/// arithmetic library, we compute the target's leading-zero bit count
/// — log2(hashrate × interval), rounded — and map it to the
/// `0..0 1..1` shape returned by [`leading_zero_bits_target`].
///
/// Clamp behaviour:
/// - non-finite or non-positive hashrate / interval → `0xFF…FF` (every
///   hash accepted; pool falls back to default sizing)
/// - hashrate × interval ≤ 1 → `0xFF…FF` (no extra zero bits required)
/// - log2 ≥ 256 → `0x00…00` (impossible target; clamps absurd input)
pub fn target_for_hashrate(hashrate_hps: f64, target_share_interval_secs: f64) -> [u8; 32] {
    if !hashrate_hps.is_finite() || hashrate_hps <= 0.0 {
        return [0xFFu8; 32];
    }
    if !target_share_interval_secs.is_finite() || target_share_interval_secs <= 0.0 {
        return [0xFFu8; 32];
    }
    let work_per_share = hashrate_hps * target_share_interval_secs;
    if work_per_share <= 1.0 {
        return [0xFFu8; 32];
    }
    let bits = work_per_share.log2().round() as i64;
    if bits <= 0 {
        [0xFFu8; 32]
    } else if bits >= 256 {
        [0u8; 32]
    } else {
        leading_zero_bits_target(bits as u32)
    }
}

/// Convenience: derive a "leading zero bits" target for share difficulty.
///
/// Returns a target where the top `bits` bits are zero and all lower
/// bits are 1. Any hash with at least `bits` leading zero bits will be
/// strictly less than this target.
pub fn leading_zero_bits_target(bits: u32) -> [u8; 32] {
    let mut target = [0xFFu8; 32];
    if bits == 0 {
        return target;
    }
    if bits >= 256 {
        return [0u8; 32];
    }
    let full = (bits / 8) as usize;
    let rem = (bits % 8) as u8;
    for b in target.iter_mut().take(full) {
        *b = 0;
    }
    if rem > 0 {
        target[full] = 0xFFu8 >> rem;
    }
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_matches_daemon_target_for_1e00806f() {
        // Observed live from getblocktemplate at height 5180:
        //   bits=0x1e00806f
        //   target="000000806f00...00"
        let target = compact_to_target(0x1e00806f);
        let hex_out = hex::encode(target);
        assert_eq!(
            hex_out,
            "000000806f000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn compact_for_genesis_v7_difficulty() {
        // v7 genesis: nBits=0x1d31ffce (per memory).
        // target = 0x31ffce * 2^(8 * (29 - 3))
        //        = mantissa 0x31 0xff 0xce at offset (32 - 29) = 3
        let target = compact_to_target(0x1d31ffce);
        assert_eq!(target[0..3], [0, 0, 0]);
        assert_eq!(target[3..6], [0x31, 0xff, 0xce]);
        assert_eq!(target[6..32], [0u8; 26]);
    }

    #[test]
    fn hash_meets_target_basic() {
        let target = compact_to_target(0x1e00806f);
        let mut hash = [0u8; 32];
        // All-zero hash is below any non-zero target.
        assert!(hash_meets_target(&hash, &target));
        // Flipping a high bit makes it larger than target.
        hash[0] = 0xFF;
        assert!(!hash_meets_target(&hash, &target));
    }

    #[test]
    fn leading_zero_bits_target_acceptance() {
        let t = leading_zero_bits_target(16);
        // First two bytes zero, third byte 0xFF, rest 0xFF.
        assert_eq!(&t[0..2], &[0, 0]);
        assert_eq!(t[2], 0xFF);

        // A hash with exactly 16 leading zeros and then a 1 bit —
        // byte 0 and 1 are zero, byte 2 is any value — should be less
        // than target if byte 2 ≤ 0xFE? Actually target has byte 2 =
        // 0xFF so any byte 2 value is <. Let's just test a clear
        // accept and clear reject.
        let mut hash_good = [0u8; 32];
        hash_good[2] = 0x00;
        assert!(hash_meets_target(&hash_good, &t));

        let mut hash_bad = [0u8; 32];
        hash_bad[0] = 0x01;
        assert!(!hash_meets_target(&hash_bad, &t));
    }

    #[test]
    fn leading_zero_bits_target_extremes() {
        // bits=0 → all 0xFF → anything meets
        let t0 = leading_zero_bits_target(0);
        assert_eq!(t0, [0xFFu8; 32]);
        // bits=256 → all 0 → nothing meets
        let t256 = leading_zero_bits_target(256);
        assert_eq!(t256, [0u8; 32]);
    }
}
