//! BIP158-style GCS block filter — Dinero "DNRF" variant.
//!
//! Byte-for-byte compatible with `src/consensus/block_filter.cpp` in
//! the dinero daemon. Two differences from vanilla BIP158:
//!
//! 1. The SipHash key is the first 16 bytes of the *previous* block
//!    hash in little-endian storage order. This avoids a circular
//!    dependency with the commitment the filter is being built for.
//! 2. OP_RETURN outputs are excluded by the caller (the daemon's
//!    block assembler filters `scriptPubKey[0] == 0x6a` before
//!    calling [`gcs_build`]). This module doesn't enforce that — it
//!    hashes exactly what you give it.
//!
//! Parameters (matching consensus/block_filter.h):
//!
//! - `P = 19`  Golomb-Rice parameter.
//! - `M = 784931`  false-positive denominator.
//!
//! The filter hash [`gcs_filter_hash`] is `SHA256d(encoded_data)`,
//! returned as raw bytes in little-endian (storage) order — exactly
//! the 32 bytes to splice into the DNRF commitment script.

use sha2::{Digest, Sha256};

/// Golomb-Rice P parameter.
pub const GCS_P: u8 = 19;
/// Golomb-Rice M parameter — false-positive denominator.
pub const GCS_M: u64 = 784_931;

/// SipHash-2-4 over `data` with 128-bit key `(k0, k1)`.
///
/// Matches `dinero::crypto::SipHash24` in
/// `include/crypto/siphash.h`.
pub fn siphash24(k0: u64, k1: u64, data: &[u8]) -> u64 {
    const C0: u64 = 0x736f6d65_70736575;
    const C1: u64 = 0x646f7261_6e646f6d;
    const C2: u64 = 0x6c796765_6e657261;
    const C3: u64 = 0x74656462_79746573;

    let mut v0 = C0 ^ k0;
    let mut v1 = C1 ^ k1;
    let mut v2 = C2 ^ k0;
    let mut v3 = C3 ^ k1;

    let full = data.len() / 8;
    for i in 0..full {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&data[i * 8..(i + 1) * 8]);
        let m = u64::from_le_bytes(buf);
        v3 ^= m;
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    let mut last: u64 = ((data.len() & 0xFF) as u64) << 56;
    let tail = &data[full * 8..];
    for (i, b) in tail.iter().enumerate() {
        last |= (*b as u64) << (8 * i);
    }

    v3 ^= last;
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    v2 ^= 0xFF;
    for _ in 0..4 {
        sipround(&mut v0, &mut v1, &mut v2, &mut v3);
    }

    v0 ^ v1 ^ v2 ^ v3
}

fn sipround(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Build a GCS filter over `scripts` keyed by `prev_block_hash_le`
/// (the 32 raw LE bytes of the prev block hash, i.e. the internal
/// storage order, *not* display-hex).
///
/// Returns `(encoded_data, element_count)`. The encoded data is the
/// raw Golomb-Rice byte stream with no length prefix. Empty input
/// (after dedupe + non-empty filter) returns `(vec![], 0)`.
pub fn gcs_build(prev_block_hash_le: &[u8; 32], scripts: &[&[u8]]) -> (Vec<u8>, u32) {
    let mut unique: Vec<Vec<u8>> = Vec::with_capacity(scripts.len());
    for s in scripts {
        if s.is_empty() {
            continue;
        }
        if unique.iter().all(|u| u.as_slice() != *s) {
            unique.push(s.to_vec());
        }
    }

    if unique.is_empty() {
        return (Vec::new(), 0);
    }

    let element_count = unique.len() as u32;

    let mut k0_bytes = [0u8; 8];
    k0_bytes.copy_from_slice(&prev_block_hash_le[0..8]);
    let k0 = u64::from_le_bytes(k0_bytes);
    let mut k1_bytes = [0u8; 8];
    k1_bytes.copy_from_slice(&prev_block_hash_le[8..16]);
    let k1 = u64::from_le_bytes(k1_bytes);

    let range = (element_count as u64).wrapping_mul(GCS_M);

    let mut hashed: Vec<u64> = Vec::with_capacity(unique.len());
    for s in &unique {
        let h = siphash24(k0, k1, s);
        let product = (h as u128).wrapping_mul(range as u128);
        hashed.push((product >> 64) as u64);
    }

    hashed.sort_unstable();

    let encoded = golomb_rice_encode(&hashed);
    (encoded, element_count)
}

/// Golomb-Rice encode sorted `values`: delta-encode then for each
/// delta write `unary(delta >> P) || bits(delta & (2^P - 1), P)`
/// MSB-first into a byte stream.
fn golomb_rice_encode(sorted_values: &[u64]) -> Vec<u8> {
    let mut w = BitWriter::default();
    let mut prev: u64 = 0;
    for &v in sorted_values {
        let delta = v - prev;
        prev = v;
        let q = delta >> GCS_P;
        let r = delta & ((1u64 << GCS_P) - 1);
        w.write_unary(q);
        w.write_bits(r, GCS_P as u32);
    }
    w.finish()
}

#[derive(Default)]
struct BitWriter {
    buf: Vec<u8>,
    current: u8,
    bits_written: u8,
}

impl BitWriter {
    fn write_bit(&mut self, bit: bool) {
        if bit {
            self.current |= 1 << (7 - self.bits_written);
        }
        self.bits_written += 1;
        if self.bits_written == 8 {
            self.buf.push(self.current);
            self.current = 0;
            self.bits_written = 0;
        }
    }

    fn write_bits(&mut self, value: u64, nbits: u32) {
        for i in (0..nbits).rev() {
            self.write_bit(((value >> i) & 1) == 1);
        }
    }

    fn write_unary(&mut self, value: u64) {
        for _ in 0..value {
            self.write_bit(true);
        }
        self.write_bit(false);
    }

    fn finish(mut self) -> Vec<u8> {
        if self.bits_written > 0 {
            self.buf.push(self.current);
        }
        self.buf
    }
}

/// `SHA256d(encoded_data)` returned as raw LE bytes — exactly what
/// the DNRF commitment script carries. For display-hex, reverse.
pub fn gcs_filter_hash(encoded_data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(encoded_data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vector extracted 2026-04-23 from a running regtest
    /// `dinerod` at block 1 via `blockchain.getblockfilters`.
    /// Sole non-OP_RETURN script in that block's coinbase was a
    /// 34-byte Taproot `5120a390f713…` output. Regtest genesis hash
    /// is `0000001c36…b76f` display-order, which means the LE
    /// storage-order bytes start with `6fb72815…`.
    #[test]
    fn regtest_block1_coinbase_only_filter() {
        let display_prev = "0000001c36abf27e2c233ff40ed0c08888926c24450f3bff82a047ae1528b76f";
        let mut prev_le = [0u8; 32];
        let display_bytes = hex::decode(display_prev).unwrap();
        for (i, b) in display_bytes.iter().rev().enumerate() {
            prev_le[i] = *b;
        }

        let script =
            hex::decode("5120a390f713ae65d0962512dcf28f0bc2c9026fce7a1613898c78bd84e9377382fb")
                .unwrap();

        let (encoded, n) = gcs_build(&prev_le, &[&script]);
        assert_eq!(n, 1, "element_count");
        assert_eq!(hex::encode(&encoded), "8e4ef0");

        let fh = gcs_filter_hash(&encoded);
        assert_eq!(
            hex::encode(fh),
            "dc86cb44925d230d276c79987a7207482bb6555a0a562388123bdc22f9a85500"
        );
    }

    #[test]
    fn siphash_known_vectors() {
        assert_eq!(siphash24(0, 0, &[]), 0x1e924b9d737700d7);
        let data = b"abc";
        let _ = siphash24(0x0706050403020100, 0x0f0e0d0c0b0a0908, data);
    }
}
