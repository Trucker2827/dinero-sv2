//! Merkle path evaluation for the coinbase leaf.
//!
//! Dinero's merkle tree follows Bitcoin's layout: a binary tree of
//! `sha256d` hashes, leaves in txid order, last leaf duplicated on odd
//! levels. The coinbase is always `tx_index = 0`, so walking upward
//! means always concatenating `current || sibling` — the coinbase is
//! perpetually a left child.
//!
//! Note: Dinero stores the raw `sha256d` bytes as the header merkle
//! root (no byte-reversal, unlike Bitcoin display hashes). This module
//! therefore operates exclusively in raw byte order.

use dinero_sv2_common::sha256d;

/// Thin alias so callers don't have to spell the type out every time.
pub type MerklePath = Vec<[u8; 32]>;

/// Merkle computation errors.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    /// Not applicable yet — reserved for future path-position validation
    /// when we support non-coinbase leaves.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
}

/// Compute the header `merkle_root` from the coinbase txid and a merkle
/// path of right siblings.
///
/// Empty `path` → root is the leaf itself (single-tx block).
pub fn compute_root(coinbase_txid: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = coinbase_txid;
    for sibling in path {
        let mut cat = [0u8; 64];
        cat[..32].copy_from_slice(&acc);
        cat[32..].copy_from_slice(sibling);
        acc = sha256d(&cat);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_path_returns_leaf() {
        let leaf = [0x42u8; 32];
        assert_eq!(compute_root(leaf, &[]), leaf);
    }

    #[test]
    fn single_sibling_matches_manual_hash() {
        let leaf = [0x11u8; 32];
        let sib = [0x22u8; 32];
        let mut cat = [0u8; 64];
        cat[..32].copy_from_slice(&leaf);
        cat[32..].copy_from_slice(&sib);
        let expected = sha256d(&cat);
        assert_eq!(compute_root(leaf, &[sib]), expected);
    }

    #[test]
    fn two_levels_chain_correctly() {
        // leaf -> sib_a -> sib_b
        let leaf = [0x01u8; 32];
        let a = [0x02u8; 32];
        let b = [0x03u8; 32];

        let mut level0 = [0u8; 64];
        level0[..32].copy_from_slice(&leaf);
        level0[32..].copy_from_slice(&a);
        let after_a = sha256d(&level0);

        let mut level1 = [0u8; 64];
        level1[..32].copy_from_slice(&after_a);
        level1[32..].copy_from_slice(&b);
        let expected = sha256d(&level1);

        assert_eq!(compute_root(leaf, &[a, b]), expected);
    }
}
