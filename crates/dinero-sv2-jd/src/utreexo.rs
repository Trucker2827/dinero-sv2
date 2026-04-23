//! Utreexo accumulator state and delta application (Phase 3b).
//!
//! The Utreexo accumulator is a forest of perfect binary trees whose
//! leaves are UTXO hashes. Adding `N` new leaves is `O(N log n)` and
//! requires only the current forest roots plus the total leaf count —
//! not the full UTXO set. That property is what makes miner-side
//! coinbase customization possible on a phone: the TP can ship a small
//! snapshot (at most `log₂(num_leaves)` 32-byte roots), the miner
//! applies its chosen coinbase outputs locally, and arrives at the
//! post-block root set.
//!
//! What this module DOES NOT do (scope for Phase 3c):
//!
//! - Implement Dinero's exact `utreexo_commitment` aggregation. The
//!   header field is a single 32-byte value; Dinero's dinerod folds
//!   the forest roots into one commitment by a specific algorithm
//!   defined in `include/consensus/utreexo_accumulator.h`. We expose
//!   a [`commitment_placeholder`] for testing wire roundtrips only —
//!   callers needing the real aggregation must link against the
//!   Dinero implementation (FFI via `bulletproofs_ffi`-style pattern)
//!   or port the C++ algorithm to Rust.
//!
//! - Compute Dinero's UTXO leaf hash from `(outpoint, value, script,
//!   height, is_coinbase, ...)`. That's also consensus-defined and
//!   belongs in the Dinero port. Callers pass 32-byte leaf hashes in.

use dinero_sv2_common::sha256d;

/// Snapshot of the forest that lets a miner apply its own coinbase
/// additions locally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtreexoAccumulatorState {
    /// Root of each perfect binary tree in the forest, ordered from
    /// smallest (roots[0]) to largest. Its length equals
    /// `num_leaves.count_ones()` — one root per 1-bit in the binary
    /// representation of `num_leaves`.
    pub forest_roots: Vec<[u8; 32]>,
    /// Total leaves added to the accumulator so far. Determines the
    /// shape of future additions (which existing trees will merge).
    pub num_leaves: u64,
}

/// Errors applying additions to the forest.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UtreexoError {
    /// Forest root count is inconsistent with `num_leaves`.
    #[error(
        "forest_roots.len()={roots} disagrees with num_leaves.count_ones()={popcount} for \
         num_leaves={num_leaves}"
    )]
    RootCountMismatch {
        /// `forest_roots.len()` on the input state.
        roots: usize,
        /// Total leaves on the input state.
        num_leaves: u64,
        /// What `forest_roots.len()` should be.
        popcount: usize,
    },
    /// `num_leaves` would overflow `u64` after applying the additions.
    #[error("num_leaves overflows u64 (current={current}, adding={adding})")]
    NumLeavesOverflow {
        /// Value of `num_leaves` on entry.
        current: u64,
        /// Leaves the caller asked us to add.
        adding: usize,
    },
}

impl UtreexoAccumulatorState {
    /// The empty forest: no leaves, no roots.
    pub fn empty() -> Self {
        Self {
            forest_roots: Vec::new(),
            num_leaves: 0,
        }
    }

    /// Validate the structural invariant: `forest_roots.len()` must
    /// equal `num_leaves.count_ones()`.
    pub fn validate(&self) -> Result<(), UtreexoError> {
        let popcount = self.num_leaves.count_ones() as usize;
        if self.forest_roots.len() != popcount {
            return Err(UtreexoError::RootCountMismatch {
                roots: self.forest_roots.len(),
                num_leaves: self.num_leaves,
                popcount,
            });
        }
        Ok(())
    }

    /// Apply one new leaf, updating `forest_roots` and `num_leaves`
    /// in-place.
    ///
    /// Algorithm: a leaf always enters at the lowest tree. If that
    /// slot is already occupied (bit 0 of `num_leaves` set), merge
    /// with the existing root by `sha256d(existing || new)` and carry
    /// up; keep merging while the carry bit is set. As each existing
    /// root is consumed we clear its bit in `num_leaves` so
    /// position-lookups for subsequent pops remain correct. At the
    /// end we set the bit for the target level; together these bit
    /// manipulations are equivalent to `num_leaves += 1` (binary
    /// carry propagation).
    pub fn add_leaf(&mut self, leaf: [u8; 32]) -> Result<(), UtreexoError> {
        if self.num_leaves == u64::MAX {
            return Err(UtreexoError::NumLeavesOverflow {
                current: self.num_leaves,
                adding: 1,
            });
        }
        let mut carry = leaf;
        let mut level = 0usize;
        while (self.num_leaves >> level) & 1 == 1 {
            let existing = pop_root_at_level(self, level);
            self.num_leaves &= !(1u64 << level);
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&existing);
            cat[32..].copy_from_slice(&carry);
            carry = sha256d(&cat);
            level += 1;
        }
        insert_root_at_level(self, level, carry);
        self.num_leaves |= 1u64 << level;
        Ok(())
    }

    /// Apply a batch of leaves.
    pub fn add_leaves(&mut self, leaves: &[[u8; 32]]) -> Result<(), UtreexoError> {
        let adding = leaves.len();
        if (u64::MAX - self.num_leaves) < adding as u64 {
            return Err(UtreexoError::NumLeavesOverflow {
                current: self.num_leaves,
                adding,
            });
        }
        for l in leaves {
            self.add_leaf(*l)?;
        }
        Ok(())
    }
}

/// Non-consensus placeholder aggregation over a forest snapshot.
///
/// This is `sha256d(root_0 || root_1 || ... || root_k || num_leaves_le)`.
/// DO NOT put this value into a block header; the real
/// `utreexo_commitment` aggregation is defined by dinerod's consensus
/// code and may differ. This function exists so the wire codec's
/// round-trip tests can make a deterministic "commitment" comparison.
pub fn commitment_placeholder(state: &UtreexoAccumulatorState) -> [u8; 32] {
    let mut buf = Vec::with_capacity(state.forest_roots.len() * 32 + 8);
    for r in &state.forest_roots {
        buf.extend_from_slice(r);
    }
    buf.extend_from_slice(&state.num_leaves.to_le_bytes());
    sha256d(&buf)
}

// ------------------------- internal root-slot helpers -------------------------

/// Given `level` (a tree height), find the index inside
/// `state.forest_roots` that currently holds the tree at that height
/// and remove it.
fn pop_root_at_level(state: &mut UtreexoAccumulatorState, level: usize) -> [u8; 32] {
    // Roots are stored smallest-first. The position of the `level`-th
    // root is the number of 1-bits in num_leaves below `level`.
    let idx = count_ones_below(state.num_leaves, level);
    state.forest_roots.remove(idx)
}

/// Insert a new root at a given tree height, preserving smallest-first
/// ordering.
fn insert_root_at_level(state: &mut UtreexoAccumulatorState, level: usize, root: [u8; 32]) {
    let idx = count_ones_below(state.num_leaves, level);
    state.forest_roots.insert(idx, root);
}

/// Number of 1-bits in `n` at positions strictly below `level`.
fn count_ones_below(n: u64, level: usize) -> usize {
    if level >= 64 {
        return n.count_ones() as usize;
    }
    let mask = (1u64 << level) - 1;
    (n & mask).count_ones() as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn empty_state_is_valid() {
        let s = UtreexoAccumulatorState::empty();
        assert!(s.validate().is_ok());
        assert_eq!(s.forest_roots.len(), 0);
        assert_eq!(s.num_leaves, 0);
    }

    #[test]
    fn add_one_leaf_produces_single_root() {
        let mut s = UtreexoAccumulatorState::empty();
        s.add_leaf(leaf(1)).unwrap();
        assert_eq!(s.num_leaves, 1);
        assert_eq!(s.forest_roots, vec![leaf(1)]);
    }

    #[test]
    fn add_two_leaves_merges_into_one_tree_of_height_1() {
        let mut s = UtreexoAccumulatorState::empty();
        s.add_leaf(leaf(1)).unwrap();
        s.add_leaf(leaf(2)).unwrap();
        assert_eq!(s.num_leaves, 2);
        assert_eq!(s.forest_roots.len(), 1);
        // Expected root is sha256d(leaf1 || leaf2)
        let mut cat = [0u8; 64];
        cat[..32].copy_from_slice(&leaf(1));
        cat[32..].copy_from_slice(&leaf(2));
        assert_eq!(s.forest_roots[0], sha256d(&cat));
    }

    #[test]
    fn add_three_leaves_produces_two_trees_height_1_and_0() {
        let mut s = UtreexoAccumulatorState::empty();
        s.add_leaves(&[leaf(1), leaf(2), leaf(3)]).unwrap();
        assert_eq!(s.num_leaves, 3);
        // num_leaves = 0b11, so two trees: one at height 0 (lonely
        // leaf), one at height 1 (merged pair). Smallest-first order
        // → [height-0, height-1].
        assert_eq!(s.forest_roots.len(), 2);
        assert_eq!(s.forest_roots[0], leaf(3));
        let mut cat = [0u8; 64];
        cat[..32].copy_from_slice(&leaf(1));
        cat[32..].copy_from_slice(&leaf(2));
        assert_eq!(s.forest_roots[1], sha256d(&cat));
    }

    #[test]
    fn add_four_leaves_produces_one_tree_of_height_2() {
        let mut s = UtreexoAccumulatorState::empty();
        s.add_leaves(&[leaf(1), leaf(2), leaf(3), leaf(4)]).unwrap();
        assert_eq!(s.num_leaves, 4);
        assert_eq!(s.forest_roots.len(), 1);

        // Expected: sha256d( sha256d(leaf1 || leaf2) || sha256d(leaf3 || leaf4) )
        let mut left = [0u8; 64];
        left[..32].copy_from_slice(&leaf(1));
        left[32..].copy_from_slice(&leaf(2));
        let left_root = sha256d(&left);

        let mut right = [0u8; 64];
        right[..32].copy_from_slice(&leaf(3));
        right[32..].copy_from_slice(&leaf(4));
        let right_root = sha256d(&right);

        let mut top = [0u8; 64];
        top[..32].copy_from_slice(&left_root);
        top[32..].copy_from_slice(&right_root);
        assert_eq!(s.forest_roots[0], sha256d(&top));
    }

    #[test]
    fn validate_rejects_mismatched_root_count() {
        let bad = UtreexoAccumulatorState {
            forest_roots: vec![leaf(1)],
            num_leaves: 3, // popcount=2 but only 1 root
        };
        assert!(matches!(
            bad.validate(),
            Err(UtreexoError::RootCountMismatch { .. })
        ));
    }

    #[test]
    fn placeholder_commitment_is_deterministic() {
        let mut s = UtreexoAccumulatorState::empty();
        s.add_leaves(&[leaf(1), leaf(2)]).unwrap();
        let c1 = commitment_placeholder(&s);
        let c2 = commitment_placeholder(&s);
        assert_eq!(c1, c2);
    }

    #[test]
    fn placeholder_commitment_differs_across_states() {
        let mut a = UtreexoAccumulatorState::empty();
        a.add_leaves(&[leaf(1), leaf(2)]).unwrap();
        let mut b = UtreexoAccumulatorState::empty();
        b.add_leaves(&[leaf(1), leaf(3)]).unwrap();
        assert_ne!(commitment_placeholder(&a), commitment_placeholder(&b));
    }

    #[test]
    fn count_ones_below_matches_reference() {
        // num_leaves = 0b1011 (11). Bits set below level=2 are bits 0, 1.
        assert_eq!(count_ones_below(0b1011, 2), 2);
        // Below level 0: none.
        assert_eq!(count_ones_below(0b1011, 0), 0);
        // Below level 4: all three below = 3.
        assert_eq!(count_ones_below(0b1011, 4), 3);
    }
}
