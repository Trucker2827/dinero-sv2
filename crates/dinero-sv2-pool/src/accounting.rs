//! In-memory share ledger keyed by the miner's Noise static public key.
//!
//! Phase 4 is deliberately ephemeral: credits reset on pool restart.
//! Persistence + real PPLNS scoring is Phase 4b once we see how real
//! miners actually connect (single-user home rigs? many anonymous
//! clients? known-identity worker pools?).

use std::collections::HashMap;
use std::sync::Mutex;

/// A miner identity: their Noise static public key (32 bytes). Anonymous
/// NX handshakes from miners that didn't bring a static key are keyed
/// by `[0u8; 32]` (they get bucketed together in Phase 4 — an explicit
/// TODO for Phase 4b auth).
pub type MinerKey = [u8; 32];

/// In-memory credit ledger.
#[derive(Debug, Default)]
pub struct Ledger {
    inner: Mutex<HashMap<MinerKey, Credit>>,
}

/// Per-miner credit tally.
#[derive(Debug, Clone, Copy, Default)]
pub struct Credit {
    /// Number of shares that met the pool's share target.
    pub accepted_shares: u64,
    /// Number of shares that ALSO met the block target (blocks found).
    pub found_blocks: u64,
    /// Number of shares rejected (bad shape, stale template, etc).
    pub rejected_shares: u64,
}

impl Ledger {
    /// Credit one accepted share.
    pub fn credit_share(&self, miner: MinerKey) {
        let mut g = self.inner.lock().expect("ledger mutex");
        g.entry(miner).or_default().accepted_shares += 1;
    }

    /// Credit one block (also implies the share that found it was
    /// already counted via `credit_share`).
    pub fn credit_block(&self, miner: MinerKey) {
        let mut g = self.inner.lock().expect("ledger mutex");
        g.entry(miner).or_default().found_blocks += 1;
    }

    /// Count one rejection.
    pub fn reject(&self, miner: MinerKey) {
        let mut g = self.inner.lock().expect("ledger mutex");
        g.entry(miner).or_default().rejected_shares += 1;
    }

    /// Snapshot of the whole ledger. Used by tests and the (future)
    /// ops endpoint; the `dinero-sv2-pool` binary doesn't call it yet
    /// but Phase 4b's persistence/payout code will.
    #[allow(dead_code)]
    pub fn snapshot(&self) -> HashMap<MinerKey, Credit> {
        self.inner.lock().expect("ledger mutex").clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_share_and_block_accumulates() {
        let l = Ledger::default();
        let m: MinerKey = [0x11; 32];
        l.credit_share(m);
        l.credit_share(m);
        l.credit_block(m);
        l.reject(m);
        let snap = l.snapshot();
        let c = snap[&m];
        assert_eq!(c.accepted_shares, 2);
        assert_eq!(c.found_blocks, 1);
        assert_eq!(c.rejected_shares, 1);
    }

    #[test]
    fn separate_miners_are_scored_separately() {
        let l = Ledger::default();
        let a: MinerKey = [0x01; 32];
        let b: MinerKey = [0x02; 32];
        l.credit_share(a);
        l.credit_share(a);
        l.credit_share(b);
        let snap = l.snapshot();
        assert_eq!(snap[&a].accepted_shares, 2);
        assert_eq!(snap[&b].accepted_shares, 1);
    }
}
