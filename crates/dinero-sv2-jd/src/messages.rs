//! Job Declaration message types.

/// Template for a miner that customizes its own coinbase outputs.
///
/// The TP/pool picks the tx set (so `merkle_path` is fixed); the miner
/// fills in the coinbase's output list with its own payout script and
/// any protocol-required commitments. The resulting coinbase txid is
/// used as the leaf for [`merkle::compute_root`](crate::merkle::compute_root)
/// to produce the header's `merkle_root`.
///
/// Wire framing is variable-length (see `crate::codec`); this type is
/// not the simple fixed-size `NewTemplateDinero` from Phase 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTemplateDineroJD {
    /// Monotonic per-session template id.
    pub template_id: u64,
    /// If true, template applies to the *next* tip.
    pub future_template: bool,
    /// Header field: block version (offset 0x00, 4 bytes LE).
    pub version: u32,
    /// Header field: previous block hash (offset 0x04, 32 bytes LE).
    pub prev_block_hash: [u8; 32],
    /// Header field: Utreexo accumulator root (offset 0x44, 32 bytes LE).
    ///
    /// **Phase 3 limitation:** this value is the TP's idea of the
    /// post-block utreexo_root assuming its own coinbase. If the miner
    /// alters the coinbase outputs in a way that changes the set of
    /// UTXOs created (i.e., changes the scriptPubKey of any output),
    /// this value is stale and the resulting block will not validate.
    /// A future phase must ship a utreexo-delta protocol so the miner
    /// can recompute locally.
    pub utreexo_root: [u8; 32],
    /// Header field: block timestamp (offset 0x64, 8 bytes LE, `u64`).
    pub timestamp: u64,
    /// Header field: compact difficulty target (offset 0x6C, 4 bytes LE).
    pub difficulty: u32,
    /// Raw coinbase bytes up to (but not including) the output count.
    ///
    /// For a standard coinbase: `version (4) || input_count=1 ||
    /// null_outpoint (36) || scriptSig_len (varint) || scriptSig ||
    /// input_sequence (4)`.
    pub coinbase_prefix: Vec<u8>,
    /// Raw coinbase bytes after the output list.
    ///
    /// For a standard coinbase: `locktime (4)`.
    pub coinbase_suffix: Vec<u8>,
    /// Merkle path from the coinbase leaf (tx index 0) to the root.
    ///
    /// Each entry is a right-sibling hash at the corresponding tree
    /// level, in raw (header-order) bytes. Empty for a coinbase-only
    /// block (merkle_root = coinbase_txid).
    pub merkle_path: Vec<[u8; 32]>,
}
