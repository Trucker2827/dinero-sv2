//! Pass-B: SV2-aligned handshake, channel-open, and share-result
//! messages.
//!
//! These complement the Phase-1 `NewTemplateDinero` /
//! `SubmitSharesDinero` shapes with the minimum logical-protocol
//! vocabulary SV2 tools expect to see:
//!
//! - `SetupConnection` pair: protocol / version / feature-flag
//!   negotiation between miner and pool (the "which SV2 dialect are we
//!   speaking" step).
//! - `OpenStandardMiningChannel` pair: the miner requests a mining
//!   channel; the pool assigns `channel_id` + initial target.
//! - `SubmitShares{Success,Error}`: replace the Phase-4 single-byte
//!   ACK with SV2-shaped structured responses.
//!
//! Field selections follow SV2 reasonably closely but drop parts we
//! don't need yet (e.g., `OpenStandardMiningChannelSuccess` has no
//! `extranonce_prefix` — Dinero's extranonce lives in the coinbase
//! witness, see Phase 3 notes; no `group_channel_id` — Pass B only
//! supports single-channel connections).

/// SV2 sub-protocol: 0 = Mining. Other values reserved for future
/// (Template Distribution, Job Declaration, Job Distribution).
pub const PROTOCOL_MINING: u8 = 0x00;

/// SV2 protocol version we implement.
pub const PROTOCOL_VERSION: u16 = 2;

/// Miner → pool: initial protocol / capability negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupConnection {
    /// Sub-protocol. `PROTOCOL_MINING` (0) for Pass B.
    pub protocol: u8,
    /// Minimum SV2 protocol version the miner supports.
    pub min_version: u16,
    /// Maximum SV2 protocol version the miner supports.
    pub max_version: u16,
    /// Feature-flag bitmap. Pass B accepts `flags == 0`.
    pub flags: u32,
    /// Free-form miner identification (≤ 255 bytes). Used by the pool
    /// for operator-facing logs; not authenticated.
    pub user_agent: Vec<u8>,
}

/// Pool → miner: negotiation succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupConnectionSuccess {
    /// Protocol version the two sides will speak (clamped to the
    /// miner's [min_version, max_version] range).
    pub used_version: u16,
    /// Feature flags the pool accepted (subset of miner's requested).
    pub flags: u32,
}

/// Pool → miner: negotiation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupConnectionError {
    /// Subset of the miner's requested flags that the pool does NOT
    /// support. Empty (= 0) for protocol-level rejections.
    pub flags: u32,
    /// Short error code string (≤ 255 bytes), e.g.
    /// `b"unsupported-protocol"`, `b"version-too-old"`.
    pub error_code: Vec<u8>,
}

/// Miner → pool: request a standard mining channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStandardMiningChannel {
    /// Miner-chosen id, echoed back in the success/error reply so the
    /// miner can correlate concurrent opens.
    pub request_id: u32,
    /// Free-form worker name / identity (≤ 255 bytes).
    pub user_identity: Vec<u8>,
    /// Nominal hashrate in H/s, IEEE-754 `f32` bit pattern. Stored as
    /// `u32` on the wire to avoid a float dependency in the codec.
    pub nominal_hash_rate_bits: u32,
    /// Highest target the miner is willing to accept. Pool replies with
    /// a target ≤ `max_target`.
    pub max_target: [u8; 32],
}

/// Pool → miner: channel granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStandardMiningChannelSuccess {
    /// Echo of the miner's `request_id`.
    pub request_id: u32,
    /// Pool-assigned channel id. Miner sends this in every subsequent
    /// `SubmitSharesDinero`.
    pub channel_id: u32,
    /// Per-miner share target (32-byte big-endian u256). Shares whose
    /// header hash is strictly less than `target` are credited.
    pub target: [u8; 32],
}

/// Pool → miner: channel open refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenStandardMiningChannelError {
    /// Echo of the miner's `request_id`.
    pub request_id: u32,
    /// Short error code string (≤ 255 bytes), e.g.
    /// `b"max-target-too-high"`.
    pub error_code: Vec<u8>,
}

/// Pool → miner: batched share acceptance.
///
/// SV2 allows the pool to ack many shares with one message (saves
/// bandwidth). Pass B sends one of these per accepted share for
/// simplicity; batching is a later optimization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSharesSuccess {
    /// Channel the ack applies to.
    pub channel_id: u32,
    /// Latest `sequence_number` observed from the miner on that
    /// channel.
    pub last_sequence_number: u32,
    /// Number of shares newly accepted since the previous Success
    /// message (1 in the non-batched Pass-B flow).
    pub new_submits_accepted_count: u32,
    /// Sum of share weights (for share-value accounting). Pass B uses
    /// share_count as the weight; precision matters only once payout
    /// logic lands in Phase 4b.
    pub new_shares_sum: u64,
}

/// Pool → miner: per-share rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSharesError {
    /// Channel the rejection applies to.
    pub channel_id: u32,
    /// The share's `sequence_number`.
    pub sequence_number: u32,
    /// Short error code string (≤ 255 bytes), e.g.
    /// `b"invalid-payload"`, `b"stale-share"`, `b"no-channel"`,
    /// `b"under-target"`.
    pub error_code: Vec<u8>,
}

/// Pool → miner: coinbase-construction context (Phase 5, Dinero
/// extension).
///
/// Carries the bytes and merkle position the miner needs to assemble
/// its own coinbase with its own payout outputs — then apply the
/// resulting UTXO leaves to the pre-block Utreexo state received
/// earlier. `coinbase_prefix` is everything up to (but not including)
/// the output_count varint; `coinbase_suffix` is everything after the
/// outputs (locktime, typically 4 zero bytes). `merkle_path` is the
/// sequence of right-sibling hashes from the coinbase leaf up to the
/// block's merkle root — empty when the block is coinbase-only.
///
/// Height and value are sent so the miner can cross-check the prefix
/// (BIP34 height encoding in scriptSig) and total-value allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseContext {
    /// Channel this applies to.
    pub channel_id: u32,
    /// Raw bytes from the start of the stripped coinbase serialization
    /// up to the output_count varint (not inclusive).
    pub coinbase_prefix: Vec<u8>,
    /// Raw bytes from after the outputs section to the end of the
    /// stripped coinbase (typically just the 4-byte locktime).
    pub coinbase_suffix: Vec<u8>,
    /// Right-sibling hashes from the coinbase leaf up to the root.
    /// Empty for a single-tx (coinbase-only) block.
    pub merkle_path: Vec<[u8; 32]>,
    /// Block height of the job (matches BIP34 height in scriptSig).
    pub height: u32,
    /// Total coinbase output value in `una` (block reward + fees).
    pub coinbase_value_una: u64,
}

/// Miner → pool: Job-Declaration share submission (Phase 5, Dinero
/// extension).
///
/// Identical to `SubmitSharesDinero` (channel/seq/job/nonce/ntime/ver)
/// plus the miner's chosen coinbase outputs. The pool reconstructs the
/// full share candidate:
///
/// 1. Assemble coinbase = `prefix || varint(|outputs|) || serialize(outputs) || suffix`
/// 2. `coinbase_txid = sha256d(coinbase_bytes)`
/// 3. For each output i: `leaf_i = leaf_hash(coinbase_txid, i, value, script)`
/// 4. `new_state = pre_block_state.add_leaves(&leaves)`, `utreexo_root =
///    commitment(&new_state)`
/// 5. `merkle_root = compute_root(coinbase_txid, &merkle_path)`
/// 6. Assemble 128-byte header with nonce/ntime/version + these
///    computed fields
/// 7. Hash = `sha256d(header)`, verify against share_target (and block_target)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmitSharesExtendedDinero {
    /// Mining channel on which the share was found.
    pub channel_id: u32,
    /// Monotonic share counter; replay prevention.
    pub sequence_number: u32,
    /// Which job on that channel (echoes NewMiningJob's template_id).
    pub job_id: u32,
    /// Header field: miner nonce.
    pub nonce: u32,
    /// Header field: block timestamp (u64 per Dinero).
    pub timestamp: u64,
    /// Header field: block version.
    pub version: u32,
    /// Miner-chosen coinbase outputs as `(value_una, script_pubkey)`
    /// tuples. Serialization order must match the miner's local
    /// coinbase assembly or the pool's recomputed hash will diverge.
    pub coinbase_outputs: Vec<CoinbaseOutputWire>,
}

/// Wire-shape for a single coinbase output. Lives in
/// `dinero-sv2-common` so the codec crate can decode it without
/// depending on `dinero-sv2-jd`. It's the same struct shape as
/// `dinero_sv2_jd::CoinbaseOutput`, just re-declared here to keep the
/// layering clean (sv2-jd can `impl From` both ways if needed later).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseOutputWire {
    /// Output value in `una`.
    pub value_una: u64,
    /// Raw scriptPubKey bytes.
    pub script_pubkey: Vec<u8>,
}

/// Pool → miner: retarget the channel's share difficulty.
///
/// Used by pool-side vardiff. The pool sizes `max_target` to the miner's
/// reported / measured hashrate so the miner produces ~1 share / 5 sec —
/// frequent enough to feel responsive in a UI, sparse enough to avoid
/// flooding the pool with shares from a fast GPU. Forward-compatible:
/// pre-vardiff clients that don't recognise the `MSG_SET_TARGET` opcode
/// log "unexpected frame type" and keep mining at their channel-open
/// target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetTarget {
    /// Channel the new target applies to.
    pub channel_id: u32,
    /// New 32-byte big-endian max_target. Hash ≤ this is a credited share.
    pub max_target: [u8; 32],
}

/// Pool → miner: tip changed.
///
/// Sent *before* the next `NewMiningJob`. Miners MUST treat any
/// in-flight share computation for the previous tip as invalidated —
/// further submits against it will be rejected as stale.
///
/// Dinero deviates from SV2's `SetNewPrevHash` in one field: `min_ntime`
/// is `u64` to match the Dinero header's 64-bit timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetNewPrevHash {
    /// Channel this applies to (must match the channel_id the miner
    /// opened).
    pub channel_id: u32,
    /// New tip hash (header offset 0x04, raw bytes, not display-order).
    pub prev_hash: [u8; 32],
    /// Minimum block timestamp the miner may use for jobs on this
    /// `prev_hash`. `u64` per Dinero's 8-byte `timestamp` field.
    pub min_ntime: u64,
    /// Compact difficulty target for jobs on this `prev_hash`.
    pub nbits: u32,
}
