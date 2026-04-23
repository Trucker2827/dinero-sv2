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
