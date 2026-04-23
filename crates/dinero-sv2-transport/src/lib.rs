//! Dinero Stratum V2 — transport layer.
//!
//! Pass A (wire alignment) format: SV2-shaped framing over Noise NX.
//!
//! Outer length prefix (per-frame, both handshake and post-handshake):
//!
//! ```text
//! | 3 bytes: u24 LE frame length | frame bytes |
//! ```
//!
//! Post-handshake inner plaintext (inside the encrypted ChaChaPoly
//! payload) follows the SV2 message header:
//!
//! ```text
//! | 2 bytes: u16 LE ext_type | 1 byte: msg_type | 3 bytes: u24 LE msg_length | payload |
//! ```
//!
//! This is the structural-compatibility layer only. Logical-protocol
//! alignment (OpenStandardMiningChannel handshake, separate
//! SubmitSharesSuccess / SubmitSharesError messages, explicit
//! SetNewPrevHash) is Pass B.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod keys;
pub mod noise;

pub use keys::StaticKeys;
pub use noise::{Frame, NoiseSession, EXT_BASIC, NOISE_MAX_PAYLOAD};

// SV2-aligned message types. Numbers mirror the Stratum V2 spec's
// Common / Mining extension codes where applicable.

/// Common: `SetupConnection` (miner → pool).
pub const MSG_SETUP_CONNECTION: u8 = 0x00;
/// Common: `SetupConnection.Success` (pool → miner).
pub const MSG_SETUP_CONNECTION_SUCCESS: u8 = 0x01;
/// Common: `SetupConnection.Error` (pool → miner).
pub const MSG_SETUP_CONNECTION_ERROR: u8 = 0x02;

/// Mining: `OpenStandardMiningChannel` (miner → pool).
pub const MSG_OPEN_STANDARD_MINING_CHANNEL: u8 = 0x10;
/// Mining: `OpenStandardMiningChannel.Success` (pool → miner).
pub const MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS: u8 = 0x11;
/// Mining: `OpenStandardMiningChannel.Error` (pool → miner).
pub const MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR: u8 = 0x12;

/// Mining: `NewMiningJob` — carries a `NewTemplateDinero` payload
/// after channel-open completes (pool → miner).
pub const MSG_NEW_MINING_JOB: u8 = 0x15;

/// Mining: `SetNewPrevHash` — sent by pool to invalidate in-flight
/// work when the tip changes. Always precedes the next
/// [`MSG_NEW_MINING_JOB`] on that channel.
pub const MSG_SET_NEW_PREV_HASH: u8 = 0x20;

/// Mining (Dinero extension): `UtreexoStateAnnouncement` — pool
/// ships the **pre-coinbase** Utreexo forest state that miners need
/// to recompute the header's `utreexo_root` if they customize
/// coinbase outputs. Sent between [`MSG_SET_NEW_PREV_HASH`] and
/// [`MSG_NEW_MINING_JOB`].
pub const MSG_UTREEXO_STATE: u8 = 0x21;

/// Mining: `SubmitSharesStandard` (miner → pool). Payload is the
/// fixed-size `SubmitSharesDinero`.
pub const MSG_SUBMIT_SHARES_STANDARD: u8 = 0x1A;
/// Mining: `SubmitShares.Success` (pool → miner).
pub const MSG_SUBMIT_SHARES_SUCCESS: u8 = 0x1C;
/// Mining: `SubmitShares.Error` (pool → miner).
pub const MSG_SUBMIT_SHARES_ERROR: u8 = 0x1D;
