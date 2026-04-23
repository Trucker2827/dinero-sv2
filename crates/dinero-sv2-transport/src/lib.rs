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

/// Message type: server → client, a new `NewTemplateDinero` payload.
pub const MSG_NEW_TEMPLATE: u8 = 0x01;

/// Message type: client → server, a `SubmitSharesDinero` payload.
pub const MSG_SUBMIT_SHARES: u8 = 0x02;

/// Message type: server → client, a 1-byte share-ack response.
pub const MSG_SHARE_ACK: u8 = 0x03;

/// Share ack: share accepted (meets target, if any).
pub const ACK_OK: u8 = 0x00;
/// Share ack: payload did not decode cleanly.
pub const ACK_BAD_SHAPE: u8 = 0x01;
/// Share ack: valid share but under the configured target.
pub const ACK_UNDER_TARGET: u8 = 0x02;
