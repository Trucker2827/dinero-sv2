//! Dinero Stratum V2 — Job Declaration primitives.
//!
//! Phase 3 scope:
//!
//! - [`NewTemplateDineroJD`] — a template where the pool/TP provides
//!   coinbase fragments and a merkle path, and the *miner* assembles the
//!   coinbase with its own outputs (payout address, commitments).
//! - [`CoinbaseBuilder::build`] — glue the miner's outputs into the
//!   template's `coinbase_prefix` / `coinbase_suffix` and compute the
//!   resulting coinbase txid (stripped, pre-witness serialization).
//! - [`merkle::compute_root`] — climb `merkle_path` from the coinbase
//!   leaf to reconstruct the header's `merkle_root`.
//!
//! **Out of scope for Phase 3** (deferred to Phase 3b/4):
//!
//! - Utreexo root delta recomputation when miner changes coinbase
//!   outputs. Phase 3 treats `utreexo_root` from the template as-is; a
//!   real pool must either (a) supply a utreexo_root consistent with the
//!   miner-chosen outputs or (b) send the accumulator state plus a delta
//!   so the miner can recompute locally.
//! - Witness bytes / extranonce rolling. The stripped coinbase is enough
//!   for txid + merkle root; witness injection happens at block-submit
//!   time in the pool server (Phase 4).
//! - `DeclareMiningJob` / `ProvideMissingTransactions` for
//!   miner-declared *transaction sets* (full sovereignty). Phase 3 is
//!   miner-customize-coinbase only; txs are still TP-chosen.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod codec;
pub mod coinbase;
pub mod merkle;
pub mod messages;

pub use codec::{decode_new_template_jd, encode_new_template_jd, JdCodecError};
pub use coinbase::{assemble_stripped_coinbase, CoinbaseOutput, CoinbaseOutputs};
pub use merkle::{compute_root, MerkleError, MerklePath};
pub use messages::NewTemplateDineroJD;
