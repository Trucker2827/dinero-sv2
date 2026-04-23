//! Full-block assembly for `submitblock`.
//!
//! Given a retained [`PoolTemplate`](crate::mapper::PoolTemplate), a
//! share that meets block target, and the template's full-coinbase hex
//! (witness-included), produce the serialized block hex that dinerod
//! can validate and accept.
//!
//! Layout matches Dinero's serialization:
//!
//! ```text
//! | header (128 bytes) | tx_count (varint) | coinbase (as-is) | [txs...] |
//! ```
//!
//! Phase 4 refuses non-empty mempools (consistent with `mapper`), so
//! the block is always `header || 0x01 (varint) || coinbase`. A future
//! mempool-aware pool (Phase 5+) assembles the full tx list here.

use anyhow::{Context, Result};
use dinero_sv2_common::{HeaderAssembly, NewTemplateDinero, SubmitSharesDinero};

/// Serialize a found block as hex, ready for `submitblock`.
pub fn assemble_block_hex(
    template: &NewTemplateDinero,
    share: &SubmitSharesDinero,
    coinbase_full_hex: &str,
) -> Result<String> {
    let header = HeaderAssembly::bytes(template, share);
    let coinbase = hex::decode(coinbase_full_hex).context("coinbase hex")?;

    // tx_count varint: always 1 in Phase 4 (empty mempool).
    let varint = [0x01u8];

    let mut buf = Vec::with_capacity(header.len() + varint.len() + coinbase.len());
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&varint);
    buf.extend_from_slice(&coinbase);

    Ok(hex::encode(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_template() -> NewTemplateDinero {
        NewTemplateDinero {
            template_id: 1,
            future_template: false,
            version: 1,
            prev_block_hash: [0x11; 32],
            merkle_root: [0x22; 32],
            utreexo_root: [0x33; 32],
            timestamp: 1_776_384_000,
            difficulty: 0x1d_31_ff_ce,
            coinbase_outputs_commitment: [0x44; 32],
        }
    }

    fn fixture_share() -> SubmitSharesDinero {
        SubmitSharesDinero {
            channel_id: 1,
            sequence_number: 1,
            job_id: 1,
            nonce: 0xDEAD_BEEF,
            timestamp: 1_776_384_000,
            version: 1,
        }
    }

    #[test]
    fn assembles_header_varint_coinbase() {
        let cb_hex = "deadbeefcafe";
        let hex_out = assemble_block_hex(&fixture_template(), &fixture_share(), cb_hex).unwrap();
        let bytes = hex::decode(&hex_out).unwrap();
        assert_eq!(bytes.len(), 128 + 1 + 6);
        assert_eq!(&bytes[128..129], &[0x01]); // varint count
        assert_eq!(&bytes[129..], &hex::decode(cb_hex).unwrap()[..]);
    }
}
