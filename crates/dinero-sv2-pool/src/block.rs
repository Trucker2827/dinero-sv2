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

/// Serialize a found block as hex, ready for `submitblock`. Includes
/// the coinbase plus any mempool txs in their daemon-supplied order.
pub fn assemble_block_hex(
    template: &NewTemplateDinero,
    share: &SubmitSharesDinero,
    coinbase_full_hex: &str,
    mempool_tx_data: &[Vec<u8>],
) -> Result<String> {
    let coinbase = hex::decode(coinbase_full_hex).context("coinbase hex")?;
    assemble_block_hex_raw(template, share, &coinbase, mempool_tx_data)
}

/// Like [`assemble_block_hex`] but takes raw coinbase bytes. Used by
/// Phase-5 extended-share submission where the pool rebuilds the
/// coinbase on its own rather than using the daemon's verbatim hex.
pub fn assemble_block_hex_raw(
    template: &NewTemplateDinero,
    share: &SubmitSharesDinero,
    coinbase_bytes: &[u8],
    mempool_tx_data: &[Vec<u8>],
) -> Result<String> {
    let header = HeaderAssembly::bytes(template, share);
    let tx_count = 1 + mempool_tx_data.len();
    let varint = compact_size(tx_count as u64);
    let mempool_size: usize = mempool_tx_data.iter().map(|t| t.len()).sum();
    let mut buf = Vec::with_capacity(
        header.len() + varint.len() + coinbase_bytes.len() + mempool_size,
    );
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&varint);
    buf.extend_from_slice(coinbase_bytes);
    for t in mempool_tx_data {
        buf.extend_from_slice(t);
    }
    Ok(hex::encode(buf))
}

fn compact_size(n: u64) -> Vec<u8> {
    if n < 0xFD {
        vec![n as u8]
    } else if n <= 0xFFFF {
        let mut v = vec![0xFD];
        v.extend_from_slice(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xFFFF_FFFF {
        let mut v = vec![0xFE];
        v.extend_from_slice(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xFF];
        v.extend_from_slice(&n.to_le_bytes());
        v
    }
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
        let hex_out =
            assemble_block_hex(&fixture_template(), &fixture_share(), cb_hex, &[]).unwrap();
        let bytes = hex::decode(&hex_out).unwrap();
        assert_eq!(bytes.len(), 128 + 1 + 6);
        assert_eq!(&bytes[128..129], &[0x01]); // varint count
        assert_eq!(&bytes[129..], &hex::decode(cb_hex).unwrap()[..]);
    }

    #[test]
    fn assembles_header_varint_coinbase_with_mempool() {
        let cb = vec![0xCA, 0xFE];
        let tx1 = vec![0x11, 0x22, 0x33];
        let tx2 = vec![0xAA, 0xBB];
        let hex_out = assemble_block_hex_raw(
            &fixture_template(),
            &fixture_share(),
            &cb,
            &[tx1.clone(), tx2.clone()],
        )
        .unwrap();
        let bytes = hex::decode(&hex_out).unwrap();
        assert_eq!(bytes.len(), 128 + 1 + cb.len() + tx1.len() + tx2.len());
        assert_eq!(&bytes[128..129], &[0x03]); // 1 coinbase + 2 mempool
        let cb_end = 129 + cb.len();
        assert_eq!(&bytes[129..cb_end], &cb[..]);
        assert_eq!(&bytes[cb_end..cb_end + tx1.len()], &tx1[..]);
        assert_eq!(&bytes[cb_end + tx1.len()..], &tx2[..]);
    }
}
