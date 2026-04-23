//! Miner-side coinbase assembly.
//!
//! The template from the pool carries `coinbase_prefix` and
//! `coinbase_suffix` as raw bytes. The miner assembles the output list
//! — a Bitcoin-style varint count followed by `(value_una(u64 LE) ||
//! script_pubkey_len(varint) || script_pubkey)` tuples — and sandwiches
//! it between prefix and suffix. The resulting bytes are the stripped
//! (pre-witness) coinbase serialization, and their `sha256d` is the
//! coinbase txid.
//!
//! Witness bytes (for Dinero's witness-based extranonce rolling, see
//! stratum V1 analysis) don't factor into txid and are added at block
//! submission time by the pool. Phase 3 doesn't cover witness handling.

use dinero_sv2_common::sha256d;

/// One coinbase output — value in `una` plus scriptPubKey bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinbaseOutput {
    /// Output value in the smallest Dinero unit.
    pub value_una: u64,
    /// Raw scriptPubKey bytes (e.g., Taproot `OP_1 <32-byte x-only>` or
    /// P2MR equivalent).
    pub script_pubkey: Vec<u8>,
}

/// A miner's chosen set of coinbase outputs, in order.
pub type CoinbaseOutputs = Vec<CoinbaseOutput>;

/// Assemble the stripped (pre-witness) coinbase serialization and
/// return `(bytes, txid_raw)`. `txid_raw` is the `sha256d` of the
/// bytes, in header / raw order (not display-reversed — Dinero's
/// hash convention is raw = display).
pub fn assemble_stripped_coinbase(
    coinbase_prefix: &[u8],
    outputs: &[CoinbaseOutput],
    coinbase_suffix: &[u8],
) -> (Vec<u8>, [u8; 32]) {
    let mut bytes = Vec::with_capacity(coinbase_prefix.len() + coinbase_suffix.len() + 64);
    bytes.extend_from_slice(coinbase_prefix);
    write_varint(&mut bytes, outputs.len() as u64);
    for out in outputs {
        bytes.extend_from_slice(&out.value_una.to_le_bytes());
        write_varint(&mut bytes, out.script_pubkey.len() as u64);
        bytes.extend_from_slice(&out.script_pubkey);
    }
    bytes.extend_from_slice(coinbase_suffix);
    let txid = sha256d(&bytes);
    (bytes, txid)
}

/// Encode a Bitcoin varint (compact size) in-place.
pub fn write_varint(buf: &mut Vec<u8>, n: u64) {
    if n < 0xFD {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&n.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_boundaries() {
        let mut b = Vec::new();
        write_varint(&mut b, 0);
        write_varint(&mut b, 0xFC);
        write_varint(&mut b, 0xFD);
        write_varint(&mut b, 0xFFFF);
        write_varint(&mut b, 0x10000);
        write_varint(&mut b, 0xFFFF_FFFF);
        write_varint(&mut b, 0x1_0000_0000);
        assert_eq!(
            hex::encode(&b),
            concat!(
                "00",                 // 0
                "fc",                 // 0xFC
                "fdfd00",             // 0xFD
                "fdffff",             // 0xFFFF
                "fe00000100",         // 0x10000
                "feffffffff",         // 0xFFFFFFFF
                "ff0000000001000000", // 0x100000000
            )
        );
    }

    #[test]
    fn single_output_txid_is_sha256d_of_bytes() {
        // Minimal synthetic coinbase: version=1, one null input (no
        // scriptSig / sequence=ffffffff), one output, locktime=0.
        //
        //   version:     01000000
        //   vin count:   01
        //   prevout:     00...00 ffffffff (36 bytes)
        //   scriptsig_len: 00
        //   sequence:    ffffffff
        //   ...output goes here...
        //   locktime:    00000000
        let prefix: Vec<u8> = [
            &1u32.to_le_bytes()[..],
            &[0x01],
            &[0u8; 36],
            &[0x00],
            &[0xFF, 0xFF, 0xFF, 0xFF],
        ]
        .concat();
        let suffix = vec![0, 0, 0, 0];

        let outputs = vec![CoinbaseOutput {
            value_una: 50_000_000_000,
            script_pubkey: vec![0xAA, 0xBB],
        }];

        let (bytes, txid) = assemble_stripped_coinbase(&prefix, &outputs, &suffix);
        assert_eq!(txid, sha256d(&bytes));
        // Spot-check the layout
        assert_eq!(&bytes[..4], &1u32.to_le_bytes());
        assert_eq!(bytes[prefix.len()], 1); // output count varint
    }
}
