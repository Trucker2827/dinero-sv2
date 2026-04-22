//! Map dinerod's `getblocktemplate` JSON response to a
//! [`NewTemplateDinero`].
//!
//! Byte-order quirks (all empirically verified in Phase 1 Layer B):
//!
//! - `previousblockhash`, `utreexocommitment` are **display order** hex —
//!   the bytes are byte-reversed from what goes into the header. We
//!   reverse here before emitting.
//! - `coinbasetxn.txid` is display order; when `transactions` is empty the
//!   merkle root is the reversed txid.
//! - `bits` is compact-difficulty hex; parse as `u32` big-endian, store
//!   little-endian in the header.
//! - `curtime` is seconds since epoch as `u64`.
//! - `coinbase_outputs_commitment` is a Dinero-SV2 addition (not part of
//!   getblocktemplate) — we compute it here as `sha256d(coinbase_tx_data
//!   || concat_of_tx_hashes)`. For Phase 2.1 with empty mempools this is
//!   just `sha256d(coinbase_tx_data)`.

use anyhow::{anyhow, bail, Context, Result};
use dinero_sv2_common::{sha256d, NewTemplateDinero};
use serde_json::Value;

/// Translate a raw `getblocktemplate` JSON object into a
/// [`NewTemplateDinero`].
pub fn map_template(gbt: &Value, template_id: u64) -> Result<NewTemplateDinero> {
    let version = gbt.get("version").and_then(Value::as_u64).unwrap_or(1) as u32;

    let prev_display = gbt
        .get("previousblockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing previousblockhash"))?;
    let prev_block_hash = hex_reverse_32(prev_display)?;

    let utreexo_display = gbt
        .get("utreexocommitment")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing utreexocommitment"))?;
    let utreexo_root = hex_reverse_32(utreexo_display)?;

    let bits_hex = gbt
        .get("bits")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing bits"))?;
    let difficulty =
        u32::from_str_radix(bits_hex, 16).with_context(|| format!("parsing bits='{bits_hex}'"))?;

    let timestamp = gbt
        .get("curtime")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing curtime"))?;

    // Merkle root.
    // For Phase 2.1 we only handle the empty-transactions case: merkle
    // root is the reversed coinbase txid. Richer mempools arrive in the
    // JD / pool phases.
    let coinbase = gbt
        .get("coinbasetxn")
        .ok_or_else(|| anyhow!("missing coinbasetxn"))?;
    let txid_display = coinbase
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing coinbasetxn.txid"))?;
    let tx_list = gbt
        .get("transactions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if !tx_list.is_empty() {
        bail!(
            "Phase 2.1 cannot handle mempool transactions yet ({} present). \
             Re-run against a quiet mempool or a fresh regtest.",
            tx_list.len()
        );
    }
    let merkle_root = hex_reverse_32(txid_display)?;

    let coinbase_hex = coinbase
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing coinbasetxn.data"))?;
    let coinbase_bytes = hex::decode(coinbase_hex).context("coinbase.data hex")?;
    let coinbase_outputs_commitment = sha256d(&coinbase_bytes);

    Ok(NewTemplateDinero {
        template_id,
        future_template: false,
        version,
        prev_block_hash,
        merkle_root,
        utreexo_root,
        timestamp,
        difficulty,
        coinbase_outputs_commitment,
    })
}

fn hex_reverse_32(s: &str) -> Result<[u8; 32]> {
    let mut bytes = hex::decode(s).with_context(|| format!("hex '{s}'"))?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes, got {}", bytes.len());
    }
    bytes.reverse();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Real Phase-2-shaped template sample pulled from the Mac regtest
    /// daemon at height 5180 (captured live). The values are the ones we
    /// actually received on the wire.
    fn fixture() -> Value {
        json!({
            "version": 1,
            "previousblockhash": "00000062e5750d87588e0e7f0ebf6a9e46dc9ad99ca3a187fdeffe43d32593fb",
            "utreexocommitment": "9f950e6fa80f6fc089e540458684c7e4e642ba4738ec16d30be68639d3c543e0",
            "bits": "1e00806f",
            "curtime": 1_776_898_125u64,
            "coinbasetxn": {
                "data": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03023c14ffffffff0300e40b5402000000225120d09a7dccc98a44fb62121ee035cac4dcf69908a8b0c20be5aff2233adda99d420000000000000000276a25444e525701e2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf90000000000000000276a25444e524601bab3eaeaa70b996897460780718fd39be58802c6afe458c2ae8cffc7f37911230108000000000000000000000000",
                "txid": "cba515386b70fd686523b5ff1cc558e223ffd0776fadbed7b1396f4fba91a1f4"
            },
            "transactions": []
        })
    }

    #[test]
    fn maps_real_getblocktemplate_sample() {
        let gbt = fixture();
        let m = map_template(&gbt, 42).unwrap();

        assert_eq!(m.template_id, 42);
        assert_eq!(m.version, 1);
        assert_eq!(m.timestamp, 1_776_898_125);
        assert_eq!(m.difficulty, 0x1e00806f);

        // previousblockhash reversed:
        let expected_prev: [u8; 32] = {
            let mut v =
                hex::decode("00000062e5750d87588e0e7f0ebf6a9e46dc9ad99ca3a187fdeffe43d32593fb")
                    .unwrap();
            v.reverse();
            v.try_into().unwrap()
        };
        assert_eq!(m.prev_block_hash, expected_prev);

        // utreexocommitment reversed:
        let expected_utreexo: [u8; 32] = {
            let mut v =
                hex::decode("9f950e6fa80f6fc089e540458684c7e4e642ba4738ec16d30be68639d3c543e0")
                    .unwrap();
            v.reverse();
            v.try_into().unwrap()
        };
        assert_eq!(m.utreexo_root, expected_utreexo);

        // merkle root = reversed coinbase txid (no mempool txs):
        let expected_merkle: [u8; 32] = {
            let mut v =
                hex::decode("cba515386b70fd686523b5ff1cc558e223ffd0776fadbed7b1396f4fba91a1f4")
                    .unwrap();
            v.reverse();
            v.try_into().unwrap()
        };
        assert_eq!(m.merkle_root, expected_merkle);
    }

    #[test]
    fn rejects_missing_fields() {
        assert!(map_template(&json!({}), 0).is_err());
    }

    #[test]
    fn rejects_nonempty_mempool_for_now() {
        let mut gbt = fixture();
        gbt["transactions"] = json!([{ "txid": "deadbeef" }]);
        let err = map_template(&gbt, 0).unwrap_err().to_string();
        assert!(err.contains("Phase 2.1 cannot handle mempool"));
    }
}
