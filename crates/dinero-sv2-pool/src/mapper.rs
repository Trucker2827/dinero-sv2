//! getblocktemplate → PoolTemplate.
//!
//! Like `dinero-tp::mapper` but retains fields needed at block-submit
//! time: the full coinbase hex (witness-included, as dinerod serves it)
//! and the decoded 256-bit block target.

use anyhow::{anyhow, bail, Context, Result};
use dinero_sv2_common::{sha256d, NewTemplateDinero};
use dinero_sv2_jd::UtreexoAccumulatorState;
use serde_json::Value;

use crate::target::compact_to_target;

/// Extended template retained inside the pool: wire message for the
/// miner + submission-side state the pool owns.
#[derive(Debug, Clone)]
pub struct PoolTemplate {
    /// Message broadcast to miners.
    pub wire: NewTemplateDinero,
    /// Full coinbase serialization (witness-included) as hex, ready to
    /// paste into a block for `submitblock`.
    pub coinbase_full_hex: String,
    /// Block target (32-byte big-endian u256) derived from
    /// `getblocktemplate.bits`.
    pub block_target: [u8; 32],
    /// Pre-coinbase Utreexo forest state (post-tip, pre-next-block).
    /// JD-aware miners apply their own coinbase's leaves to this to
    /// derive the header's final `utreexo_root`. Populated from
    /// `getutreexoroots` at template-emission time.
    pub utreexo_pre_block: Option<UtreexoAccumulatorState>,
}

/// Translate a `getblocktemplate` JSON object into a [`PoolTemplate`].
///
/// Phase 4 shares Phase 2.1 limits: rejects non-empty mempools; the
/// merkle root is `reverse(coinbase.txid)` (empty-path case only).
pub fn map_template(gbt: &Value, template_id: u64) -> Result<PoolTemplate> {
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

    let coinbase = gbt
        .get("coinbasetxn")
        .ok_or_else(|| anyhow!("missing coinbasetxn"))?;
    let txid_display = coinbase
        .get("txid")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing coinbasetxn.txid"))?;
    let coinbase_full_hex = coinbase
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("missing coinbasetxn.data"))?
        .to_string();

    let tx_list = gbt
        .get("transactions")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if !tx_list.is_empty() {
        bail!(
            "Phase 4 pool cannot handle mempool transactions yet ({} present). \
             Re-run against a quiet mempool or a fresh regtest.",
            tx_list.len()
        );
    }
    let merkle_root = hex_reverse_32(txid_display)?;

    let coinbase_bytes = hex::decode(&coinbase_full_hex).context("coinbase.data hex")?;
    let coinbase_outputs_commitment = sha256d(&coinbase_bytes);

    let wire = NewTemplateDinero {
        template_id,
        future_template: false,
        version,
        prev_block_hash,
        merkle_root,
        utreexo_root,
        timestamp,
        difficulty,
        coinbase_outputs_commitment,
    };

    Ok(PoolTemplate {
        wire,
        coinbase_full_hex,
        block_target: compact_to_target(difficulty),
        utreexo_pre_block: None,
    })
}

/// Parse `getutreexoroots` RPC response into a [`UtreexoAccumulatorState`].
/// The RPC returns roots in display-order hex; since Dinero's Utreexo
/// hashes are not byte-reversed for display (raw == display), we can
/// take them as-is.
pub fn map_utreexo_roots(json: &Value) -> Result<UtreexoAccumulatorState> {
    let num_leaves = json
        .get("num_leaves")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing num_leaves"))?;
    let roots_arr = json
        .get("roots")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("missing roots"))?;
    let mut forest_roots = Vec::with_capacity(roots_arr.len());
    for (i, v) in roots_arr.iter().enumerate() {
        let s = v
            .as_str()
            .ok_or_else(|| anyhow!("roots[{i}] is not a string"))?;
        let bytes = hex::decode(s).with_context(|| format!("roots[{i}] hex"))?;
        if bytes.len() != 32 {
            bail!("roots[{i}] is {} bytes, expected 32", bytes.len());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&bytes);
        forest_roots.push(a);
    }
    Ok(UtreexoAccumulatorState {
        forest_roots,
        num_leaves,
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

    fn fixture() -> Value {
        json!({
            "version": 1,
            "previousblockhash": "00000062e5750d87588e0e7f0ebf6a9e46dc9ad99ca3a187fdeffe43d32593fb",
            "utreexocommitment": "9f950e6fa80f6fc089e540458684c7e4e642ba4738ec16d30be68639d3c543e0",
            "bits": "1e00806f",
            "curtime": 1_776_898_125u64,
            "coinbasetxn": {
                "data": "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff03023c14ffffffff0300e40b5402000000225120d09a7dccc98a44fb62121ee035cac4dcf69908a8b0c20be5aff2233adda99d42000000000000000000",
                "txid": "cba515386b70fd686523b5ff1cc558e223ffd0776fadbed7b1396f4fba91a1f4"
            },
            "transactions": []
        })
    }

    #[test]
    fn maps_and_retains_coinbase_for_submit() {
        let pt = map_template(&fixture(), 42).unwrap();
        assert_eq!(pt.wire.difficulty, 0x1e00806f);
        assert_eq!(
            pt.coinbase_full_hex,
            fixture()["coinbasetxn"]["data"].as_str().unwrap()
        );
        // block_target is consistent with compact_to_target logic
        assert_eq!(
            hex::encode(pt.block_target),
            "000000806f000000000000000000000000000000000000000000000000000000"
        );
    }
}
