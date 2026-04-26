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
    /// Block height (from `getblocktemplate.height`).
    pub height: u32,
    /// Sum of the daemon's coinbase output values in `una`.
    pub coinbase_value_una: u64,
    /// Stripped-coinbase PREFIX extracted from the daemon's segwit
    /// coinbase bytes: version + input_count varint + the single
    /// coinbase input + sequence (everything before the output_count
    /// varint). Used verbatim by JD miners and by the pool on reassembly.
    pub coinbase_prefix: Vec<u8>,
    /// Stripped-coinbase SUFFIX: everything after the outputs section
    /// in the stripped serialization — typically 4 bytes of locktime.
    pub coinbase_suffix: Vec<u8>,
    /// The full witness section bytes from the daemon's segwit
    /// coinbase, needed to re-wrap the stripped form for
    /// `submitblock`.
    pub coinbase_witness_bytes: Vec<u8>,
    /// Merkle path from the coinbase leaf to the header merkle root.
    /// Empty for coinbase-only blocks (what Phase 5's MVP requires).
    pub merkle_path: Vec<[u8; 32]>,
    /// Coinbase txid in raw byte order (header merkle leaf for the
    /// coinbase). Cached so the mempool-fallback path can rebuild a
    /// coinbase-only `wire.merkle_root` without re-parsing.
    pub coinbase_txid_raw: [u8; 32],
    /// Mempool transactions to include after the coinbase, in GBT order.
    /// Empty in the coinbase-only case. When populated, the pool fetches
    /// inclusion proofs for each input via `getutxoproofs_batch` and
    /// applies them to `utreexo_pre_block` to produce
    /// `utreexo_pre_coinbase` — the state JD miners build their own
    /// coinbase on top of.
    pub mempool_txs: Vec<MempoolTx>,
}

/// One mempool tx: the daemon's serialized form + identity + the leaf
/// metadata for each output (so the pool can apply additions after
/// deletions, without re-parsing the wire bytes).
#[derive(Debug, Clone)]
pub struct MempoolTx {
    /// Raw segwit-form tx bytes from `getblocktemplate.transactions[i].data`.
    pub data: Vec<u8>,
    /// Stripped (non-segwit) `txid` in raw byte order — the merkle leaf.
    pub txid_raw: [u8; 32],
    /// Inputs: `(prev_txid_raw, vout)`. Used to fetch deletion proofs.
    pub inputs: Vec<([u8; 32], u32)>,
    /// Outputs: `(value_una, script_pubkey)`. Used to derive Utreexo
    /// leaf hashes for the additions step.
    pub outputs: Vec<(u64, Vec<u8>)>,
}

/// Parse a full (segwit-form) coinbase hex into its pieces:
///   (prefix, suffix, witness_bytes).
/// The "stripped" coinbase that hashes to the txid is exactly
/// `prefix || varint(output_count) || serialize(outputs) || suffix`
/// with no witness bytes in sight.
pub fn split_coinbase_segwit(hex_data: &str) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let bytes = hex::decode(hex_data).context("coinbase hex decode")?;
    let mut cur = 0usize;

    // version (4)
    let version_end = cur + 4;
    cur = version_end;

    // segwit marker+flag
    let has_witness = bytes.get(cur) == Some(&0x00) && bytes.get(cur + 1) == Some(&0x01);
    if has_witness {
        cur += 2;
    }
    let after_maybe_marker = cur;

    // input_count (varint)
    let (in_count, in_count_len) = read_compact_size(&bytes, cur)?;
    cur += in_count_len;

    // Walk inputs
    for _ in 0..in_count {
        cur += 36; // prevout (32 txid + 4 index)
        let (ss_len, ss_var_len) = read_compact_size(&bytes, cur)?;
        cur += ss_var_len;
        cur += ss_len as usize; // scriptSig
        cur += 4; // sequence
    }

    // PREFIX ends right here (before output_count). But note the
    // stripped form must skip the marker/flag; rebuild prefix from
    // version + everything from (after_maybe_marker) up to cur.
    let mut prefix = Vec::with_capacity(4 + (cur - after_maybe_marker));
    prefix.extend_from_slice(&bytes[..4]);
    prefix.extend_from_slice(&bytes[after_maybe_marker..cur]);

    // Walk outputs (we don't need the bytes, just to advance `cur`).
    let (out_count, out_count_len) = read_compact_size(&bytes, cur)?;
    cur += out_count_len;
    for _ in 0..out_count {
        cur += 8; // value
        let (s_len, s_var_len) = read_compact_size(&bytes, cur)?;
        cur += s_var_len;
        cur += s_len as usize;
    }

    // Witness section (if segwit): per-input witness stacks.
    let witness_start = cur;
    if has_witness {
        for _ in 0..in_count {
            let (stack_items, siv_len) = read_compact_size(&bytes, cur)?;
            cur += siv_len;
            for _ in 0..stack_items {
                let (item_len, iv_len) = read_compact_size(&bytes, cur)?;
                cur += iv_len;
                cur += item_len as usize;
            }
        }
    }
    let witness_end = cur;
    let witness_bytes = bytes[witness_start..witness_end].to_vec();

    // Suffix = locktime (4 bytes, last).
    if cur + 4 != bytes.len() {
        bail!(
            "coinbase parse trailing mismatch: cur={cur}+4 != len={}",
            bytes.len()
        );
    }
    let suffix = bytes[cur..cur + 4].to_vec();

    Ok((prefix, suffix, witness_bytes))
}

/// Read a Bitcoin CompactSize varint at `off`. Returns `(value, bytes_consumed)`.
fn read_compact_size(buf: &[u8], off: usize) -> Result<(u64, usize)> {
    if off >= buf.len() {
        bail!("compactsize out of range: off={off} len={}", buf.len());
    }
    let first = buf[off];
    if first < 0xFD {
        Ok((first as u64, 1))
    } else if first == 0xFD {
        if off + 3 > buf.len() {
            bail!("compactsize u16 truncated");
        }
        Ok((u16::from_le_bytes([buf[off + 1], buf[off + 2]]) as u64, 3))
    } else if first == 0xFE {
        if off + 5 > buf.len() {
            bail!("compactsize u32 truncated");
        }
        let v = u32::from_le_bytes([buf[off + 1], buf[off + 2], buf[off + 3], buf[off + 4]]);
        Ok((v as u64, 5))
    } else {
        if off + 9 > buf.len() {
            bail!("compactsize u64 truncated");
        }
        let mut a = [0u8; 8];
        a.copy_from_slice(&buf[off + 1..off + 9]);
        Ok((u64::from_le_bytes(a), 9))
    }
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

    // Phase 6: parse mempool txs into structured form. Their leaves
    // contribute to the merkle root alongside the coinbase. Their
    // inputs become Utreexo deletions and their outputs become Utreexo
    // additions, applied in `serve_miner` after fetching deletion
    // proofs via `getutxoproofs_batch`. Coinbase-only blocks collapse
    // through with an empty `mempool_txs` and unchanged behaviour.
    let mut mempool_txs: Vec<MempoolTx> = Vec::with_capacity(tx_list.len());
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(1 + tx_list.len());
    let coinbase_txid_raw = hex_reverse_32(txid_display)?;
    leaves.push(coinbase_txid_raw);
    for (i, t) in tx_list.iter().enumerate() {
        let tx_data_hex = t
            .get("data")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing transactions[{i}].data"))?;
        let txid_disp = t
            .get("txid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing transactions[{i}].txid"))?;
        let txid_raw = hex_reverse_32(txid_disp)?;
        leaves.push(txid_raw);
        let data_bytes = hex::decode(tx_data_hex)
            .with_context(|| format!("transactions[{i}].data hex"))?;
        let (inputs, outputs) = parse_segwit_tx_inputs_outputs(&data_bytes)
            .with_context(|| format!("transactions[{i}] parse"))?;
        mempool_txs.push(MempoolTx {
            data: data_bytes,
            txid_raw,
            inputs,
            outputs,
        });
    }
    let merkle_root = if leaves.len() == 1 {
        leaves[0]
    } else {
        compute_merkle_root_from_leaves(&leaves)
    };

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

    let height = gbt
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing height"))? as u32;
    let coinbase_value_una = gbt
        .get("coinbasevalue")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("missing coinbasevalue"))?;
    let (coinbase_prefix, coinbase_suffix, coinbase_witness_bytes) =
        split_coinbase_segwit(&coinbase_full_hex).context("split_coinbase_segwit")?;

    // Coinbase merkle path: walk the tree of `leaves` and collect the
    // right-siblings the coinbase sees on its way up. Empty for
    // coinbase-only.
    let merkle_path = if leaves.len() <= 1 {
        Vec::new()
    } else {
        coinbase_merkle_path(&leaves)
    };

    Ok(PoolTemplate {
        wire,
        coinbase_full_hex,
        block_target: compact_to_target(difficulty),
        utreexo_pre_block: None,
        height,
        coinbase_value_una,
        coinbase_prefix,
        coinbase_suffix,
        coinbase_witness_bytes,
        merkle_path,
        coinbase_txid_raw,
        mempool_txs,
    })
}

/// Walk the tx list (coinbase first, then mempool order) and compute
/// the same merkle root dinerod's GBT advertised. Bitcoin-style: odd
/// leaves duplicated at each level, parent = `sha256d(left || right)`.
fn compute_merkle_root_from_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
    debug_assert!(!leaves.is_empty());
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&left);
            cat[32..].copy_from_slice(&right);
            next.push(sha256d(&cat));
        }
        level = next;
    }
    level[0]
}

/// Coinbase-leaf merkle path: list of right-siblings the coinbase (leaf
/// 0) walks past on its way to the merkle root. Each level's sibling is
/// at index 1; promote pairs (last duplicated on odd levels) and repeat.
fn coinbase_merkle_path(leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut path: Vec<[u8; 32]> = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        // The coinbase sits at index 0 every level, so its sibling is
        // index 1 (or duplicate when level is just [coinbase]).
        let sibling = if level.len() >= 2 {
            level[1]
        } else {
            level[0]
        };
        path.push(sibling);

        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut cat = [0u8; 64];
            cat[..32].copy_from_slice(&left);
            cat[32..].copy_from_slice(&right);
            next.push(sha256d(&cat));
        }
        level = next;
    }
    path
}

/// Parse a segwit-form Bitcoin/Dinero tx into `(inputs, outputs)` where
/// inputs = `[(prev_txid_raw, vout), ...]` and outputs =
/// `[(value_una, script_pubkey_bytes), ...]`. Witness data, locktime,
/// and version are skipped — the pool re-emits the daemon's verbatim
/// `data` bytes for submitblock, so we only need the structured slices
/// we'll feed to Utreexo apply_deletions / leaf_hash.
fn parse_segwit_tx_inputs_outputs(
    bytes: &[u8],
) -> Result<(Vec<([u8; 32], u32)>, Vec<(u64, Vec<u8>)>)> {
    let mut cur = 0usize;
    if bytes.len() < 10 {
        bail!("tx too short ({} bytes)", bytes.len());
    }
    cur += 4; // version
    let has_witness = bytes.get(cur) == Some(&0x00) && bytes.get(cur + 1) == Some(&0x01);
    if has_witness {
        cur += 2;
    }
    let (in_count, n) = read_compact_size(bytes, cur)?;
    cur += n;
    let mut inputs: Vec<([u8; 32], u32)> = Vec::with_capacity(in_count as usize);
    for _ in 0..in_count {
        if cur + 36 > bytes.len() {
            bail!("input prevout overflow");
        }
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&bytes[cur..cur + 32]);
        cur += 32;
        let mut vout_arr = [0u8; 4];
        vout_arr.copy_from_slice(&bytes[cur..cur + 4]);
        let vout = u32::from_le_bytes(vout_arr);
        cur += 4;
        let (ss_len, n2) = read_compact_size(bytes, cur)?;
        cur += n2 + ss_len as usize;
        cur += 4; // sequence
        // dinerod's `getutxoproofs_batch` takes display-order txid, so
        // callers will reverse `prev_txid` before issuing the RPC. We
        // store raw here for symmetry with the rest of the codebase
        // ("raw is what consensus uses").
        inputs.push((prev_txid, vout));
    }
    let (out_count, n3) = read_compact_size(bytes, cur)?;
    cur += n3;
    let mut outputs: Vec<(u64, Vec<u8>)> = Vec::with_capacity(out_count as usize);
    for _ in 0..out_count {
        if cur + 8 > bytes.len() {
            bail!("output value overflow");
        }
        let mut val_arr = [0u8; 8];
        val_arr.copy_from_slice(&bytes[cur..cur + 8]);
        let value_una = u64::from_le_bytes(val_arr);
        cur += 8;
        let (spk_len, n4) = read_compact_size(bytes, cur)?;
        cur += n4;
        if cur + spk_len as usize > bytes.len() {
            bail!("output scriptpubkey overflow");
        }
        let spk = bytes[cur..cur + spk_len as usize].to_vec();
        cur += spk_len as usize;
        outputs.push((value_una, spk));
    }
    // We don't need to walk the witness section or locktime — the raw
    // `data` is preserved verbatim for submitblock.
    Ok((inputs, outputs))
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
            "height": 5180,
            "coinbasevalue": 10_000_000_000u64,
            "coinbasetxn": {
                // A full segwit coinbase: version + marker+flag + 1 input
                // + 1 output (trivial 0xAB×34 Taproot-shape script) +
                // 1 witness stack of a single 32-byte zero item + locktime.
                "data": concat!(
                    "01000000",                 // version
                    "0001",                     // segwit marker+flag
                    "01",                       // in_count
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "ffffffff",                 // prevout idx
                    "03", "023c14",             // scriptSig: push 2 bytes 0x3c14 = height 5180
                    "ffffffff",                 // sequence
                    "01",                       // out_count
                    "00e40b5402000000",         // value = 10000000000 una LE
                    "22", "5120",
                    "d09a7dccc98a44fb62121ee035cac4dcf69908a8b0c20be5aff2233adda99d42",
                    "01", "20",                 // witness: 1 item of 32 bytes
                    "0000000000000000000000000000000000000000000000000000000000000000",
                    "00000000"                  // locktime
                ),
                "txid": "cba515386b70fd686523b5ff1cc558e223ffd0776fadbed7b1396f4fba91a1f4"
            },
            "transactions": []
        })
    }

    #[test]
    fn maps_and_retains_coinbase_for_submit() {
        let pt = map_template(&fixture(), 42).unwrap();
        assert_eq!(pt.wire.difficulty, 0x1e00806f);
        assert_eq!(pt.height, 5180);
        assert_eq!(pt.coinbase_value_una, 10_000_000_000);
        assert!(!pt.coinbase_prefix.is_empty());
        assert_eq!(pt.coinbase_suffix, vec![0, 0, 0, 0]);
        // Witness bytes: 1-item stack of 32 bytes = 1 byte (stack_count)
        // + 1 byte (item_len=0x20) + 32 bytes payload = 34 bytes.
        assert_eq!(pt.coinbase_witness_bytes.len(), 34);
        // block_target consistency
        assert_eq!(
            hex::encode(pt.block_target),
            "000000806f000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn split_coinbase_roundtrip_simple() {
        // Minimal: stripped coinbase (no segwit), version=1, 1 input,
        // 1 output, locktime=0. prefix = version + 1 input; suffix = locktime.
        let hex_data = concat!(
            "01000000", // version
            "01",       // in_count
            "0000000000000000000000000000000000000000000000000000000000000000",
            "ffffffff", // prevout idx
            "03",
            "023c14",           // scriptSig
            "ffffffff",         // sequence
            "01",               // out_count
            "00e40b5402000000", // value
            "22",
            "5120",
            "d09a7dccc98a44fb62121ee035cac4dcf69908a8b0c20be5aff2233adda99d42",
            "00000000" // locktime
        );
        let (prefix, suffix, witness) = split_coinbase_segwit(hex_data).unwrap();
        assert_eq!(witness.len(), 0);
        assert_eq!(suffix, vec![0, 0, 0, 0]);
        // prefix = version(4) + in_count(1) + prev(36) + scriptSig varint(1) + scriptSig(3) + seq(4) = 49
        assert_eq!(prefix.len(), 4 + 1 + 36 + 1 + 3 + 4);
    }
}
