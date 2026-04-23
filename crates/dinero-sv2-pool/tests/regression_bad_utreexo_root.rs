//! Regression test for the `submitblock` utreexo_root validator.
//!
//! ## What this test asserts
//!
//! A block submitted via `submitblock` whose header carries an
//! incorrect `utreexo_root` MUST be rejected. The rejection should
//! be `bad-utreexo-root`-shaped — NOT the old
//! `coinbase-modified-after-template` guard (removed in Dinero
//! `afbff521b`).
//!
//! ## Background
//!
//! When `afbff521b` removed the early template-root guard to let
//! SV2-JD miners land blocks with self-chosen coinbases, an
//! initial run of this test revealed the supposed canonical
//! backstop wasn't active on the submitblock path:
//! `BlockAcceptor::AcceptBlockFromRPC` called `ConnectBlock` with
//! `updateTip=false` (`src/daemon/block_acceptor.cpp:192`), and
//! the recompute-and-compare at `block_acceptor.cpp:1597-1636` was
//! gated on `updateTip=true`.
//!
//! Dinero's follow-up commit added an explicit
//! `ComputeUtreexoRootPure` → header-comparison step inside
//! `AcceptBlockFromRPC` before `ConnectBlock`, so the check now
//! runs synchronously for every externally-submitted block and
//! this test passes.
//!
//! ## Running
//!
//! `#[ignore]`'d so `cargo test` doesn't require dinerod on PATH.
//! Run explicitly with:
//!
//! ```sh
//! cargo test -p dinero-sv2-pool --test regression_bad_utreexo_root \
//!   -- --ignored --nocapture
//! ```
//!
//! Requires `~/src/dinero/build/dinerod` (override via the
//! `DINEROD_BIN` env var).

use anyhow::{bail, Context, Result};
use dinero_sv2_common::{HeaderAssembly, NewTemplateDinero, SubmitSharesDinero};
use dinero_sv2_pool::{
    block::assemble_block_hex,
    mapper::map_template,
    rpc::{Auth, RpcClient, SubmitBlockResult},
    target::hash_meets_target,
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Regtest dinerod lifecycle
// ---------------------------------------------------------------------------

/// Guard that kills the regtest dinerod on drop. `_datadir` is
/// retained so the tempdir path outlives the daemon for post-mortem
/// inspection if a test fails.
struct RegtestDaemon {
    child: Child,
    _datadir: PathBuf,
    rpc_url: String,
    cookie_path: PathBuf,
}

impl RegtestDaemon {
    fn spawn() -> Result<Self> {
        let binary = std::env::var("DINEROD_BIN").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{home}/src/dinero/build/dinerod")
        });
        if !Path::new(&binary).is_file() {
            bail!("dinerod binary not found at {binary}; set DINEROD_BIN");
        }

        // Unique datadir per test run. Using pid + nanos keeps parallel
        // test runs isolated.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let datadir =
            PathBuf::from(format!("/tmp/dinero-sv2-regression-{}-{nanos}", std::process::id()));
        if datadir.exists() {
            std::fs::remove_dir_all(&datadir).ok();
        }
        std::fs::create_dir_all(&datadir).context("mkdir datadir")?;

        // Pick a port that's very unlikely to collide with anything the
        // user has running. Full randomization would require binding a
        // probe socket first; not worth it for a one-off regression test.
        let port: u16 = 29_998;
        let rpc_url = format!("http://127.0.0.1:{port}");

        // Run dinerod in the foreground so `child` refers to the actual
        // daemon process. With `-daemon`, the immediate child is a
        // short-lived parent that forks the real daemon away, leaving
        // the test harness unable to stop it on drop.
        let child = Command::new(&binary)
            .arg("--regtest")
            .arg(format!("--datadir={}", datadir.display()))
            .arg("--rpc")
            .arg(format!("--rpcport={port}"))
            .arg("--rpcbind=127.0.0.1")
            .arg("--listen=0")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning dinerod")?;

        let cookie_path = datadir.join(".cookie");
        Ok(Self {
            child,
            _datadir: datadir,
            rpc_url,
            cookie_path,
        })
    }

    fn wait_for_cookie(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if self.cookie_path.exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        bail!("timed out waiting for cookie at {}", self.cookie_path.display())
    }
}

impl Drop for RegtestDaemon {
    fn drop(&mut self) {
        // Best-effort RPC stop, then SIGKILL as fallback. Never hard-kill
        // a daemon on a real chain — this is regtest in a tempdir, so
        // SIGKILL is fine if graceful shutdown stalls.
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Don't rm datadir on drop — keep it for post-mortem if the test
        // failed. Tempdir path is printed on spawn.
    }
}

// ---------------------------------------------------------------------------
// Block helpers
// ---------------------------------------------------------------------------

/// Nonce search against the regtest block target (`0x207fffff`).
///
/// The easiest regtest target has a ~50% hit rate per nonce so a
/// sequential scan from 0 almost always finds one inside a few tries.
fn find_nonce(
    wire: &NewTemplateDinero,
    share_template: &SubmitSharesDinero,
    target: &[u8; 32],
) -> Option<u32> {
    for nonce in 0u32..1_000_000 {
        let mut share = share_template.clone();
        share.nonce = nonce;
        let hash = HeaderAssembly::hash(wire, &share);
        if hash_meets_target(&hash, target) {
            return Some(nonce);
        }
    }
    None
}

fn make_share(wire: &NewTemplateDinero) -> SubmitSharesDinero {
    SubmitSharesDinero {
        channel_id: 0,
        sequence_number: 0,
        job_id: 0,
        nonce: 0,
        timestamp: wire.timestamp,
        version: wire.version,
    }
}

/// Wall-clock seconds since the UNIX epoch, clamped above `floor`
/// so the resulting timestamp beats `mintime` / median-time-past
/// on regtest even if the last block was minted milliseconds ago.
fn now_secs(floor: u64) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(floor);
    now.max(floor + 1)
}

// ---------------------------------------------------------------------------
// The test itself
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "spawns regtest dinerod; run with --ignored"]
async fn submitblock_rejects_tampered_utreexo_root() -> Result<()> {
    let daemon = RegtestDaemon::spawn().context("spawn regtest dinerod")?;
    daemon.wait_for_cookie().context("wait for cookie")?;

    let rpc = RpcClient::new(
        daemon.rpc_url.clone(),
        Auth::Cookie(daemon.cookie_path.display().to_string()),
    )?;

    // Create a regtest wallet so we have an address to mine to.
    let create = rpc
        .call_raw("wallet.createhd", serde_json::json!(["regtestw", "", false]))
        .await
        .context("createhd")?;
    let address = create
        .get("first_address")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("createhd did not return first_address: {create}"))?
        .to_string();

    // Seed one block so we're past the genesis edge cases and have
    // a non-trivial Utreexo state to compute against.
    let _ = rpc
        .call_raw(
            "generatetoaddress",
            serde_json::json!([1u32, address.clone()]),
        )
        .await
        .context("generatetoaddress 1")?;

    // --- Positive baseline: a valid block mined through the same
    //     codepath the pool uses. If THIS fails, the test harness is
    //     broken; no point asserting rejection behavior.
    let gbt_ok = rpc
        .get_block_template(&address)
        .await
        .context("getblocktemplate (positive)")?;
    let mut pt_ok = map_template(&gbt_ok, 1).context("map_template (positive)")?;
    // Bump the template timestamp past MTP. dinerod rejects blocks whose
    // header timestamp isn't strictly greater than the median time past;
    // GBT's `curtime` can be equal to the last seed block's timestamp on
    // a just-spun-up regtest chain.
    let mintime = gbt_ok
        .get("mintime")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(pt_ok.wire.timestamp);
    pt_ok.wire.timestamp = now_secs(mintime);
    let share_tmpl = make_share(&pt_ok.wire);
    let nonce_ok = find_nonce(&pt_ok.wire, &share_tmpl, &pt_ok.block_target)
        .ok_or_else(|| anyhow::anyhow!("no nonce found for valid block"))?;
    let mut share_ok = share_tmpl.clone();
    share_ok.nonce = nonce_ok;
    let block_hex_ok = assemble_block_hex(&pt_ok.wire, &share_ok, &pt_ok.coinbase_full_hex)?;
    match rpc.submit_block(&block_hex_ok).await? {
        SubmitBlockResult::Accepted => {}
        SubmitBlockResult::Rejected(r) => {
            bail!("baseline valid block was unexpectedly rejected: {r}")
        }
    }

    // --- Negative case: rebuild against the NEW tip, then tamper the
    //     header's utreexo_root before mining + submitting. Everything
    //     else (coinbase, merkle root, PoW) stays consistent. We expect
    //     BlockAcceptor::ConnectBlock to recompute the correct root
    //     from the coinbase and reject with `bad-utreexo-root`.
    let gbt_bad = rpc
        .get_block_template(&address)
        .await
        .context("getblocktemplate (tampered)")?;
    let mut pt_bad = map_template(&gbt_bad, 2).context("map_template (tampered)")?;
    let mintime_bad = gbt_bad
        .get("mintime")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(pt_bad.wire.timestamp);
    pt_bad.wire.timestamp = now_secs(mintime_bad);
    let mut tampered_wire = pt_bad.wire.clone();
    tampered_wire.utreexo_root[0] ^= 0xFF; // flip one byte — guaranteed wrong

    let share_tmpl_bad = make_share(&tampered_wire);
    let nonce_bad = find_nonce(&tampered_wire, &share_tmpl_bad, &pt_bad.block_target)
        .ok_or_else(|| anyhow::anyhow!("no nonce found for tampered block"))?;
    let mut share_bad = share_tmpl_bad.clone();
    share_bad.nonce = nonce_bad;
    let block_hex_bad =
        assemble_block_hex(&tampered_wire, &share_bad, &pt_bad.coinbase_full_hex)?;

    let rejection = match rpc.submit_block(&block_hex_bad).await? {
        SubmitBlockResult::Accepted => {
            bail!(
                "tampered block with bad utreexo_root was ACCEPTED by dinerod — \
                 the canonical validator in ConnectBlock is no longer catching \
                 utreexo_root mismatches"
            )
        }
        SubmitBlockResult::Rejected(r) => r,
    };

    // The daemon no longer emits `coinbase-modified-after-template`
    // for this case (that early guard was deleted). It emits
    // `bad-utreexo-root` from ConnectBlock instead.
    let lower = rejection.to_lowercase();
    assert!(
        !lower.contains("coinbase-modified-after-template"),
        "rejection still cites the removed early guard: {rejection}",
    );
    assert!(
        lower.contains("utreexo"),
        "expected a utreexo-flavored rejection, got: {rejection}",
    );

    // Chain should still be at height 2 (the positive block we mined).
    // The tampered submit must not have silently landed.
    let tip = rpc
        .call_raw("getblockcount", serde_json::json!([]))
        .await
        .context("getblockcount")?;
    assert_eq!(
        tip.as_u64(),
        Some(2),
        "chain tip advanced past the valid block — tampered block sneaked in"
    );

    Ok(())
}

/// Companion test — tampered `utreexo_root` submitted as a
/// **side-chain** block (parent != current tip).
///
/// Background. The first accept-time fix in Dinero `a3c9fd839`
/// gated the utreexo check on `isMainChainExtension`, so
/// side-chain blocks skipped it. That was a disk/DoS vector
/// (tampered blocks stored on disk even though ConnectTip's
/// reorg-time backstop refused to activate them).
///
/// The follow-up fix adds `ComputeUtreexoRootPureFromForest` to
/// `BlockValidator` and uses it in `AcceptBlockFromRPC` for the
/// common case: side-chain blocks that are coinbase-only and
/// whose parent is in the main chain at a known height. The
/// daemon loads the saved utreexo checkpoint at the parent's
/// height (`chain_db->getUtreexoCheckpoint`), re-applies the
/// block's coinbase outputs, and compares to the header root.
///
/// Still deferred to the reorg-time backstop:
///   - Multi-tx side-chain blocks (would need a fork-aware UTXO
///     lookup — the live `consensus_utxo_set_` may have spent
///     or never had outputs the side chain is spending).
///   - Side-chain blocks whose parent is itself on a fork
///     (no checkpoint available cheaply).
///
/// What this test asserts: a coinbase-only side-chain block
/// with a tampered `utreexo_root` is rejected at accept time,
/// not silently stored.
///
/// Flow:
///   1. Before seeding, capture a template built on genesis.
///   2. Seed one block so the captured template's parent
///      becomes a non-tip ancestor (side-chain relative to the
///      new main tip).
///   3. Build the side-chain block from the captured template
///      with a tampered `utreexo_root`.
///   4. Submit. Expect rejection with a utreexo-flavored error.
#[tokio::test]
#[ignore = "spawns regtest dinerod; run with --ignored"]
async fn side_chain_tampered_utreexo_root() -> Result<()> {
    let daemon = RegtestDaemon::spawn().context("spawn regtest dinerod")?;
    daemon.wait_for_cookie().context("wait for cookie")?;

    let rpc = RpcClient::new(
        daemon.rpc_url.clone(),
        Auth::Cookie(daemon.cookie_path.display().to_string()),
    )?;

    let create = rpc
        .call_raw("wallet.createhd", serde_json::json!(["regtestw", "", false]))
        .await
        .context("createhd")?;
    let address = create
        .get("first_address")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("createhd did not return first_address: {create}"))?
        .to_string();

    // 1. Capture a pre-seed template. Its parent is genesis; its
    //    height is 1. Using this template AFTER generatetoaddress
    //    below yields a side-chain submission (same height as the
    //    seed, different parent reference since the seed's prev IS
    //    genesis too but different coinbase/hash — so B1 is a
    //    competing height-1 block).
    let gbt_side = rpc
        .get_block_template(&address)
        .await
        .context("getblocktemplate (pre-seed)")?;
    let mut pt_side = map_template(&gbt_side, 0).context("map_template side")?;

    // 2. Seed one block so the chain advances past genesis and the
    //    captured template's parent is no longer the main tip.
    //    (Strictly speaking, after seeding the tip IS a height-1
    //    block whose parent is genesis, same as our B1. The check
    //    at block_acceptor.cpp:146 compares `block.prevBlockHash
    //    == tip.hash`, which is false here because B1's prev is
    //    genesis but the current tip is the seed block.)
    let _ = rpc
        .call_raw(
            "generatetoaddress",
            serde_json::json!([1u32, address.clone()]),
        )
        .await
        .context("generatetoaddress 1")?;

    // Refresh timestamp past current MTP.
    let mintime = gbt_side
        .get("mintime")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(pt_side.wire.timestamp);
    pt_side.wire.timestamp = now_secs(mintime);

    // 3. Tamper the utreexo_root.
    let mut tampered = pt_side.wire.clone();
    tampered.utreexo_root[0] ^= 0xFF;

    let share_tmpl = make_share(&tampered);
    let nonce = find_nonce(&tampered, &share_tmpl, &pt_side.block_target)
        .ok_or_else(|| anyhow::anyhow!("no nonce found for tampered side-chain block"))?;
    let mut share = share_tmpl.clone();
    share.nonce = nonce;
    let block_hex = assemble_block_hex(&tampered, &share, &pt_side.coinbase_full_hex)?;

    // 4. Submit. Record outcome.
    let outcome = rpc.submit_block(&block_hex).await?;

    match outcome {
        SubmitBlockResult::Rejected(reason) => {
            let lower = reason.to_lowercase();
            eprintln!("side-chain tampered block rejected at accept time: {reason}");
            // Whatever the exact reason, this is safe: a block with
            // a known-bad utreexo_root did not reach storage. The
            // bad-utreexo-root string is ideal (proves the utreexo
            // check actively fired) but any rejection is fine.
            assert!(
                !lower.contains("coinbase-modified-after-template"),
                "rejection still cites the removed early guard: {reason}",
            );
            Ok(())
        }
        SubmitBlockResult::Accepted => {
            // Kept as a belt-and-suspenders path in case the
            // fork-aware check ever regresses: the test will at
            // least fail loudly rather than silently passing.
            eprintln!(
                "side-chain tampered block was ACCEPTED at submit time — \
                 daemon has stored a block with a known-bad utreexo_root"
            );

            // Compute our tampered block's hash so we can tell
            // whether it became tip or is merely sitting in
            // side-chain storage.
            let tampered_hash = HeaderAssembly::hash(&tampered, &share);
            let tampered_hash_display = {
                let mut v = tampered_hash;
                v.reverse();
                hex::encode(v)
            };
            eprintln!("our tampered block hash = {tampered_hash_display}");

            let tip_before = rpc
                .call_raw("getbestblockhash", serde_json::json!([]))
                .await
                .context("getbestblockhash (pre-reorg)")?;
            let tip_before_str = tip_before.as_str().unwrap_or("").to_string();
            eprintln!("tip BEFORE reorg attempt: {tip_before_str}");

            // Probe the reorg-time backstop. Invalidate the current
            // tip so the daemon must choose another best chain; if
            // our tampered block is the only other candidate at
            // height 1, ConnectTip will try to activate it, hitting
            // `block_validator_->ConnectBlock → ValidateAndApplyBlock`
            // at chainstate_service.cpp:8290. That path is supposed
            // to catch the root mismatch via
            // ConnectBlockInternal(verify_root=true).
            //
            // After invalidate, one of:
            //   a) tip = genesis   — reorg refused to activate the
            //                        tampered block. Backstop works.
            //                        Latent side-chain storage is
            //                        harmless in practice.
            //   b) tip = tampered  — daemon activated a block with
            //                        a known-bad utreexo_root.
            //                        Reorg-time backstop broken;
            //                        mainnet safety gap.
            let _ = rpc
                .call_raw(
                    "invalidateblock",
                    serde_json::json!([tip_before_str]),
                )
                .await
                .context("invalidateblock")?;

            // ActivateBestChain runs synchronously inside the
            // invalidateblock handler, but give it a moment to
            // settle just in case.
            tokio::time::sleep(Duration::from_millis(500)).await;

            let tip_after = rpc
                .call_raw("getbestblockhash", serde_json::json!([]))
                .await
                .context("getbestblockhash (post-reorg)")?;
            let tip_after_str = tip_after.as_str().unwrap_or("").to_string();
            eprintln!("tip AFTER invalidateblock:  {tip_after_str}");

            if tip_after_str == tampered_hash_display {
                bail!(
                    "GAP CONFIRMED: tampered utreexo_root block activated \
                     as chain tip via reorg. ConnectTip's verify_root=true \
                     did not catch the mismatch. See \
                     src/consensus/block_validation.cpp:1668-1705 and \
                     src/daemon/services/chainstate_service.cpp:8290."
                )
            }

            // Reorg refused to activate; tampered block is only
            // in side-chain storage. Document and keep the test
            // failing so the acceptance-time gap doesn't silently
            // reopen — even though reorg-time is a functional
            // backstop, defense-in-depth at accept time is the
            // user's explicit preference.
            bail!(
                "side-chain tampered block accepted into storage \
                 (not activated as tip — reorg backstop held). \
                 Still a gap: a block with a known-bad utreexo_root \
                 shouldn't reach on-disk storage in the first place. \
                 Fix site: block_acceptor.cpp AcceptBlockFromRPC \
                 step 5.6 — extend the check to cover side-chain \
                 blocks (or add a step 5.7 using the fork-aware \
                 forest walk)."
            )
        }
    }
}
