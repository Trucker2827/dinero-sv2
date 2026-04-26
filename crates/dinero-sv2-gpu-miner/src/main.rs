//! Dinero Stratum V2 GPU miner (Metal backend).
//!
//! Speaks Noise NX + SV2 + Job Declaration to a pool like the LA reference
//! pool. Unlike `dinero-sv2-miner` (CPU), this binary dispatches the nonce
//! sweep to the Apple GPU via a Metal compute kernel.
//!
//! The SV2 session code mirrors `dinero-sv2-miner/src/main.rs` — duplicated
//! rather than shared so the CPU miner stays untouched. The only mining-
//! relevant difference is `start_hashing_gpu` replacing the CPU rayon sweep.
//!
//! Mac-only for now. CUDA/OpenCL backends can ship as sibling binaries later.

use anyhow::{bail, Context, Result};
use clap::Parser;
use dinero_sv2_codec::{
    decode_coinbase_context, decode_new_template, decode_open_standard_mining_channel_success,
    decode_set_new_prev_hash, decode_setup_connection_success, decode_submit_shares_error,
    decode_submit_shares_success, encode_open_standard_mining_channel, encode_setup_connection,
    encode_submit_shares_extended,
};
use dinero_sv2_common::{
    CoinbaseContext, CoinbaseOutputWire, HeaderAssembly, NewTemplateDinero,
    OpenStandardMiningChannel, SetupConnection, SubmitSharesDinero, SubmitSharesExtendedDinero,
    PROTOCOL_MINING, PROTOCOL_VERSION,
};
use dinero_sv2_jd::{
    assemble_stripped_coinbase,
    block_filter::{gcs_build, gcs_filter_hash},
    commitment as utreexo_commitment, compute_root, decode_utreexo_accumulator_state,
    filter_commitment::{build_dnrf_script, requires_filter_commitment},
    leaf_hash, CoinbaseOutput, UtreexoAccumulatorState,
};
use dinero_sv2_transport::{
    Frame, NoiseReader, NoiseSession, MSG_COINBASE_CONTEXT, MSG_NEW_MINING_JOB,
    MSG_OPEN_STANDARD_MINING_CHANNEL, MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR,
    MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MSG_SETUP_CONNECTION, MSG_SETUP_CONNECTION_ERROR,
    MSG_SETUP_CONNECTION_SUCCESS, MSG_SET_NEW_PREV_HASH, MSG_SUBMIT_SHARES_ERROR,
    MSG_SUBMIT_SHARES_EXTENDED, MSG_SUBMIT_SHARES_SUCCESS, MSG_UTREEXO_STATE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;

#[cfg(target_os = "macos")]
mod metal_backend;

#[derive(Parser, Clone)]
#[command(version, about = "Dinero SV2 GPU pool miner (Metal)")]
struct Args {
    #[arg(long)]
    pool: SocketAddr,

    #[arg(long)]
    server_pubkey: Option<String>,

    #[arg(long)]
    payout_script_hex: String,

    #[arg(long, default_value = "dinero-sv2-gpu-miner")]
    user_agent: String,

    /// Nonces per Metal dispatch. Larger = less overhead but longer time
    /// to respond to new jobs. Default 1M is ~3-15 ms on Apple Silicon
    /// depending on die.
    #[arg(long, default_value_t = 1u32 << 20)]
    batch_size: u32,

    #[arg(long)]
    json: bool,

    #[arg(long, default_value_t = 5)]
    reconnect_secs: u64,

    #[arg(long, default_value_t = 0)]
    max_blocks: u64,
}

fn main() -> Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args = Args::parse();

    let pinned = parse_server_pubkey(args.server_pubkey.as_deref())?;
    let payout_script = hex::decode(&args.payout_script_hex)
        .context("payout_script_hex must be hex")?;
    if payout_script.is_empty() {
        bail!("payout_script_hex decoded to empty script");
    }

    let emitter = Emitter::new(args.json);
    emitter.emit_startup(&args);

    #[cfg(not(target_os = "macos"))]
    {
        emitter.emit(
            "error",
            &serde_json::json!({
                "message": "dinero-sv2-gpu-miner currently supports Metal (macOS) only. \
                            Use dinero-sv2-miner for CPU mining.",
            }),
        );
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        let gpu = metal_backend::MetalMiner::init().context("metal init")?;
        emitter.emit(
            "gpu_ready",
            &serde_json::json!({
                "device": gpu.device_name(),
                "max_threads_per_group": gpu.max_threads_per_group(),
                "batch_size": args.batch_size,
            }),
        );

        // Process-wide generation counter (lives across reconnects) so
        // hashing threads from a previous session observe a bump and
        // exit; otherwise their per-session generation Arc would never
        // increment and the GPU dispatch thread would run forever.
        let generation = Arc::new(AtomicU64::new(0));

        let mut blocks_found: u64 = 0;
        loop {
            match run_session(&args, pinned.as_ref(), &payout_script, &gpu, Arc::clone(&generation), &emitter).await {
                Ok(found) => {
                    blocks_found += found;
                    if args.max_blocks > 0 && blocks_found >= args.max_blocks {
                        emitter.emit(
                            "session_end",
                            &serde_json::json!({"reason": "max-blocks-reached"}),
                        );
                        return Ok(());
                    }
                    emitter.emit(
                        "session_end",
                        &serde_json::json!({"reason": "clean-close"}),
                    );
                }
                Err(err) => {
                    emitter.emit(
                        "session_end",
                        &serde_json::json!({
                            "reason": "error",
                            "error": err.to_string(),
                        }),
                    );
                    if args.reconnect_secs == 0 {
                        return Err(err);
                    }
                }
            }
            if args.reconnect_secs == 0 {
                return Ok(());
            }
            emitter.emit(
                "reconnect_wait",
                &serde_json::json!({"seconds": args.reconnect_secs}),
            );
            sleep(Duration::from_secs(args.reconnect_secs)).await;
        }
    }
}

fn parse_server_pubkey(hex_opt: Option<&str>) -> Result<Option<[u8; 32]>> {
    match hex_opt {
        Some(h) => {
            let bytes = hex::decode(h).context("server-pubkey must be hex")?;
            if bytes.len() != 32 {
                bail!("server-pubkey must be 32 bytes (64 hex chars)");
            }
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
        None => Ok(None),
    }
}

#[cfg(target_os = "macos")]
async fn run_session(
    args: &Args,
    pinned: Option<&[u8; 32]>,
    payout_script: &[u8],
    gpu: &metal_backend::MetalMiner,
    generation: Arc<AtomicU64>,
    emitter: &Emitter,
) -> Result<u64> {
    let tcp = TcpStream::connect(args.pool).await.context("connect")?;
    let session = NoiseSession::initiate_nx(tcp, pinned).await.context("noise handshake")?;
    let peer_pubkey = hex::encode(session.peer_static_key());
    emitter.emit(
        "connected",
        &serde_json::json!({
            "pool": args.pool.to_string(),
            "server_pubkey": peer_pubkey,
            "backend": "metal",
        }),
    );

    let (mut reader, mut writer) = session.split();

    let setup = SetupConnection {
        protocol: PROTOCOL_MINING,
        min_version: PROTOCOL_VERSION,
        max_version: PROTOCOL_VERSION,
        flags: 0,
        user_agent: args.user_agent.as_bytes().to_vec(),
    };
    writer
        .write_frame(MSG_SETUP_CONNECTION, &encode_setup_connection(&setup)?)
        .await?;
    expect_setup_success(&mut reader).await?;

    let open = OpenStandardMiningChannel {
        request_id: 1,
        user_identity: args.user_agent.as_bytes().to_vec(),
        // GPU hashrate estimate: 100 MH/s ballpark for Apple Silicon.
        nominal_hash_rate_bits: f32::to_bits(100_000_000.0),
        max_target: [0xFFu8; 32],
    };
    writer
        .write_frame(
            MSG_OPEN_STANDARD_MINING_CHANNEL,
            &encode_open_standard_mining_channel(&open)?,
        )
        .await?;
    let (channel_id, share_target) = expect_channel_open(&mut reader).await?;
    emitter.emit(
        "channel_open",
        &serde_json::json!({
            "channel_id": channel_id,
            "share_target": hex::encode(share_target),
        }),
    );

    let (frame_tx, mut frame_rx) = mpsc::unbounded_channel::<Frame>();
    let reader_task = tokio::spawn(async move {
        loop {
            match reader.read_frame().await {
                Ok(Some(f)) => {
                    if frame_tx.send(f).is_err() {
                        return Ok(());
                    }
                }
                Ok(None) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    });

    let mut pre_block_state: Option<UtreexoAccumulatorState> = None;
    let mut coinbase_ctx: Option<CoinbaseContext> = None;
    let mut blocks_found: u64 = 0;
    let mut seq: u32 = 0;

    let (share_tx, mut share_rx) = mpsc::unbounded_channel::<FoundShare>();

    // Coalesce share-accept telemetry. With the GPU running at ~500
    // shares/sec, emitting a JSON event per pool ack drowns the Qt UI
    // thread. We collect into a 1-second window and flush a single
    // summary event per window. The timer arm in the select! below
    // forces a flush even when share traffic stops, so the UI doesn't
    // freeze a half-emitted batch when the pool goes quiet after a burst.
    let mut acc_window_count: u64 = 0;
    let mut acc_window_last_seq: u64 = 0;
    let mut acc_window_last_channel: u32 = channel_id;
    let mut acc_window_last_shares_sum: u64 = 0;
    let mut acc_window_started: std::time::Instant = std::time::Instant::now();
    const ACCEPT_FLUSH_MS: u128 = 1000;
    let mut accept_flush_tick =
        tokio::time::interval(std::time::Duration::from_millis(ACCEPT_FLUSH_MS as u64));
    accept_flush_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let result: Result<u64> = loop {
        tokio::select! {
            frame = frame_rx.recv() => {
                let Some(frame) = frame else {
                    break Err(anyhow::anyhow!("pool closed the session"));
                };
                match frame.msg_type {
                    MSG_SET_NEW_PREV_HASH => {
                        let snph = decode_set_new_prev_hash(&frame.payload)?;
                        emitter.emit(
                            "set_new_prev_hash",
                            &serde_json::json!({
                                "prev_hash": hex::encode(snph.prev_hash),
                                "min_ntime": snph.min_ntime,
                                "nbits": format!("0x{:08x}", snph.nbits),
                            }),
                        );
                        // Generation bump invalidates any in-flight hashing
                        // thread immediately (next stale() check returns
                        // true) — replaces the old `cancel` bool flag,
                        // which had a race window where a subsequent
                        // start_hashing_gpu could clear the flag before
                        // the old thread observed it.
                        generation.fetch_add(1, Ordering::SeqCst);
                        pre_block_state = None;
                        coinbase_ctx = None;
                    }
                    MSG_UTREEXO_STATE => {
                        let state = decode_utreexo_accumulator_state(&frame.payload)?;
                        pre_block_state = Some(state);
                    }
                    MSG_COINBASE_CONTEXT => {
                        let ctx = decode_coinbase_context(&frame.payload)?;
                        coinbase_ctx = Some(ctx);
                    }
                    MSG_NEW_MINING_JOB => {
                        let tmpl = decode_new_template(&frame.payload)?;
                        let Some(state) = pre_block_state.clone() else {
                            tracing::warn!("NewMiningJob without UtreexoStateAnnouncement");
                            continue;
                        };
                        let Some(ctx) = coinbase_ctx.clone() else {
                            tracing::warn!("NewMiningJob without CoinbaseContext");
                            continue;
                        };
                        start_hashing_gpu(
                            tmpl,
                            state,
                            ctx,
                            payout_script.to_vec(),
                            share_target,
                            gpu.clone(),
                            args.batch_size,
                            Arc::clone(&generation),
                            share_tx.clone(),
                            emitter,
                        );
                    }
                    MSG_SUBMIT_SHARES_SUCCESS => {
                        let s = decode_submit_shares_success(&frame.payload)?;
                        acc_window_count += s.new_submits_accepted_count.max(1) as u64;
                        acc_window_last_seq = s.last_sequence_number as u64;
                        acc_window_last_channel = s.channel_id;
                        acc_window_last_shares_sum = s.new_shares_sum as u64;
                        if acc_window_started.elapsed().as_millis() >= ACCEPT_FLUSH_MS {
                            emitter.emit(
                                "share_accepted",
                                &serde_json::json!({
                                    "channel_id": acc_window_last_channel,
                                    "last_seq": acc_window_last_seq,
                                    "accepted_count": acc_window_count,
                                    "shares_sum": acc_window_last_shares_sum,
                                    "window_ms": acc_window_started.elapsed().as_millis() as u64,
                                }),
                            );
                            acc_window_count = 0;
                            acc_window_started = std::time::Instant::now();
                        }
                    }
                    MSG_SUBMIT_SHARES_ERROR => {
                        let e = decode_submit_shares_error(&frame.payload)?;
                        emitter.emit(
                            "share_rejected",
                            &serde_json::json!({
                                "channel_id": e.channel_id,
                                "sequence_number": e.sequence_number,
                                "error": String::from_utf8_lossy(&e.error_code).to_string(),
                            }),
                        );
                    }
                    other => {
                        tracing::debug!("unhandled frame msg_type=0x{:02x}", other);
                    }
                }
            }
            Some(found) = share_rx.recv() => {
                if found.generation != generation.load(Ordering::SeqCst) {
                    continue;
                }
                seq += 1;
                let ext = SubmitSharesExtendedDinero {
                    channel_id,
                    sequence_number: seq,
                    job_id: u32::try_from(found.template_id).unwrap_or(0),
                    nonce: found.nonce,
                    timestamp: found.timestamp,
                    version: found.version,
                    coinbase_outputs: found.coinbase_outputs,
                };
                let buf = encode_submit_shares_extended(&ext)?;
                writer.write_frame(MSG_SUBMIT_SHARES_EXTENDED, &buf).await?;
                // Only emit share_submitted JSON for block-target hits.
                // Sub-block shares fire ~500/sec at full GPU speed; the
                // per-event UI-thread cost on the Qt side is the dominant
                // cause of frontend freeze + stdout pipe back-pressure
                // that throttled the kernel itself. The pool's
                // SubmitSharesSuccess stream carries the count we need
                // ('share_accepted' events, throttled separately).
                if found.meets_block_target {
                    emitter.emit(
                        "share_submitted",
                        &serde_json::json!({
                            "sequence_number": seq,
                            "nonce": format!("0x{:08x}", found.nonce),
                            "hash": hex::encode(found.hash),
                            "meets_block_target": true,
                            "hashes": found.hashes,
                        }),
                    );
                }
                if found.meets_block_target {
                    blocks_found += 1;
                    if args.max_blocks > 0 && blocks_found >= args.max_blocks {
                        break Ok(blocks_found);
                    }
                }
            }
            _ = accept_flush_tick.tick() => {
                // Periodic flush: if shares accumulated but the next pool
                // ack hasn't arrived, emit what we have so the UI counter
                // tracks the live state instead of freezing on the last
                // burst's tail.
                if acc_window_count > 0
                    && acc_window_started.elapsed().as_millis() >= ACCEPT_FLUSH_MS
                {
                    emitter.emit(
                        "share_accepted",
                        &serde_json::json!({
                            "channel_id": acc_window_last_channel,
                            "last_seq": acc_window_last_seq,
                            "accepted_count": acc_window_count,
                            "shares_sum": acc_window_last_shares_sum,
                            "window_ms": acc_window_started.elapsed().as_millis() as u64,
                        }),
                    );
                    acc_window_count = 0;
                    acc_window_started = std::time::Instant::now();
                }
            }
        }
    };

    reader_task.abort();
    // Bump generation so any GPU dispatch thread still alive from this
    // session observes it and exits before the next session re-spawns.
    generation.fetch_add(1, Ordering::SeqCst);
    result
}

async fn expect_setup_success<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut NoiseReader<R>,
) -> Result<()> {
    let f = reader
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("EOF after SetupConnection"))?;
    match f.msg_type {
        MSG_SETUP_CONNECTION_SUCCESS => {
            let _succ = decode_setup_connection_success(&f.payload)?;
            Ok(())
        }
        MSG_SETUP_CONNECTION_ERROR => bail!(
            "SetupConnection.Error: {}",
            String::from_utf8_lossy(&f.payload)
        ),
        other => bail!("unexpected response to SetupConnection: 0x{other:02x}"),
    }
}

async fn expect_channel_open<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut NoiseReader<R>,
) -> Result<(u32, [u8; 32])> {
    let f = reader
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("EOF after OpenStandardMiningChannel"))?;
    match f.msg_type {
        MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
            let succ = decode_open_standard_mining_channel_success(&f.payload)?;
            Ok((succ.channel_id, succ.target))
        }
        MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR => bail!(
            "OpenStandardMiningChannel.Error: {}",
            String::from_utf8_lossy(&f.payload)
        ),
        other => bail!("unexpected response to OpenStandardMiningChannel: 0x{other:02x}"),
    }
}

#[derive(Debug)]
struct FoundShare {
    generation: u64,
    template_id: u64,
    timestamp: u64,
    version: u32,
    nonce: u32,
    hash: [u8; 32],
    meets_block_target: bool,
    hashes: u64,
    coinbase_outputs: Vec<CoinbaseOutputWire>,
}

/// GPU mining: assemble miner-owned coinbase + header, dispatch Metal
/// kernel in batches, report found shares via `share_tx`.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn start_hashing_gpu(
    tmpl: NewTemplateDinero,
    pre_block_state: UtreexoAccumulatorState,
    ctx: CoinbaseContext,
    payout_script: Vec<u8>,
    share_target: [u8; 32],
    gpu: metal_backend::MetalMiner,
    batch_size: u32,
    generation: Arc<AtomicU64>,
    share_tx: mpsc::UnboundedSender<FoundShare>,
    emitter: &Emitter,
) {
    // Race-free cancellation: each spawned thread captures its own
    // generation number; if the global counter has moved past it, the
    // thread is stale and must exit. The previous bool-flag approach had
    // a window where a new `start_hashing_gpu` call could `cancel=false`
    // before the old thread observed `cancel=true`, leading to two
    // dispatch threads racing for the GPU buffer mutex and roughly
    // halving effective throughput.
    let gen = generation.fetch_add(1, Ordering::SeqCst) + 1;

    let (encoded_filter, _n) = gcs_build(&tmpl.prev_block_hash, &[&payout_script]);
    let filter_hash = gcs_filter_hash(&encoded_filter);
    let dnrf_script = build_dnrf_script(&filter_hash);
    let mut miner_outputs = vec![CoinbaseOutput {
        value_una: ctx.coinbase_value_una,
        script_pubkey: payout_script.clone(),
    }];
    if requires_filter_commitment(ctx.height as u64) {
        miner_outputs.push(CoinbaseOutput {
            value_una: 0,
            script_pubkey: dnrf_script,
        });
    }
    let (_coinbase_bytes, coinbase_txid) =
        assemble_stripped_coinbase(&ctx.coinbase_prefix, &miner_outputs, &ctx.coinbase_suffix);
    let mut post_state = pre_block_state.clone();
    for (i, out) in miner_outputs.iter().enumerate() {
        let leaf = leaf_hash(&coinbase_txid, i as u32, out.value_una, &out.script_pubkey);
        if let Err(err) = post_state.add_leaf(leaf) {
            tracing::error!("post-state add_leaf failed: {err}");
            return;
        }
    }
    let our_utreexo_root = match utreexo_commitment(&post_state) {
        Ok(v) => v,
        Err(err) => {
            tracing::error!("utreexo_commitment failed: {err}");
            return;
        }
    };
    let merkle_root = compute_root(coinbase_txid, &ctx.merkle_path);
    let our_template = NewTemplateDinero {
        template_id: tmpl.template_id,
        future_template: tmpl.future_template,
        version: tmpl.version,
        prev_block_hash: tmpl.prev_block_hash,
        merkle_root,
        utreexo_root: our_utreexo_root,
        timestamp: tmpl.timestamp,
        difficulty: tmpl.difficulty,
        coinbase_outputs_commitment: [0u8; 32],
    };
    let block_target = nbits_to_target(tmpl.difficulty);

    let coinbase_outputs_wire: Vec<CoinbaseOutputWire> = miner_outputs
        .iter()
        .map(|o| CoinbaseOutputWire {
            value_una: o.value_una,
            script_pubkey: o.script_pubkey.clone(),
        })
        .collect();

    emitter.emit(
        "new_job",
        &serde_json::json!({
            "template_id": tmpl.template_id,
            "height": ctx.height,
            "coinbase_value_una": ctx.coinbase_value_una,
            "utreexo_root": hex::encode(our_utreexo_root),
            "merkle_root": hex::encode(merkle_root),
            "difficulty_nbits": format!("0x{:08x}", tmpl.difficulty),
            "block_target": hex::encode(block_target),
            "share_target": hex::encode(share_target),
            "backend": "metal",
        }),
    );

    let tmpl_initial_timestamp = tmpl.timestamp;
    let tmpl_version = tmpl.version;
    let tmpl_id = tmpl.template_id;

    // Hash thread:
    // - Inner loop: sweep the full u32 nonce space at the current timestamp.
    // - Outer loop: when the nonce space exhausts, bump timestamp by 1 and
    //   re-sweep. Each timestamp gives a fresh 4.3B-nonce search space.
    //   At ~535 MH/s on M4 Max one sweep takes ~8 s, so we cycle through
    //   timestamps at 1 Hz — well within any pool-side ntime tolerance.
    //   Without this wrap, the thread would silently exit after 8 s of
    //   work and the share counter freezes whenever new pool jobs lag.
    std::thread::spawn(move || {
        let gen_at_spawn = gen;
        let global_generation = Arc::clone(&generation);
        let stale = move || global_generation.load(Ordering::Relaxed) > gen_at_spawn;

        let batch: u64 = batch_size as u64;
        let mut total_ms_since_emit: f64 = 0.0;
        let mut hashes_since_emit: u64 = 0;
        let mut last_emit = std::time::Instant::now();
        const EMIT_INTERVAL_MS: u128 = 1000;

        let mut current_timestamp: u64 = tmpl_initial_timestamp;
        loop {
            if stale() {
                return;
            }
            let header_bytes = assemble_header_bytes(&our_template, current_timestamp, tmpl_version);
            let mut nonce_start: u64 = 0;
            while nonce_start <= u32::MAX as u64 {
                if stale() {
                    return;
                }
                let this_batch = std::cmp::min(batch, (u32::MAX as u64 + 1).saturating_sub(nonce_start)) as u32;
                let outcome = match gpu.dispatch(&header_bytes, &share_target, nonce_start as u32, this_batch) {
                    Ok(out) => out,
                    Err(err) => {
                        tracing::error!("metal dispatch failed: {err}");
                        return;
                    }
                };
                total_ms_since_emit += outcome.elapsed_ms;
                hashes_since_emit += this_batch as u64;
                if last_emit.elapsed().as_millis() >= EMIT_INTERVAL_MS {
                    let mhs = (hashes_since_emit as f64 / (total_ms_since_emit / 1000.0)) / 1e6;
                    let dispatch_ms = total_ms_since_emit / ((hashes_since_emit as f64) / (batch_size as f64)).max(1.0);
                    println!(
                        "{{\"event\":\"hashrate\",\"mhs\":{:.2},\"dispatch_ms\":{:.3},\"nonce_start\":\"0x{:08x}\",\"timestamp\":{},\"backend\":\"metal\"}}",
                        mhs,
                        dispatch_ms,
                        nonce_start as u32,
                        current_timestamp,
                    );
                    last_emit = std::time::Instant::now();
                    total_ms_since_emit = 0.0;
                    hashes_since_emit = 0;
                }
                if outcome.found {
                    let nonce = outcome.nonce;
                    let share = SubmitSharesDinero {
                        channel_id: 0,
                        sequence_number: 0,
                        job_id: 0,
                        nonce,
                        timestamp: current_timestamp,
                        version: tmpl_version,
                    };
                    let hash = HeaderAssembly::hash(&our_template, &share);
                    if hash < share_target {
                        let meets_block = hash < block_target;
                        let hashes = nonce_start + outcome.nonce.wrapping_sub(nonce_start as u32) as u64;
                        let _ = share_tx.send(FoundShare {
                            generation: gen,
                            template_id: tmpl_id,
                            timestamp: current_timestamp,
                            version: tmpl_version,
                            nonce,
                            hash,
                            meets_block_target: meets_block,
                            hashes,
                            coinbase_outputs: coinbase_outputs_wire.clone(),
                        });
                    }
                }
                nonce_start += this_batch as u64;
            }
            // Nonce space exhausted at this timestamp. Bump timestamp and
            // continue with a fresh 4.3B-nonce search space.
            current_timestamp = current_timestamp.wrapping_add(1);
            // Sanity bound: don't drift more than ~1 hour past the
            // template-issued timestamp; pool may reject shares that far
            // in the future. Park here until generation flips so the GPU
            // doesn't spin re-sweeping the same exhausted (timestamp,
            // nonce) range; the next NewMiningJob respawns this thread.
            if current_timestamp.saturating_sub(tmpl_initial_timestamp) > 3600 {
                while !stale() {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                return;
            }
        }
    });
}

/// Emit the 128-byte Dinero block header layout (LE) as a byte array so
/// the Metal kernel can hash it per-thread. Nonce bytes at offset 112
/// are set to zero; the kernel overwrites them per thread_position.
fn assemble_header_bytes(
    tmpl: &NewTemplateDinero,
    timestamp: u64,
    version: u32,
) -> [u8; 128] {
    let mut buf = [0u8; 128];
    buf[0..4].copy_from_slice(&version.to_le_bytes());
    buf[4..36].copy_from_slice(&tmpl.prev_block_hash);
    buf[36..68].copy_from_slice(&tmpl.merkle_root);
    buf[68..100].copy_from_slice(&tmpl.utreexo_root);
    buf[100..108].copy_from_slice(&timestamp.to_le_bytes());
    buf[108..112].copy_from_slice(&tmpl.difficulty.to_le_bytes());
    // buf[112..116] nonce — left zero (kernel writes per-thread)
    // buf[116..128] reserved — left zero (consensus requires all zeros)
    buf
}

fn nbits_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) & 0xff;
    let mantissa = bits & 0x00ff_ffff;
    let mut target = [0u8; 32];
    if exponent <= 3 {
        let shift = 8 * (3 - exponent as usize);
        let shifted = (mantissa >> shift) & 0x00ff_ffff;
        target[29] = ((shifted >> 16) & 0xff) as u8;
        target[30] = ((shifted >> 8) & 0xff) as u8;
        target[31] = (shifted & 0xff) as u8;
    } else {
        let offset = 32usize.saturating_sub(exponent as usize);
        if offset + 3 <= 32 {
            target[offset] = ((mantissa >> 16) & 0xff) as u8;
            target[offset + 1] = ((mantissa >> 8) & 0xff) as u8;
            target[offset + 2] = (mantissa & 0xff) as u8;
        }
    }
    target
}

struct Emitter {
    json: bool,
}

impl Emitter {
    fn new(json: bool) -> Self {
        Self { json }
    }

    fn emit_startup(&self, args: &Args) {
        self.emit(
            "startup",
            &serde_json::json!({
                "pool": args.pool.to_string(),
                "server_pubkey_pinned": args.server_pubkey.is_some(),
                "batch_size": args.batch_size,
                "user_agent": args.user_agent,
                "version": env!("CARGO_PKG_VERSION"),
                "backend": "metal",
            }),
        );
    }

    fn emit(&self, event: &str, data: &serde_json::Value) {
        if self.json {
            let mut map = data_as_object(data);
            map.insert(
                "event".to_string(),
                serde_json::Value::String(event.to_string()),
            );
            let line = serde_json::Value::Object(map);
            println!("{}", line);
        } else {
            println!("[{event}] {data}");
        }
    }
}

fn data_as_object(data: &serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    match data {
        serde_json::Value::Object(map) => map.clone(),
        other => {
            let mut map = serde_json::Map::new();
            map.insert("data".to_string(), other.clone());
            map
        }
    }
}
