//! Dinero Stratum V2 CPU miner.
//!
//! Long-running client that speaks SV2 + Noise NX to a pool like the one on
//! LA. Receives `NewMiningJob` frames, hashes a rayon-parallel nonce sweep
//! against the channel's share target, and submits `SubmitSharesExtended`
//! with miner-owned coinbase outputs (Job Declaration path).
//!
//! Designed to be spawned from a GUI wrapper (dinero-qt) with structured
//! event output via `--json`, but also usable standalone from a terminal.

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
use rayon::prelude::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;

#[derive(Parser, Clone)]
#[command(version, about = "Dinero SV2 pool miner")]
struct Args {
    /// Pool endpoint, e.g. 172.93.160.131:4444
    #[arg(long)]
    pool: SocketAddr,

    /// Expected pool static pubkey (64-char hex). Strongly recommended —
    /// without it the client accepts any server key on first contact.
    #[arg(long)]
    server_pubkey: Option<String>,

    /// Coinbase payout scriptPubKey as hex (34 bytes for Taproot `din1p…`).
    /// Consensus sends the block reward to this script on a block-find.
    #[arg(long)]
    payout_script_hex: String,

    /// Worker identity reported to the pool. Shows up in pool logs.
    #[arg(long, default_value = "dinero-sv2-miner")]
    user_agent: String,

    /// Number of CPU hash threads. 0 = detect logical cores.
    #[arg(long, default_value_t = 0)]
    threads: usize,

    /// Emit newline-delimited JSON events on stdout instead of human-
    /// readable lines. Intended for GUI frontends to parse.
    #[arg(long)]
    json: bool,

    /// Reconnect back-off seconds on disconnect. 0 = exit on disconnect.
    #[arg(long, default_value_t = 5)]
    reconnect_secs: u64,

    /// Stop after this many block-target solutions (not share-target).
    /// 0 = run forever. Mostly for testing.
    #[arg(long, default_value_t = 0)]
    max_blocks: u64,
}

fn main() -> Result<()> {
    // Use a multi-threaded tokio runtime so share submits don't block
    // the reader.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async_main())
}

async fn async_main() -> Result<()> {
    let args = Args::parse();

    // Resolve thread count once.
    let threads = if args.threads == 0 {
        num_cpus::get()
    } else {
        args.threads
    };

    // Rayon global pool sized to the chosen thread count. `build_global`
    // fails if called twice in the same process — fine here since we only
    // ever call it once.
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .ok();

    let pinned = parse_server_pubkey(args.server_pubkey.as_deref())?;
    let payout_script = hex::decode(&args.payout_script_hex)
        .context("payout_script_hex must be hex")?;
    if payout_script.is_empty() {
        bail!("payout_script_hex decoded to empty script");
    }

    let emitter = Emitter::new(args.json);
    emitter.emit_startup(&args, threads);

    let mut blocks_found: u64 = 0;
    loop {
        match run_session(&args, pinned.as_ref(), &payout_script, threads, &emitter).await {
            Ok(round_blocks) => {
                blocks_found += round_blocks;
                if args.max_blocks > 0 && blocks_found >= args.max_blocks {
                    emitter.emit("session_end", &serde_json::json!({
                        "reason": "max-blocks-reached",
                        "blocks_found": blocks_found,
                    }));
                    return Ok(());
                }
                emitter.emit(
                    "session_end",
                    &serde_json::json!({"reason": "clean-close", "blocks_found": blocks_found}),
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

/// One full SV2 session. Returns the number of block-target hits found
/// before the session closed normally, or an error if the pool disconnected
/// unexpectedly.
async fn run_session(
    args: &Args,
    pinned: Option<&[u8; 32]>,
    payout_script: &[u8],
    threads: usize,
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
            "threads": threads,
        }),
    );

    // Split into reader/writer halves. Reader runs in a dedicated task
    // so its in-flight `read_frame` future is never dropped by a
    // `select!` — dropping mid-read desyncs the Noise cipher and the
    // pool immediately disconnects with a decrypt error.
    let (mut reader, mut writer) = session.split();

    // ---- SetupConnection ----
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

    // ---- OpenStandardMiningChannel ----
    let open = OpenStandardMiningChannel {
        request_id: 1,
        user_identity: args.user_agent.as_bytes().to_vec(),
        nominal_hash_rate_bits: f32::to_bits((threads as f32) * 3_000_000.0),
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

    // Move the reader into a task that forwards frames via channel.
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

    // Session state carried across frames.
    let mut pre_block_state: Option<UtreexoAccumulatorState> = None;
    let mut coinbase_ctx: Option<CoinbaseContext> = None;
    let mut blocks_found: u64 = 0;
    let mut seq: u32 = 0;

    let cancel = Arc::new(AtomicBool::new(false));
    let generation = Arc::new(AtomicU64::new(0));
    let (share_tx, mut share_rx) = mpsc::unbounded_channel::<FoundShare>();

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
                        cancel.store(true, Ordering::SeqCst);
                        // New prev hash invalidates pre-block state until
                        // the pool re-sends it with the next job cycle.
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
                            tracing::warn!("NewMiningJob without UtreexoStateAnnouncement — skipping");
                            continue;
                        };
                        let Some(ctx) = coinbase_ctx.clone() else {
                            tracing::warn!("NewMiningJob without CoinbaseContext — skipping");
                            continue;
                        };
                        start_hashing(
                            tmpl,
                            state,
                            ctx,
                            payout_script.to_vec(),
                            share_target,
                            channel_id,
                            threads,
                            Arc::clone(&cancel),
                            Arc::clone(&generation),
                            share_tx.clone(),
                            emitter,
                        );
                    }
                    MSG_SUBMIT_SHARES_SUCCESS => {
                        let s = decode_submit_shares_success(&frame.payload)?;
                        emitter.emit(
                            "share_accepted",
                            &serde_json::json!({
                                "channel_id": s.channel_id,
                                "last_seq": s.last_sequence_number,
                                "accepted_count": s.new_submits_accepted_count,
                                "shares_sum": s.new_shares_sum,
                            }),
                        );
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
                // Stale result from a superseded generation — drop.
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
                emitter.emit(
                    "share_submitted",
                    &serde_json::json!({
                        "sequence_number": seq,
                        "nonce": format!("0x{:08x}", found.nonce),
                        "hash": hex::encode(found.hash),
                        "meets_block_target": found.meets_block_target,
                        "tries": found.tries,
                    }),
                );
                if found.meets_block_target {
                    blocks_found += 1;
                    if args.max_blocks > 0 && blocks_found >= args.max_blocks {
                        break Ok(blocks_found);
                    }
                }
            }
        }
    };

    reader_task.abort();
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
    tries: u64,
    coinbase_outputs: Vec<CoinbaseOutputWire>,
}

/// Build the miner-owned coinbase + post-block Utreexo commitment, then
/// dispatch a rayon parallel nonce sweep. First thread to find a hash
/// under the share target (or the block target, whichever comes first)
/// reports via `share_tx`; the sweep aborts on `cancel` flag.
#[allow(clippy::too_many_arguments)]
fn start_hashing(
    tmpl: NewTemplateDinero,
    pre_block_state: UtreexoAccumulatorState,
    ctx: CoinbaseContext,
    payout_script: Vec<u8>,
    share_target: [u8; 32],
    _channel_id: u32,
    threads: usize,
    cancel: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    share_tx: mpsc::UnboundedSender<FoundShare>,
    emitter: &Emitter,
) {
    // Bump generation first, then clear cancel for the new round.
    let gen = generation.fetch_add(1, Ordering::SeqCst) + 1;
    cancel.store(false, Ordering::SeqCst);

    // Assemble the miner's coinbase outputs (payout + DNRF OP_RETURN).
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

    // Block target from compact nBits. Used only to flag "this share is
    // also a full block" in the telemetry; the pool re-validates.
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
        }),
    );

    // Snapshot state used by each rayon worker. Cloned into the closure.
    let start_instant = Instant::now();
    let tmpl_timestamp = tmpl.timestamp;
    let tmpl_version = tmpl.version;
    let tmpl_id = tmpl.template_id;

    std::thread::spawn(move || {
        let per_thread = (u32::MAX as u64 + 1) / (threads.max(1) as u64);
        let mut ranges: Vec<(u32, u32)> = Vec::with_capacity(threads);
        let mut cursor: u64 = 0;
        for i in 0..threads {
            let start = cursor as u32;
            let end = if i == threads - 1 {
                u32::MAX
            } else {
                (cursor + per_thread - 1) as u32
            };
            ranges.push((start, end));
            cursor += per_thread;
        }

        ranges.par_iter().for_each(|(start, end)| {
            let mut tries: u64 = 0;
            let mut nonce = *start;
            loop {
                if cancel.load(Ordering::Relaxed) {
                    return;
                }
                // Cheap timer check every 1M hashes.
                if tries & 0xFFFFF == 0 && tries > 0 {
                    // no-op, placeholder for future periodic reporting
                }

                let share = SubmitSharesDinero {
                    channel_id: 0,
                    sequence_number: 0,
                    job_id: 0,
                    nonce,
                    timestamp: tmpl_timestamp,
                    version: tmpl_version,
                };
                let hash = HeaderAssembly::hash(&our_template, &share);
                if hash < share_target {
                    let meets_block = hash < block_target;
                    let _ = share_tx.send(FoundShare {
                        generation: gen,
                        template_id: tmpl_id,
                        timestamp: tmpl_timestamp,
                        version: tmpl_version,
                        nonce,
                        hash,
                        meets_block_target: meets_block,
                        tries,
                        coinbase_outputs: coinbase_outputs_wire.clone(),
                    });
                    // Keep searching for more shares; only stop if the
                    // session invalidates the template.
                }
                tries += 1;
                if nonce == *end {
                    break;
                }
                nonce = nonce.wrapping_add(1);
            }
        });
        let _ = start_instant; // suppress unused if future telemetry is added
    });
}

/// Expand compact nBits into a 32-byte big-endian target.
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

// ───── Structured event emitter ─────

struct Emitter {
    json: bool,
}

impl Emitter {
    fn new(json: bool) -> Self {
        Self { json }
    }

    fn emit_startup(&self, args: &Args, threads: usize) {
        self.emit(
            "startup",
            &serde_json::json!({
                "pool": args.pool.to_string(),
                "server_pubkey_pinned": args.server_pubkey.is_some(),
                "threads": threads,
                "user_agent": args.user_agent,
                "version": env!("CARGO_PKG_VERSION"),
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

/// Flatten `data` into the top-level JSON line if it's an object; else
/// nest under a `data` key.
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
