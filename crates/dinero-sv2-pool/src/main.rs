//! `dinero-sv2-pool` — Phase 4 reference pool server.
//!
//! Extends the template-provider flow from `dinero-tp` with two-tier
//! target acceptance and `submitblock` on found blocks:
//!
//! - Any share whose header hash ≤ `--share-leading-bits` (a loose
//!   pool-local target) gets credited to the miner.
//! - Any share whose header hash ≤ `block_target` (from
//!   `template.difficulty`) causes the pool to assemble the full block
//!   and `submitblock` it to dinerod; result logged.
//!
//! Phase 4 explicitly keeps pool-built coinbase, empty mempools, and
//! no persistent share ledger. See crate docs in
//! `~/.claude/plans/lovely-chasing-puzzle.md` for the longer roadmap.

use dinero_sv2_pool::{accounting, block, mapper, rpc, target};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dinero_sv2_codec::{
    decode_open_standard_mining_channel, decode_setup_connection, decode_submit_shares,
    decode_submit_shares_extended, encode_coinbase_context, encode_new_template,
    encode_open_standard_mining_channel_error, encode_open_standard_mining_channel_success,
    encode_set_new_prev_hash, encode_set_target, encode_setup_connection_error,
    encode_setup_connection_success, encode_submit_shares_error, encode_submit_shares_success,
};
use dinero_sv2_common::{
    CoinbaseContext, HeaderAssembly, NewTemplateDinero, OpenStandardMiningChannelError,
    OpenStandardMiningChannelSuccess, SetNewPrevHash, SetupConnectionError, SetupConnectionSuccess,
    SubmitSharesDinero, SubmitSharesError, SubmitSharesSuccess, PROTOCOL_MINING, PROTOCOL_VERSION,
};
use dinero_sv2_jd::{
    assemble_stripped_coinbase, commitment as utreexo_commitment, compute_root,
    encode_utreexo_accumulator_state,
    filter_commitment::{is_dnrf_script, requires_filter_commitment},
    leaf_hash, CoinbaseOutput,
};
use dinero_sv2_transport::{
    Frame, NoiseSession, StaticKeys, MSG_COINBASE_CONTEXT, MSG_NEW_MINING_JOB,
    MSG_OPEN_STANDARD_MINING_CHANNEL, MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR,
    MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MSG_SETUP_CONNECTION, MSG_SETUP_CONNECTION_ERROR,
    MSG_SETUP_CONNECTION_SUCCESS, MSG_SET_NEW_PREV_HASH, MSG_SET_TARGET, MSG_SUBMIT_SHARES_ERROR,
    MSG_SUBMIT_SHARES_EXTENDED, MSG_SUBMIT_SHARES_STANDARD, MSG_SUBMIT_SHARES_SUCCESS,
    MSG_UTREEXO_STATE,
};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::accounting::{Ledger, MinerKey};
use crate::mapper::PoolTemplate;
use crate::rpc::{Auth, RpcClient, SubmitBlockResult};
use crate::target::{hash_meets_target, leading_zero_bits_target, target_for_hashrate};

/// Per-channel vardiff config. `None` = vardiff off (use fallback target
/// from `--share-leading-bits` for everyone, legacy behaviour).
#[derive(Debug, Clone, Copy)]
struct VardiffConfig {
    /// Target ~1 share per N seconds per channel.
    target_interval_secs: f64,
    /// Recompute observed-rate-based target every N seconds. `None`
    /// means "initial target only, no follow-up retargeting".
    window: Option<Duration>,
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Bind address for miner connections.
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: SocketAddr,

    /// dinerod RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:20998")]
    rpc_url: String,

    /// Cookie file (ignored if --rpc-user / --rpc-password are set).
    #[arg(long)]
    cookie: Option<String>,

    /// Explicit rpcuser.
    #[arg(long)]
    rpc_user: Option<String>,

    /// Explicit rpcpassword.
    #[arg(long)]
    rpc_password: Option<String>,

    /// Payout address for getblocktemplate (pool-built coinbase; miners
    /// don't alter outputs in Phase 4).
    #[arg(long)]
    payout_address: String,

    /// Tip-poll interval.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,

    /// Force-refresh the in-flight template at most this often, even
    /// when the chain tip hasn't changed. Picks up ASERT difficulty
    /// drift while the chain stalls (the daemon's getblocktemplate
    /// returns easier nBits as the proposed-ntime advances). Without
    /// this, miners are stuck mining against the stale (harder) target
    /// from the last prev_hash change. Set to 0 to disable.
    #[arg(long, default_value_t = 15)]
    refresh_same_tip_secs: u64,

    /// Fallback share-acceptance target as leading zero bits. Used as
    /// the channel's target ONLY when vardiff can't infer a real
    /// hashrate (miner reports 0 in OpenStandardMiningChannel and never
    /// produces a share). With vardiff active, each channel's effective
    /// target is sized off the miner's reported / observed hashrate.
    #[arg(long, default_value_t = 8)]
    share_leading_bits: u32,

    /// Vardiff target: aim for ~1 accepted share per N seconds per
    /// channel. Smaller = faster UI feedback, more share traffic; larger
    /// = sparser shares, less network/log noise. Set to 0 to disable
    /// vardiff and use `--share-leading-bits` for everyone (legacy).
    #[arg(long, default_value_t = 5)]
    vardiff_target_seconds: u64,

    /// Vardiff measurement window: recompute the per-channel target
    /// every N seconds based on observed share rate. The new target is
    /// emitted as `MSG_SET_TARGET` (0x22). Forward-compatible — clients
    /// that don't recognise the opcode keep mining at their channel-open
    /// target. Set to 0 to disable runtime adjustment (initial target
    /// from `nominal_hash_rate_bits` only, no follow-up).
    #[arg(long, default_value_t = 30)]
    vardiff_window_seconds: u64,

    /// Static Noise identity file.
    #[arg(long)]
    tp_key: Option<PathBuf>,

    /// Print the pool's static public key (hex) and exit.
    #[arg(long)]
    print_pubkey: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let key_path = args.tp_key.clone().unwrap_or_else(default_pool_key_path);
    let static_keys = StaticKeys::load_or_generate(&key_path)
        .with_context(|| format!("loading pool key from {}", key_path.display()))?;

    if args.print_pubkey {
        println!("{}", static_keys.public_hex());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dinero_sv2_pool=info".into()),
        )
        .init();
    info!(
        key = %key_path.display(),
        pubkey = %static_keys.public_hex(),
        "pool static identity"
    );

    let auth = match (&args.rpc_user, &args.rpc_password, &args.cookie) {
        (Some(u), Some(p), _) => Auth::UserPass(u.clone(), p.clone()),
        _ => Auth::Cookie(args.cookie.clone().unwrap_or_else(default_cookie_path)),
    };
    let rpc = Arc::new(RpcClient::new(args.rpc_url.clone(), auth).context("building rpc client")?);

    let best = rpc
        .get_best_block_hash()
        .await
        .context("initial getbestblockhash — is dinerod running?")?;
    info!(tip = %best, "connected to dinerod");

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;
    info!(bind = %args.bind, "dinero-sv2-pool listening");

    let share_target_fallback = leading_zero_bits_target(args.share_leading_bits);
    let vardiff = if args.vardiff_target_seconds == 0 {
        None
    } else {
        Some(VardiffConfig {
            target_interval_secs: args.vardiff_target_seconds as f64,
            window: if args.vardiff_window_seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(args.vardiff_window_seconds))
            },
        })
    };
    info!(
        vardiff_target_seconds = args.vardiff_target_seconds,
        vardiff_window_seconds = args.vardiff_window_seconds,
        share_leading_bits = args.share_leading_bits,
        "share difficulty policy"
    );
    let ledger = Arc::new(Ledger::default());
    // Per-connection channel id allocator. Channel 1 is reserved as the
    // historical default; new connections take 2, 3, … so pool logs and
    // future SetTarget routing can disambiguate miners on the wire.
    let next_channel_id = Arc::new(AtomicU32::new(2));

    let (tx, rx) = watch::channel::<Option<PoolTemplate>>(None);

    // Template producer task.
    {
        let rpc = rpc.clone();
        let payout = args.payout_address.clone();
        let poll = Duration::from_secs(args.poll_secs);
        let refresh_same_tip = if args.refresh_same_tip_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(args.refresh_same_tip_secs))
        };
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            let mut last_tip: Option<String> = None;
            let mut last_template_at: Option<std::time::Instant> = None;
            let mut last_nbits: Option<u32> = None;
            let mut template_id: u64 = 0;
            loop {
                ticker.tick().await;
                let tip = match rpc.get_best_block_hash().await {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(error = %e, "getbestblockhash failed");
                        continue;
                    }
                };
                let tip_changed = last_tip.as_deref() != Some(tip.as_str());
                let stale_same_tip = match (refresh_same_tip, last_template_at) {
                    (Some(window), Some(t)) => t.elapsed() >= window,
                    (Some(_), None) => true,
                    (None, _) => false,
                };
                if !tip_changed && !stale_same_tip {
                    continue;
                }
                let gbt = match rpc.get_block_template(&payout).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(error = %e, "getblocktemplate failed");
                        continue;
                    }
                };
                template_id = template_id.wrapping_add(1);
                let mut pt = match mapper::map_template(&gbt, template_id) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(error = %e, "map_template failed");
                        continue;
                    }
                };
                match rpc.get_utreexo_roots().await {
                    Ok(v) => match mapper::map_utreexo_roots(&v) {
                        Ok(s) => {
                            debug!(
                                num_leaves = s.num_leaves,
                                num_roots = s.forest_roots.len(),
                                "utreexo pre-block state fetched"
                            );
                            pt.utreexo_pre_block = Some(s);
                        }
                        Err(e) => warn!(error = %e, "map_utreexo_roots failed"),
                    },
                    Err(e) => {
                        warn!(error = %e, "getutreexoroots failed — JD miners won't be able to recompute utreexo_root");
                    }
                }
                let nbits_changed = last_nbits != Some(pt.wire.difficulty);
                if !tip_changed && !nbits_changed {
                    // Same tip, same nbits — daemon hasn't drifted yet. Skip
                    // pushing a new job to avoid spamming miners with
                    // identical NewMiningJob frames.
                    last_template_at = Some(std::time::Instant::now());
                    continue;
                }
                info!(
                    template_id = pt.wire.template_id,
                    tip = %tip,
                    nbits = format!("0x{:08x}", pt.wire.difficulty),
                    nbits_changed,
                    tip_changed,
                    block_target = %hex::encode(pt.block_target),
                    utreexo_leaves = pt.utreexo_pre_block.as_ref().map(|s| s.num_leaves),
                    "new template"
                );
                let _ = tx.send(Some(pt.clone()));
                last_tip = Some(tip);
                last_template_at = Some(std::time::Instant::now());
                last_nbits = Some(pt.wire.difficulty);
            }
        });
    }

    // Miner acceptor.
    loop {
        let (sock, peer) = listener.accept().await?;
        let rx = rx.clone();
        let rpc = rpc.clone();
        let ledger = ledger.clone();
        let share_target_copy = share_target_fallback;
        let keys = static_keys.clone();
        let channel_id = next_channel_id.fetch_add(1, Ordering::Relaxed);
        let vardiff_copy = vardiff;
        tokio::spawn(async move {
            info!(%peer, channel_id, "miner connected — handshake starting");
            let session = match NoiseSession::accept_nx(sock, &keys).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%peer, error = %e, "noise handshake failed");
                    return;
                }
            };
            let miner_key = session.peer_static_key();
            info!(%peer, channel_id, miner = %hex::encode(miner_key), "noise handshake complete");
            if let Err(e) = serve_miner(
                session,
                rx,
                share_target_copy,
                vardiff_copy,
                miner_key,
                rpc,
                ledger,
                channel_id,
            )
            .await
            {
                warn!(%peer, channel_id, error = %e, "miner session ended with error");
            } else {
                info!(%peer, channel_id, "miner disconnected");
            }
        });
    }
}

fn default_cookie_path() -> String {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    format!("{home}/.dinero/.cookie")
}

fn default_pool_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(format!("{home}/.dinero/dinero-sv2-pool.key"))
}

async fn serve_miner(
    mut session: NoiseSession<TcpStream>,
    mut rx: watch::Receiver<Option<PoolTemplate>>,
    share_target_fallback: [u8; 32],
    vardiff: Option<VardiffConfig>,
    miner_key: MinerKey,
    rpc: Arc<RpcClient>,
    ledger: Arc<Ledger>,
    channel_id: u32,
) -> Result<()> {
    // ---- Phase A: SetupConnection ----
    let f = session
        .read_frame()
        .await?
        .context("EOF before SetupConnection")?;
    if f.msg_type != MSG_SETUP_CONNECTION {
        warn!(msg_type = f.msg_type, "expected SetupConnection");
        return Ok(());
    }
    let setup = match decode_setup_connection(&f.payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "bad SetupConnection payload");
            let err = SetupConnectionError {
                flags: 0,
                error_code: b"invalid-payload".to_vec(),
            };
            session
                .write_frame(
                    MSG_SETUP_CONNECTION_ERROR,
                    &encode_setup_connection_error(&err)?,
                )
                .await?;
            return Ok(());
        }
    };
    if setup.protocol != PROTOCOL_MINING {
        let err = SetupConnectionError {
            flags: 0,
            error_code: b"unsupported-protocol".to_vec(),
        };
        session
            .write_frame(
                MSG_SETUP_CONNECTION_ERROR,
                &encode_setup_connection_error(&err)?,
            )
            .await?;
        return Ok(());
    }
    // Simple range check: PROTOCOL_VERSION must fall within the miner's
    // declared [min, max]. Otherwise the dialects are incompatible.
    if PROTOCOL_VERSION < setup.min_version || PROTOCOL_VERSION > setup.max_version {
        let err = SetupConnectionError {
            flags: 0,
            error_code: b"version-incompatible".to_vec(),
        };
        session
            .write_frame(
                MSG_SETUP_CONNECTION_ERROR,
                &encode_setup_connection_error(&err)?,
            )
            .await?;
        return Ok(());
    }
    session
        .write_frame(
            MSG_SETUP_CONNECTION_SUCCESS,
            &encode_setup_connection_success(&SetupConnectionSuccess {
                used_version: PROTOCOL_VERSION,
                flags: 0,
            }),
        )
        .await?;
    info!(
        user_agent = %String::from_utf8_lossy(&setup.user_agent),
        "SetupConnection OK"
    );

    // ---- Phase B: OpenStandardMiningChannel ----
    let f = session
        .read_frame()
        .await?
        .context("EOF before OpenStandardMiningChannel")?;
    if f.msg_type != MSG_OPEN_STANDARD_MINING_CHANNEL {
        warn!(msg_type = f.msg_type, "expected OpenStandardMiningChannel");
        return Ok(());
    }
    let open = match decode_open_standard_mining_channel(&f.payload) {
        Ok(o) => o,
        Err(e) => {
            warn!(error = %e, "bad OpenStandardMiningChannel payload");
            let err = OpenStandardMiningChannelError {
                request_id: 0,
                error_code: b"invalid-payload".to_vec(),
            };
            session
                .write_frame(
                    MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR,
                    &encode_open_standard_mining_channel_error(&err)?,
                )
                .await?;
            return Ok(());
        }
    };
    // Vardiff: size the channel's initial target from the miner's
    // declared `nominal_hash_rate_bits` (a Hz value packed as f32 bits),
    // aiming for ~1 share per `target_interval_secs`. If the miner
    // reports a 0 / NaN / negative rate, or vardiff is disabled, fall
    // back to the pool default.
    let initial_share_target = match vardiff {
        Some(cfg) => {
            let rate_hps = f32::from_bits(open.nominal_hash_rate_bits) as f64;
            let t = target_for_hashrate(rate_hps, cfg.target_interval_secs);
            // Clamp: never give a channel an EASIER target than the
            // pool's default fallback. A miner reporting 0 hashrate
            // shouldn't get an "every hash is a share" target.
            if t > share_target_fallback {
                share_target_fallback
            } else {
                t
            }
        }
        None => share_target_fallback,
    };
    let mut share_target = initial_share_target;
    info!(
        channel_id,
        nominal_hps = f32::from_bits(open.nominal_hash_rate_bits),
        vardiff = vardiff.is_some(),
        initial_target = %hex::encode(initial_share_target),
        "channel-open vardiff sizing",
    );
    // Miner's max_target must be ≥ the pool's assigned share target;
    // otherwise the miner's hardware can't produce shares we'd accept.
    if open.max_target < share_target {
        let err = OpenStandardMiningChannelError {
            request_id: open.request_id,
            error_code: b"max-target-too-low".to_vec(),
        };
        session
            .write_frame(
                MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR,
                &encode_open_standard_mining_channel_error(&err)?,
            )
            .await?;
        return Ok(());
    }
    session
        .write_frame(
            MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            &encode_open_standard_mining_channel_success(&OpenStandardMiningChannelSuccess {
                request_id: open.request_id,
                channel_id,
                target: share_target,
            }),
        )
        .await?;
    info!(
        channel_id,
        user_identity = %String::from_utf8_lossy(&open.user_identity),
        "channel open"
    );

    // ---- Phase C: normal operation ----
    let mut current: Option<PoolTemplate> = None;
    let mut last_sequence_number: u32 = 0;

    let initial = rx.borrow_and_update().clone();
    if let Some(pt) = initial {
        push_job(&mut session, channel_id, &pt).await?;
        current = Some(pt);
    }

    // Vardiff measurement: count accepted shares since the last
    // retarget tick, recompute observed rate, emit MSG_SET_TARGET if
    // the new sizing is materially different from the current target.
    // Disabled when `vardiff.window` is None or vardiff itself is None.
    let mut accepted_in_window: u64 = 0;
    let mut window_start = std::time::Instant::now();
    let vardiff_window = vardiff.and_then(|v| v.window);
    let mut vardiff_tick = vardiff_window
        .map(|w| {
            let mut t = tokio::time::interval(w);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // First tick fires immediately; consume it so we wait a
            // full window before our first measurement.
            t
        });

    loop {
        tokio::select! {
            biased;

            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let maybe_t = rx.borrow_and_update().clone();
                if let Some(pt) = maybe_t {
                    push_job(&mut session, channel_id, &pt).await?;
                    current = Some(pt);
                }
            }

            // Vardiff retargeting: only armed when configured. Sized so
            // the next-emitted target produces ~1 share / target_interval
            // at the OBSERVED rate (smoothed against the last setting).
            _ = async {
                match vardiff_tick.as_mut() {
                    Some(t) => { t.tick().await; }
                    None => std::future::pending::<()>().await,
                }
            }, if vardiff_tick.is_some() => {
                if let Some(cfg) = vardiff {
                    let elapsed = window_start.elapsed().as_secs_f64().max(0.001);
                    let observed_share_rate = accepted_in_window as f64 / elapsed;
                    if observed_share_rate > 0.0 {
                        // observed_share_rate (shares/sec) under the CURRENT
                        // target T means hashrate ≈ shares/sec × 2²⁵⁶ / T,
                        // and a ~1-share-per-interval target needs hashrate
                        // × interval. Easier to express in terms of the
                        // current target shape: new_target = current_target ×
                        // (shares observed) / (shares we wanted).
                        //
                        // But we already track hashrate via the miner's
                        // declared `nominal_hash_rate_bits` at open. After
                        // one window we have a much better number:
                        //   hashrate = (shares × 2²⁵⁶ / current_target) /
                        //              elapsed
                        // For the leading-zero-target shape, that simplifies
                        // to a small integer adjustment in `bits`. Recompute
                        // from observed rate directly via `target_for_hashrate`.
                        let leading_zero_bits_in_current =
                            count_leading_zero_bits(&share_target) as f64;
                        let work_per_share = 2f64.powf(leading_zero_bits_in_current);
                        let inferred_hashrate = observed_share_rate * work_per_share;
                        let new_target = target_for_hashrate(
                            inferred_hashrate,
                            cfg.target_interval_secs,
                        );
                        // Clamp easier-than-fallback (paranoia).
                        let new_target = if new_target > share_target_fallback {
                            share_target_fallback
                        } else {
                            new_target
                        };
                        if new_target != share_target {
                            info!(
                                channel_id,
                                accepted_in_window,
                                window_secs = elapsed,
                                observed_rate_per_sec = observed_share_rate,
                                inferred_hashrate_hps = inferred_hashrate,
                                new_target = %hex::encode(new_target),
                                old_target = %hex::encode(share_target),
                                "vardiff retarget"
                            );
                            share_target = new_target;
                            let payload = encode_set_target(
                                &dinero_sv2_common::SetTarget {
                                    channel_id,
                                    max_target: share_target,
                                },
                            );
                            session.write_frame(MSG_SET_TARGET, &payload).await?;
                        }
                    }
                    accepted_in_window = 0;
                    window_start = std::time::Instant::now();
                }
            }

            frame = session.read_frame() => {
                let f = match frame? {
                    Some(f) => f,
                    None => return Ok(()),
                };
                let Frame { msg_type: mtype, payload, .. } = f;
                match mtype {
                    MSG_SUBMIT_SHARES_STANDARD => {
                        handle_share(
                            &mut session,
                            &payload,
                            current.as_ref(),
                            share_target,
                            channel_id,
                            &mut last_sequence_number,
                            &mut accepted_in_window,
                            miner_key,
                            rpc.as_ref(),
                            ledger.as_ref(),
                        )
                        .await?;
                    }
                    MSG_SUBMIT_SHARES_EXTENDED => {
                        handle_extended_share(
                            &mut session,
                            &payload,
                            current.as_ref(),
                            share_target,
                            channel_id,
                            &mut last_sequence_number,
                            &mut accepted_in_window,
                            miner_key,
                            rpc.as_ref(),
                            ledger.as_ref(),
                        )
                        .await?;
                    }
                    other => warn!(msg_type = other, "unexpected frame type from miner"),
                }
            }
        }
    }
}

/// Emit `SetNewPrevHash`, optionally `UtreexoStateAnnouncement`, then
/// `NewMiningJob` for this template.
///
/// Every push starts with `SetNewPrevHash` so miners can explicitly
/// invalidate any in-flight work on the old tip. Between that and the
/// job, the pool sends the pre-coinbase Utreexo forest state (when
/// available from dinerod) so JD-aware miners can apply their own
/// coinbase leaves and recompute the header's `utreexo_root` —
/// observable on the wire even before a miner actually diverges
/// (useful Phase 4b verification).
async fn push_job(
    session: &mut NoiseSession<TcpStream>,
    channel_id: u32,
    pt: &PoolTemplate,
) -> Result<()> {
    let snph = SetNewPrevHash {
        channel_id,
        prev_hash: pt.wire.prev_block_hash,
        min_ntime: pt.wire.timestamp,
        nbits: pt.wire.difficulty,
    };
    session
        .write_frame(MSG_SET_NEW_PREV_HASH, &encode_set_new_prev_hash(&snph))
        .await?;

    if let Some(state) = &pt.utreexo_pre_block {
        let payload = encode_utreexo_accumulator_state(state)
            .map_err(|e| anyhow::anyhow!("utreexo state encode: {e}"))?;
        session.write_frame(MSG_UTREEXO_STATE, &payload).await?;

        // When we have pre-block state, we also have the coinbase
        // fragments + height + value the miner needs for JD. Emit
        // `MSG_COINBASE_CONTEXT` so extended-share miners can assemble
        // their own coinbase.
        let ctx = CoinbaseContext {
            channel_id,
            coinbase_prefix: pt.coinbase_prefix.clone(),
            coinbase_suffix: pt.coinbase_suffix.clone(),
            merkle_path: pt.merkle_path.clone(),
            height: pt.height,
            coinbase_value_una: pt.coinbase_value_una,
        };
        let payload = encode_coinbase_context(&ctx)
            .map_err(|e| anyhow::anyhow!("coinbase context encode: {e}"))?;
        session.write_frame(MSG_COINBASE_CONTEXT, &payload).await?;
    }

    let payload = encode_new_template(&pt.wire);
    session.write_frame(MSG_NEW_MINING_JOB, &payload).await?;
    debug!(
        template_id = pt.wire.template_id,
        utreexo_leaves = pt.utreexo_pre_block.as_ref().map(|s| s.num_leaves),
        "pushed SNPH + (utreexo + ctx) + job"
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_share(
    session: &mut NoiseSession<TcpStream>,
    payload: &[u8],
    current: Option<&PoolTemplate>,
    share_target: [u8; 32],
    channel_id: u32,
    last_sequence_number: &mut u32,
    accepted_in_window: &mut u64,
    miner_key: MinerKey,
    rpc: &RpcClient,
    ledger: &Ledger,
) -> Result<()> {
    let share = match decode_submit_shares(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "bad share shape");
            ledger.reject(miner_key);
            let err = SubmitSharesError {
                channel_id,
                sequence_number: *last_sequence_number,
                error_code: b"invalid-payload".to_vec(),
            };
            session
                .write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?)
                .await?;
            return Ok(());
        }
    };
    *last_sequence_number = share.sequence_number;

    let Some(pt) = current else {
        warn!("share received before any template");
        ledger.reject(miner_key);
        let err = SubmitSharesError {
            channel_id,
            sequence_number: share.sequence_number,
            error_code: b"no-template".to_vec(),
        };
        session
            .write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?)
            .await?;
        return Ok(());
    };

    let hash = HeaderAssembly::hash(&pt.wire, &share);
    let meets_share = hash_meets_target(&hash, &share_target);
    let meets_block = hash_meets_target(&hash, &pt.block_target);

    if !meets_share {
        debug!(hash = %hex::encode(hash), "share below share-target");
        let err = SubmitSharesError {
            channel_id,
            sequence_number: share.sequence_number,
            error_code: b"under-target".to_vec(),
        };
        session
            .write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?)
            .await?;
        return Ok(());
    }

    ledger.credit_share(miner_key);
    *accepted_in_window += 1;
    info!(
        hash = %hex::encode(hash),
        template_id = pt.wire.template_id,
        nonce = share.nonce,
        "accepted share"
    );
    session
        .write_frame(
            MSG_SUBMIT_SHARES_SUCCESS,
            &encode_submit_shares_success(&SubmitSharesSuccess {
                channel_id,
                last_sequence_number: share.sequence_number,
                new_submits_accepted_count: 1,
                new_shares_sum: 1,
            }),
        )
        .await?;

    if meets_block {
        match try_submit_block(&pt.wire, &share, &pt.coinbase_full_hex, rpc).await {
            Ok(SubmitBlockResult::Accepted) => {
                info!(
                    template_id = pt.wire.template_id,
                    hash = %hex::encode(hash),
                    "★ block accepted by dinerod"
                );
                ledger.credit_block(miner_key);
            }
            Ok(SubmitBlockResult::Rejected(reason)) => {
                warn!(
                    reason,
                    hash = %hex::encode(hash),
                    "dinerod rejected our block"
                );
            }
            Err(e) => {
                warn!(error = %e, "submitblock RPC failed");
            }
        }
    }

    Ok(())
}

async fn try_submit_block(
    template: &dinero_sv2_common::NewTemplateDinero,
    share: &SubmitSharesDinero,
    coinbase_full_hex: &str,
    rpc: &RpcClient,
) -> Result<SubmitBlockResult> {
    let block_hex = block::assemble_block_hex(template, share, coinbase_full_hex)?;
    rpc.submit_block(&block_hex).await
}

// =====================================================================
// Phase 5: extended-share handling (miner supplies its own coinbase)
// =====================================================================

#[allow(clippy::too_many_arguments)]
async fn handle_extended_share(
    session: &mut NoiseSession<TcpStream>,
    payload: &[u8],
    current: Option<&PoolTemplate>,
    share_target: [u8; 32],
    channel_id: u32,
    last_sequence_number: &mut u32,
    accepted_in_window: &mut u64,
    miner_key: MinerKey,
    rpc: &RpcClient,
    ledger: &Ledger,
) -> Result<()> {
    let ext = match decode_submit_shares_extended(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "bad extended share shape");
            ledger.reject(miner_key);
            let err = SubmitSharesError {
                channel_id,
                sequence_number: *last_sequence_number,
                error_code: b"invalid-payload".to_vec(),
            };
            session
                .write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?)
                .await?;
            return Ok(());
        }
    };
    *last_sequence_number = ext.sequence_number;

    let Some(pt) = current else {
        warn!("extended share before any template");
        ledger.reject(miner_key);
        send_share_error(session, channel_id, ext.sequence_number, "no-template").await?;
        return Ok(());
    };
    let Some(pre_block_state) = pt.utreexo_pre_block.as_ref() else {
        warn!("extended share but no pre-block Utreexo state");
        ledger.reject(miner_key);
        send_share_error(session, channel_id, ext.sequence_number, "no-utreexo-state").await?;
        return Ok(());
    };

    // 1. Validate the output value sum matches the block's coinbase value.
    let miner_total: u64 = ext.coinbase_outputs.iter().map(|o| o.value_una).sum();
    if miner_total != pt.coinbase_value_una {
        warn!(
            miner_total,
            expected = pt.coinbase_value_una,
            "extended share: coinbase output sum mismatch"
        );
        ledger.reject(miner_key);
        send_share_error(session, channel_id, ext.sequence_number, "value-mismatch").await?;
        return Ok(());
    }

    // 1b. Past the DNRF activation height, the coinbase MUST contain at
    //     least one OP_RETURN output with the DNRF commitment shape.
    //     Without this, dinerod rejects the block at submitblock and a
    //     found block is burned. We only validate the script SHAPE here
    //     (39 bytes, "DNRF" magic, version 0x01); dinerod re-verifies the
    //     filter_hash payload against the block's actual filter at
    //     accept-time. A buggy or stale miner client sending zero DNRF
    //     outputs is exactly the failure mode this guards.
    if requires_filter_commitment(pt.height as u64)
        && !ext
            .coinbase_outputs
            .iter()
            .any(|o| is_dnrf_script(&o.script_pubkey))
    {
        warn!(
            height = pt.height,
            outputs = ext.coinbase_outputs.len(),
            "extended share: missing DNRF commitment in miner outputs"
        );
        ledger.reject(miner_key);
        send_share_error(session, channel_id, ext.sequence_number, "missing-dnrf").await?;
        return Ok(());
    }

    // 2. Reassemble the stripped coinbase using pool's prefix/suffix
    //    and the miner's outputs.
    let miner_outputs: Vec<CoinbaseOutput> = ext
        .coinbase_outputs
        .iter()
        .map(|w| CoinbaseOutput {
            value_una: w.value_una,
            script_pubkey: w.script_pubkey.clone(),
        })
        .collect();
    let (coinbase_stripped, coinbase_txid) =
        assemble_stripped_coinbase(&pt.coinbase_prefix, &miner_outputs, &pt.coinbase_suffix);

    // 3. Compute Utreexo leaf hashes for each output and apply.
    let mut post_state = pre_block_state.clone();
    for (i, out) in miner_outputs.iter().enumerate() {
        let leaf = leaf_hash(&coinbase_txid, i as u32, out.value_una, &out.script_pubkey);
        if let Err(e) = post_state.add_leaf(leaf) {
            warn!(error = %e, "utreexo add_leaf failed");
            ledger.reject(miner_key);
            send_share_error(session, channel_id, ext.sequence_number, "utreexo-apply").await?;
            return Ok(());
        }
    }
    let utreexo_root = match utreexo_commitment(&post_state) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = %e, "utreexo commitment failed");
            ledger.reject(miner_key);
            send_share_error(session, channel_id, ext.sequence_number, "utreexo-commit").await?;
            return Ok(());
        }
    };

    // 4. Merkle root from coinbase txid + (possibly empty) merkle_path.
    let merkle_root = compute_root(coinbase_txid, &pt.merkle_path);

    // 5. Reconstruct the header via `HeaderAssembly` using our
    //    computed (merkle_root, utreexo_root) and miner's (nonce,
    //    ntime, version). Everything else inherits from the job.
    let reconstructed = NewTemplateDinero {
        template_id: pt.wire.template_id,
        future_template: false,
        version: ext.version,
        prev_block_hash: pt.wire.prev_block_hash,
        merkle_root,
        utreexo_root,
        timestamp: ext.timestamp,
        difficulty: pt.wire.difficulty,
        coinbase_outputs_commitment: [0u8; 32], // not header-relevant
    };
    let share = SubmitSharesDinero {
        channel_id: ext.channel_id,
        sequence_number: ext.sequence_number,
        job_id: ext.job_id,
        nonce: ext.nonce,
        timestamp: ext.timestamp,
        version: ext.version,
    };
    let hash = HeaderAssembly::hash(&reconstructed, &share);
    let meets_share = hash_meets_target(&hash, &share_target);
    let meets_block = hash_meets_target(&hash, &pt.block_target);

    if !meets_share {
        debug!(hash = %hex::encode(hash), "extended share below share-target");
        send_share_error(session, channel_id, ext.sequence_number, "under-target").await?;
        return Ok(());
    }

    ledger.credit_share(miner_key);
    *accepted_in_window += 1;
    info!(
        hash = %hex::encode(hash),
        template_id = pt.wire.template_id,
        nonce = ext.nonce,
        utreexo_root = %hex::encode(utreexo_root),
        "accepted extended share"
    );
    session
        .write_frame(
            MSG_SUBMIT_SHARES_SUCCESS,
            &encode_submit_shares_success(&SubmitSharesSuccess {
                channel_id,
                last_sequence_number: ext.sequence_number,
                new_submits_accepted_count: 1,
                new_shares_sum: 1,
            }),
        )
        .await?;

    if meets_block {
        // Reassemble the full block (segwit coinbase) for submitblock:
        //   stripped-coinbase bytes with segwit marker+flag inserted
        //   after version, and the pool-retained witness bytes inserted
        //   before the locktime.
        let full_coinbase = wrap_stripped_with_segwit_witness(
            &coinbase_stripped,
            &pt.coinbase_witness_bytes,
            &pt.coinbase_suffix,
        );
        match block::assemble_block_hex_raw(&reconstructed, &share, &full_coinbase) {
            Ok(block_hex) => match rpc.submit_block(&block_hex).await {
                Ok(SubmitBlockResult::Accepted) => {
                    info!("★ extended-share block ACCEPTED by dinerod");
                    ledger.credit_block(miner_key);
                }
                Ok(SubmitBlockResult::Rejected(reason)) => {
                    warn!(reason, "dinerod rejected our extended-share block");
                }
                Err(e) => warn!(error = %e, "submitblock RPC failed"),
            },
            Err(e) => warn!(error = %e, "assemble_block_hex_raw failed"),
        }
    }

    Ok(())
}

async fn send_share_error(
    session: &mut NoiseSession<TcpStream>,
    channel_id: u32,
    sequence_number: u32,
    code: &str,
) -> Result<()> {
    let err = SubmitSharesError {
        channel_id,
        sequence_number,
        error_code: code.as_bytes().to_vec(),
    };
    session
        .write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?)
        .await?;
    Ok(())
}

/// Wrap a stripped (non-segwit) coinbase with the retained segwit
/// marker/flag + witness bytes so the result is the broadcast form
/// dinerod expects in `submitblock`.
///
/// Inputs:
/// - `stripped`: version || vin || vout || locktime
/// - `witness_bytes`: the per-input witness stacks exactly as the
///   daemon emitted them for the original template
/// - `suffix`: just the 4-byte locktime (must match `stripped`'s tail)
fn wrap_stripped_with_segwit_witness(
    stripped: &[u8],
    witness_bytes: &[u8],
    suffix: &[u8],
) -> Vec<u8> {
    // stripped = version(4) || vin+vout || locktime(4)
    // broadcast = version(4) || 00 01 || vin+vout || witness || locktime(4)
    let locktime_len = suffix.len(); // typically 4
    assert!(stripped.len() >= 4 + locktime_len);
    let mid_end = stripped.len() - locktime_len;
    let mut out = Vec::with_capacity(stripped.len() + 2 + witness_bytes.len());
    out.extend_from_slice(&stripped[..4]); // version
    out.extend_from_slice(&[0x00, 0x01]); // segwit marker + flag
    out.extend_from_slice(&stripped[4..mid_end]); // vin + vout
    out.extend_from_slice(witness_bytes); // witness stacks
    out.extend_from_slice(&stripped[mid_end..]); // locktime
    out
}

/// Count leading zero bits in a 32-byte big-endian target. Used to
/// estimate the miner's effective hashrate from observed share count
/// under the current target shape (which is always `0..0 1..1` from
/// `leading_zero_bits_target`). For a non-leading-zero-shape target
/// this is just an approximation, but the vardiff loop only ever
/// produces leading-zero-shape targets so the cycle is consistent.
fn count_leading_zero_bits(target: &[u8; 32]) -> u32 {
    let mut bits = 0u32;
    for byte in target {
        if *byte == 0 {
            bits += 8;
        } else {
            bits += byte.leading_zeros();
            break;
        }
    }
    bits
}
