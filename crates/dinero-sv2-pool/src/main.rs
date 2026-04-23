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

mod accounting;
mod block;
mod mapper;
mod rpc;
mod target;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dinero_sv2_codec::{
    decode_open_standard_mining_channel, decode_setup_connection, decode_submit_shares,
    encode_new_template, encode_open_standard_mining_channel_error,
    encode_open_standard_mining_channel_success, encode_set_new_prev_hash,
    encode_setup_connection_error, encode_setup_connection_success, encode_submit_shares_error,
    encode_submit_shares_success,
};
use dinero_sv2_common::{
    HeaderAssembly, OpenStandardMiningChannelError, OpenStandardMiningChannelSuccess,
    SetNewPrevHash, SetupConnectionError, SetupConnectionSuccess, SubmitSharesDinero,
    SubmitSharesError, SubmitSharesSuccess, PROTOCOL_MINING, PROTOCOL_VERSION,
};
use dinero_sv2_transport::{
    Frame, NoiseSession, StaticKeys, MSG_NEW_MINING_JOB, MSG_OPEN_STANDARD_MINING_CHANNEL,
    MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR, MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MSG_SETUP_CONNECTION, MSG_SETUP_CONNECTION_ERROR, MSG_SETUP_CONNECTION_SUCCESS,
    MSG_SET_NEW_PREV_HASH, MSG_SUBMIT_SHARES_ERROR, MSG_SUBMIT_SHARES_STANDARD,
    MSG_SUBMIT_SHARES_SUCCESS,
};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::accounting::{Ledger, MinerKey};
use crate::mapper::PoolTemplate;
use crate::rpc::{Auth, RpcClient, SubmitBlockResult};
use crate::target::{hash_meets_target, leading_zero_bits_target};

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

    /// Share acceptance target: leading zero bits required on the
    /// header hash for a share to be *credited*. 0 = credit every
    /// structurally valid share. Keep this far looser than the block
    /// target so miners get regular feedback.
    #[arg(long, default_value_t = 8)]
    share_leading_bits: u32,

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

    let share_target = leading_zero_bits_target(args.share_leading_bits);
    let ledger = Arc::new(Ledger::default());

    let (tx, rx) = watch::channel::<Option<PoolTemplate>>(None);

    // Template producer task.
    {
        let rpc = rpc.clone();
        let payout = args.payout_address.clone();
        let poll = Duration::from_secs(args.poll_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(poll);
            let mut last_tip: Option<String> = None;
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
                if last_tip.as_deref() == Some(tip.as_str()) {
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
                let pt = match mapper::map_template(&gbt, template_id) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(error = %e, "map_template failed");
                        continue;
                    }
                };
                info!(
                    template_id = pt.wire.template_id,
                    tip = %tip,
                    block_target = %hex::encode(pt.block_target),
                    "new template"
                );
                let _ = tx.send(Some(pt));
                last_tip = Some(tip);
            }
        });
    }

    // Miner acceptor.
    loop {
        let (sock, peer) = listener.accept().await?;
        let rx = rx.clone();
        let rpc = rpc.clone();
        let ledger = ledger.clone();
        let share_target_copy = share_target;
        let keys = static_keys.clone();
        tokio::spawn(async move {
            info!(%peer, "miner connected — handshake starting");
            let session = match NoiseSession::accept_nx(sock, &keys).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(%peer, error = %e, "noise handshake failed");
                    return;
                }
            };
            let miner_key = session.peer_static_key();
            info!(%peer, miner = %hex::encode(miner_key), "noise handshake complete");
            if let Err(e) =
                serve_miner(session, rx, share_target_copy, miner_key, rpc, ledger).await
            {
                warn!(%peer, error = %e, "miner session ended with error");
            } else {
                info!(%peer, "miner disconnected");
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

/// Pool-assigned channel id for the single channel per connection that
/// Pass B supports. Real multi-channel bookkeeping is Pass C material.
const DEFAULT_CHANNEL_ID: u32 = 1;

async fn serve_miner(
    mut session: NoiseSession<TcpStream>,
    mut rx: watch::Receiver<Option<PoolTemplate>>,
    share_target: [u8; 32],
    miner_key: MinerKey,
    rpc: Arc<RpcClient>,
    ledger: Arc<Ledger>,
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
    let channel_id = DEFAULT_CHANNEL_ID;
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

/// Emit `SetNewPrevHash` followed by `NewMiningJob` for this template.
///
/// Every push is preceded by `SetNewPrevHash` so miners can explicitly
/// invalidate any in-flight work on the old tip — required by SV2 for
/// correct share/stale accounting on fast re-orgs and per-tick target
/// updates.
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
    let payload = encode_new_template(&pt.wire);
    session.write_frame(MSG_NEW_MINING_JOB, &payload).await?;
    debug!(template_id = pt.wire.template_id, "pushed SNPH + job");
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
