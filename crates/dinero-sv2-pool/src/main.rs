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
use dinero_sv2_codec::{decode_submit_shares, encode_new_template};
use dinero_sv2_common::{HeaderAssembly, SubmitSharesDinero};
use dinero_sv2_transport::{
    Frame, NoiseSession, StaticKeys, ACK_BAD_SHAPE, ACK_OK, ACK_UNDER_TARGET, MSG_NEW_TEMPLATE,
    MSG_SHARE_ACK, MSG_SUBMIT_SHARES,
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

async fn serve_miner(
    mut session: NoiseSession<TcpStream>,
    mut rx: watch::Receiver<Option<PoolTemplate>>,
    share_target: [u8; 32],
    miner_key: MinerKey,
    rpc: Arc<RpcClient>,
    ledger: Arc<Ledger>,
) -> Result<()> {
    let mut current: Option<PoolTemplate> = None;

    let initial = rx.borrow_and_update().clone();
    if let Some(pt) = initial {
        let payload = encode_new_template(&pt.wire);
        session.write_frame(MSG_NEW_TEMPLATE, &payload).await?;
        debug!(template_id = pt.wire.template_id, "pushed initial template");
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
                    let payload = encode_new_template(&pt.wire);
                    session.write_frame(MSG_NEW_TEMPLATE, &payload).await?;
                    debug!(template_id = pt.wire.template_id, "pushed template");
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
                    MSG_SUBMIT_SHARES => {
                        handle_share(
                            &mut session,
                            &payload,
                            current.as_ref(),
                            share_target,
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

async fn handle_share(
    session: &mut NoiseSession<TcpStream>,
    payload: &[u8],
    current: Option<&PoolTemplate>,
    share_target: [u8; 32],
    miner_key: MinerKey,
    rpc: &RpcClient,
    ledger: &Ledger,
) -> Result<()> {
    let share = match decode_submit_shares(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "bad share shape");
            ledger.reject(miner_key);
            session.write_frame(MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
            return Ok(());
        }
    };
    let Some(pt) = current else {
        warn!("share received before any template");
        ledger.reject(miner_key);
        session.write_frame(MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
        return Ok(());
    };

    let hash = HeaderAssembly::hash(&pt.wire, &share);
    let meets_share = hash_meets_target(&hash, &share_target);
    let meets_block = hash_meets_target(&hash, &pt.block_target);

    if !meets_share {
        debug!(hash = %hex::encode(hash), "share below share-target");
        session
            .write_frame(MSG_SHARE_ACK, &[ACK_UNDER_TARGET])
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
    session.write_frame(MSG_SHARE_ACK, &[ACK_OK]).await?;

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
