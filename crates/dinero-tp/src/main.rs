//! `dinero-tp` — Stratum V2 Template Provider for Dinero.
//!
//! Binds to a running `dinerod` over HTTP JSON-RPC, polls the tip, and on
//! every tip change fetches `getblocktemplate`, maps it into a
//! [`NewTemplateDinero`] via [`mapper::map_template`], and broadcasts the
//! encoded frame to every connected miner over clear-text TCP framing
//! from `dinero-sv2-transport`.
//!
//! Phase 2.1 is deliberately clear-text. Noise NX wrapping is Phase 2.2.
//! Share submission from miners is accepted and validated against the
//! currently-broadcast template, matching the tp-sim semantics.

mod mapper;
mod rpc;

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dinero_sv2_codec::{decode_submit_shares, encode_new_template};
use dinero_sv2_common::{HeaderAssembly, NewTemplateDinero};
use dinero_sv2_transport::{
    NoiseSession, StaticKeys, ACK_BAD_SHAPE, ACK_OK, ACK_UNDER_TARGET, MSG_NEW_TEMPLATE,
    MSG_SHARE_ACK, MSG_SUBMIT_SHARES,
};
use std::path::PathBuf;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::rpc::{Auth, RpcClient};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Bind address for miner connections.
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: SocketAddr,

    /// dinerod RPC URL.
    #[arg(long, default_value = "http://127.0.0.1:20998")]
    rpc_url: String,

    /// Path to the .cookie file (default: ~/.dinero/.cookie). Ignored if
    /// --rpc-user and --rpc-password are both set.
    #[arg(long)]
    cookie: Option<String>,

    /// rpcuser from dinero.conf (optional; requires --rpc-password).
    #[arg(long)]
    rpc_user: Option<String>,

    /// rpcpassword from dinero.conf (optional; requires --rpc-user).
    #[arg(long)]
    rpc_password: Option<String>,

    /// Payout address to hand to getblocktemplate (must be a valid
    /// Dinero Taproot or P2MR address).
    #[arg(long)]
    payout_address: String,

    /// Tip-poll interval.
    #[arg(long, default_value_t = 2)]
    poll_secs: u64,

    /// Share acceptance target — leading zero bits required. 0 = accept
    /// all structurally-valid shares (Phase 2.1 simulator default).
    #[arg(long, default_value_t = 0)]
    leading_zero_bits: u8,

    /// Static Noise identity file. 64 bytes: `priv[0..32] || pub[32..64]`.
    /// Auto-generated on first run with `0600` perms.
    #[arg(long)]
    tp_key: Option<PathBuf>,

    /// Print the TP's static public key (hex) and exit.
    #[arg(long)]
    print_pubkey: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let key_path = args.tp_key.clone().unwrap_or_else(default_tp_key_path);
    let static_keys = StaticKeys::load_or_generate(&key_path)
        .with_context(|| format!("loading TP key from {}", key_path.display()))?;

    if args.print_pubkey {
        println!("{}", static_keys.public_hex());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dinero_tp=info".into()),
        )
        .init();
    info!(
        key = %key_path.display(),
        pubkey = %static_keys.public_hex(),
        "TP static identity"
    );

    let auth = match (&args.rpc_user, &args.rpc_password, &args.cookie) {
        (Some(u), Some(p), _) => Auth::UserPass(u.clone(), p.clone()),
        _ => Auth::Cookie(args.cookie.clone().unwrap_or_else(default_cookie_path)),
    };
    let rpc = RpcClient::new(args.rpc_url.clone(), auth).context("building rpc client")?;

    // Smoke-test the connection and payout address before binding miners.
    let best = rpc
        .get_best_block_hash()
        .await
        .context("initial getbestblockhash — is dinerod running?")?;
    info!(tip = %best, "connected to dinerod");

    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;
    info!(bind = %args.bind, "dinero-tp listening");

    let (tx, rx) = watch::channel::<Option<NewTemplateDinero>>(None);

    // Template producer task: poll getbestblockhash; on tip change (or
    // first tick) call getblocktemplate, map it, publish.
    {
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
                let t = match mapper::map_template(&gbt, template_id) {
                    Ok(t) => t,
                    Err(e) => {
                        warn!(error = %e, "map_template failed");
                        continue;
                    }
                };
                info!(
                    template_id = t.template_id,
                    tip = %tip,
                    "new template"
                );
                let _ = tx.send(Some(t));
                last_tip = Some(tip);
            }
        });
    }

    loop {
        let (sock, peer) = listener.accept().await?;
        let rx = rx.clone();
        let leading = args.leading_zero_bits;
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
            info!(%peer, "noise handshake complete");
            if let Err(e) = serve_miner(session, rx, leading).await {
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

fn default_tp_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(format!("{home}/.dinero/dinero-tp.key"))
}

async fn serve_miner(
    mut session: NoiseSession<TcpStream>,
    mut rx: watch::Receiver<Option<NewTemplateDinero>>,
    leading: u8,
) -> Result<()> {
    let mut current: Option<NewTemplateDinero> = None;

    // Send the current template (if any) right after connect, instead of
    // making the miner wait for the next tip change.
    let initial = rx.borrow_and_update().clone();
    if let Some(t) = initial {
        let payload = encode_new_template(&t);
        session.write_frame(MSG_NEW_TEMPLATE, &payload).await?;
        debug!(template_id = t.template_id, "pushed initial template");
        current = Some(t);
    }

    loop {
        tokio::select! {
            biased;

            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(()); // sender dropped
                }
                let maybe_t = rx.borrow_and_update().clone();
                if let Some(t) = maybe_t {
                    let payload = encode_new_template(&t);
                    session.write_frame(MSG_NEW_TEMPLATE, &payload).await?;
                    debug!(template_id = t.template_id, "pushed template");
                    current = Some(t);
                }
            }

            frame = session.read_frame() => {
                let (mtype, payload) = match frame? {
                    Some(f) => f,
                    None => return Ok(()),
                };
                match mtype {
                    MSG_SUBMIT_SHARES => {
                        let share = match decode_submit_shares(&payload) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(error = %e, "bad share shape");
                                session.write_frame(MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
                                continue;
                            }
                        };
                        let Some(tmpl) = current.as_ref() else {
                            warn!("share before any template");
                            session.write_frame(MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
                            continue;
                        };
                        let hash = HeaderAssembly::hash(tmpl, &share);
                        if meets_leading_zero_bits(&hash, leading) {
                            info!(
                                hash = %hex::encode(hash),
                                leading,
                                template_id = tmpl.template_id,
                                nonce = share.nonce,
                                "accepted share"
                            );
                            session.write_frame(MSG_SHARE_ACK, &[ACK_OK]).await?;
                        } else {
                            debug!(hash = %hex::encode(hash), "share under target");
                            session.write_frame(MSG_SHARE_ACK, &[ACK_UNDER_TARGET]).await?;
                        }
                    }
                    other => warn!(msg_type = other, "unexpected frame type from miner"),
                }
            }
        }
    }
}

fn meets_leading_zero_bits(hash: &[u8; 32], bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let full_zero_bytes = (bits / 8) as usize;
    for byte in &hash[..full_zero_bytes] {
        if *byte != 0 {
            return false;
        }
    }
    let remainder = bits % 8;
    if remainder == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - remainder);
    (hash[full_zero_bytes] & mask) == 0
}
