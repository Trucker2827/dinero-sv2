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
use dinero_sv2_codec::{
    decode_open_standard_mining_channel, decode_setup_connection, decode_submit_shares,
    encode_new_template, encode_open_standard_mining_channel_error,
    encode_open_standard_mining_channel_success, encode_set_new_prev_hash,
    encode_setup_connection_error, encode_setup_connection_success, encode_submit_shares_error,
    encode_submit_shares_success,
};
use dinero_sv2_common::{
    HeaderAssembly, NewTemplateDinero, OpenStandardMiningChannelError,
    OpenStandardMiningChannelSuccess, SetNewPrevHash, SetupConnectionError, SetupConnectionSuccess,
    SubmitSharesError, SubmitSharesSuccess, PROTOCOL_MINING, PROTOCOL_VERSION,
};
use dinero_sv2_transport::{
    Frame, NoiseSession, StaticKeys, MSG_NEW_MINING_JOB, MSG_OPEN_STANDARD_MINING_CHANNEL,
    MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR, MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
    MSG_SETUP_CONNECTION, MSG_SETUP_CONNECTION_ERROR, MSG_SETUP_CONNECTION_SUCCESS,
    MSG_SET_NEW_PREV_HASH, MSG_SUBMIT_SHARES_ERROR, MSG_SUBMIT_SHARES_STANDARD,
    MSG_SUBMIT_SHARES_SUCCESS,
};
use std::path::PathBuf;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::rpc::{Auth, RpcClient};

const DEFAULT_CHANNEL_ID: u32 = 1;

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
    // Phase A: SetupConnection
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
    if setup.protocol != PROTOCOL_MINING
        || PROTOCOL_VERSION < setup.min_version
        || PROTOCOL_VERSION > setup.max_version
    {
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

    // Phase B: OpenStandardMiningChannel
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
    let channel_id = DEFAULT_CHANNEL_ID;
    let target = leading_zero_target(leading);
    session
        .write_frame(
            MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            &encode_open_standard_mining_channel_success(&OpenStandardMiningChannelSuccess {
                request_id: open.request_id,
                channel_id,
                target,
            }),
        )
        .await?;

    // Phase C: normal operation
    let mut current: Option<NewTemplateDinero> = None;
    let mut last_sequence_number: u32 = 0;

    let initial = rx.borrow_and_update().clone();
    if let Some(t) = initial {
        push_job(&mut session, channel_id, &t).await?;
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
                    push_job(&mut session, channel_id, &t).await?;
                    current = Some(t);
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
                        let share = match decode_submit_shares(&payload) {
                            Ok(s) => s,
                            Err(e) => {
                                warn!(error = %e, "bad share shape");
                                let err = SubmitSharesError {
                                    channel_id,
                                    sequence_number: last_sequence_number,
                                    error_code: b"invalid-payload".to_vec(),
                                };
                                session.write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?).await?;
                                continue;
                            }
                        };
                        last_sequence_number = share.sequence_number;
                        let Some(tmpl) = current.as_ref() else {
                            warn!("share before any template");
                            let err = SubmitSharesError {
                                channel_id,
                                sequence_number: share.sequence_number,
                                error_code: b"no-template".to_vec(),
                            };
                            session.write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?).await?;
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
                            session.write_frame(
                                MSG_SUBMIT_SHARES_SUCCESS,
                                &encode_submit_shares_success(&SubmitSharesSuccess {
                                    channel_id,
                                    last_sequence_number: share.sequence_number,
                                    new_submits_accepted_count: 1,
                                    new_shares_sum: 1,
                                })
                            ).await?;
                        } else {
                            debug!(hash = %hex::encode(hash), "share under target");
                            let err = SubmitSharesError {
                                channel_id,
                                sequence_number: share.sequence_number,
                                error_code: b"under-target".to_vec(),
                            };
                            session.write_frame(MSG_SUBMIT_SHARES_ERROR, &encode_submit_shares_error(&err)?).await?;
                        }
                    }
                    other => warn!(msg_type = other, "unexpected frame type from miner"),
                }
            }
        }
    }
}

/// Emit `SetNewPrevHash` then `NewMiningJob` for this template.
async fn push_job(
    session: &mut NoiseSession<TcpStream>,
    channel_id: u32,
    t: &NewTemplateDinero,
) -> Result<()> {
    let snph = SetNewPrevHash {
        channel_id,
        prev_hash: t.prev_block_hash,
        min_ntime: t.timestamp,
        nbits: t.difficulty,
    };
    session
        .write_frame(MSG_SET_NEW_PREV_HASH, &encode_set_new_prev_hash(&snph))
        .await?;
    session
        .write_frame(MSG_NEW_MINING_JOB, &encode_new_template(t))
        .await?;
    debug!(template_id = t.template_id, "pushed SNPH + job");
    Ok(())
}

fn leading_zero_target(bits: u8) -> [u8; 32] {
    let mut target = [0xFFu8; 32];
    if bits == 0 {
        return target;
    }
    if bits == u8::MAX {
        return [0u8; 32];
    }
    let full = (bits / 8) as usize;
    let rem = bits % 8;
    for b in target.iter_mut().take(full) {
        *b = 0;
    }
    if rem > 0 {
        target[full] = 0xFFu8 >> rem;
    }
    target
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
