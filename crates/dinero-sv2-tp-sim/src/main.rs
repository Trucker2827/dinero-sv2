//! Phase-1 Template Provider simulator for Dinero Stratum V2.
//!
//! Tiny in-memory TP: binds a localhost TCP port, pushes a
//! [`NewTemplateDinero`] frame to each connected client every N seconds,
//! and validates any [`SubmitSharesDinero`] the client sends back. No
//! Noise handshake, no real mempool, no daemon. Just the minimum loop
//! that exercises the codec + `HeaderAssembly`.
//!
//! Wire framing (simulator-only, not final SV2 framing):
//!
//! ```text
//! | 1 byte: msg_type | 2 bytes: payload_len LE | payload |
//!   0x01 = NewTemplateDinero  (server -> client)
//!   0x02 = SubmitSharesDinero (client -> server)
//!   0x03 = ShareAck           (server -> client, 1-byte status)
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use dinero_sv2_codec::{
    decode_submit_shares, encode_new_template, NEW_TEMPLATE_DINERO_SIZE, SUBMIT_SHARES_DINERO_SIZE,
};
use dinero_sv2_common::{HeaderAssembly, NewTemplateDinero};
use dinero_sv2_transport::{
    Frame, NoiseSession, StaticKeys, ACK_BAD_SHAPE, ACK_OK, ACK_UNDER_TARGET, MSG_NEW_TEMPLATE,
    MSG_SHARE_ACK, MSG_SUBMIT_SHARES,
};
use std::path::PathBuf;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:4444")]
    bind: SocketAddr,

    /// Template emission period (seconds).
    #[arg(long, default_value_t = 5)]
    interval_secs: u64,

    /// Share acceptance target: accept any share whose header hash,
    /// interpreted as big-endian, starts with this many leading zero bits.
    /// 0 means accept everything that decodes cleanly.
    #[arg(long, default_value_t = 0)]
    leading_zero_bits: u8,

    /// Static Noise identity file. 64 bytes: `priv[0..32] || pub[32..64]`.
    /// Defaults to `/tmp/dinero-sv2-tp-sim.key` (ephemeral, just for demos).
    #[arg(long)]
    tp_key: Option<PathBuf>,

    /// Print the sim's static public key (hex) and exit.
    #[arg(long)]
    print_pubkey: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let key_path = args
        .tp_key
        .clone()
        .unwrap_or_else(|| PathBuf::from("/tmp/dinero-sv2-tp-sim.key"));
    let static_keys = StaticKeys::load_or_generate(&key_path)
        .with_context(|| format!("loading key from {}", key_path.display()))?;

    if args.print_pubkey {
        println!("{}", static_keys.public_hex());
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dinero_sv2_tp_sim=info".into()),
        )
        .init();
    info!(
        key = %key_path.display(),
        pubkey = %static_keys.public_hex(),
        "tp-sim static identity"
    );

    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;
    info!(bind = %args.bind, interval_secs = args.interval_secs, "tp-sim listening");

    // Watch channel: new subscribers see the current template instantly
    // (no waiting for the next tick).
    let (tx, rx) = watch::channel::<Option<NewTemplateDinero>>(None);

    {
        let interval = Duration::from_secs(args.interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut id: u64 = 0;
            loop {
                ticker.tick().await;
                id = id.wrapping_add(1);
                let t = build_fixture_template(id);
                let _ = tx.send(Some(t));
            }
        });
    }

    loop {
        let (sock, peer) = listener.accept().await?;
        let rx = rx.clone();
        let leading = args.leading_zero_bits;
        let keys = static_keys.clone();
        tokio::spawn(async move {
            info!(peer = %peer, "client connected — handshake starting");
            let session = match NoiseSession::accept_nx(sock, &keys).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(peer = %peer, error = %e, "noise handshake failed");
                    return;
                }
            };
            info!(peer = %peer, "noise handshake complete");
            if let Err(e) = serve_client(session, rx, leading).await {
                warn!(peer = %peer, error = %e, "client session ended with error");
            } else {
                info!(peer = %peer, "client disconnected");
            }
        });
    }
}

/// Build a deterministic fixture template. In Phase 1 the contents don't
/// matter semantically — only that the wire shape round-trips and the
/// header assembly produces exactly 128 bytes.
pub(crate) fn build_fixture_template(id: u64) -> NewTemplateDinero {
    NewTemplateDinero {
        template_id: id,
        future_template: false,
        version: 1,
        prev_block_hash: splat_array([0x11, (id & 0xff) as u8]),
        merkle_root: splat_array([0x22, (id & 0xff) as u8]),
        utreexo_root: splat_array([0x33, (id & 0xff) as u8]),
        timestamp: 1_776_384_000 + id,
        difficulty: 0x1d_31_ff_ce,
        coinbase_outputs_commitment: splat_array([0x44, (id & 0xff) as u8]),
    }
}

fn splat_array(seed: [u8; 2]) -> [u8; 32] {
    let mut out = [seed[0]; 32];
    for i in (0..32).step_by(2) {
        out[i] = seed[0];
        if i + 1 < 32 {
            out[i + 1] = seed[1];
        }
    }
    out
}

async fn serve_client<S: AsyncRead + AsyncWrite + Unpin>(
    mut session: NoiseSession<S>,
    mut rx: watch::Receiver<Option<NewTemplateDinero>>,
    leading: u8,
) -> Result<()> {
    let mut current: Option<NewTemplateDinero> = None;

    let initial = rx.borrow_and_update().clone();
    if let Some(t) = initial {
        send_template(&mut session, &t).await?;
        current = Some(t);
    }

    loop {
        tokio::select! {
            biased;

            changed = rx.changed() => {
                if changed.is_err() {
                    return Ok(());
                }
                let maybe_t = rx.borrow_and_update().clone();
                if let Some(t) = maybe_t {
                    send_template(&mut session, &t).await?;
                    current = Some(t);
                }
            }

            frame = session.read_frame() => {
                let f = match frame? {
                    Some(f) => f,
                    None => return Ok(()),
                };
                let Frame { msg_type, payload, .. } = f;
                match msg_type {
                    MSG_SUBMIT_SHARES => {
                        handle_submit_shares(&mut session, &payload, current.as_ref(), leading).await?;
                    }
                    other => warn!(msg_type = other, "unexpected msg from client"),
                }
            }
        }
    }
}

async fn send_template<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut NoiseSession<S>,
    tmpl: &NewTemplateDinero,
) -> Result<()> {
    let payload = encode_new_template(tmpl);
    session.write_frame(MSG_NEW_TEMPLATE, &payload).await?;
    debug!(id = tmpl.template_id, "sent template");
    Ok(())
}

async fn handle_submit_shares<S: AsyncRead + AsyncWrite + Unpin>(
    session: &mut NoiseSession<S>,
    payload: &[u8],
    current: Option<&NewTemplateDinero>,
    leading: u8,
) -> Result<()> {
    let share = match decode_submit_shares(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "bad share shape");
            session.write_frame(MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
            return Ok(());
        }
    };
    let Some(tmpl) = current else {
        warn!("share received before any template was sent");
        session.write_frame(MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
        return Ok(());
    };
    let hash = HeaderAssembly::hash(tmpl, &share);
    if meets_leading_zero_bits(&hash, leading) {
        info!(
            hash = %hex::encode(hash),
            leading,
            template = tmpl.template_id,
            nonce = share.nonce,
            "accepted share"
        );
        session.write_frame(MSG_SHARE_ACK, &[ACK_OK]).await?;
    } else {
        debug!(
            hash = %hex::encode(hash),
            leading,
            "share under target"
        );
        session
            .write_frame(MSG_SHARE_ACK, &[ACK_UNDER_TARGET])
            .await?;
    }
    Ok(())
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
    // Leading bits in the big-endian interpretation means the *most
    // significant* bits of the next byte must be zero.
    let mask = 0xFFu8 << (8 - remainder);
    (hash[full_zero_bytes] & mask) == 0
}

// Assert the wire sizes so a codec change can't silently desync the sim.
const _: () = {
    assert!(NEW_TEMPLATE_DINERO_SIZE == 153);
    assert!(SUBMIT_SHARES_DINERO_SIZE == 28);
};

#[cfg(test)]
mod tests {
    use super::*;
    use dinero_sv2_codec::encode_submit_shares;
    use dinero_sv2_common::SubmitSharesDinero;

    fn fixture_share(nonce: u32, ts: u64) -> SubmitSharesDinero {
        SubmitSharesDinero {
            channel_id: 7,
            sequence_number: 0,
            job_id: 1,
            nonce,
            timestamp: ts,
            version: 1,
        }
    }

    #[tokio::test]
    async fn client_receives_template_and_share_is_acked() {
        // Run the whole session over an in-memory duplex pipe so Noise
        // can wrap both sides end-to-end without the TCP round-trip.
        let (server_io, client_io) = tokio::io::duplex(16_384);
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let tmpl = build_fixture_template(1);
        let (_tx, rx) = watch::channel::<Option<NewTemplateDinero>>(Some(tmpl.clone()));
        let rx_spawn = rx.clone();
        let keys_spawn = keys.clone();
        tokio::spawn(async move {
            let session = NoiseSession::accept_nx(server_io, &keys_spawn)
                .await
                .unwrap();
            serve_client(session, rx_spawn, 0).await.unwrap();
        });

        let mut client = NoiseSession::initiate_nx(client_io, Some(&server_pub))
            .await
            .unwrap();

        // Receive a NewTemplate frame.
        let Frame {
            msg_type: mtype,
            payload,
            ..
        } = client.read_frame().await.unwrap().unwrap();
        assert_eq!(mtype, MSG_NEW_TEMPLATE);
        assert_eq!(payload.len(), NEW_TEMPLATE_DINERO_SIZE);

        // Submit a share — with leading=0 the sim accepts everything.
        let share = fixture_share(0x1234_5678, tmpl.timestamp);
        let share_buf = encode_submit_shares(&share);
        client
            .write_frame(MSG_SUBMIT_SHARES, &share_buf)
            .await
            .unwrap();

        let Frame {
            msg_type: mtype,
            payload,
            ..
        } = client.read_frame().await.unwrap().unwrap();
        assert_eq!(mtype, MSG_SHARE_ACK);
        assert_eq!(payload, vec![ACK_OK]);
    }

    #[tokio::test]
    async fn malformed_share_gets_bad_shape_ack() {
        let (server_io, client_io) = tokio::io::duplex(16_384);
        let keys = StaticKeys::generate().unwrap();
        let server_pub = keys.public;

        let tmpl = build_fixture_template(1);
        let (_tx, rx) = watch::channel::<Option<NewTemplateDinero>>(Some(tmpl));
        let rx_spawn = rx.clone();
        let keys_spawn = keys.clone();
        tokio::spawn(async move {
            let session = NoiseSession::accept_nx(server_io, &keys_spawn)
                .await
                .unwrap();
            serve_client(session, rx_spawn, 0).await.unwrap();
        });

        let mut client = NoiseSession::initiate_nx(client_io, Some(&server_pub))
            .await
            .unwrap();
        // Drain the initial template frame.
        let _ = client.read_frame().await.unwrap().unwrap();

        // Send short share payload.
        client
            .write_frame(MSG_SUBMIT_SHARES, &[0u8; 10])
            .await
            .unwrap();
        let Frame {
            msg_type: mtype,
            payload,
            ..
        } = client.read_frame().await.unwrap().unwrap();
        assert_eq!(mtype, MSG_SHARE_ACK);
        assert_eq!(payload, vec![ACK_BAD_SHAPE]);
    }

    #[test]
    fn leading_zero_bits_check() {
        let mut h = [0u8; 32];
        assert!(meets_leading_zero_bits(&h, 0));
        assert!(meets_leading_zero_bits(&h, 255));
        h[0] = 0x0F;
        assert!(meets_leading_zero_bits(&h, 4));
        assert!(!meets_leading_zero_bits(&h, 5));
    }
}
