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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

pub(crate) const MSG_NEW_TEMPLATE: u8 = 0x01;
pub(crate) const MSG_SUBMIT_SHARES: u8 = 0x02;
pub(crate) const MSG_SHARE_ACK: u8 = 0x03;

pub(crate) const ACK_OK: u8 = 0x00;
pub(crate) const ACK_BAD_SHAPE: u8 = 0x01;
pub(crate) const ACK_UNDER_TARGET: u8 = 0x02;

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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "dinero_sv2_tp_sim=info".into()),
        )
        .init();

    let args = Args::parse();
    let listener = TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("binding {}", args.bind))?;
    info!(bind = %args.bind, interval_secs = args.interval_secs, "tp-sim listening");

    // Broadcast channel: producer task builds templates on a timer, each
    // connected client relays them out.
    let (tx, _rx) = broadcast::channel::<NewTemplateDinero>(8);

    {
        let tx = tx.clone();
        let interval = Duration::from_secs(args.interval_secs);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            let mut id: u64 = 0;
            loop {
                ticker.tick().await;
                id = id.wrapping_add(1);
                let t = build_fixture_template(id);
                if tx.send(t).is_err() {
                    debug!("no clients subscribed; skipping tick");
                }
            }
        });
    }

    loop {
        let (sock, peer) = listener.accept().await?;
        let rx = tx.subscribe();
        let leading = args.leading_zero_bits;
        tokio::spawn(async move {
            info!(peer = %peer, "client connected");
            if let Err(e) = serve_client(sock, rx, leading).await {
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

async fn serve_client(
    mut sock: TcpStream,
    mut rx: broadcast::Receiver<NewTemplateDinero>,
    leading: u8,
) -> Result<()> {
    // Simple single-threaded loop: wait for either an incoming frame from
    // the miner or a new broadcast template, and act accordingly.
    let mut current: Option<NewTemplateDinero> = None;

    loop {
        tokio::select! {
            biased;

            maybe_tmpl = rx.recv() => {
                match maybe_tmpl {
                    Ok(t) => {
                        send_template(&mut sock, &t).await?;
                        current = Some(t);
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(skipped = n, "client lagged, skipping templates");
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }

            frame = read_frame(&mut sock) => {
                let (msg_type, payload) = match frame? {
                    Some(f) => f,
                    None => return Ok(()), // clean EOF
                };
                match msg_type {
                    MSG_SUBMIT_SHARES => {
                        handle_submit_shares(&mut sock, &payload, current.as_ref(), leading).await?;
                    }
                    other => warn!(msg_type = other, "unexpected msg from client"),
                }
            }
        }
    }
}

async fn send_template(sock: &mut TcpStream, tmpl: &NewTemplateDinero) -> Result<()> {
    let payload = encode_new_template(tmpl);
    write_frame(sock, MSG_NEW_TEMPLATE, &payload).await?;
    debug!(id = tmpl.template_id, "sent template");
    Ok(())
}

async fn handle_submit_shares(
    sock: &mut TcpStream,
    payload: &[u8],
    current: Option<&NewTemplateDinero>,
    leading: u8,
) -> Result<()> {
    let share = match decode_submit_shares(payload) {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "bad share shape");
            write_frame(sock, MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
            return Ok(());
        }
    };
    let Some(tmpl) = current else {
        warn!("share received before any template was sent");
        write_frame(sock, MSG_SHARE_ACK, &[ACK_BAD_SHAPE]).await?;
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
        write_frame(sock, MSG_SHARE_ACK, &[ACK_OK]).await?;
    } else {
        debug!(
            hash = %hex::encode(hash),
            leading,
            "share under target"
        );
        write_frame(sock, MSG_SHARE_ACK, &[ACK_UNDER_TARGET]).await?;
    }
    Ok(())
}

/// Read one `| type | u16 len LE | payload |` frame. Returns `None` on
/// clean EOF.
async fn read_frame(sock: &mut TcpStream) -> Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0u8; 3];
    match sock.read_exact(&mut header).await {
        Ok(_) => {}
        Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let msg_type = header[0];
    let len = u16::from_le_bytes([header[1], header[2]]) as usize;
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload).await?;
    Ok(Some((msg_type, payload)))
}

async fn write_frame(sock: &mut TcpStream, msg_type: u8, payload: &[u8]) -> Result<()> {
    let len: u16 = payload
        .len()
        .try_into()
        .context("payload exceeds u16 length")?;
    let mut hdr = [0u8; 3];
    hdr[0] = msg_type;
    hdr[1..3].copy_from_slice(&len.to_le_bytes());
    sock.write_all(&hdr).await?;
    sock.write_all(payload).await?;
    sock.flush().await?;
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
        // Bind ephemeral port.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, _rx) = broadcast::channel::<NewTemplateDinero>(8);
        let tx_spawn = tx.clone();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let rx = tx_spawn.subscribe();
            serve_client(sock, rx, 0).await.unwrap();
        });

        // Client side
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Send one template through the broadcast channel.
        let tmpl = build_fixture_template(1);
        // Small delay so the server task has subscribed before we send.
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send(tmpl.clone()).unwrap();

        // Receive a NewTemplate frame.
        let (mtype, payload) = read_frame(&mut client).await.unwrap().unwrap();
        assert_eq!(mtype, MSG_NEW_TEMPLATE);
        assert_eq!(payload.len(), NEW_TEMPLATE_DINERO_SIZE);

        // Submit a share — with leading=0 the sim accepts everything.
        let share = fixture_share(0x1234_5678, tmpl.timestamp);
        let share_buf = encode_submit_shares(&share);
        write_frame(&mut client, MSG_SUBMIT_SHARES, &share_buf)
            .await
            .unwrap();

        let (mtype, payload) = read_frame(&mut client).await.unwrap().unwrap();
        assert_eq!(mtype, MSG_SHARE_ACK);
        assert_eq!(payload, vec![ACK_OK]);
    }

    #[tokio::test]
    async fn malformed_share_gets_bad_shape_ack() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (tx, _rx) = broadcast::channel::<NewTemplateDinero>(8);
        let tx_spawn = tx.clone();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let rx = tx_spawn.subscribe();
            serve_client(sock, rx, 0).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        tx.send(build_fixture_template(1)).unwrap();
        // Drain the template.
        let _ = read_frame(&mut client).await.unwrap().unwrap();

        // Send short share payload.
        write_frame(&mut client, MSG_SUBMIT_SHARES, &[0u8; 10])
            .await
            .unwrap();
        let (mtype, payload) = read_frame(&mut client).await.unwrap().unwrap();
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
