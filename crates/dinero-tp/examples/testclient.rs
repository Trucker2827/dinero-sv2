//! Minimal Noise NX initiator for smoke-testing a running `dinero-tp`.
//!
//! Connects, optionally pins the TP's static key, receives one
//! `NewTemplateDinero` frame, submits a synthetic share with nonce
//! 0xDEADBEEF, prints the ack, and exits.
//!
//! Usage:
//!   cargo run -p dinero-tp --example testclient --release -- \
//!       --addr 127.0.0.1:4444 \
//!       [--server-pubkey <hex-32b>]

use anyhow::Result;
use clap::Parser;
use dinero_sv2_codec::{decode_new_template, encode_submit_shares};
use dinero_sv2_common::SubmitSharesDinero;
use dinero_sv2_transport::{NoiseSession, MSG_NEW_TEMPLATE, MSG_SHARE_ACK, MSG_SUBMIT_SHARES};
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4444")]
    addr: SocketAddr,

    /// Expected TP static public key (64-char hex). Run
    /// `dinero-tp --print-pubkey` to get it.
    #[arg(long)]
    server_pubkey: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pinned: Option<[u8; 32]> = match args.server_pubkey {
        Some(hex_str) => {
            let v = hex::decode(&hex_str)?;
            if v.len() != 32 {
                anyhow::bail!("server-pubkey must be 32 bytes hex");
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            Some(a)
        }
        None => None,
    };

    let tcp = TcpStream::connect(args.addr).await?;
    let mut session = NoiseSession::initiate_nx(tcp, pinned.as_ref()).await?;
    println!(
        "handshake ok; server static pubkey = {}",
        hex::encode(session.peer_static_key())
    );

    let (mtype, payload) = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no template frame"))?;
    if mtype != MSG_NEW_TEMPLATE {
        anyhow::bail!("expected MSG_NEW_TEMPLATE (0x01), got 0x{:02x}", mtype);
    }
    let tmpl = decode_new_template(&payload)?;
    println!(
        "template received: id={} utreexo_root={} timestamp={} difficulty=0x{:08x}",
        tmpl.template_id,
        hex::encode(tmpl.utreexo_root),
        tmpl.timestamp,
        tmpl.difficulty
    );

    let share = SubmitSharesDinero {
        channel_id: 0,
        sequence_number: 0,
        job_id: 1,
        nonce: 0xDEAD_BEEF,
        timestamp: tmpl.timestamp,
        version: tmpl.version,
    };
    let buf = encode_submit_shares(&share);
    session.write_frame(MSG_SUBMIT_SHARES, &buf).await?;

    let (mtype, payload) = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no ack"))?;
    if mtype != MSG_SHARE_ACK {
        anyhow::bail!("expected MSG_SHARE_ACK (0x03), got 0x{:02x}", mtype);
    }
    let code = payload.first().copied().unwrap_or(0xff);
    let code_str = match code {
        0 => "OK",
        1 => "BAD_SHAPE",
        2 => "UNDER_TARGET",
        _ => "UNKNOWN",
    };
    println!("share ack: 0x{:02x} ({})", code, code_str);

    Ok(())
}
