//! Noise NX + full SV2 handshake initiator for smoke-testing the pool
//! or the tp-sim.
//!
//! Flow:
//!   1. TCP connect + Noise NX handshake (optionally pinning the
//!      server's static pubkey).
//!   2. Send `SetupConnection`, wait for `SetupConnectionSuccess` (or
//!      abort on `SetupConnectionError`).
//!   3. Send `OpenStandardMiningChannel` with the widest possible
//!      `max_target`, wait for `OpenStandardMiningChannelSuccess`.
//!   4. Read one `NewMiningJob` (Pass-B rename of the old
//!      `NewTemplate`), print the decoded template.
//!   5. Submit one synthetic share with nonce 0xDEADBEEF, print the
//!      resulting `SubmitSharesSuccess` or `SubmitSharesError`.

use anyhow::{bail, Result};
use clap::Parser;
use dinero_sv2_codec::{
    decode_coinbase_context, decode_new_template, decode_open_standard_mining_channel_success,
    decode_set_new_prev_hash, decode_setup_connection_success, decode_submit_shares_error,
    decode_submit_shares_success, encode_open_standard_mining_channel, encode_setup_connection,
    encode_submit_shares, encode_submit_shares_extended,
};
use dinero_sv2_common::{
    CoinbaseOutputWire, OpenStandardMiningChannel, SetupConnection, SubmitSharesDinero,
    SubmitSharesExtendedDinero, PROTOCOL_MINING, PROTOCOL_VERSION,
};
use dinero_sv2_jd::{
    assemble_stripped_coinbase, commitment as utreexo_commitment, compute_root,
    decode_utreexo_accumulator_state, leaf_hash, CoinbaseOutput, UtreexoAccumulatorState,
};
use dinero_sv2_transport::{
    Frame, NoiseSession, MSG_COINBASE_CONTEXT, MSG_NEW_MINING_JOB,
    MSG_OPEN_STANDARD_MINING_CHANNEL, MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR,
    MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MSG_SETUP_CONNECTION, MSG_SETUP_CONNECTION_ERROR,
    MSG_SETUP_CONNECTION_SUCCESS, MSG_SET_NEW_PREV_HASH, MSG_SUBMIT_SHARES_ERROR,
    MSG_SUBMIT_SHARES_EXTENDED, MSG_SUBMIT_SHARES_STANDARD, MSG_SUBMIT_SHARES_SUCCESS,
    MSG_UTREEXO_STATE,
};
use std::net::SocketAddr;
use tokio::net::TcpStream;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:4444")]
    addr: SocketAddr,

    /// Expected server static public key (64-char hex). Run
    /// `dinero-sv2-pool --print-pubkey` to obtain it.
    #[arg(long)]
    server_pubkey: Option<String>,

    /// Phase 5: Job Declaration mode. Instead of submitting a
    /// standard share against the pool's coinbase, pick a local
    /// payout script and submit a `SubmitSharesExtended` carrying
    /// our own outputs. The pool will recompute the header's
    /// `utreexo_root` from its pre-block state + our outputs.
    #[arg(long)]
    jd: bool,

    /// JD mode: the payout scriptPubKey to use (hex). Defaults to a
    /// 34-byte Taproot script with an all-`0xAB` key, so it's
    /// structurally valid but unspendable — fine for wire-loop
    /// verification.
    #[arg(long)]
    payout_script_hex: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let pinned: Option<[u8; 32]> = match args.server_pubkey {
        Some(hex_str) => {
            let v = hex::decode(&hex_str)?;
            if v.len() != 32 {
                bail!("server-pubkey must be 32 bytes hex");
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

    // ---- SetupConnection ----
    let setup = SetupConnection {
        protocol: PROTOCOL_MINING,
        min_version: PROTOCOL_VERSION,
        max_version: PROTOCOL_VERSION,
        flags: 0,
        user_agent: b"dinero-testclient/0.1".to_vec(),
    };
    session
        .write_frame(MSG_SETUP_CONNECTION, &encode_setup_connection(&setup)?)
        .await?;
    let f = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("EOF after SetupConnection"))?;
    match f.msg_type {
        MSG_SETUP_CONNECTION_SUCCESS => {
            let succ = decode_setup_connection_success(&f.payload)?;
            println!(
                "SetupConnection.Success: used_version={} flags=0x{:08x}",
                succ.used_version, succ.flags
            );
        }
        MSG_SETUP_CONNECTION_ERROR => {
            bail!(
                "SetupConnection.Error: {}",
                String::from_utf8_lossy(&f.payload)
            );
        }
        other => bail!("unexpected response to SetupConnection: 0x{other:02x}"),
    }

    // ---- OpenStandardMiningChannel ----
    let open = OpenStandardMiningChannel {
        request_id: 1,
        user_identity: b"testclient-worker-1".to_vec(),
        nominal_hash_rate_bits: f32::to_bits(1.0), // 1 H/s, placeholder
        max_target: [0xFFu8; 32],
    };
    session
        .write_frame(
            MSG_OPEN_STANDARD_MINING_CHANNEL,
            &encode_open_standard_mining_channel(&open)?,
        )
        .await?;
    let f = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("EOF after OpenStandardMiningChannel"))?;
    let channel_id = match f.msg_type {
        MSG_OPEN_STANDARD_MINING_CHANNEL_SUCCESS => {
            let succ = decode_open_standard_mining_channel_success(&f.payload)?;
            println!(
                "OpenStandardMiningChannel.Success: channel_id={} target={}",
                succ.channel_id,
                hex::encode(succ.target)
            );
            succ.channel_id
        }
        MSG_OPEN_STANDARD_MINING_CHANNEL_ERROR => {
            bail!(
                "OpenStandardMiningChannel.Error: {}",
                String::from_utf8_lossy(&f.payload)
            );
        }
        other => bail!("unexpected response to OpenStandardMiningChannel: 0x{other:02x}"),
    };

    // ---- SetNewPrevHash ----
    let f = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no SetNewPrevHash"))?;
    if f.msg_type != MSG_SET_NEW_PREV_HASH {
        bail!(
            "expected MSG_SET_NEW_PREV_HASH (0x{:02x}), got 0x{:02x}",
            MSG_SET_NEW_PREV_HASH,
            f.msg_type
        );
    }
    let snph = decode_set_new_prev_hash(&f.payload)?;
    println!(
        "SetNewPrevHash: channel_id={} prev_hash={} min_ntime={} nbits=0x{:08x}",
        snph.channel_id,
        hex::encode(snph.prev_hash),
        snph.min_ntime,
        snph.nbits,
    );

    // ---- Optional UtreexoStateAnnouncement + CoinbaseContext (Phase 4b/5) ----
    // Between SetNewPrevHash and NewMiningJob we may get zero, one, or
    // two extra frames depending on whether the pool is JD-capable.
    let mut pre_block_state: Option<UtreexoAccumulatorState> = None;
    let mut coinbase_ctx: Option<dinero_sv2_common::CoinbaseContext> = None;

    let mut next = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no frame after SetNewPrevHash"))?;

    if next.msg_type == MSG_UTREEXO_STATE {
        let state = decode_utreexo_accumulator_state(&next.payload)?;
        let pre_block_commitment = utreexo_commitment(&state)?;
        println!(
            "UtreexoStateAnnouncement: num_leaves={} num_roots={} pre_block_commitment={}",
            state.num_leaves,
            state.forest_roots.len(),
            hex::encode(pre_block_commitment),
        );
        pre_block_state = Some(state);
        next = session
            .read_frame()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no frame after UtreexoState"))?;
    }

    if next.msg_type == MSG_COINBASE_CONTEXT {
        let ctx = decode_coinbase_context(&next.payload)?;
        println!(
            "CoinbaseContext: height={} value_una={} merkle_path_len={} prefix={}B suffix={}B",
            ctx.height,
            ctx.coinbase_value_una,
            ctx.merkle_path.len(),
            ctx.coinbase_prefix.len(),
            ctx.coinbase_suffix.len(),
        );
        coinbase_ctx = Some(ctx);
        next = session
            .read_frame()
            .await?
            .ok_or_else(|| anyhow::anyhow!("no frame after CoinbaseContext"))?;
    }

    // ---- NewMiningJob ----
    let Frame {
        msg_type: mtype,
        payload,
        ..
    } = next;
    if mtype != MSG_NEW_MINING_JOB {
        bail!(
            "expected MSG_NEW_MINING_JOB (0x{:02x}), got 0x{mtype:02x}",
            MSG_NEW_MINING_JOB
        );
    }
    let tmpl = decode_new_template(&payload)?;
    println!(
        "NewMiningJob: template_id={} utreexo_root={} timestamp={} difficulty=0x{:08x}",
        tmpl.template_id,
        hex::encode(tmpl.utreexo_root),
        tmpl.timestamp,
        tmpl.difficulty
    );

    // ---- Submit a share ----
    if args.jd {
        submit_extended_share(
            &mut session,
            &tmpl,
            channel_id,
            pre_block_state
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("JD mode requires UtreexoStateAnnouncement"))?,
            coinbase_ctx
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("JD mode requires CoinbaseContext"))?,
            args.payout_script_hex.as_deref(),
        )
        .await?;
    } else {
        let share = SubmitSharesDinero {
            channel_id,
            sequence_number: 1,
            job_id: u32::try_from(tmpl.template_id).unwrap_or(0),
            nonce: 0xDEAD_BEEF,
            timestamp: tmpl.timestamp,
            version: tmpl.version,
        };
        let buf = encode_submit_shares(&share);
        session
            .write_frame(MSG_SUBMIT_SHARES_STANDARD, &buf)
            .await?;
    }
    let f = session
        .read_frame()
        .await?
        .ok_or_else(|| anyhow::anyhow!("no share response"))?;
    match f.msg_type {
        MSG_SUBMIT_SHARES_SUCCESS => {
            let s = decode_submit_shares_success(&f.payload)?;
            println!(
                "SubmitShares.Success: channel_id={} last_seq={} accepted={} sum={}",
                s.channel_id,
                s.last_sequence_number,
                s.new_submits_accepted_count,
                s.new_shares_sum
            );
        }
        MSG_SUBMIT_SHARES_ERROR => {
            let e = decode_submit_shares_error(&f.payload)?;
            println!(
                "SubmitShares.Error: channel_id={} seq={} error_code={}",
                e.channel_id,
                e.sequence_number,
                String::from_utf8_lossy(&e.error_code)
            );
        }
        other => bail!("unexpected response to share submit: 0x{other:02x}"),
    }

    Ok(())
}

/// JD mode: the miner owns its coinbase outputs end to end. Picks a
/// local payout script, assembles the coinbase locally, computes the
/// post-coinbase Utreexo state + header `utreexo_root`, and submits
/// an extended share carrying those outputs.
async fn submit_extended_share(
    session: &mut NoiseSession<tokio::net::TcpStream>,
    tmpl: &dinero_sv2_common::NewTemplateDinero,
    channel_id: u32,
    pre_block_state: &UtreexoAccumulatorState,
    ctx: &dinero_sv2_common::CoinbaseContext,
    payout_script_hex: Option<&str>,
) -> Result<()> {
    let payout_script = match payout_script_hex {
        Some(h) => hex::decode(h)?,
        None => {
            // Default: 34-byte Taproot-shaped script `OP_1 0x20 <32 bytes of 0xAB>`.
            // Structurally valid, unspendable — perfect for wire
            // demonstration.
            let mut s = vec![0x51, 0x20];
            s.extend_from_slice(&[0xAB; 32]);
            s
        }
    };

    // Single output paying the entire coinbase value to our chosen
    // payout script.
    let miner_outputs = vec![CoinbaseOutput {
        value_una: ctx.coinbase_value_una,
        script_pubkey: payout_script.clone(),
    }];

    let (_coinbase_bytes, coinbase_txid) =
        assemble_stripped_coinbase(&ctx.coinbase_prefix, &miner_outputs, &ctx.coinbase_suffix);

    // Apply our one coinbase output's leaf to the pre-block state.
    let mut post_state = pre_block_state.clone();
    for (i, out) in miner_outputs.iter().enumerate() {
        let leaf = leaf_hash(&coinbase_txid, i as u32, out.value_una, &out.script_pubkey);
        post_state.add_leaf(leaf)?;
    }
    let our_utreexo_root = utreexo_commitment(&post_state)?;
    let merkle_root = compute_root(coinbase_txid, &ctx.merkle_path);

    println!(
        "JD locally computed: coinbase_txid={} merkle_root={} utreexo_root={} (pool said {})",
        hex::encode(coinbase_txid),
        hex::encode(merkle_root),
        hex::encode(our_utreexo_root),
        hex::encode(tmpl.utreexo_root),
    );

    let ext = SubmitSharesExtendedDinero {
        channel_id,
        sequence_number: 1,
        job_id: u32::try_from(tmpl.template_id).unwrap_or(0),
        nonce: 0xDEAD_BEEF,
        timestamp: tmpl.timestamp,
        version: tmpl.version,
        coinbase_outputs: vec![CoinbaseOutputWire {
            value_una: miner_outputs[0].value_una,
            script_pubkey: miner_outputs[0].script_pubkey.clone(),
        }],
    };
    let buf = encode_submit_shares_extended(&ext)?;
    session
        .write_frame(MSG_SUBMIT_SHARES_EXTENDED, &buf)
        .await?;
    Ok(())
}
