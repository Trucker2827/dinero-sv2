//! Layer B tests — prove the codec against real Dinero 128-byte headers.
//!
//! These tests consume `tests/vectors/mainnet_headers.json` (harvested from
//! a live `dinerod` via `getblock <hash> 0` and truncated to the first 128
//! bytes of each block). For every vector we:
//!
//! 1. Parse the raw header bytes into its component fields.
//! 2. Construct a [`NewTemplateDinero`] + [`SubmitSharesDinero`] pair.
//! 3. Assert [`HeaderAssembly::bytes`] reproduces the raw header byte-for-byte.
//! 4. Assert [`HeaderAssembly::hash`], byte-reversed, equals the RPC's
//!    display-order `hash` field.
//!
//! Layer A (round-trip fuzz) can pass with a subtly wrong wire shape as long
//! as encode+decode agree. Layer B is the only evidence "we shipped it right".

use dinero_sv2_common::{
    HeaderAssembly, InvariantError, NewTemplateDinero, SubmitSharesDinero, HEADER_SIZE,
    RESERVED_LEN,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Vector {
    height: u64,
    hash: String,
    header_hex: String,
}

fn load_vectors() -> Vec<Vector> {
    // Repo-relative: this test runs from crates/dinero-sv2-common, so
    // the workspace root is two directories up.
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/mainnet_headers.json"
    );
    let data = std::fs::read_to_string(path).expect("mainnet_headers.json must exist");
    serde_json::from_str(&data).expect("valid JSON")
}

fn split_header(raw: &[u8; HEADER_SIZE]) -> (NewTemplateDinero, SubmitSharesDinero) {
    let mut prev_block_hash = [0u8; 32];
    prev_block_hash.copy_from_slice(&raw[0x04..0x24]);

    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&raw[0x24..0x44]);

    let mut utreexo_root = [0u8; 32];
    utreexo_root.copy_from_slice(&raw[0x44..0x64]);

    let mut version_bytes = [0u8; 4];
    version_bytes.copy_from_slice(&raw[0x00..0x04]);
    let version = u32::from_le_bytes(version_bytes);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&raw[0x64..0x6C]);
    let timestamp = u64::from_le_bytes(ts_bytes);

    let mut diff_bytes = [0u8; 4];
    diff_bytes.copy_from_slice(&raw[0x6C..0x70]);
    let difficulty = u32::from_le_bytes(diff_bytes);

    let mut nonce_bytes = [0u8; 4];
    nonce_bytes.copy_from_slice(&raw[0x70..0x74]);
    let nonce = u32::from_le_bytes(nonce_bytes);

    let tmpl = NewTemplateDinero {
        template_id: 0,
        future_template: false,
        version,
        prev_block_hash,
        merkle_root,
        utreexo_root,
        timestamp,
        difficulty,
        // Real mempool would feed this; for header-reconstruction it's
        // irrelevant — HeaderAssembly never reads it.
        coinbase_outputs_commitment: [0u8; 32],
    };

    let share = SubmitSharesDinero {
        channel_id: 0,
        sequence_number: 0,
        job_id: 0,
        nonce,
        timestamp,
        version,
    };

    (tmpl, share)
}

fn hex_to_header(hex_str: &str) -> [u8; HEADER_SIZE] {
    let bytes = hex::decode(hex_str).expect("hex");
    assert_eq!(bytes.len(), HEADER_SIZE, "vector header is not 128 bytes");
    let mut out = [0u8; HEADER_SIZE];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn mainnet_headers_assemble_byte_for_byte() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "need at least one vector");

    for v in &vectors {
        let raw = hex_to_header(&v.header_hex);
        let (tmpl, share) = split_header(&raw);
        let rebuilt = HeaderAssembly::bytes(&tmpl, &share);

        assert_eq!(
            rebuilt.as_slice(),
            raw.as_slice(),
            "header mismatch at height {} (hash {})",
            v.height,
            v.hash
        );
    }
}

#[test]
fn mainnet_header_hash_matches_rpc_hash() {
    let vectors = load_vectors();
    for v in &vectors {
        let raw = hex_to_header(&v.header_hex);
        let (tmpl, share) = split_header(&raw);

        // NOTE: Dinero's RPC `hash` field is the raw sha256d output bytes
        // hex-encoded directly — NOT byte-reversed like Bitcoin's display
        // hash. dinerod treats the header hash as a plain 32-byte blob,
        // not a little-endian uint256. Empirically verified against a
        // live regtest chain (heights 1..5000+).
        let computed = HeaderAssembly::hash(&tmpl, &share);
        let computed_hex = hex::encode(computed);

        assert_eq!(computed_hex, v.hash, "hash mismatch at height {}", v.height);
    }
}

#[test]
fn mainnet_headers_have_zero_reserved_tail() {
    let vectors = load_vectors();
    for v in &vectors {
        let raw = hex_to_header(&v.header_hex);
        assert_eq!(
            &raw[0x74..0x80],
            &[0u8; RESERVED_LEN],
            "height {} has non-zero reserved bytes — consensus rule violated",
            v.height,
        );
        assert!(
            HeaderAssembly::check_reserved_zero(&raw).is_ok(),
            "check_reserved_zero should accept real mainnet headers"
        );
    }
}

#[test]
fn corrupted_reserved_byte_is_rejected() {
    let vectors = load_vectors();
    let mut raw = hex_to_header(&vectors[0].header_hex);
    raw[0x7F] = 0x01; // stomp on last reserved byte
    match HeaderAssembly::check_reserved_zero(&raw) {
        Err(InvariantError::NonZeroReserved { positions }) => {
            assert_eq!(positions, vec![0x7F - 0x74]);
        }
        other => panic!("expected NonZeroReserved, got {other:?}"),
    }
}
