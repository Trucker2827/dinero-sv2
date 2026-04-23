//! Layer B for JD: prove that our txid computation and empty-path
//! merkle logic match real Dinero single-tx blocks.
//!
//! Vectors live in `tests/vectors/mainnet_coinbases.json`, harvested
//! with the Python extractor documented in `README.md` ("Regenerating
//! mainnet vectors"). For each block we record:
//!
//! - `header_hex` (128 bytes, from Phase 1)
//! - `coinbase_stripped_hex` (pre-witness serialization of the
//!   coinbase tx)
//! - `coinbase_txid_hex` (`sha256d` of the stripped bytes, raw order)
//!
//! All the vectors are single-tx blocks (regtest), so the merkle path
//! is empty and `merkle_root == coinbase_txid`.

use dinero_sv2_common::{sha256d, HEADER_SIZE};
use dinero_sv2_jd::{compute_root, MerklePath};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Vector {
    height: u64,
    #[allow(dead_code)]
    hash: String,
    header_hex: String,
    coinbase_stripped_hex: String,
    coinbase_txid_hex: String,
}

fn load_vectors() -> Vec<Vector> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/mainnet_coinbases.json"
    );
    let data = std::fs::read_to_string(path).expect("mainnet_coinbases.json must exist");
    serde_json::from_str(&data).expect("valid JSON")
}

fn header_merkleroot(header_hex: &str) -> [u8; 32] {
    let bytes = hex::decode(header_hex).expect("header hex");
    assert_eq!(bytes.len(), HEADER_SIZE);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[0x24..0x44]);
    out
}

#[test]
fn stripped_coinbase_hashes_to_recorded_txid() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty());

    for v in &vectors {
        let stripped = hex::decode(&v.coinbase_stripped_hex).unwrap();
        let computed = sha256d(&stripped);
        let expected_bytes = hex::decode(&v.coinbase_txid_hex).unwrap();
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&expected_bytes);
        assert_eq!(computed, expected, "txid mismatch at height {}", v.height);
    }
}

#[test]
fn empty_path_merkle_equals_coinbase_txid_equals_header_merkleroot() {
    let vectors = load_vectors();

    for v in &vectors {
        let txid_bytes = hex::decode(&v.coinbase_txid_hex).unwrap();
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&txid_bytes);

        let path: MerklePath = Vec::new();
        let root_via_jd = compute_root(txid, &path);

        assert_eq!(root_via_jd, txid, "empty path root must equal leaf");

        let header_root = header_merkleroot(&v.header_hex);
        assert_eq!(
            root_via_jd, header_root,
            "JD-reconstructed merkle_root disagrees with the header's merkleroot at height {}",
            v.height
        );
    }
}
