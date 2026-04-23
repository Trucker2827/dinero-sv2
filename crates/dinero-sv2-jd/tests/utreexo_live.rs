//! Phase 3c: verify our Utreexo `commitment()` reproduces the live
//! daemon's `getutreexocommitment` RPC output byte-for-byte.
//!
//! Fixture: `tests/vectors/utreexo_live.json` — harvested from the
//! Mac regtest daemon at Phase 3c time via:
//!
//! ```sh
//! dinero-cli getutreexoroots        # → num_leaves + roots[]
//! dinero-cli getutreexocommitment   # → expected commitment
//! ```
//!
//! This is the strongest parity guarantee we can give without linking
//! against dinerod itself: we fed the same forest state into both
//! implementations and got the same 32-byte output.

use dinero_sv2_jd::{commitment, UtreexoAccumulatorState};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct LiveVector {
    #[allow(dead_code)]
    source: String,
    num_leaves: u64,
    forest_roots_hex: Vec<String>,
    expected_commitment_hex: String,
}

fn load() -> LiveVector {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/vectors/utreexo_live.json"
    );
    let s = std::fs::read_to_string(path).expect("utreexo_live.json must exist");
    serde_json::from_str(&s).expect("valid JSON")
}

#[test]
fn commitment_matches_live_rpc_output() {
    let v = load();
    let forest_roots: Vec<[u8; 32]> = v
        .forest_roots_hex
        .iter()
        .map(|h| {
            let bytes = hex::decode(h).expect("hex");
            let mut a = [0u8; 32];
            a.copy_from_slice(&bytes);
            a
        })
        .collect();

    let state = UtreexoAccumulatorState {
        forest_roots,
        num_leaves: v.num_leaves,
    };

    let rust_hash = commitment(&state).expect("state validates");
    let rust_hex = hex::encode(rust_hash);
    assert_eq!(
        rust_hex, v.expected_commitment_hex,
        "Rust commitment() diverged from dinerod's getutreexocommitment"
    );
}
