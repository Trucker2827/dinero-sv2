# dinero-sv2

Dinero's Stratum V2 profile — message types, wire codec, and a Phase-1
Template Provider simulator.

This is **protocol infrastructure**, not a daemon. It is consumed by
`dinerod`'s future `dinero-tp`, by standalone pool/worker implementations,
and by DineroDPI (iOS) via UniFFI.

## Why a Dinero profile and not an SRI fork?

The [Stratum Reference Implementation](https://github.com/stratum-mining/stratum)
assumes a Bitcoin-shaped header: 80 bytes total, `ntime: u32`, no first-class
`utreexo_root`. Dinero's consensus header is:

```
128 bytes, frozen layout (see dinero/include/primitives/block.h):
  0x00  version             u32 LE
  0x04  prev_block_hash     32
  0x24  merkle_root         32
  0x44  utreexo_root        32       ← consensus field
  0x64  timestamp           u64 LE   ← NOT u32 (Dinero dodged 2038)
  0x6C  difficulty          u32 LE
  0x70  nonce               u32 LE
  0x74  reserved[12]        all zero, consensus-checked
```

Forking SRI to carry these extras creates permanent drift. Instead this
workspace owns wire-level message types that **mirror** SRI's roles but
treat Dinero's consensus surface as first-class.

## Crates

| Crate | Purpose |
|-------|---------|
| `dinero-sv2-common` | Message structs, header assembly, consensus invariants |
| `dinero-sv2-codec`  | Fixed-size wire encode/decode with strict length checks |
| `dinero-sv2-tp-sim` | Phase-1 TP simulator binary (localhost loopback, no Noise) |

Planned additions (not in this release): `dinero-sv2-jd-client`,
`dinero-sv2-pool-client`.

## Phase-1 scope

- `NewTemplateDinero` and `SubmitSharesDinero` message types.
- `HeaderAssembly::bytes / hash` — the single source of truth for layout.
- Round-trip fuzz tests (`proptest`).
- **Layer B verification** against 9 real mainnet headers harvested via
  `dinero-cli getblock <hash> 0`; byte-for-byte reconstruction plus
  `sha256d` hash match (see `tests/vectors/mainnet_headers.json`).
- TP simulator that pushes templates every N seconds and ACKs shares.

Explicitly **deferred** to later phases (see `docs/ROADMAP.md` once that
exists, or `~/.claude/plans/lovely-chasing-puzzle.md` for the full
sequencing):

- Noise NX handshake / TCP framing with real miners
- `dinero-tp` daemon binary that binds to dinerod's RPC
- Real pool server
- Job Declaration (miner-built coinbase)
- DineroDPI / iOS UniFFI binding

## Running

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings

# start the Phase-1 simulator
cargo run --bin dinero-sv2-tp-sim -- --bind 127.0.0.1:4444 --interval-secs 5
```

A hand-written test client lives in the tp-sim integration tests.

## Consensus invariants (encoded, not just documented)

- `reserved[12] = [0; 12]` — not extranonce, not pool scratch, not miner
  entropy. Any frame carrying non-zero reserved bytes is **rejected**.
- `timestamp: u64` — no `u32` shortcuts anywhere in the codec path.
- `utreexo_root` is not auxiliary metadata: it lives at header offset
  `0x44` and is hashed into the block hash. Miners cannot alter it.
- Header serialization is little-endian throughout, matching
  `dinero/include/primitives/block.h`.

## Regenerating mainnet vectors

```bash
python3 <<'EOF' > tests/vectors/mainnet_headers.json
import json, subprocess
CLI = "dinero-cli"
TIP = int(subprocess.check_output([CLI, "getblockcount"]).decode().strip())
HEIGHTS = [1, 100, 500, 1000, 2000, 3000, 4000, 5000, TIP]
out = []
for h in HEIGHTS:
    hash_ = subprocess.check_output([CLI, "getblockhash", str(h)]).decode().strip().strip('"')
    blk = subprocess.check_output([CLI, "getblock", hash_, "0"]).decode().strip().strip('"')
    out.append({"height": h, "hash": hash_, "header_hex": blk[:256]})
print(json.dumps(out, indent=2))
EOF
```

## License

MIT.
