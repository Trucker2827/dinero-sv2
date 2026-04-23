# dinero-sv2

Stratum V2 for Dinero, in Rust. Protocol messages, wire codec, Noise NX
transport, reference pool server, Template Provider binary, and
miner-side Job Declaration — the sovereignty loop that lets a miner
(including a phone) pick its own coinbase outputs and let the pool
independently verify every byte, including the header's Utreexo root.

Pure Rust, no FFI. Works anywhere a Rust crate works: DineroDPI (iOS),
future pool operators, TP processes running beside `dinerod`, tests.

## What's in here

```
crates/
├── dinero-sv2-common       messages + header layout + Utreexo invariants
├── dinero-sv2-codec        strict wire codec (fixed + var-len)
├── dinero-sv2-jd           Job Declaration primitives + pure-Rust Utreexo
├── dinero-sv2-transport    Noise NX + SV2-shaped framing
├── dinero-sv2-tp-sim       in-memory Template Provider simulator
├── dinero-tp               TP binary — binds dinerod, serves miners
└── dinero-sv2-pool         reference pool server (two-tier target +
                            submitblock + JD acceptance)
```

## The sovereignty loop

Phase 5 is the finish line. With a `dinerod` running at `127.0.0.1:20998`
and the daemon's cookie in `~/.dinero/.cookie`:

```bash
# Terminal 1 — pool
ADDR=din1p6zd8mnxf3fz0kcsjrmsrtjkymnmfjz9gkrpqhed07g3n4hdfn4pq6nxmch
cargo run --release -p dinero-sv2-pool -- \
  --bind 127.0.0.1:4444 \
  --payout-address "$ADDR" \
  --share-leading-bits 0

# Terminal 2 — print the pool's static Noise pubkey for pinning
cargo run --release -p dinero-sv2-pool -- \
  --payout-address "$ADDR" --print-pubkey
# → 47e4c132fefc04bce63f87b2d5d0a70575541da47d4dbe23247ea135eafcfb58

# Terminal 3 — a miner that picks its own payout and runs the full JD loop
cargo run --release -p dinero-tp --example testclient -- \
  --server-pubkey 47e4c132fefc04bce63f87b2d5d0a70575541da47d4dbe23247ea135eafcfb58 \
  --jd
```

The miner prints:

```
handshake ok; server static pubkey = 47e4c132…
SetupConnection.Success: used_version=2
OpenStandardMiningChannel.Success: channel_id=1 target=FF..FF
SetNewPrevHash: prev_hash=b07ae72d… nbits=0x1d00ffd2
UtreexoStateAnnouncement: num_leaves=15993 num_roots=10
  pre_block_commitment=2af38633…
CoinbaseContext: height=5332 value_una=10000000000 …
NewMiningJob: template_id=1 utreexo_root=5cec2b43…
JD locally computed: coinbase_txid=c78077d7…
                     utreexo_root=ceded42b7…  (pool's was 5cec2b43…)
SubmitShares.Success: accepted=1
```

The pool prints:

```
accepted extended share
  hash=46bc4e92…
  template_id=1 utreexo_root=ceded42b7…
```

That match — `ceded42b7…` — is the whole point. The miner chose its
payout, built its own coinbase, derived the header's `utreexo_root`
locally. The pool reassembled the candidate from the miner's submitted
outputs, applied the same Utreexo math, and got the same 32 bytes.
Neither side's result relied on the other.

## Phase history

Each phase is one commit. `git log --oneline` reads like a story from
messages-on-paper to a running sovereignty loop.

| Phase | Commit | Deliverable |
|-------|--------|-------------|
| 1 | `b0796aa` | Codec foundation: 128-byte header, NewTemplateDinero, SubmitSharesDinero, HeaderAssembly, byte-for-byte parity against 9 live mainnet headers |
| 2.1 | `7277201` | dinero-tp binds real daemon via HTTP JSON-RPC, emits real templates |
| 2.2 | `8064bc9` | Noise NX wrapping (ChaChaPoly + BLAKE2s), static key pinning |
| 3 | `2af044a` | JD message + coinbase assembly + merkle path computation |
| 4 | `b657531` | Reference pool server: two-tier target + submitblock on block-target shares |
| A | `c7220cc` | SV2-shaped framing: u24 outer length prefix, 6-byte inner header (ext_type u16 + msg_type u8 + msg_length u24) |
| B | `229278c` | Setup / OpenStandardMiningChannel / SubmitShares.Success+Error |
| C | `9e4e478` | Explicit SetNewPrevHash before every NewMiningJob |
| 3b | `63a12b7` | Utreexo accumulator state + delta-addition primitives |
| 3c | `07a1098` | Pure-Rust port of Dinero's Utreexo primitives; byte-for-byte verified against the live `getutreexocommitment` RPC |
| 4b | `c1b7e46` | Pre-block Utreexo state on the wire (UtreexoStateAnnouncement) |
| 5 | `24cf530` | Miner-owned coinbase end-to-end: CoinbaseContext + SubmitSharesExtended + pool-side reassembly |

99 tests across the workspace at Phase 5 head, all green. `cargo clippy
-- -D warnings` clean.

## Consensus-critical invariants (encoded, not just documented)

- **128-byte header with `reserved[12] = 0`.** Not extranonce, not pool
  scratch, not miner entropy. Enforced at encode and decode in
  `dinero-sv2-common::HeaderAssembly`.
- **`timestamp: u64`.** Dinero dodged 2038; no u32 shortcuts anywhere.
- **`utreexo_root` at offset 0x44** is a first-class header field —
  Dinero-specific. Miners compute it locally in JD mode.
- **Leaf hash = `SHA256("DINERO-UTXO-LEAF-v1" || txid || vout_LE32 ||
  amount_LE64 || CompactSize(script_len) || script)`.** Matches
  `HashUTXO` in `dinerod/src/consensus/utreexo_accumulator.cpp:216-266`.
- **Node hash = `SHA256("DINERO-UTREEXO-NODE-v1" || left || right)`.**
  Matches `HashNode` in the same file, 201-214.
- **Commitment = `SHA256(num_leaves_LE64 || slot[0] || … || slot[63])`**
  with 32-byte zeros for empty slots. Fixed 2056-byte preimage. Matches
  `UtreexoForest::getCommitment` at 1845-1874. Cross-verified
  byte-for-byte against the live `getutreexocommitment` RPC
  (`cb8592403b46beee…` at `num_leaves=15939`).

## SV2 wire shape (Pass A-C)

After Noise NX:

```text
| u24 LE ciphertext_len | ChaChaPoly ciphertext |

plaintext inside the cipher:
| u16 LE ext_type | u8 msg_type | u24 LE msg_length | payload |
```

Pool → miner message order per tip:

```text
SetNewPrevHash 0x20
→ UtreexoStateAnnouncement 0x21          (Dinero ext; JD-capable pools)
→ CoinbaseContext 0x17                   (Dinero ext; JD-capable pools)
→ NewMiningJob 0x15
```

Miner → pool shares:

```text
Standard:  SubmitSharesStandard 0x1A → SubmitShares.Success 0x1C / .Error 0x1D
JD:        SubmitSharesExtended 0x1B → same ack messages
```

## Spec drift observed

`docs/DINERO-UTREEXO-SPEC.md §3.5` in the Dinero repo publishes three
golden leaf-hash vectors computed *before* the C++ added a CompactSize
varint before the script. Current consensus code (and this Rust port)
include the varint, so the spec's goldens are stale. See the Phase 3c
commit for details.

## License

MIT.
