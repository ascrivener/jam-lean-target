# Shadow mode

`scripts/shadow.py` follows a JAM chain block by block and checks each post-state root against the
model. It feeds the chain to any fuzzer-protocol target (default `jam-lean-target serve` on
stdin/stdout, one process per feed) and compares our root with the node's.

```
lake build
python3 scripts/shadow.py session DIR…  [options]   # recorded fuzzer sessions
python3 scripts/shadow.py trace DIR…    [options]   # fuzz-reports traces
python3 scripts/shadow.py dump DIR…     [options]   # a node's block dump
```

| option | meaning |
| --- | --- |
| `--continue` | keep going after a mismatch (default: stop at the first) |
| `--known FILE` | label known divergences (`scripts/shadow-known.txt`: header hash, then label) |
| `--out DIR` | where states go on a mismatch (default `shadow-out`) |
| `--quiet` | print only mismatches and the summary |
| `--spec tiny\|full` | header layout for hashing (V, E); default `tiny` |
| `--genesis-header SESSION` | trace feed without `genesis.bin`: use that session's Initialize header |
| `--target-log FILE` | keep the target's stderr (default: discarded) |
| `--target CMD…` | another target command, given last (default `.lake/build/bin/jam-lean-target serve`) |

The exit status is 0 when every checked block matches or is listed as known.

## What it checks

For each block the driver sends `ImportBlock` and compares the result with the node's:

* **node root**: from the feed. When the feed has none for a block, it comes from the next block's
  header (H_R, the parent's posterior state root) if that block is a child of this one.
* **node verdict**: a block the node rejected must be rejected by the model too (error text not
  compared, as in minifuzz).

A block whose parent the feed never supplied (a trace that skips steps) is *skipped* rather than
counted. The summary gives blocks imported, matches, known divergences, unexplained mismatches,
blocks without a node root, skipped blocks and the mean import time per block (the target's
`ImportBlock` round trip).

## On a mismatch

1. `GetState(header hash)` from the target goes to `OUT/NAME.ours.state`.
2. If the feed holds the node's post-state, it goes to `OUT/NAME.node.state`. The driver prints the
   differing components and runs `scripts/diffstate.py` on the pair.
3. A **hint** points at the post-0.8.0 GP changes worth checking first (`docs/gp-after-0.8.0.md`).
   It works from the kind of mismatch (node rejects, model rejects, root) and the differing
   components. It is a hint, not a verdict: classify every mismatch against GP v0.8.0 and that
   table before calling it a bug, and report it to the parent session (minimised block, both
   roots, the state diff). `docs/findings.md` is not edited from here.
4. Without `--continue` the run stops. With it, the driver **resyncs** when the feed has the node's
   post-state: a fresh target session is initialised from that state, keyed by the block's header,
   with the ancestry seen so far, and it must reproduce the node's root. Later blocks are then
   checked against the node's chain. Without a node post-state, or when the resync does not reproduce
   the root, the block's descendants are skipped ("descendants of a divergence") rather than
   reported as follow-on mismatches.

A feed whose genesis state the model cannot reproduce is skipped whole. Today that means states
holding service storage (`docs/gaps.md` #2, until jam-lean's storage-key stage 2).

## Feeds

A feed supplies three things: an `Initialize` message (genesis header, key-values, ancestry), the
node's genesis root if known, and the blocks in import order. Each block comes with the node's
verdict, root and post-state where known (`Feed` and `Step` in the script).

* **`session DIR`**: a recorded fuzzer session (jam-fuzzing `fuzz-proto/examples/<v>/<name>`). The
  fuzzer's requests are the chain; the recorded target responses give roots and
  verdicts. No node states.
* **`trace DIR`**: a fuzz-reports trace. `genesis.bin` = ℰ(header, state); `NNNNNNNN.bin` =
  ℰ(pre-state, block, post-state) with state = (root, key-values). The `NNNNNNNN.json` beside each
  step supplies the post-state root that marks where the block ends. Traces carry full node
  post-states, so mismatches are diffed. Without `genesis.bin`, the first pre-state is used under
  `--genesis-header`'s header (as `scripts/askimpls.py` does). A trace whose first parent is not that header's hash shows up as skipped blocks.
* **`dump DIR`**: the format for a real node. `genesis.bin` = ℰ(header, key-values) (the Initialize
  body without ancestry); per block `NNNNNNNN.block` = ℰ(block), optionally `NNNNNNNN.root`
  (32 octets) and `NNNNNNNN.state` = ℰ(key-values). Files are taken in name order. With only
  `.block` files, roots come from the next header's H_R, so every block but the last is checked.
  `.state` files enable diffs and resyncs.
* **node RPC** (not yet): a class with the same `peer_info` / `initialize` / `init_root` /
  `steps()` interface, pulling blocks and roots from a node (JIP-2 RPC or a debug endpoint).
  No node could be run in this sandbox yet. Starting from a mid-chain snapshot also needs
  `docs/gaps.md` #2 closed when the snapshot holds storage.

## A PolkaJam testnet feed (GitHub Actions)

No node binary can run in the development sandbox, so `.github/workflows/polkajam-feed.yml` runs
one in this repo's Actions. It is started manually (Actions → "polkajam feed" → Run workflow;
inputs: release `tag`, default `v0.8.0`; `blocks`, the slot to run to; `rpc`, the JIP-2 endpoint;
extra `testnet_args`). It:

1. downloads the release's Linux assets from `paritytech/polkajam-releases`, lists them
   (`release.txt`) and unpacks them;
2. saves `--help` for every executable and its subcommands (`help/`), flagging pages that mention
   export, dump, block or state;
3. runs `polkajam-testnet` and records its best chain over JIP-2 with `scripts/polkajam_chain.py`:
   per block the slot, header hash and posterior state root (`chain.json`);
4. uploads `feed/` as the artifact `polkajam-feed`, with the testnet log and the files it wrote.

JIP-2 has no method that returns blocks or full states (`bestBlock`, `parent` and `stateRoot`
are the chain methods), so `chain.json` gives roots without blocks. A `dump` feed also needs
the blocks, from an export command if the help pages show one. That conversion is the next step.
