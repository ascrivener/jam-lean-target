# Block-level vectors (GP v0.8.0)

Crafted blocks (`jam-lean-target probe` / `craft`, signed with the JIP-5 development keys) on the
genesis state of the fuzzer's 0.8.0 sessions (jam-fuzzing `fuzz-proto/examples/0.8.0/no_forks`,
`Initialize`). Each directory is a fuzz-reports trace: `genesis.bin` = ℰ(genesis header, state)
and `NNNNNNNN.bin` = ℰ(pre-state, block, post-state), each state ℰ(root, ↕[(key, ↕value)]). The
post-states are jam-lean's, i.e. GP v0.8.0's. CI replays them with `jam-lean-target trace` and
checks that `scripts/blocks-vectors.sh` regenerates them byte for byte. JSON is not provided.

Every signature verifies with `JamCrypto`, with ed25519-dalek (`verify_strict`) and with ark-vrf
0.1.0 (`JamCryptoTest/generator verify` on the crafter's `signatures.txt`).

## `probe_*`: findings F4 and F6 at block level (`JamTarget.Probe`)

The genesis state, with two additions:
* service 0x0b0b0b0b, whose code is a standard program around the probe's PVM blob;
* a work report for it pending on core 0 (ρ[0], t = 0; its guarantee is signed by validators 0–2,
  and ρ's contents are not re-validated at assurance time).

The block (slot 1, sealed by the fallback key γ_S[1]) carries assurances by validators 0–4 for
core 0. The report becomes available and accumulates with g = 100,000. The gas used goes into
π_S, and so into the state root.

| vector | code from instruction 5 | GP v0.8.0 result | π_S gas |
| --- | --- | --- | --- |
| `probe_control` | `jump_ind ω0` | halt | 22 |
| `probe_panic` | `trap` | ☇ | 2 |
| `probe_oog` | `jump` to itself | ∞ | 99,990 |
| `probe_f4` | `fallthrough`, the last instruction (F4) | the blob is valid: charge the block, ☇ | 2 |
| `probe_f6` | \|j\| = 1, z = 0; `jump_ind` to j₀ = 0, then a loop (F6) | ∞ | 99,998 |

For ∞, GP v0.8.0 §A.4 leaves ϱ unchanged when a block's cost exceeds the gas left (ϱ* = ϱ), so u =
g − (that remainder) rather than g.

`scripts/askprobe.py OUT IMAGE…` compares an implementation's answers with these.

## `craft_epoch`

`tests/craft/epoch.txt`: four blocks (slots 1, 5, 12, 14) with empty-bit assurances. Slot 12
carries an epoch mark and is sealed from the new γ_S.
