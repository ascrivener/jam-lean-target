# Profiling the target

Where the target spends time on a block import or a refine, and how to measure it again. The
results are reported to Adam, not kept here; this file only describes the method.

## Run

```sh
git clone https://github.com/jam-conformance/jam-fuzzing vendor/jam-fuzzing   # as CI does
scripts/profile.sh [REPS]          # timings (default 3 repetitions per message, minimum kept)
PERF=1 scripts/profile.sh          # also a perf profile of the harness (needs `perf`)
```

The script builds `jam-lean-target` and the `profile` harness (`Profile.lean`, `lake exe profile`).
Then it crafts sessions from the fuzzer's 0.8.0 genesis converted to v0.8.1, the same way
`scripts/blocks-vectors.sh` does: `craft_epoch` (a plain block, assurance blocks, and an epoch
change that computes the ring root) and the probes `control` and `oog` (five assurances make a
report available, and it accumulates on the PVM). It then prints:

1. **process start → PeerInfo reply**: what the fuzzer waits for on each connection, because
   `scripts/entrypoint.sh` starts one process per connection (Lean module initialisation, then
   SRS loading);
2. **primitives** (`profile --prims`): ring root O(k) at the GP v0.8.1 domain (2048), ring VRF
   verification (the Draft 35 vector, and the same proof at the target's keyset size), Ed25519
   verification, Thin VRF verification, Y(s), Blake2b;
3. **per message**, for each session and for `vectors/refine/0.8.1-tiny`:
   * `decode`: the wire message;
   * `full`: `Session.handle` with the target's crypto, as `serve` runs it;
   * `-ring`, `-bs`, `-ed`: the same call with the ring root and ring VRF, then the Thin VRF
     verification, then Ed25519 replaced one after another by the accept-all stand-ins of
     `oracleCrypto`. Each difference between neighbouring columns is the cost of that primitive
     in this block. `-ed` is the cost without signature, VRF or ring work;
   * `M(pre)`, `M(post)`: M_σ (T(σ) plus the trie) of the parent state and the posterior state.
     Υ checks H_R against M_σ of the parent, and the session answers with M_σ of the posterior,
     so a block import computes both;
   * `encode`: the response.

   What is left of `-ed` after `M(pre) + M(post)` is the STF logic, including accumulation on the
   PVM. The perf summary splits it further.

The harness only calls `Session.handle` with different `Crypto` values. It does not change the
target. The sessions advance with the `full` result.

## perf

`scripts/perfcat.py` reads `perf script` output. It assigns each sample to the first matching
component in its stack, in this order: ring (BLS12-381 MSM, pairing), Bandersnatch, Ed25519, PVM,
merklisation/serialization, hashing, then other. It also lists the Lean functions with the
largest inclusive share. The shares cover the harness as a whole, which runs every block four
times (once per crypto variant), so read them for function names. The per-component costs come
from the timing table. `perf record -D 16000` skips module initialisation.

## Startup

Lean evaluates closed top-level terms when a module is initialised, before `main` runs.
`perf record` on `jam-lean-target serve` without `-D` shows how much of the PeerInfo latency
comes from that.

## What is not covered

* Blocks with tickets: the crafter cannot produce ring VRF proofs. The cost per ticket is the
  ring VRF verification primitive.
* Blocks with guarantees: no valid crafted report yet. The cost per guarantee is about two or
  three Ed25519 verifications plus the report checks.
* The full chain (`JAM_FUZZ_SPEC=full`): no full-chain genesis in the repository. Scale the
  primitives by V = 1023 and C = 341.
