# Refine: work reports from the model (`feature-refine`)

The target answers `RefineBundle` (tag 6) with `WorkReport` (tag 7) or `Error`, as proposed in
jam-fuzzing PR #214 (branch `refinement-extension-followup`, `feature-refine` = 2^2). The report
is Ξ(p, c, l, v) of GP v0.8.1 §14.4, computed by `JamTarget/Refine.lean` on the service accounts
of the posterior state of the last block imported with success (or the `Initialize` state).

## What comes from where

| term | GP v0.8.1 | here |
| --- | --- | --- |
| Ψ_I, Ψ_R, refine host calls | App. B | jam-lean `JAM.psiI`, `JAM.psiR` |
| report, digest, spec types and ℰ | §11, App. C | jam-lean `JAM/Work.lean` |
| ℰ_C (erasure code, GP #580), R(v) | App. H | jam-lean `JAM.Erasure` |
| ℳ_B, N | App. E | jam-lean `JAM.Merkle` |
| ℳ, C, T, J_x, L_x | App. E | `Refine.constRoot`, `constancy`, `trace`, `justPath`, `leafPage` |
| P (paged proofs) | eq. `pagedproofs` | `Refine.pagedProofs` |
| B (bundle), A (availability spec) | §14.4, §14.4.1 | `Refine.Bundle.encode`, `Refine.availability` |
| Ξ, I, C, p_a | §14.3, §14.4 | `Refine.xi`, `countUp`, `digest`, `packageAuthorizer` |

jam-lean has no Ξ, A, P or constant-depth Merkle functions; they are written here from the paper.

## The request

`RefineBundle = (core-index U16, segment-root-lookup, erasure-shards U16, work-package,
extrinsics, import-segments, justifications)`. The bundle part is read as the GP bundle encoding
B (eq. `makebundle`): no length prefixes for the three sequences or for each extrinsic (the
lengths come from the work-items), each justification ↕. The ASN's `SEQUENCE OF` would suggest
prefixes, but its comment ("Parts of the GP work-package bundle, in the order of the GP bundle
encoding. The GP encoding has no length prefix for the three sequences and for each extrinsic.")
points to the GP encoding. This is an assumption until the protocol says which.

`Error` when:
* the bundle does not verify: the extrinsics are not the data of the items' (hash, length) pairs
  in order; an import segment does not lead through its justification (a path in a tree of depth
  |path|, leaf H($leaf ⌢ segment)) to its segment root (r, or l[h] for h^⊞); the counts differ;
* Ξ gives ∇: Is-Authorized fails or its trace exceeds 𝖶_R, or K(l) is not the set of imported
  package hashes;
* R(v) = 0 or v > 1023.

Not checked (PR #214: block import does it): the authorizer pool, the refinement context, whether
segment roots are known.

## What GP v0.8.1 changed (and the target follows)

Until the pin moved to GP v0.8.1 (2026-11-25) the target answered with GP v0.8.0's Ξ. Three
definitions changed, each now taken from v0.8.1:

* **Erasure code (GP #580, App. H).** p is padded to d' = 2^⌈log₂ d⌉ (zeros at d̃ … (d'−1)~;
  validator i ≥ d gets p((i + d' − d)~)), the official erasure vectors' convention. jam-lean's
  `JAM.Erasure` implements it (`paddedShards`, `encodeWith`); `refinegen` checks jam-lean's
  weights against GP #580's, written out independently (`weights580`). Every erasure root differs
  from v0.8.0's (data shards agree, parity shards do not; tiny: d = 3, d' = 4).
* **No exports (GP #583).** **s**♣ uses the sized transpose ᵀ_v, so with **s** = [] each of its
  v items is ℳ_B([]) = H_0 (the paper's note: "if no segments are exported, each item of
  **s**♣ is the zero hash"). v0.8.0 left the erasure root undefined there and the target answered
  `Error`; now such a package gets a report (vectors `nothing_exported`,
  `nothing_exported_two_items`).
* **Refine errors first (GP #568).** I(p, j) keeps an error r ∉ 𝔹 first, then checks
  |r| + z > 𝖶_R, then |**e**| ≠ w_e. v0.8.0 checked bad exports first, so an item with w_e > 0
  that panicked gave ⊚; now it gives ☇ (vectors `panic_with_exports`, `export_then_panic`).

## Other readings that matter

* **Out of gas (App. A).** "the execution is interrupted and the gas counter remains unchanged":
  an item whose next basic block costs more than the gas left reports u < g (vector
  `out_of_gas`: 990 of 1000).
* z in I sums the final (post-replacement) blob outputs of earlier items (I is the count-up
  function itself).

## Vectors

`vectors/refine/0.8.1-tiny/` is one fuzzer session (minifuzz format, as
`fuzz-proto/examples`): `PeerInfo` (features 7), `Initialize` with the 0.8.0 example genesis in
GP v0.8.1 form (`JamTarget/Upgrade.lean`) plus service 1000 holding five tiny programs as
preimages, then one `RefineBundle` per case; `CASES.md` lists them. The responses are GP v0.8.1's.
`lake exe refinegen BASE OUT [--prefixed]` regenerates it (BASE = jam-fuzzing
`fuzz-proto/examples/0.8.0/no_forks/00000001_fuzzer_initialize.bin`); CI replays it with
`jam-lean-target session`. `scripts/askrefine.py` asks Docker images what they advertise
(`features`) and replays a session against them field by field (`replay`).
