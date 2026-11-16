# Refine: work reports from the model (`feature-refine`)

The target answers `RefineBundle` (tag 6) with `WorkReport` (tag 7) or `Error`, as proposed in
jam-fuzzing PR #214 (branch `refinement-extension-followup`, `feature-refine` = 2^2). The report
is Ξ(p, c, l, v) of GP v0.8.0 §14.4, computed by `JamTarget/Refine.lean` on the service accounts
of the posterior state of the last block imported with success (or the `Initialize` state).

## What comes from where

| term | GP v0.8.0 | here |
| --- | --- | --- |
| Ψ_I, Ψ_R, refine host calls | App. B | jam-lean `JAM.psiI`, `JAM.psiR` |
| report, digest, spec types and ℰ | §11, App. C | jam-lean `JAM/Work.lean` |
| ℰ_C (erasure code), R(v) | App. H | jam-lean `JAM.Erasure` |
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
prefixes, but its comment points to the GP encoding, and JavaJAM (the one 0.8.0 target that
advertises `feature-refine`) reads it this way.

`Error` when:
* the bundle does not verify: the extrinsics are not the data of the items' (hash, length) pairs
  in order; an import segment does not lead through its justification (a path in a tree of depth
  |path|, leaf H($leaf ⌢ segment)) to its segment root (r, or l[h] for h^⊞); the counts differ;
* Ξ gives ∇: Is-Authorized fails or its trace exceeds 𝖶_R, or K(l) is not the set of imported
  package hashes;
* R(v) = 0 or v > 1023.

Not checked (PR #214: block import does it): the authorizer pool, the refinement context, whether
segment roots are known.

## Readings of GP v0.8.0 that matter

* **Erasure code (App. H.3).** v0.8.0: p of degree < d = R(v) through the message words at
  0̃ … (d−1)~, validator i gets p(ĩ). jam-lean follows this (its README, note 28). GP #580
  (2026-11-12) pads to d' = 2^⌈log₂ d⌉ (zeros at d̃ … (d'−1)~, validator i ≥ d gets
  p((i + d' − d)~)), which is what the official erasure vectors use. Data shards agree, parity
  shards differ, so **every erasure root differs** between the two (tiny: d = 3, d' = 4).
  An implementation that follows #580 differs from us in `erasure_root` only: "follows GP #580".
* **No exports (GP #583).** With **s** = [], v0.8.0's ᵀ[] has no size and ᵀ[**b**♣, **s**♣] is
  ragged. We take **s**♣ = v items ℳ_B([]) = H_0, so each erasure-root leaf is **b**♣_i ⌢ H_0
  — the completion GP #583 later wrote down. (Pending confirmation, see the PR.)
* **Bad exports before errors (GP #568).** v0.8.0 checks |**e**| ≠ w_e before r ∉ 𝔹, and Ψ_R
  returns no exports for ☇ and ∞, so an item with w_e > 0 that panics or runs out of gas gives
  ⊚ (`BadExports`); after GP #568 it gives ☇ / ∞. Vectors `panic_with_exports`,
  `export_then_panic`.
* **Out of gas (App. A).** "the execution is interrupted and the gas counter remains unchanged":
  an item whose next basic block costs more than the gas left reports u < g (vector
  `out_of_gas`: 990 of 1000).
* z in I sums the final (post-replacement) blob outputs of earlier items (I is the count-up
  function itself).

## Vectors

`vectors/refine/0.8.0-tiny/` is one fuzzer session (minifuzz format, as
`fuzz-proto/examples`): `PeerInfo` (features 7), `Initialize` with the 0.8.0 example genesis plus
service 1000 holding five tiny programs as preimages, then one `RefineBundle` per case;
`CASES.md` lists them, with each report's erasure root under GP #580's code for cross-checks.
`lake exe refinegen BASE OUT [--prefixed]` regenerates it (BASE = jam-fuzzing
`fuzz-proto/examples/0.8.0/no_forks/00000001_fuzzer_initialize.bin`); CI replays it with
`jam-lean-target session`. `scripts/askrefine.py` asks Docker images what they advertise
(`features`) and replays a session against them field by field (`replay`).
