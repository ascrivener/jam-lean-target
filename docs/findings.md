# Findings

Each entry: minimised input, both outputs, GP v0.8.0 reference, verdict, status.

## F1. jam-lean: lookup-anchor ancestry check uses the anchor's state root

* **Input**: any guarantee whose refinement context has lookup anchor ≠ anchor (found by reading;
  no vector yet).
* **Model**: `lookupAnchorKnown` (`JAM/BlockImport.lean`) requires h'_R = x_s (the anchor's
  posterior state root, `anchorStateRoot`).
* **GP v0.8.0**: eq. 11.36 (`reporting_assurance.tex` l. 373–377) requires
  h'_R = x_{lookup-anchor post-state} (`lookupAnchorStateRoot`).
* **Verdict**: model wrong. **Status**: confirmed by the jam-lean parent against eq. 11.36 (2026-11-15); a jam-lean session is fixing it with a regression test.

## F2. `grow_heap` out of gas: GP 0.8.0 charges nothing, the process charges all (GP #533)

* **Input** (minimised to one block): jam-fuzzing `fuzz-proto/examples/0.8.0/no_forks`, steps
  0–25, then step 26 (block at slot 25, 6 assurances, no guarantees). That block makes one report
  available whose two digests go to service 4035190182 (gas limits 2,500,000 each, so g = 5,000,000).
  Its accumulate calls `grow_heap` (host call 1) repeatedly, doubling the request; the last call asks
  for ω_7 = 65,597 pages with ϱ = 351,276 < g. That call is ∞ (out of gas).
* **Model** (jam-lean `hostGrowHeap`): ϱ' = ϱ = 351,276, so Ψ_M's u = 5,000,000 − 351,276 =
  **4,648,724**, recorded in π_S[4035190182] (accumulation gas).
* **polkajam** (the fuzzer's expected root, step 26) and **jamduna** (0.8.0 image, GetState):
  **5,000,000**. Every other state component is identical (the run is reverted to the checkpoint in
  both, as ∞ requires).
* **GP v0.8.0**: Ω_♊ (`pvm_invocations.tex` l. 331–337) defines ⟨ε', ϱ', ω'_7⟩ itself:
  ⟨∞, ϱ, h⟩ when ϱ < g ("Only enlarge the heap if we have enough gas; otherwise abort with OOG").
  Ψ_H* passes ϱ'' on (`pvm.tex` l. 774–777) and Ψ_M sets u = ϱ − max(ϱ', 0) (`pvm.tex` l. 874).
  So u = 4,648,724.
* **Cause**: a Gray Paper change after v0.8.0. GP PR #533 "Various host function fixes/improvements"
  (merged 2026-07-22; v0.8.0 was released 2026-06-03) removed Ω_♊'s own ⟨∞, ϱ, h⟩ case, so the
  general rule ϱ' = ϱ − g applies and an out-of-gas `grow_heap` uses up all gas. polkajam and
  jamduna follow GP main; the model follows v0.8.0 as released.
* **Verdict**: model right for GP v0.8.0; implementations right for GP after #533. Not a bug on
  either side relative to its target. Under Adam's decision (model strictly 0.8.0) this is logged
  as "the process follows GP #533", like the `bless` change (#519/#558).
* **Status**: explained 2026-11-15. Nothing to report.

## F3. Reports beyond work-package limits: valid in GP 0.8.0, rejected after GP #563

* **Input**: 16 published traces in jam-fuzzing `fuzz-reports/0.8.0/traces`, each one block on the
  genesis state (slot 0 or 1) with a guarantee whose report has one field beyond a work-package
  limit; signatures valid (checked with the Lean Ed25519, ZIP-215). Smallest cases:
  * `1792928756_4797`: auth gas used r_g = 50,000,001 = 𝖦_I + 1, everything else ordinary;
  * `1792929672_3352` step 2: a digest's import count 3,073 = 𝖶_M + 1;
  * `1792929838_3893`: a digest's refine gas used 1,000,000,001 (tiny 𝖦_R + 1);
  * `1792930096_8385`: exports count 65,535 (> 𝖶_X = 3,072);
  * `1792930398_2612`: bundle length 2³² − 1 (> 𝖶_B).
  Others: 1792929525_1916, 1792929619_8124, 1792929743_9484, 1792929975_2030, 1792930230_1191,
  1792930259_5359, 1792931352_6642, 1792931620_4387, 1792931776_5866, 1792933026_3178,
  1792933514_9961.
* **polkajam** (trace: post-state = pre-state, i.e. rejected) and all eight GP 0.8.0 teams in the
  summary table agree with it: block invalid.
* **Model**: imports the block.
* **GP v0.8.0**: the report's fields are typed r_g ∈ ℕ_G (`reporting_assurance.tex` l. 44),
  s_l ∈ ℕ_L, s_n ∈ ℕ (eq. `avspec`), d_u ∈ ℕ_G, d_i, d_x, d_z, d_e ∈ ℕ (eq. `workdigest`). The
  limits 𝖦_I, 𝖶_M, 𝖶_X, 𝖶_B, 𝖦_R bound the work-package and its refinement (§14, e.g.
  `work_packages_and_reports.tex` l. 93–117), which guarantors check off-chain; §11.4 (guarantee
  validity) checks none of these fields on-chain.
* **Implementations' reasons** (asked directly with `scripts/askimpls.py`, GP 0.8.0 images of
  jamduna, javajam, jamforge, lasair, pyjamaz; turbojam and jampy did not start here):
  | Case | Answers |
  | --- | --- |
  | auth gas 𝖦_I + 1 | "auth gas too high" (all five) |
  | refine gas 𝖦_R + 1 | "refine load too high" / "refine_load_above_limits" (all five) |
  | exports count 65,535 | "bad exports count" / "segment_count_mismatch" / "exports_count_mismatch" |
  | bundle length 2³² − 1 | "bundle too big" / "bundle_length_too_high" (all five) |
  The model (our image) imports all four.
* **Not in GP v0.8.0 nor its vectors**: §11's complete list of guarantee conditions has none of
  these, and jam-test-vectors v0.8.0 `stf/reports` has no such error code.
* **Cause**: GP PR #563 "Bound work-report values by work-package limits" (merged 2026-11-02, after
  v0.8.0) adds eq. `reportrefineload`: Σ d_u ≤ 𝖦_R, Σ d_i ≤ 𝖶_M, s_n = Σ d_e ≤ 𝖶_X, Σ d_x ≤ 𝖳,
  the input-size bound, s_l ≤ 𝖶_B and r_g ≤ 𝖦_I. Each case above violates exactly one of them.
* **Verdict**: model right for GP v0.8.0; implementations and fuzzer right for GP after #563. Logged
  as "the process follows GP #563" under Adam's strictly-0.8.0 decision.
* **Status**: explained 2026-11-15. Nothing to report.
