# Findings

Each entry: minimised input, both outputs, GP v0.8.0 reference, verdict, status.

## F1. jam-lean: lookup-anchor ancestry check uses the anchor's state root

* **Input**: any guarantee whose refinement context has lookup anchor ≠ anchor (found by reading;
  no vector yet).
* **Model**: `lookupAnchorKnown` (`JAM/BlockImport.lean`) requires h'_R = x_s (the anchor's
  posterior state root, `anchorStateRoot`).
* **GP v0.8.0**: eq. 11.36 (`reporting_assurance.tex` l. 373–377) requires
  h'_R = x_{lookup-anchor post-state} (`lookupAnchorStateRoot`).
* **Verdict**: model wrong. **Status**: confirmed by the jam-lean parent against eq. 11.36 (2026-11-15); fixed in jam-lean PR #195 (acb9e94) with regression guards; jam-lean-target pins it since 2026-11-15.

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

## F4–F6. PolkaVM vs GP v0.8.0 at the PVM level

Found by the PVM differential harness (`docs/pvm-diff.md`, PR #7): jam-lean's PVM against PolkaVM
0.38.1 (newest release, = master a485609 on 2026-11-15), interpreter with spectool's setup and,
where possible, the recompiler. Neither GP v0.8.0 nor any later GP change (#554, #559, #582,
#588 read) explains them. In all three the model follows GP v0.8.0 and PolkaVM does not. PolkaVM
is the PVM behind polkajam, the fuzzer's reference; whether polkajam (or other implementations)
behaves the same at block level is not yet tested.

| | Minimised case | Model (GP v0.8.0) | PolkaVM | GP v0.8.0 reference |
| --- | --- | --- | --- | --- |
| F4 (D4) | blob `[0,0,1,1,1]` (code = one `fallthrough`); also a branch as last instruction | valid blob: Ψ charges the block, then panics | refused at load ("validation failed"); interpreter and recompiler | 𝔳_blob only requires the last instruction ∈ T (`pvm.tex` l. 57–63); branch/fallthrough ∈ T; panic via branch/ı+1+skip ∉ ϖ (l. 255–259) |
| F5 (D5) | `store_u16` at 0x21FFF, page 0x21000 read-only, 0x22000 unmapped | fault at 0x21000 | fault at 0x22000 (interpreter) | ε^μ: x has every written index not in 𝕍*_μ, so min(x) = 0x21FFF → page 0x21000 (l. 168–179; prose: "lowest page address to be written which is inaccessible") |
| F6 (D6) | blob `[1,0,2,50,7,1]` (|j| = 1, z = 0), `jump_ind` to 2, gas 100 | j₀ = 0 ∈ ϖ, so continues at 0 and loops to ∞ | panic, one block's gas; interpreter and recompiler | E_0 ⇒ j₀ = 0; djump (eq. `jumptablealignment`, l. 267–271); still valid after #559 (z ≤ 4) |

**Where they reach consensus** (GP v0.8.0):
* Ψ_M (is-authorized, refine, accumulate): F4 — GP charges a block then ☇; refusing at load would
  give u = 0. F6 — GP gives ∞, PolkaVM ☇ with one block. On ∞ GP v0.8.0 §A.4 leaves ϱ unchanged when the
  next block's cost exceeds it (ϱ* = ϱ), so u = g − the leftover, not all of g (99,998 of 100,000
  in the block-level probe). u enters π_S (state
  root) for accumulate and the work digest (report hash) for refine; the result decides
  is-authorized. F5 is invisible at Ψ_M (fault ends as ☇ with the same u).
* Inner PVM (refine's `machine`/`invoke`): F4 — `machine` returns HUH only if deblob = ∇, so GP
  gives a handle where a PolkaVM-style validator would return HUH; F5 — `invoke` returns FAULT with
  ω8 = the address (0x21000 vs 0x22000); F6 — OOG vs PANIC with different gas.

**Verdict**: model right per GP v0.8.0 in all three; PolkaVM is stricter (F4, F6) or reports a
different page (F5). Vectors with the GP v0.8.0 results are in `vectors/pvm` (`min_d4`…`min_d6`).
**Status** (2026-11-16; Adam: keep public):
* F4: reported by Adam as paritytech/polkavm#455.
* F5: already known upstream as paritytech/polkavm#429 (opened 2026-10-15): the interpreter reports
  the upper page; the recompiler agrees with the GP.
* F6: same root cause as paritytech/polkavm#447 (opened 2026-11-02): a jump-table entry pointing at
  code offset 0 is dropped and the jump traps; with z = 0 every entry is 0.

**Block level** (2026-11-16, block crafter): genesis plus a service whose accumulate code is the
probe blob, a report for it pending in ρ, then one crafted block (all signatures real) that makes
it available and accumulates it with g = 100,000. Compared: state root and full GetState.
* jamduna, javajam, pyjamaz, jam-lean-target: equal to the model on all probes (control, panic,
  out-of-gas, F4, F6).
* jamforge: equal on all but F6, where π_S records 23 gas (one block, then panic, as PolkaVM)
  against the model's 99,998; only C(13) differs. **F6 shows at block level in jamforge.**
* No implementation shows F4: all charge the block and panic (gas 2), as GP v0.8.0 says.
* lasair: never ran the service in this setup, controls included (report preloaded in ρ via
  `Initialize`); not F-related, not investigated further.
* F5 lives only in refine's inner PVM, which block import does not run: not tested at block level.
* polkajam not yet tested (binary not reachable from the sandbox; see the shadow-mode work).

## F0. jam-lean: signing context strings kept the GP's `$` sigil

* **Model**: `JAM.contextString "$jam_ticket_seal"` gave the octets `$jam_ticket_seal`, so with real
  crypto every ticket, seal, entropy and Ed25519 signature failed.
* **GP v0.8.0**: `$` marks the set of ASCII strings 𝔹_$ (`notation.tex` l. 149); the 0.8.0 vectors
  (58 real ticket proofs) and every fuzzer block verify only without it.
* **Verdict**: model wrong. **Status**: fixed in jam-lean PR #196 (2b88de9); pinned here.
