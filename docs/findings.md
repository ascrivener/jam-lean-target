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

## F2. polkajam and jamduna charge all gas when `grow_heap` runs out; GP 0.8.0 charges none

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
* **Verdict**: by the letter of GP v0.8.0 the model is right and polkajam and jamduna are wrong
  (they charge the whole gas, as the general host-function rule ϱ' = ϱ − g < 0 would, but Ω_♊
  overrides ϱ'). It may also be a GP wording slip (OOG usually exhausts gas); either way the
  implementations and the paper disagree, and the state root depends on it.
* **Status**: found 2026-11-15. Not reported anywhere; disclosure is Adam's call.
