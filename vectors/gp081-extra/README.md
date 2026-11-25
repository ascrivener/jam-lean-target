# Extra GP v0.8.1 vectors (`gp081-extra`)

Vectors for cases that the existing suites (davxy/jam-test-vectors, the official PVM vectors
koute/jamtestvectors `pvm/programs`) do not cover, chosen where an implementation built on
PolkaVM may differ from the paper. Formats are the official ones, so any team can run them:

* `blocks/`: block-import traces, the format of jam-test-vectors `traces/` (binary only):
  `genesis.bin` = ℰ(genesis header, state), `00000001.bin` = ℰ(pre-state, block, post-state), each
  state ℰ(root, ↕[(key, ↕value)]). All signatures are real (JIP-5 development keys).
* `pvm/`: the koute/jamtestvectors `pvm/programs` JSON format (schema `pvm/schema.asn`). As in the
  official vectors, `pc` after ☇ is the instruction that ended the run (Ψ itself returns ı = 0), and
  `memory` lists the runs of non-zero octets.

**Source of the expected values.** Every expected value is jam-lean's (GP v0.8.1 model, the pin in
`lakefile.lean`). For each vector, the GP v0.8.1 equations that dictate the key values are given
below; they were derived by reading graypaper tag `v0.8.1` (`text/pvm.tex` line numbers, `pvm_invocations.tex`,
`accumulation.tex`, `statistics.tex`) and computed by hand **before** being compared with the
model; all agree. Gas costs are hand traces of the §A.9 gas model (eq. `gascostforblock`, l. 1002–1124;
constants 4 decode slots and 5 starts per cycle, units ⟨4, 4, 4, 1, 1⟩).

**Regenerate / check.** `scripts/gp081-extra.sh [OUT]` (needs `vendor/jam-fuzzing`, as in CI).
CI replays `blocks/` with `jam-lean-target trace`, checks `pvm/` with `pvmrun check`, and
regenerates the whole directory and compares it byte for byte.

## Common GP v0.8.1 facts used below

* **Single-instruction block costs** (§A.9): a block of one instruction with c cycles and no
  dependencies costs c (decode at cycle 0, waiting at 1, starts at 1, c cycles later its counter is
  0, executed one cycle after, retired one after that: final cycle c + 3, ϱ^Δ = max(c + 3 − 3, 1)).
  `trap` and `fallthrough` cost 2, `jump` 15, a branch 𝔟.
* **𝔟** (l. 1179): 1 when ζ at the branch's fall-through or at its target is `unlikely` (2) or `trap`
  (0), else 20. ζ = c ⌢ [0, 0, …] (eq. `instructions`, l. 104), so ζ at any index ≥ |c| is 0 = `trap`.
* **ϖ** (l. 138): only indices n < |c| with k_n = 1 and c_n ∈ U; so no index ≥ |c| is in ϖ.
* **Gas is charged before the instruction's effects** (l. 163–188): ε^ϱ charges ϱ^Δ(𝔏(ı)) on block
  entry; a ☇, F or ε^μ outcome of that instruction keeps the charge.

## `blocks/`: F4 and F6 at block level (`JamTarget.Probe`)

Setup (as `vectors/blocks/README.md`): the fuzzer's 0.8.0 genesis converted to v0.8.1 form, plus
service 0x0b0b0b0b whose code is ℰ(↕[]) ⌢ a standard program (no RO/RW data, no heap, 4096-octet stack)
around the probe blob, and a report for it pending on core 0. The block (slot 1, assurances by
validators 0–4) makes it available; it accumulates with g = 100,000. The gas used u goes into
π_S[0x0b0b0b0b] (accumulation gas) and so into the state root; nothing else differs between the three.

Chain of equations, the same for all three: Ψ_A (`pvm_invocations.tex` l. 171) calls
Ψ_M(code, 5, g, …) since |code| ≤ 𝖶_C (#582); Y succeeds (l. 796–854: metadata ℰ(↕[]), eq.
`ramlayoutfits` holds); Ψ_H starts with the gas-charged flag ⊥ (l. 783), so the first step charges
ϱ^Δ(𝔏(5)). Ψ_M's R (l. 861–878) gives u = g − ϱ' for ☇ and ∞ alike; u is the service's gas in S
(`accumulation.tex` eq. `accumulationstatisticsdef`, l. 416) and π_S[s] = (…, …, u) (`statistics.tex`
l. 166). The blob passes deblob (l. 49–74) in every case: z ≤ 4, |c| ≤ 2²⁵, |j| ≤ 2²⁴.

| vector | PVM blob (from instruction 5) | GP v0.8.1 | u = π_S gas |
| --- | --- | --- | --- |
| `f4_fallthrough_last` | c = [1,1,1,1,1,1] (`fallthrough` ×6), all starts | 𝔳_blob (l. 59–67) ends ⊤: at ı = 5, ı + 1 + skip = 6 = \|k\| but c₅ ∈ T, so the ⊥ case does not apply; 𝔳_blob(6) = ⊤ (6 > 0, 6 = \|k\|). Valid. ϖ = {0,…,5}; block 𝔏(5) = 5 = [fallthrough], cost 2. `fallthrough` = sjump(6) (l. 250), 6 ∉ ϖ → ☇. | **2** |
| `f4_branch_last` | c = [1,1,1,1,1,81,0]: 5 = `branch_eq_imm ω0, 0, 5` (ℓ = 1: l_X = 0, l_Y = 0, ν_Y = 5; l. 434–445) | Valid as above (c₅ = 81 ∈ T, 5 + 1 + 1 = 7 = \|k\|). branch(5, ·) (l. 258): ı + 1 + skip = 7 ∉ ϖ → ☇ whether or not taken. Block [branch] costs 𝔟 = 1 (ζ₇ = 0 = trap), a 1-cycle block. | **1** |
| `f6_jump_table_z0` | \|j\| = 1, z = 0; c = [40,1,1,1,1,51,1,2,50,1]: 0 `jump 0`, 1–4 `fallthrough`, 5 `load_imm ω1, 2`, 8 `jump_ind ω1, 0` | ℰ₀(j₀) = [] with j₀ ∈ ℕ_{2⁰}, so j₀ = 0 (z = 0 ≤ 4, valid since #559). djump(2) (l. 268–273): a = 2 ≠ 0, a ≤ \|j\|·2, even, j₀ = 0 ∈ ϖ → continue at 0. Block 5 = [load_imm; jump_ind]: jump_ind depends on ω1, starts at cycle 2, 22 cycles, retired at 26 → cost 23. Block 0 = [jump 0] costs 15 and loops. 100,000 − 23 = 99,977 = 6,665·15 + 2; then 2 < 15 → ∞ with ϱ' = 2 (ε^ϱ keeps ϱ). | **99,998** |

The reference values for the same setup with a plain `trap` (u = 2), a self-loop (u = 99,990) and a
halt (u = 22) are `vectors/blocks/probe_{panic,oog,control}`. A PolkaVM-style loader refuses the F4
blobs (u = 0) and traps on F6's jump (u = one block): see docs/findings.md F4–F6.

## `pvm/`

All start at ı = 0 with ϱ = 10,000; registers 0 unless set. "cost" is ϱ^Δ of the block at pc 0.

### `cmov_nz_imm` (opcode 148; the official vectors cover only `cmov_iz_imm`)

Two registers and one immediate (l. 500–512): r_A = min(12, ζ_{ı+1} mod 16), r_B = min(12, ⌊ζ_{ı+1}/16⌋),
l_X = min(4, max(0, ℓ − 1)), ν_X = 𝒳_{l_X}(…). Semantics (l. 551): ω'_A = ν_X if ω_B ≠ 0, else ω_A.
Cost row `cmovimm` (l. 1211): 2 cycles, 3 decode slots, 1 ALU. v0.8.1 also counts the destination
as a source (l. 996; GP #559).

| vector | program | key values and why |
| --- | --- | --- |
| `cmov_nz_imm_ok` | `cmov_nz_imm ω7, ω10, 100; trap`, ω10 = 1 | ω7 = 100. Cost 2: cmov (3 slots) and trap (1) decode at cycle 0, both start at 1, trap retires behind cmov at cycle 5. ☇ at the trap (pc 3), gas 9,998. |
| `cmov_nz_imm_nok` | same, ω10 = 0, ω7 = 5 | ω7 stays 5 (the "otherwise" case keeps ω_A). Gas 9,998. |
| `cmov_nz_imm_same_reg` | `cmov_nz_imm ω7, ω7, 100`, ω7 = 3 | r_A = r_B = 7, ω_B ≠ 0 → ω7 = 100. |
| `cmov_nz_imm_same_reg_zero` | same, ω7 = 0 | ω_B = 0 → ω7 = ω_A = 0. |
| `cmov_nz_imm_sext` | immediate octet 0x80, ω10 = 1 | ν_X = 𝒳₁(0x80) = 2⁶⁴ − 128 (eq. `signedextension`). |
| `cmov_nz_imm_no_imm` | `cmov_nz_imm ω7, ω10` with ℓ = 1 (no immediate octets), ω7 = 5, ω10 = 1 | l_X = 0, ν_X = 𝒳₀(0) = 0 → ω7 = 0. |
| `cmov_nz_imm_decode_slots` | `cmov_nz_imm ω7, ω10, 1; cmov_nz_imm ω8, ω11, 2; trap`, ω8 = 7, ω10 = 1 | ω7 = 1, ω8 stays 7. **Cost 3**: 3 + 3 > 4 decode slots, so the second cmov and the trap decode at cycle 1; last retirement at cycle 6. (With 2 slots, as `cmov_nz`, it would be 2.) Gas 9,997. |
| `cmov_nz_imm_dest_dependency` | `mul_imm_64 ω7, ω7, 3; cmov_nz_imm ω7, ω10, 9; trap`, ω7 = 2, ω10 = 1 | ω7 = 9. **Cost 5**: the cmov reads its destination ω7 (l. 996), so it depends on the mul (3 cycles, starts at 1, done at 4); the cmov starts at 4, executed at 7, retired at 8. (Without the dependency: 3.) Gas 9,995. |

### Branch targets outside [0, |c|)

Code: 0 = the branch, 3 = `fallthrough`, 4 = `trap` (|c| = 5). For `branch_eq_imm ω7, 0, off`
(l. 434–445): ℓ = 2, l_X = 0, l_Y = 1, ν_Y = 0 + 𝒵₁(off). branch(b, C) (l. 258): ☇ when b ∉ ϖ or the
fall-through ∉ ϖ, **regardless of C**. Fall-through 3 ∈ ϖ here, so only the target decides.

| vector | target | key values and why |
| --- | --- | --- |
| `branch_eq_imm_target_past_end` | 100, taken (ω7 = 0) | 100 ∉ ϖ → ☇ at pc 0. **Cost 𝔟 = 1**: ζ₁₀₀ = 0 = trap (ζ₃ = 1 is not). Gas 9,999. |
| `branch_eq_imm_target_at_end` | 5 = \|c\| | Same: 5 ∉ ϖ, ζ₅ = 0 → 𝔟 = 1. Gas 9,999. |
| `branch_eq_imm_target_past_end_not_taken` | 100, not taken (ω7 = 1) | Still ☇ (the b ∉ ϖ case precedes ¬C). Gas 9,999, ω7 = 1. |
| `branch_eq_target_past_end` | `branch_eq ω7, ω8, 100` (l. 572–585) | Same as the first: ☇, 𝔟 = 1, gas 9,999. |
| `branch_eq_imm_target_in_range` (control) | 3, taken | 3 ∈ ϖ → continue at 3. 𝔟 = 20 (ζ₃ = 1, fall-through ζ₃ = 1), then [fallthrough] 2 (sjump(4), 4 ∈ ϖ), [trap] 2: ☇ at pc 4, gas 10,000 − 24 = 9,976. |

Negative targets (ı + offset < 0) are left out: 𝔟 then reads ζ at a negative index, which
eq. `instructions` does not define, so the paper does not fix the cost (jam-lean
`docs/upstream-candidates.md`, note 2).

### RAM below 2¹⁶

The prose (l. 170) says any access to an index below 2¹⁶ panics "regardless of the apparent
(in)accessibility". The formula (l. 175–181) puts in **x** only the indices that are *not* accessible,
and panics only when min(x) mod 2³² < 2¹⁶. They disagree when a page below 2¹⁶ is accessible, or when
an access straddles 2¹⁶. **These vectors follow the formula.** (Under Ψ_M such pages are never mapped,
eq. `memlayout`; the vector format can map them.) The load/store blocks cost 𝔪 = 25 (l. 1172): a
25-cycle load or store, with the trap retiring behind it.

| vector | setup and access | formula's result (prose's) |
| --- | --- | --- |
| `low_page_mapped_load` | page 0x1000 readable, octet 42 at 0x1000; `load_u8 ω7, 0x1000; trap` | x = ∅ → continue: ω7 = 42, then ☇ at the trap (pc 4), gas 9,975. (Prose: ☇ at pc 0.) |
| `low_page_mapped_store` | page 0x1000 writable; `store_u8 ω7, 0x1000; trap`, ω7 = 0x55 | x = ∅ → μ'[0x1000] = 0x55, ☇ at pc 4, gas 9,975. (Prose: ☇ at pc 0, no write.) |
| `low_page_unmapped_load` | nothing mapped; `load_u8 ω7, 0x1000` | x = {0x1000}, min < 2¹⁶ → ☇ at pc 0, gas 9,975 (both readings agree). |
| `low_straddle_fault_above` | page 0xF000 readable, 0x10000 unmapped; `load_u16 ω7, 0xFFFF` | x = {0x10000} → **F at 0x10000** (pc 0, gas 9,975, ω7 unchanged). (Prose: ☇, index 0xFFFF < 2¹⁶ is required.) |
| `low_straddle_panic_below` | page 0xF000 unmapped, 0x10000 readable; same load | x = {0xFFFF} → ☇ at pc 0 (both agree). |

### F5

`f5_store_u16_ro_then_unmapped`: `store_u16 ω7 at 0x21FFF` with page 0x21000 read-only and 0x22000
unmapped. w = {0x21FFF, 0x22000}, both not writable, min(x) = 0x21FFF → **F at 0x21000**
(l. 175–181; the prose's "lowest page address to be written which is inaccessible" agrees). Gas
9,975 (cost 25), memory unchanged. Same as `vectors/pvm/min_d5_store_ro_unmapped` (v0.8.0): the
ε^μ equation did not change in v0.8.1 (diff of `pvm.tex` v0.8.0 → v0.8.1), only the name differs.

## Not included: STF-level cases (C)

* **Safrole: valid tickets not all kept in γ_A'** (eq. n ⊆ γ_A', `safrole.tex` l. 347).
  jam-test-vectors already has `stf/safrole/*/ticket-not-retained-1` (v0.8.0). A v0.8.1 version
  needs a valid v0.8.1 Ring VRF proof (Draft 35, ring domain 2048); jam-lean has a Ring VRF verifier
  but no prover, and no v0.8.1 ticket proofs exist yet to reuse.
* **Reports: lookup anchor** (x_t ≥ H_T − 𝖫 and ancestry). The age condition is already
  `stf/reports/*/lookup_anchor_not_recent-1`. The ancestry condition cannot be carried by the STF
  format (no headers in the state), so it is not expressible there; block-level traces carry it only
  through the chain of imported blocks.
