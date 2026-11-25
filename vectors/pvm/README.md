# PVM edge-case vectors (GP v0.8.1)

1,408 testcases in the koute/jamtestvectors `pvm/programs` format (schema `pvm/schema.asn`). Each
gives status, registers, pc, gas, page-fault address, host call, memory (maximal runs of non-zero
octets) and `block-gas-costs` (ϱ^Δ at every block start). Expected values are GP v0.8.1's: GP
v0.8.0's as made, with the 94 changes below that v0.8.1 dictates.

CI checks them with `lake exe pvmrun check vectors/pvm`, which runs jam-lean's Ψ.

## GP v0.8.1 changes (2026-11-25)

When the target moved to GP v0.8.1, 94 expectations changed, each derived from its v0.8.0
expectation by the v0.8.1 rule alone (`tools/pvm-gen/derive081.py`), never from the model's output;
jam-lean's Ψ was then checked against them (all agree). PolkaVM 0.38.1 (GP v0.8.0) no longer
applies to these 94. The script reads the v0.8.0 files (commit 671f256) and `text/pvm.tex` of
graypaper tag v0.8.1: `python3 tools/pvm-gen/derive081.py pvm.tex LIST check|write`.

* **GP #554** (`pvm.tex`: r_D = min(12, ζ_{ı+2} mod 16), was min(12, ζ_{ı+2})), 87 vectors whose
  third register octet is 16, 23, 41 or 128: the result moves from ω_12 to ω_{r_D}, ω_12 keeps its
  initial value, all else as before except the block cost, recomputed with an independent
  transcription of the gas model (§A.9) and the v0.8.1 cost table. The script first reproduces
  each old v0.8.0 cost with it. The cost changes only for the three 32-bit shifts with r_D = r_A
  (decode slots 𝔓_S(3, 4) = 3, so the trap decodes in the same cycle): 3 → 2, gas 9997 → 9998.
* **GP #559** (eq. `deblob`: z ≤ 4), 7 vectors whose jump-table entry size z > 4: the blob is
  invalid, so Ψ panics before any step (pc 0, gas, registers and memory unchanged, no blocks).

| vector | change |
| --- | --- |
| `jthdr_z255` | #559 |
| `jthdr_z5` | #559 |
| `jthdr_z5_one` | #559 |
| `jthdr_z6` | #559 |
| `jthdr_z7` | #559 |
| `jthdr_z8` | #559 |
| `min_d1_threereg_rd16` | #554 add_64 rD 12->0 cost 2->2 |
| `min_d2_z5` | #559 |
| `skip_add_64_2` | #554 add_64 rD 12->9 cost 2->2 |
| `skip_add_64_3` | #554 add_64 rD 12->9 cost 2->2 |
| `threereg_add_32_rd128` | #554 add_32 rD 12->0 cost 2->2 |
| `threereg_add_32_rd16` | #554 add_32 rD 12->0 cost 2->2 |
| `threereg_add_32_rd23` | #554 add_32 rD 12->7 cost 2->2 |
| `threereg_and_inv_rd128` | #554 and_inv rD 12->0 cost 2->2 |
| `threereg_and_inv_rd16` | #554 and_inv rD 12->0 cost 2->2 |
| `threereg_and_inv_rd23` | #554 and_inv rD 12->7 cost 2->2 |
| `threereg_and_rd128` | #554 and rD 12->0 cost 2->2 |
| `threereg_and_rd16` | #554 and rD 12->0 cost 2->2 |
| `threereg_and_rd23` | #554 and rD 12->7 cost 2->2 |
| `threereg_cmov_nz_rd128` | #554 cmov_nz rD 12->0 cost 2->2 |
| `threereg_cmov_nz_rd16` | #554 cmov_nz rD 12->0 cost 2->2 |
| `threereg_cmov_nz_rd23` | #554 cmov_nz rD 12->7 cost 2->2 |
| `threereg_div_s_32_rd128` | #554 div_s_32 rD 12->0 cost 60->60 |
| `threereg_div_s_32_rd16` | #554 div_s_32 rD 12->0 cost 60->60 |
| `threereg_div_s_32_rd23` | #554 div_s_32 rD 12->7 cost 60->60 |
| `threereg_div_u_32_rd128` | #554 div_u_32 rD 12->0 cost 60->60 |
| `threereg_div_u_32_rd16` | #554 div_u_32 rD 12->0 cost 60->60 |
| `threereg_div_u_32_rd23` | #554 div_u_32 rD 12->7 cost 60->60 |
| `threereg_max_rd128` | #554 max rD 12->0 cost 3->3 |
| `threereg_max_rd16` | #554 max rD 12->0 cost 3->3 |
| `threereg_max_rd23` | #554 max rD 12->7 cost 3->3 |
| `threereg_max_u_rd128` | #554 max_u rD 12->0 cost 3->3 |
| `threereg_max_u_rd16` | #554 max_u rD 12->0 cost 3->3 |
| `threereg_max_u_rd23` | #554 max_u rD 12->7 cost 3->3 |
| `threereg_min_rd128` | #554 min rD 12->0 cost 3->3 |
| `threereg_min_rd16` | #554 min rD 12->0 cost 3->3 |
| `threereg_min_rd23` | #554 min rD 12->7 cost 3->3 |
| `threereg_min_u_rd128` | #554 min_u rD 12->0 cost 3->3 |
| `threereg_min_u_rd16` | #554 min_u rD 12->0 cost 3->3 |
| `threereg_min_u_rd23` | #554 min_u rD 12->7 cost 3->3 |
| `threereg_mul_32_rd128` | #554 mul_32 rD 12->0 cost 4->4 |
| `threereg_mul_32_rd16` | #554 mul_32 rD 12->0 cost 4->4 |
| `threereg_mul_32_rd23` | #554 mul_32 rD 12->7 cost 4->4 |
| `threereg_mul_upper_s_s_rd128` | #554 mul_upper_s_s rD 12->0 cost 4->4 |
| `threereg_mul_upper_s_s_rd16` | #554 mul_upper_s_s rD 12->0 cost 4->4 |
| `threereg_mul_upper_s_s_rd23` | #554 mul_upper_s_s rD 12->7 cost 4->4 |
| `threereg_mul_upper_s_u_rd128` | #554 mul_upper_s_u rD 12->0 cost 6->6 |
| `threereg_mul_upper_s_u_rd16` | #554 mul_upper_s_u rD 12->0 cost 6->6 |
| `threereg_mul_upper_s_u_rd23` | #554 mul_upper_s_u rD 12->7 cost 6->6 |
| `threereg_mul_upper_u_u_rd128` | #554 mul_upper_u_u rD 12->0 cost 4->4 |
| `threereg_mul_upper_u_u_rd16` | #554 mul_upper_u_u rD 12->0 cost 4->4 |
| `threereg_mul_upper_u_u_rd23` | #554 mul_upper_u_u rD 12->7 cost 4->4 |
| `threereg_or_inv_rd128` | #554 or_inv rD 12->0 cost 2->2 |
| `threereg_or_inv_rd16` | #554 or_inv rD 12->0 cost 2->2 |
| `threereg_or_inv_rd23` | #554 or_inv rD 12->7 cost 2->2 |
| `threereg_or_rd128` | #554 or rD 12->0 cost 2->2 |
| `threereg_or_rd16` | #554 or rD 12->0 cost 2->2 |
| `threereg_or_rd23` | #554 or rD 12->7 cost 2->2 |
| `threereg_rem_s_32_rd128` | #554 rem_s_32 rD 12->0 cost 60->60 |
| `threereg_rem_s_32_rd16` | #554 rem_s_32 rD 12->0 cost 60->60 |
| `threereg_rem_s_32_rd23` | #554 rem_s_32 rD 12->7 cost 60->60 |
| `threereg_rem_u_32_rd128` | #554 rem_u_32 rD 12->0 cost 60->60 |
| `threereg_rem_u_32_rd16` | #554 rem_u_32 rD 12->0 cost 60->60 |
| `threereg_rem_u_32_rd23` | #554 rem_u_32 rD 12->7 cost 60->60 |
| `threereg_rot_l_64_rd128` | #554 rot_l_64 rD 12->0 cost 2->2 |
| `threereg_rot_l_64_rd16` | #554 rot_l_64 rD 12->0 cost 2->2 |
| `threereg_rot_l_64_rd23` | #554 rot_l_64 rD 12->7 cost 2->2 |
| `threereg_rot_r_64_rd128` | #554 rot_r_64 rD 12->0 cost 2->2 |
| `threereg_rot_r_64_rd16` | #554 rot_r_64 rD 12->0 cost 2->2 |
| `threereg_rot_r_64_rd23` | #554 rot_r_64 rD 12->7 cost 2->2 |
| `threereg_set_lt_s_rd128` | #554 set_lt_s rD 12->0 cost 3->3 |
| `threereg_set_lt_s_rd16` | #554 set_lt_s rD 12->0 cost 3->3 |
| `threereg_set_lt_s_rd23` | #554 set_lt_s rD 12->7 cost 3->3 |
| `threereg_set_lt_u_rd128` | #554 set_lt_u rD 12->0 cost 3->3 |
| `threereg_set_lt_u_rd16` | #554 set_lt_u rD 12->0 cost 3->3 |
| `threereg_set_lt_u_rd23` | #554 set_lt_u rD 12->7 cost 3->3 |
| `threereg_shar_r_32_rd128` | #554 shar_r_32 rD 12->0 cost 3->3 |
| `threereg_shar_r_32_rd16` | #554 shar_r_32 rD 12->0 cost 3->3 |
| `threereg_shar_r_32_rd23` | #554 shar_r_32 rD 12->7 cost 3->2 |
| `threereg_shlo_l_32_rd128` | #554 shlo_l_32 rD 12->0 cost 3->3 |
| `threereg_shlo_l_32_rd16` | #554 shlo_l_32 rD 12->0 cost 3->3 |
| `threereg_shlo_l_32_rd23` | #554 shlo_l_32 rD 12->7 cost 3->2 |
| `threereg_shlo_r_32_rd128` | #554 shlo_r_32 rD 12->0 cost 3->3 |
| `threereg_shlo_r_32_rd16` | #554 shlo_r_32 rD 12->0 cost 3->3 |
| `threereg_shlo_r_32_rd23` | #554 shlo_r_32 rD 12->7 cost 3->2 |
| `threereg_sub_32_rd128` | #554 sub_32 rD 12->0 cost 2->2 |
| `threereg_sub_32_rd16` | #554 sub_32 rD 12->0 cost 2->2 |
| `threereg_sub_32_rd23` | #554 sub_32 rD 12->7 cost 2->2 |
| `threereg_xnor_rd128` | #554 xnor rD 12->0 cost 2->2 |
| `threereg_xnor_rd16` | #554 xnor rD 12->0 cost 2->2 |
| `threereg_xnor_rd23` | #554 xnor rD 12->7 cost 2->2 |
| `threereg_xor_rd128` | #554 xor rD 12->0 cost 2->2 |
| `threereg_xor_rd16` | #554 xor rD 12->0 cost 2->2 |
| `threereg_xor_rd23` | #554 xor rD 12->7 cost 2->2 |

## How they were made

They come from the generators of `docs/pvm-diff.md`, which use `tools/pvm-gen/gen.py` with the
default seed. A curated selection was run on jam-lean's Ψ and on PolkaVM 0.38.1, configured as
spectool configures it. Reproduce with:

```
python3 tools/pvm-gen/gen.py GEN
python3 tools/pvm-gen/export.py GEN vectors/pvm --extra tools/pvm-gen/minimised.jsonl \
    --divergent tools/pvm-gen/verdicts.json
```

The vectors fall into these groups:

* **About 1,276 vectors where both sides agree.** They hold the shared result. They cover:
  * every opcode on boundary operands;
  * page edges;
  * gas at the out-of-gas boundary of 14 programs;
  * jump-table and static jumps;
  * invalid code and blob headers;
  * skip lengths;
  * `ecalli`;
  * random programs.

  Among them are 72 blobs that GP v0.8.0 rejects (Ψ panics before any step, gas unchanged) and
  that PolkaVM refuses to load.
* **126 vectors where the sides diverge** (listed in `tools/pvm-gen/verdicts.json`). They hold the
  GP v0.8.0 result, which is Ψ's; the parent session confirmed each class against `pvm.tex`
  v0.8.0. PolkaVM 0.38.1 fails these vectors.
* **8 minimised cases**, one or two per class, named `min_d*`.

| Class | Vectors | GP v0.8.0 | PolkaVM | Note |
| --- | --- | --- | --- | --- |
| D1 | `threereg_*_rd{16,23,28,128,255}`, `skip_add_64_*`, `min_d1_*` (87) | r_D = min(12, ζ_{ı+2}) | ζ_{ı+2} mod 16 | GP #554 changes this after v0.8.0 |
| D2 | `jthdr_z{5..8}*`, `jthdr_z255`, `min_d2_*` (7) | any z | z ≤ 4 | GP #559 adds z ≤ 4 after v0.8.0 |
| D3 | `ecalli_*`, `skip_ecalli_*`, `random_3`, `min_d3_*` (6) | host-call id sign-extended to 64 bits | u32 | representation |
| D4 | `code_oponly{1,81..90,170..175}`, `skipend_{branch_eq_imm,fallthrough}_*`, `min_d4_*` (9) | the block is charged, then panic | blob refused | |
| D5 | `mem_store*_{roend,unm1,roend7,unm4}*`, `min_d5_*` (14) | fault at the read-only page (min x) | fault at the unmapped page | |
| D6 | `jthdr_z0*`, `min_d6_*` (3) | z = 0 entries are 0, a valid target | panic | |

Not included:

* **D8**: pages mapped below 2¹⁶. PolkaVM cannot map them, so they are not compared.
* **D7 as its own class**: an out-of-range jump-table entry that is never used. GP v0.8.0 runs the
  program; PolkaVM in strict mode refuses it at load, and non-strict it agrees. Such cases are
  among the agreeing vectors, with the GP result.
