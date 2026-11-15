# PVM edge-case vectors (GP v0.8.0)

1,408 testcases in the koute/jamtestvectors `pvm/programs` format (schema `pvm/schema.asn`). Each
gives status, registers, pc, gas, page-fault address, host call, memory (maximal runs of non-zero
octets) and `block-gas-costs` (ϱ^Δ at every block start). Expected values are GP v0.8.0's.

CI checks them with `lake exe pvmrun check vectors/pvm`, which runs jam-lean's Ψ.

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
