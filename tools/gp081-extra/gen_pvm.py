#!/usr/bin/env python3
"""Write the PVM vectors of vectors/gp081-extra/pvm (koute/jamtestvectors `pvm/programs` format).

    python3 tools/gp081-extra/gen_pvm.py OUTDIR [--lean .lake/build/bin/pvmrun]

Each case below is a program and its setup steps. The expected values (asserts and
`block-gas-costs`) are jam-lean's Ψ (pvmrun run); vectors/gp081-extra/README.md gives, per case,
the GP v0.8.1 equations that dictate them, checked by reading. Deterministic: CI regenerates the
directory and compares it byte for byte.
"""
import argparse, json, os, re, subprocess, sys, tempfile

KEY_ORDER = ["name", "initial-pc", "initial-gas", "program", "steps", "block-gas-costs"]
ASSERT_ORDER = ["status", "regs", "pc", "memory", "gas", "page-fault-address", "hostcall"]


def blob(code, starts, jumps=(), z=0):
    """deblob's encoding E(|j|) ++ E_1(z) ++ E(|c|) ++ E_z(j) ++ c ++ E(k) (GP v0.8.1 eq. deblob), short lengths."""
    assert len(code) < 128 and len(jumps) < 128
    k = [sum(1 << b for b in range(8) if 8 * i + b in starts) for i in range((len(code) + 7) // 8)]
    j = [b for x in jumps for b in x.to_bytes(z, "little")]
    return [len(jumps), z, len(code)] + j + list(code) + k


def reg(r, v):
    return {"set-reg": {"reg": r, "value": v}}


def mp(a, w, n=4096):
    return {"map": {"address": a, "is-writable": w, "length": n}}


def wr(a, bs):
    return {"write": {"address": a, "contents": bs}}


TRAP = 0
CASES = [
    # --- cmov_nz_imm (opcode 148): r_A = ζ_{ı+1} mod 16, r_B = ⌊ζ_{ı+1}/16⌋; 0xA7: ω7 ← ν if ω10 ≠ 0
    ("cmov_nz_imm_ok", blob([148, 0xA7, 100, TRAP], {0, 3}), [reg(10, 1)]),
    ("cmov_nz_imm_nok", blob([148, 0xA7, 100, TRAP], {0, 3}), [reg(7, 5)]),
    ("cmov_nz_imm_same_reg", blob([148, 0x77, 100, TRAP], {0, 3}), [reg(7, 3)]),
    ("cmov_nz_imm_same_reg_zero", blob([148, 0x77, 100, TRAP], {0, 3}), []),
    ("cmov_nz_imm_sext", blob([148, 0xA7, 0x80, TRAP], {0, 3}), [reg(10, 1)]),
    ("cmov_nz_imm_no_imm", blob([148, 0xA7, TRAP], {0, 2}), [reg(7, 5), reg(10, 1)]),
    # two cmov_nz_imm (3 decode slots each) cannot be decoded in the same cycle
    ("cmov_nz_imm_decode_slots", blob([148, 0xA7, 1, 148, 0xB8, 2, TRAP], {0, 3, 6}), [reg(8, 7), reg(10, 1)]),
    # mul_imm_64 ω7 ← ω7·3, then cmov_nz_imm ω7: the destination counts as a source (§A.9), so it waits for the mul
    ("cmov_nz_imm_dest_dependency", blob([150, 0x77, 3, 148, 0xA7, 9, TRAP], {0, 3, 6}), [reg(7, 2), reg(10, 1)]),
    # --- branches whose target is outside [0, |c|); code: 0 branch, 3 fallthrough, 4 trap (|c| = 5)
    ("branch_eq_imm_target_past_end", blob([81, 0x07, 100, 1, TRAP], {0, 3, 4}), []),
    ("branch_eq_imm_target_at_end", blob([81, 0x07, 5, 1, TRAP], {0, 3, 4}), []),
    ("branch_eq_imm_target_past_end_not_taken", blob([81, 0x07, 100, 1, TRAP], {0, 3, 4}), [reg(7, 1)]),
    ("branch_eq_imm_target_in_range", blob([81, 0x07, 3, 1, TRAP], {0, 3, 4}), []),
    ("branch_eq_target_past_end", blob([170, 0x87, 100, 1, TRAP], {0, 3, 4}), []),
    # --- RAM below 2^16 (ε^μ formula, not the prose)
    ("low_page_mapped_load", blob([52, 0x07, 0x00, 0x10, TRAP], {0, 4}), [mp(0x1000, False), wr(0x1000, [42])]),
    ("low_page_mapped_store", blob([59, 0x07, 0x00, 0x10, TRAP], {0, 4}), [mp(0x1000, True), reg(7, 0x55)]),
    ("low_page_unmapped_load", blob([52, 0x07, 0x00, 0x10, TRAP], {0, 4}), []),
    ("low_straddle_fault_above", blob([54, 0x07, 0xFF, 0xFF, 0x00, TRAP], {0, 5}), [mp(0xF000, False), wr(0xFFFF, [1])]),
    ("low_straddle_panic_below", blob([54, 0x07, 0xFF, 0xFF, 0x00, TRAP], {0, 5}), [mp(0x10000, False), wr(0x10000, [1])]),
    # --- F5: store_u16 ω7 at 0x21FFF, page 0x21000 read-only, 0x22000 unmapped
    ("f5_store_u16_ro_then_unmapped", blob([60, 7, 255, 31, 2, TRAP], {0, 5}), [mp(0x21000, False)]),
]


def ordered(tc):
    o = {k: tc[k] for k in KEY_ORDER if k in tc}
    o["steps"] = [{"assert": {k: s["assert"][k] for k in ASSERT_ORDER if k in s["assert"]}} if "assert" in s else s
                  for s in o["steps"]]
    return o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--lean", default=".lake/build/bin/pvmrun")
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as d:
        inp = os.path.join(d, "cases.jsonl")
        with open(inp, "w") as h:
            for name, prog, steps in CASES:
                h.write(json.dumps({"name": name, "initial-pc": 0, "initial-gas": 10000, "program": prog,
                                    "steps": steps + [{"run": {}}]}) + "\n")
        out = subprocess.run([a.lean, "run", inp], check=True, capture_output=True, text=True).stdout
    os.makedirs(a.outdir, exist_ok=True)
    for line in out.splitlines():
        if not line.strip():
            continue
        tc = json.loads(line)
        text = json.dumps(ordered(tc), indent=2, ensure_ascii=False)
        text = re.sub(r"\[\s*(-?\d+(?:,\s*-?\d+)*)\s*\]", lambda m: "[" + ", ".join(re.split(r",\s*", m.group(1))) + "]", text)
        with open(os.path.join(a.outdir, tc["name"] + ".json"), "w") as f:
            f.write(text + "\n")


if __name__ == "__main__":
    main()
