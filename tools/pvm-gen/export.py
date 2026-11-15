#!/usr/bin/env python3
"""Export curated PVM vectors (jamtestvectors `pvm/programs` format) into vectors/pvm/.

    python3 tools/pvm-gen/export.py GENDIR OUTDIR [--lean EXE] [--ref EXE] [--divergent FILE]

GENDIR holds the generator's JSONL files (gen.py). A curated selection of cases is run on both
sides. Agreeing cases are written with the shared result as expected values (status, regs, pc,
gas, fault address, host call, memory and block-gas-costs). A selected case on which the sides
disagree is skipped and reported, unless it is listed in --divergent: a JSON object mapping case
name to the side whose result is GP v0.8.0's ("lean" or "ref"), as decided in triage.
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import re
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
from pvmdiff import classify  # noqa: E402

MEM_OPS = ["load_u8", "load_i16", "load_u32", "load_u64", "store_u8", "store_u16", "store_u64", "store_imm_u32",
           "load_ind_i8", "load_ind_u64", "store_ind_u32", "store_imm_ind_u16"]
ALL_MEM_OPS = ["load_u8", "load_i8", "load_u16", "load_i16", "load_u32", "load_i32", "load_u64", "store_u8",
               "store_u16", "store_u32", "store_u64", "store_imm_u8", "store_imm_u16", "store_imm_u32", "store_imm_u64",
               "load_ind_u8", "load_ind_i8", "load_ind_u16", "load_ind_i16", "load_ind_u32", "load_ind_i32",
               "load_ind_u64", "store_ind_u8", "store_ind_u16", "store_ind_u32", "store_ind_u64",
               "store_imm_ind_u8", "store_imm_ind_u16", "store_imm_ind_u32", "store_imm_ind_u64"]
KEY_ORDER = ["name", "initial-pc", "initial-gas", "program", "steps", "block-gas-costs"]
ASSERT_ORDER = ["status", "regs", "pc", "memory", "gas", "page-fault-address", "hostcall"]


def load(gendir):
    cases = {}
    for f in sorted(os.listdir(gendir)):
        if f.endswith(".jsonl"):
            for line in open(os.path.join(gendir, f)):
                c = json.loads(line)
                cases[c["name"]] = c
    return cases


def select(cases, rng_seed=7):
    """Deterministic curated selection: names grouped by family and sub-family."""
    groups = collections.defaultdict(list)
    for n in cases:
        parts = n.split("_")
        fam = parts[0]
        if fam in ("threereg", "tworeg", "tworegimm"):
            # family, op name (everything up to a numeric or tagged suffix)
            sub = "_".join(p for p in parts[1:] if not p.isdigit())
            groups[(fam, sub)].append(n)
        elif fam == "random":
            groups[(fam, "")].append(n)
        elif fam == "mem":
            if (n.endswith("_i0") or not n.startswith("mem_load_ind") and not n.startswith("mem_store_ind")) and any(
                    n.startswith("mem_" + op + "_") for op in MEM_OPS) or not any(n.startswith("mem_" + op + "_") for op in ALL_MEM_OPS):
                groups[(fam, n)].append(n)
        elif fam in ("code", "skip", "skipend"):
            groups[(fam, re.sub(r"\d+", "", n))].append(n)
        else:
            groups[(fam, "_".join(parts[1:2]))].append(n)
    pick = []
    for (fam, sub), names in sorted(groups.items()):
        if fam in ("threereg", "tworegimm"):
            k = 2 if not any(t in sub for t in ("alias", "rd", "ra", "len", "same")) else 1
        elif fam == "tworeg":
            k = 3
        elif fam == "random":
            k = 40
        elif fam == "gas":
            k = 0  # chosen at the out-of-gas boundary below
        elif fam in ("code", "skip", "skipend", "jthdr", "clen", "varint", "blob", "initpc"):
            k = 4
        elif fam == "mem":
            k = 1
        elif fam in ("jt", "branch", "cmp", "cmpi", "lijind", "ecalli", "loadimm", "loadimm64"):
            k = 6
        else:
            k = 3
        pick += names[:k]
    return pick


def run(exe, cases):
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "c.jsonl")
        with open(f, "w") as h:
            for c in cases:
                h.write(json.dumps(c) + "\n")
        p = subprocess.run([exe, "run", f], capture_output=True, text=True)
    return {json.loads(l)["name"]: json.loads(l) for l in p.stdout.splitlines() if l.strip()}


def gas_boundary(cases, lean_exe):
    """For each gas program, the cases at gas 0 and around the smallest gas that does not run out."""
    progs = collections.defaultdict(dict)
    for n, c in cases.items():
        if n.startswith("gas_"):
            tag, g = n[4:].rsplit("_", 1)
            progs[tag][int(g)] = n
    out = run(lean_exe, [cases[n] for gs in progs.values() for n in gs.values()])
    pick = []
    for tag, gs in sorted(progs.items()):
        ok = [g for g in sorted(gs) if all(s["assert"]["status"] != "out-of-gas"
                                           for s in out[gs[g]]["steps"] if "assert" in s)]
        if not ok:
            continue
        b = ok[0]
        for g in (0, b - 2, b - 1, b, b + 1):
            if g in gs and gs[g] not in pick:
                pick.append(gs[g])
    return pick


def ordered(tc):
    o = {k: tc[k] for k in KEY_ORDER if k in tc}
    steps = []
    for s in o["steps"]:
        if "assert" in s:
            a = s["assert"]
            steps.append({"assert": {k: a[k] for k in ASSERT_ORDER if k in a}})
        else:
            steps.append(s)
    o["steps"] = steps
    return o


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("gendir")
    ap.add_argument("outdir")
    ap.add_argument("--lean", default=".lake/build/bin/pvmrun")
    ap.add_argument("--ref", default="tools/pvm-ref/target/release/pvm-ref")
    ap.add_argument("--divergent", default=None)
    ap.add_argument("--extra", default=None, help="JSONL of extra cases to export (e.g. minimised ones)")
    a = ap.parse_args()
    cases = load(a.gendir)
    extra = []
    if a.extra:
        extra = [json.loads(l) for l in open(a.extra) if l.strip()]
        for c in extra:
            cases[c["name"]] = c
    verdicts = json.load(open(a.divergent)) if a.divergent else {}
    names = select({n: c for n, c in cases.items() if not n.startswith("gas_")}) + gas_boundary(cases, a.lean)
    names += [c["name"] for c in extra] + [n for n in verdicts if n not in names]
    names = list(dict.fromkeys(names))
    sel = [cases[n] for n in names]
    lean, ref = run(a.lean, sel), run(a.ref, sel)
    os.makedirs(a.outdir, exist_ok=True)
    written, skipped = 0, []
    for n in names:
        diff, _ = classify(lean[n], ref[n])
        if diff and n not in verdicts:
            skipped.append((n, sorted(diff)))
            continue
        side = verdicts.get(n, "lean")
        tc = lean[n] if side == "lean" else ref[n]
        with open(os.path.join(a.outdir, n + ".json"), "w") as f:
            text = json.dumps(ordered(tc), indent=2)
            # number arrays on one line
            text = re.sub(r"\[\s*(-?\d+(?:,\s*-?\d+)*)\s*\]", lambda m: "[" + ", ".join(re.split(r",\s*", m.group(1))) + "]", text)
            f.write(text + "\n")
        written += 1
    print(f"wrote {written} vectors; skipped {len(skipped)} divergent cases without a verdict")
    for n, d in skipped:
        print("  skipped", n, d)


if __name__ == "__main__":
    main()
