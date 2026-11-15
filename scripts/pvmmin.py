#!/usr/bin/env python3
"""Minimise divergent PVM testcases.

    python3 scripts/pvmmin.py DIVERGENCES.jsonl OUT.jsonl [--names a,b] [--lean EXE] [--ref EXE]

For each divergence (from scripts/pvmdiff.py), greedily applies reductions (drop a setup step, zero
or shrink a register value, drop a later run, drop an instruction, drop a jump-table entry) while
the two sides still diverge in the same fields. Candidates are evaluated in batches on both
runners. Writes the minimised divergences, in pvmdiff's format, to OUT.jsonl.
"""
import argparse
import copy
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools", "pvm-gen"))
sys.path.insert(0, os.path.dirname(__file__))
from asm import blob, enc_nat  # noqa: E402
from pvmdiff import asserts, classify  # noqa: E402


def dec_nat(p, pos):
    b = p[pos]
    l = next((i for i in range(8) if not (b >> (7 - i)) & 1), 8)
    if l == 8:
        return int.from_bytes(bytes(p[pos + 1:pos + 9]), "little"), pos + 9
    rest = int.from_bytes(bytes(p[pos + 1:pos + 1 + l]), "little")
    return (b - (256 - 2 ** (8 - l))) * 2 ** (8 * l) + rest, pos + 1 + l


def parse(p):
    """(jump table, z, code, mask) if p is a well-formed blob, else None."""
    try:
        jl, pos = dec_nat(p, 0)
        z = p[pos]
        cl, pos = dec_nat(p, pos + 1)
        jt = [int.from_bytes(bytes(p[pos + i * z:pos + i * z + z]), "little") for i in range(jl)]
        pos += jl * z
        code = p[pos:pos + cl]
        mb = p[pos + cl:]
        if len(code) != cl or len(mb) != (cl + 7) // 8 or z > 8 or enc_nat(jl) + [z] + enc_nat(cl) != p[:len(enc_nat(jl)) + 1 + len(enc_nat(cl))]:
            return None
        mask = [(mb[i // 8] >> (i % 8)) & 1 for i in range(cl)]
        return jt, z, code, mask
    except IndexError:
        return None


def candidates(tc):
    steps = tc["steps"]
    # drop later runs
    runs = [i for i, s in enumerate(steps) if "run" in s]
    if len(runs) > 1:
        c = copy.deepcopy(tc)
        c["steps"] = steps[:runs[1]]
        yield c
    for i, s in enumerate(steps):
        if "run" in s:
            continue
        c = copy.deepcopy(tc)
        del c["steps"][i]
        yield c
        if "set-reg" in s and s["set-reg"]["value"] > 1:
            for v in (0, 1, s["set-reg"]["value"] >> 32, s["set-reg"]["value"] & 0xFFFFFFFF):
                if v < s["set-reg"]["value"]:
                    c = copy.deepcopy(tc)
                    c["steps"][i]["set-reg"]["value"] = v
                    yield c
        if "write" in s and len(s["write"]["contents"]) > 1:
            c = copy.deepcopy(tc)
            c["steps"][i]["write"]["contents"] = s["write"]["contents"][:1]
            yield c
    if tc["initial-gas"] > 1000:
        c = copy.deepcopy(tc)
        c["initial-gas"] = 1000
        yield c
    parsed = parse(tc["program"])
    if parsed:
        jt, z, code, mask = parsed
        starts = [i for i, b in enumerate(mask) if b] + [len(code)]
        for k in range(len(starts) - 1):
            a, b = starts[k], starts[k + 1]
            if a == 0 and b == len(code):
                continue
            c = copy.deepcopy(tc)
            c["program"] = blob(code[:a] + code[b:], mask[:a] + mask[b:], jt, z=z)
            yield c
        for k in range(len(jt)):
            c = copy.deepcopy(tc)
            c["program"] = blob(code, mask, jt[:k] + jt[k + 1:], z=z)
            yield c


def run_both(cases, lean, ref):
    with tempfile.TemporaryDirectory() as d:
        f = os.path.join(d, "c.jsonl")
        with open(f, "w") as h:
            for c in cases:
                h.write(json.dumps(c) + "\n")
        outs = []
        for exe in (lean, ref):
            p = subprocess.run([exe, "run", f], capture_output=True, text=True)
            outs.append({json.loads(l)["name"]: json.loads(l) for l in p.stdout.splitlines() if l.strip()})
    return outs


def minimise(d, lean, ref):
    target = set(d["fields"])
    tc = d["case"]
    base = tc["name"]
    while True:
        cands = list(candidates(tc))
        for k, c in enumerate(cands):
            c["name"] = f"{base}~{k}"
        lo, ro = run_both(cands, lean, ref)
        for c in cands:
            n = c["name"]
            if n in lo and n in ro:
                fs, _ = classify(lo[n], ro[n])
                if fs == target:
                    tc = c
                    break
        else:
            break
    tc["name"] = base + "_min"
    lo, ro = run_both([tc], lean, ref)
    n = tc["name"]
    return {"name": n, "fields": sorted(target), "lean": asserts(lo[n]), "ref": asserts(ro[n]), "case": tc}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("divergences")
    ap.add_argument("out")
    ap.add_argument("--names", default="")
    ap.add_argument("--lean", default=".lake/build/bin/pvmrun")
    ap.add_argument("--ref", default="tools/pvm-ref/target/release/pvm-ref")
    a = ap.parse_args()
    names = set(a.names.split(",")) if a.names else None
    with open(a.out, "w") as f:
        for line in open(a.divergences):
            d = json.loads(line)
            if names and d["name"] not in names or "case" not in d:
                continue
            m = minimise(d, a.lean, a.ref)
            f.write(json.dumps(m, separators=(",", ":")) + "\n")
            print(m["name"], m["fields"], len(m["case"]["program"]), "octets,", len(m["case"]["steps"]), "steps")


if __name__ == "__main__":
    main()
