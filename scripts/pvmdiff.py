#!/usr/bin/env python3
"""Run PVM testcases on both sides of the differential harness and compare.

    python3 scripts/pvmdiff.py INPUT... [--out DIR] [--lean EXE] [--ref EXE]

INPUT: .json / .jsonl files or directories of them (testcases in the jamtestvectors `pvm/programs`
format). Runs `pvmrun run` (jam-lean's Ψ) and `pvm-ref run` (PolkaVM) on each, compares every
observed `assert` (status, regs, pc, gas, page-fault address, host call, memory), and writes
DIR/divergences.jsonl ({"name", "fields", "lean", "ref", "case"}) and a summary by case family
and differing fields to stdout. Timings are printed per side.
"""
import argparse
import collections
import json
import os
import subprocess
import sys
import time

FIELDS = ["status", "pc", "gas", "regs", "page-fault-address", "hostcall", "memory"]


def run(cmd, inputs):
    t = time.time()
    p = subprocess.run(cmd + ["run"] + inputs, capture_output=True, text=True)
    dt = time.time() - t
    if p.stderr.strip():
        sys.stderr.write(p.stderr[-4000:])
    out = {}
    for line in p.stdout.splitlines():
        if line.strip():
            j = json.loads(line)
            out[j["name"]] = j
    return out, dt


def asserts(tc):
    return [s["assert"] for s in tc["steps"] if "assert" in s]


def classify(lt, rt):
    """(set of differing fields, both-rejected flag) for one testcase's two outputs."""
    la, ra = asserts(lt), asserts(rt)
    diff = set()
    if len(la) != len(ra):
        diff.add("assert-count")
    for x, y in zip(la, ra):
        if y.get("status") in ("load-error", "ref-crash"):
            immediate = (x.get("status") == "panic" and x.get("gas") == lt["initial-gas"]
                         and x.get("pc") == lt["initial-pc"] and len(la) == 1)
            if y["status"] == "load-error" and immediate:
                return set(), True
            diff.add(y["status"] + "/" + str(x.get("status")) + ("-immediate" if immediate else ""))
            break
        for k in FIELDS:
            if x.get(k) != y.get(k):
                diff.add(k)
        if diff:
            break
    if not diff and "block-gas-costs" in rt and lt.get("block-gas-costs") != rt["block-gas-costs"]:
        diff.add("block-gas-costs")
    return diff, False


def family(name):
    parts = name.split("_")
    return parts[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--out", default="pvmdiff-out")
    ap.add_argument("--lean", default=".lake/build/bin/pvmrun")
    ap.add_argument("--ref", default="tools/pvm-ref/target/release/pvm-ref")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    lean, tl = run([a.lean], a.inputs)
    ref, tr = run([a.ref], a.inputs)
    print(f"lean: {len(lean)} cases in {tl:.1f} s; ref: {len(ref)} cases in {tr:.1f} s")
    divs = []
    summary = collections.Counter()
    # PolkaVM refuses the blob, Ψ panics before any step (𝔳_blob / 𝔳_inst fail): same outcome.
    agree_rejected = []
    for name in sorted(set(lean) | set(ref)):
        if name not in lean or name not in ref:
            divs.append({"name": name, "fields": ["missing"], "lean": lean.get(name), "ref": ref.get(name)})
            summary[(family(name), "missing")] += 1
            continue
        diff, rejected = classify(lean[name], ref[name])
        if rejected:
            agree_rejected.append(name)
        la, ra = asserts(lean[name]), asserts(ref[name])
        if diff:
            case = dict(lean[name])
            case["steps"] = [s for s in case["steps"] if "assert" not in s]
            fs = sorted(diff)
            divs.append({"name": name, "fields": fs, "lean": la, "ref": ra, "case": case})
            if any("strict-error" in r for r in ra):
                fs = ["(lax)"] + fs
            summary[(family(name), ",".join(fs))] += 1
    with open(os.path.join(a.out, "divergences.jsonl"), "w") as f:
        for d in divs:
            f.write(json.dumps(d, separators=(",", ":")) + "\n")
    total = len(set(lean) | set(ref))
    print(f"{total - len(divs)} of {total} cases agree ({len(agree_rejected)} of them: PolkaVM refuses the blob, "
          f"Ψ panics before any step); {len(divs)} diverge")
    for (fam, fs), n in sorted(summary.items()):
        print(f"  {fam:12s} {fs:40s} {n}")


if __name__ == "__main__":
    main()
