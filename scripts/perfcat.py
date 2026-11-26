#!/usr/bin/env python3
"""Summarise `perf script` output of the target: share of samples per component (first match in
the stack, crypto before PVM before merklisation before hashing) and the top Lean functions by
inclusive share.  perf script -i perf.data --no-inline | scripts/perfcat.py [N]"""
import sys, re, collections

CATS = [
 ("ring",  ["JamCrypto_Ring", "JamCrypto_G1", "JamCrypto_Pairing", "JamCrypto_Fq", "Bls12381"]),
 ("bandersnatch", ["JamCrypto_Bandersnatch", "JamCrypto_Edwards", "ThinVrf", "PedersenVrf", "JamCrypto_Thin"]),
 ("ed25519", ["JamCrypto_Ed25519"]),
 ("pvm",   ["_PVM_"]),
 ("merkle/serialize", ["JAM_Trie", "JAM_State_serialize", "State_serializeList", "JAM_State_root", "JAM_Merkle"]),
 ("hash",  ["Blake2b", "Keccak"]),
]
def classify(frames):
    for name, pats in CATS:
        for f in frames:
            if any(p in f for p in pats): return name
    return "other"
tot = collections.Counter(); incl = collections.Counter(); n = 0
frames = []
def flush():
    global n, frames
    if frames:
        n += 1; tot[classify(frames)] += 1
        for f in set(frames):
            if f.startswith("lp_") or f.startswith("l_"): incl[f] += 1
    frames = []
for line in sys.stdin:
    if not line.strip(): flush(); continue
    if line[0] not in " \t": flush(); continue
    parts = line.split()
    if len(parts) >= 2:
        frames.append(re.sub(r"\+0x[0-9a-f]+$", "", parts[1]))
flush()
print("samples", n)
for k, v in tot.most_common(): print(f"{k:20s} {100*v/n:5.1f}%")
print("--- inclusive lean functions")
for k, v in incl.most_common(int(sys.argv[1]) if len(sys.argv)>1 else 40): print(f"{100*v/n:5.1f}% {k[:150]}")
