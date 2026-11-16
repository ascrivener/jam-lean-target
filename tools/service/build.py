#!/usr/bin/env python3
"""Build `shadow-probe`, a small JAM service whose accumulation exercises storage and preimage
state paths, as a GP v0.8.0 service code blob (for `jamt create-service`).

Code = E(↕metadata) ++ standard program (GP §A.7: E_3(|o|) E_3(|w|) E_2(z) E_3(s) o w E_4(|c|) c),
with c a program blob assembled by tools/pvm-gen/asm.py. Entry points: refine at pc 0, accumulate
at pc 5 (GP v0.8.0 Ψ_R, Ψ_A).

* refine: halts at once with an empty output (ω_8 = 0).
* accumulate, on every call:
  1. reads the counter under storage key "n" (8 octets, absent = 0), increments it, writes it back;
  2. writes the counter under key "k" + (n mod 4): creates keys k0…k3, then overwrites them;
  3. deletes key "k" + ((n + 2) mod 4) (write with v_Z = 0; absent keys are a no-op);
  4. steps a preimage P (64 octets, hash H in the read-only data) through its life cycle:
     n mod 8 = 1: solicit(H, 64); 2: provide(self, P); 5: forget(H, 64).
     Over successive cycles this gives requests [] → (provided) [t] → [t, t'] → [t, t', t''] →
     forget of an old or young entry; provide on a non-empty request returns HUH.
  It halts with ω_8 = 0 (no yield).
Host calls (GP v0.8.0 numbering): read 4, write 5, solicit 24, forget 25, provide 27.

  build.py OUT.jam      writes the blob and prints its length and the hash of P
"""
import hashlib, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'pvm-gen'))
from asm import I, enc_nat, le, program

RO, RW = 0x10000, 0x30000          # standard program zones for |o| <= 2^16
PRE = bytes(range(0x40, 0x80))      # P: 64 octets
H = hashlib.blake2b(PRE, digest_size=32).digest()
ro = b'n' + bytes(7) + H + PRE      # "n" @RO, H @RO+8, P @RO+40
rw = bytes(32)                      # counter @RW, key buffer "k?" @RW+16

READ, WRITE, SOLICIT, FORGET, PROVIDE = 4, 5, 24, 25, 27
SELF = -1                           # 2^64 - 1: the service itself

def li(r, v): return I('load_imm', r, v)

def host(n, *args):
    return [li(7 + i, a) for i, a in enumerate(args)] + [I('ecalli', n)]

def key_digit(src, add):
    """Key buffer "k" + chr(48 + ((ω_src + add) mod 4))."""
    return [I('add_imm_64', 4, src, add), I('and_imm', 4, 4, 3), I('add_imm_64', 4, 4, 48),
            li(2, RW), I('store_imm_ind_u8', 2, 16, ord('k')), I('store_ind_u8', 4, 2, 17)]

refine = [li(8, 0), I('jump_ind', 0, 0), I('fallthrough')]           # pc 0, 2, 4
accumulate = (
    host(READ, SELF, RO, 1, RW, 0, 8)                                 # counter -> μ[RW..+8]
    + [li(2, RW), I('load_ind_u64', 3, 2, 0), I('add_imm_64', 3, 3, 1), I('store_ind_u64', 3, 2, 0)]
    + host(WRITE, RO, 1, RW, 8)                                       # "n" := n + 1
    + key_digit(3, 0) + host(WRITE, RW + 16, 2, RW, 8)                # k(n mod 4) := n
    + key_digit(3, 2) + host(WRITE, RW + 16, 2, 0, 0)                 # delete k((n + 2) mod 4)
    + [I('and_imm', 5, 3, 7),
       I('branch_eq_imm', 5, 1, 'solicit'), I('branch_eq_imm', 5, 2, 'provide'),
       I('branch_eq_imm', 5, 5, 'forget'), I('jump', 'done')]
)
labels_at = {}
def label(name, instrs):
    labels_at[name] = len(refine) + len(accumulate) + sum(len(x) for x in tail)
    tail.append(instrs)
tail = []
label('solicit', host(SOLICIT, RO + 8, len(PRE)) + [I('jump', 'done')])
label('provide', host(PROVIDE, SELF, RO + 40, len(PRE)) + [I('jump', 'done')])
label('forget', host(FORGET, RO + 8, len(PRE)) + [I('jump', 'done')])
label('done', [li(8, 0), I('jump_ind', 0, 0)])
instrs = refine + accumulate + [i for t in tail for i in t]

def build():
    code, starts = program(instrs, labels=labels_at)
    assert starts[0] == 0 and starts[len(refine)] == 5, starts[:4]
    std = (le(len(ro), 3) + le(len(rw), 3) + le(0, 2) + le(4096, 3) + list(ro) + list(rw)
           + le(len(code), 4) + code)
    def s(x): return enc_nat(len(x)) + list(x.encode())
    meta = [0] + s('shadow-probe') + s('0.1.0') + s('Apache-2.0') + [1] + s('jam-lean-target')
    return bytes(enc_nat(len(meta)) + meta + std)

if __name__ == '__main__':
    b = build()
    open(sys.argv[1], 'wb').write(b)
    print(f'{sys.argv[1]}: {len(b)} octets; preimage hash {H.hex()} length {len(PRE)}')
