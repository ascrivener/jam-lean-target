#!/usr/bin/env python3
"""Diff two raw State responses (tag 5, ↕[(key 31, ↕value)]) by key; print component names."""
import sys
def nat(b, i):
    x = b[i]
    if x < 128: return x, i + 1
    l = 0
    while x & (0x80 >> l): l += 1
    if l == 8: return int.from_bytes(b[i+1:i+9], 'little'), i + 9
    hi = x & ((1 << (8 - l)) - 1)
    return int.from_bytes(b[i+1:i+1+l], 'little') + (hi << (8 * l)), i + 1 + l
def kvs(b):
    assert b[0] == 5, b[0]
    n, i = nat(b, 1); d = {}
    for _ in range(n):
        k = b[i:i+31]; i += 31
        l, i = nat(b, i); d[k] = b[i:i+l]; i += l
    return d
NAMES = {1:'alpha',2:'phi',3:'beta',4:'gamma',5:'psi',6:'eta',7:'iota',8:'kappa',9:'lambda',10:'rho',11:'tau',12:'chi',13:'pi',14:'omega',15:'xi',16:'theta',255:'delta-info'}
a, b = kvs(open(sys.argv[1],'rb').read()), kvs(open(sys.argv[2],'rb').read())
for k in sorted(set(a) | set(b)):
    name = NAMES.get(k[0], 'delta-data') if k[1:].strip(b'\0') == b'' or k[0]==255 else 'delta-data'
    if k not in a: print('only in 2:', name, k.hex(), len(b[k]))
    elif k not in b: print('only in 1:', name, k.hex(), len(a[k]))
    elif a[k] != b[k]:
        x, y = a[k], b[k]
        j = next((i for i in range(min(len(x), len(y))) if x[i] != y[i]), min(len(x), len(y)))
        print(f'differs: {name} {k.hex()[:16]} len {len(x)} vs {len(y)}, first diff at {j}: {x[j:j+24].hex()} vs {y[j:j+24].hex()}')
