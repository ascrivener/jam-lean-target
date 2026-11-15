#!/usr/bin/env python3
"""Replay a recorded fuzzer session (fuzz-proto/examples format) against a target socket.

Sends each NNNNNNNN_fuzzer_*.bin request (length-prefixed, u32 LE), prints each response's kind and
whether it equals the recorded NNNNNNNN_target_*.bin (minifuzz rules: errors match by kind, peer
info by kind). With --get-state STEP, after STEP it sends GetState(hash of that step's header
is not known here, so the hash given with --hash) and writes the raw State response to --out.
Raw bytes only; no JAM decoding.
"""
import argparse, os, socket, struct, sys

def send(sock, msg):
    sock.sendall(struct.pack('<I', len(msg)) + msg)

def recv(sock):
    hdr = b''
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: return None
        hdr += c
    n = struct.unpack('<I', hdr)[0]
    buf = b''
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: return None
        buf += c
    return buf

KIND = {0: 'peer_info', 2: 'state_root', 5: 'state', 255: 'error'}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dir'); ap.add_argument('--sock', required=True)
    ap.add_argument('--stop', type=int, default=None, help='last step to send')
    ap.add_argument('--get-state', default=None, help='header hash (hex) to request after --stop')
    ap.add_argument('--out', default=None)
    ap.add_argument('--quiet', action='store_true')
    a = ap.parse_args()
    files = sorted(f for f in os.listdir(a.dir) if f.endswith('.bin'))
    reqs = [f for f in files if '_fuzzer_' in f]
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(a.sock)
    ok = bad = 0
    for f in reqs:
        idx = int(f.split('_')[0])
        if a.stop is not None and idx > a.stop: break
        exp = [g for g in files if g.startswith(f.split('_')[0] + '_target_')]
        send(s, open(os.path.join(a.dir, f), 'rb').read())
        r = recv(s)
        if r is None: print(f'{f}: connection closed'); return 1
        want = open(os.path.join(a.dir, exp[0]), 'rb').read() if exp else b''
        same = r[:1] == want[:1] and (r[0] in (0, 255) or r == want)
        ok += same; bad += not same
        if not same or not a.quiet:
            print(f'{f}: {KIND.get(r[0], r[0])} {r[1:33].hex() if r[0]==2 else r[1:80]!r} {"ok" if same else "DIFF, recorded " + want[:33].hex()}')
    if a.get_state:
        send(s, bytes([4]) + bytes.fromhex(a.get_state.removeprefix('0x')))
        r = recv(s)
        open(a.out, 'wb').write(r)
        print(f'GetState: {len(r)} octets -> {a.out}')
    print(f'{ok}/{ok+bad} as recorded')
    return 0

sys.exit(main())
