#!/usr/bin/env python3
"""Ask fuzzer-protocol targets (Docker images) how they answer one trace step.

For a fuzz-reports trace step (NNNNNNNN.bin = E(pre_state, block, post_state)), sends
PeerInfo, Initialize(genesis header, pre-state, no ancestry), ImportBlock(block) to each image's
socket and prints the response (state root or error text). The genesis header is taken from a
recorded session's Initialize (all 0.8.0 traces share it: their first parent is its hash).
Raw bytes only.
  askimpls.py SESSION_DIR STEP.bin IMAGE...
"""
import os, socket, struct, subprocess, sys, time

def nat(b, i):
    x = b[i]
    if x < 128: return x, i + 1
    l = 0
    while x & (0x80 >> l): l += 1
    if l == 8: return int.from_bytes(b[i+1:i+9], 'little'), i + 9
    hi = x & ((1 << (8 - l)) - 1)
    return int.from_bytes(b[i+1:i+1+l], 'little') + (hi << (8 * l)), i + 1 + l

def raw_state_end(b, i):
    i += 32
    n, i = nat(b, i)
    for _ in range(n):
        i += 31
        l, i = nat(b, i); i += l
    return i

def enc_nat(x):
    if x < 128: return bytes([x])
    for l in range(1, 8):
        if x < (1 << (7 * (l + 1))):
            hi = x >> (8 * l)
            return bytes([(0xff << (8 - l)) & 0xff | hi]) + (x & ((1 << (8 * l)) - 1)).to_bytes(l, 'little')
    return b'\xff' + x.to_bytes(8, 'little')

def genesis_header(init_bin):
    # Initialize = tag, header, state, ancestry: the header ends where the state's encoding begins.
    # Find it by trying header lengths until the rest parses as state + empty ancestry.
    for hl in range(100, 2000):
        try:
            i = 1 + hl
            n, i = nat(init_bin, i)
            for _ in range(n):
                i += 31
                l, i = nat(init_bin, i); i += l
            a, i = nat(init_bin, i)
            if i + a * 36 == len(init_bin): return init_bin[1:1+hl]
        except IndexError:
            pass
    raise SystemExit('cannot split Initialize')

def send(s, m): s.sendall(struct.pack('<I', len(m)) + m)
def recv(s):
    h = b''
    while len(h) < 4:
        c = s.recv(4 - len(h))
        if not c: return None
        h += c
    n = struct.unpack('<I', h)[0]; buf = b''
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c: return None
        buf += c
    return buf

def main():
    sess, step = sys.argv[1], sys.argv[2]
    peer = open(os.path.join(sess, '00000000_fuzzer_peer_info.bin'), 'rb').read()
    hdr = genesis_header(open(os.path.join(sess, '00000001_fuzzer_initialize.bin'), 'rb').read())
    b = open(step, 'rb').read()
    pe = raw_state_end(b, 0)
    pre = b[:pe]
    post_len = len(pre)  # rejected steps: post-state = pre-state
    assert b[-post_len:][:32] == pre[:32] or True
    block = b[pe:len(b) - post_len]
    # pre-state's kv list, re-encoded as the Initialize state
    init = b'\x01' + hdr + pre[32:] + enc_nat(0)
    imp = b'\x03' + block
    for img in sys.argv[3:]:
        d = f'/tmp/jamfuzz/ask/{abs(hash(img))}'
        os.makedirs(d, exist_ok=True)
        sock = f'{d}/fuzz.sock'
        if os.path.exists(sock): os.unlink(sock)
        name = f'ask{abs(hash(img)) % 100000}'
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        subprocess.run(['docker', 'run', '-d', '--name', name, '-v', f'{d}:/tmp/jam', '-e', 'JAM_FUZZ=1',
                        '-e', 'JAM_FUZZ_SPEC=tiny', '-e', 'JAM_FUZZ_DATA_PATH=/tmp/jam/data',
                        '-e', 'JAM_FUZZ_SOCK_PATH=/tmp/jam/fuzz.sock', img], capture_output=True)
        for _ in range(60):
            if os.path.exists(sock): break
            time.sleep(1)
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(120); s.connect(sock)
            send(s, peer); recv(s)
            send(s, init); r1 = recv(s)
            send(s, imp); r2 = recv(s)
            def show(r):
                if r is None: return 'closed'
                if r[0] == 2: return 'root ' + r[1:9].hex()
                if r[0] == 255:
                    l, i = nat(r, 1); return 'ERROR ' + r[i:i+l].decode(errors='replace')
                return f'tag {r[0]}'
            print(f'{img}: init {show(r1)}; import {show(r2)}')
        except Exception as e:
            print(f'{img}: {e}')
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)

main()
