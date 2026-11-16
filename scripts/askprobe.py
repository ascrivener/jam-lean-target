#!/usr/bin/env python3
"""Send a crafted session (jam-lean-target craft/probe output) to fuzzer-protocol targets.

For each Docker image: start it, send every NNNNNNNN_fuzzer_*.bin of DIR in order (framed),
compare each response with the model's NNNNNNNN_target_*.bin (state roots exactly, errors by kind),
then GetState(last_header_hash.txt) and diff it against expected_state.bin (scripts/diffstate.py).
Raw bytes only.
  askprobe.py DIR IMAGE...
"""
import os, socket, struct, subprocess, sys, time

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

def nat(b, i):
    x = b[i]
    if x < 128: return x, i + 1
    l = 0
    while x & (0x80 >> l): l += 1
    if l == 8: return int.from_bytes(b[i+1:i+9], 'little'), i + 9
    hi = x & ((1 << (8 - l)) - 1)
    return int.from_bytes(b[i+1:i+1+l], 'little') + (hi << (8 * l)), i + 1 + l

def show(r):
    if r is None: return 'closed'
    if r[0] == 2: return 'root ' + r[1:33].hex()
    if r[0] == 255:
        l, i = nat(r, 1); return 'ERROR ' + r[i:i+l].decode(errors='replace')
    return f'tag {r[0]}'

def main():
    d = sys.argv[1]
    files = sorted(f for f in os.listdir(d) if f.endswith('.bin') and '_fuzzer_' in f)
    last = open(os.path.join(d, 'last_header_hash.txt')).read().strip()
    here = os.path.dirname(os.path.abspath(__file__))
    for img in sys.argv[2:]:
        tag = f'{abs(hash(img)) % 100000}'
        w = f'/tmp/jamfuzz/probe/{tag}'
        os.makedirs(w, exist_ok=True)
        sock = f'{w}/fuzz.sock'
        if os.path.exists(sock): os.unlink(sock)
        name = f'probe{tag}'
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        subprocess.run(['docker', 'run', '-d', '--name', name, '-v', f'{w}:/tmp/jam', '-e', 'JAM_FUZZ=1',
                        '-e', 'JAM_FUZZ_SPEC=tiny', '-e', 'JAM_FUZZ_DATA_PATH=/tmp/jam/data',
                        '-e', 'JAM_FUZZ_SOCK_PATH=/tmp/jam/fuzz.sock', img], capture_output=True)
        for _ in range(90):
            if os.path.exists(sock): break
            time.sleep(1)
        print(f'== {img}')
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.settimeout(300); s.connect(sock)
            ok = True
            for f in files:
                t0 = time.time()
                send(s, open(os.path.join(d, f), 'rb').read())
                r = recv(s)
                idx = f.split('_')[0]
                exp = [g for g in os.listdir(d) if g.startswith(idx + '_target_')]
                want = open(os.path.join(d, exp[0]), 'rb').read() if exp else None
                same = want is not None and r is not None and r[:1] == want[:1] and (r[0] in (0, 255) or r == want)
                if want is not None and want[0] == 0: same = r is not None and r[0] == 0
                ok = ok and same
                print(f'  {f}: {show(r)} {"= model" if same else "≠ model " + (show(want) if want else "")} ({time.time() - t0:.1f}s)')
                if r is None: break
            send(s, b'\x04' + bytes.fromhex(last))
            st = recv(s)
            if st is not None and st[:1] == b'\x05':
                out = f'{w}/state.bin'
                open(out, 'wb').write(st)
                diff = subprocess.run([sys.executable, os.path.join(here, 'diffstate.py'),
                                       os.path.join(d, 'expected_state.bin'), out], capture_output=True, text=True).stdout
                print('  GetState vs model:', 'identical' if not diff.strip() else '\n    ' + diff.strip().replace('\n', '\n    '))
            else:
                print('  GetState:', show(st))
        except Exception as e:
            print(f'  {e}')
        logs = subprocess.run(['docker', 'logs', '--tail', '15', name], capture_output=True, text=True)
        if '-v' in os.environ.get('ASKPROBE', ''): print('  logs:', (logs.stdout + logs.stderr)[-1500:])
        subprocess.run(['docker', 'rm', '-f', name], capture_output=True)

main()
