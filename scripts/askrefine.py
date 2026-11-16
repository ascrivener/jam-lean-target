#!/usr/bin/env python3
"""Ask fuzzer-protocol targets (Docker images) about feature-refine (jam-fuzzing PR #214).

  askrefine.py features IMAGE...          PeerInfo with features=7; print what each image advertises
  askrefine.py replay SESSION_DIR IMAGE... replay a minifuzz session (e.g. vectors/refine/...) and
                                           compare every response with the recorded one; for work
                                           reports, print the fields that differ; a report equal
                                           to NNNNNNNN_post080_work_report.bin (GP #580/#583) is
                                           reported as such
Raw bytes only; the work-report field split follows GP v0.8.0 Appendix C.
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

def peer_info(features):
    name = b'askrefine'
    return bytes([0, 1]) + struct.pack('<I', features) + bytes([0, 8, 0, 0, 1, 0]) + bytes([len(name)]) + name

def show_peer(r):
    if r is None or r[0] != 0: return f'unexpected {r[:1].hex() if r else None}'
    f = struct.unpack('<I', r[2:6])[0]
    l, i = nat(r, 12)
    return f'{r[i:i+l].decode(errors="replace")} jam {r[6]}.{r[7]}.{r[8]} features {f} (refine {"yes" if f & 4 else "no"})'

def report_fields(r):
    """Split ℰ(work-report) (GP v0.8.0 Appendix C) into named fields."""
    f = {}; i = 0
    f['package_hash'] = r[i:i+32]; i += 32
    f['bundle_length'] = r[i:i+4]; i += 4
    f['erasure_root'] = r[i:i+32]; i += 32
    f['erasure_shards'] = r[i:i+2]; i += 2
    f['segment_root'] = r[i:i+32]; i += 32
    f['segment_count'] = r[i:i+2]; i += 2
    j = i + 32 + 4 + 32 + 32 + 32 + 4 + 32
    n, j = nat(r, j); j += 32 * n
    f['context'] = r[i:j]; i = j
    _, j = nat(r, i); f['core'] = r[i:j]; i = j
    f['authorizer_hash'] = r[i:i+32]; i += 32
    _, j = nat(r, i); f['auth_gas_used'] = r[i:j]; i = j
    n, j = nat(r, i); f['auth_trace'] = r[i:j+n]; i = j + n
    n, j = nat(r, i); f['segment_root_lookup'] = r[i:j+64*n]; i = j + 64*n
    f['digests'] = r[i:]
    return f

class Target:
    def __init__(self, img):
        self.img = img
        d = f'/tmp/jamfuzz/askrefine/{abs(hash(img))}'
        os.makedirs(f'{d}/data', exist_ok=True)
        os.chmod(f'{d}/data', 0o777)
        os.chmod(d, 0o777)
        self.sock = f'{d}/fuzz.sock'
        if os.path.exists(self.sock): os.unlink(self.sock)
        self.name = f'askr{abs(hash(img)) % 100000}'
        subprocess.run(['docker', 'rm', '-f', self.name], capture_output=True)
        subprocess.run(['docker', 'run', '-d', '--name', self.name, '-v', f'{d}:/tmp/jam', '-e', 'JAM_FUZZ=1',
                        '-e', 'JAM_FUZZ_SPEC=tiny', '-e', 'JAM_FUZZ_DATA_PATH=/tmp/jam/data',
                        '-e', 'JAM_FUZZ_SOCK_PATH=/tmp/jam/fuzz.sock', '-e', 'JAM_FUZZ_LOG_LEVEL=info', img], capture_output=True)
        for _ in range(90):
            if os.path.exists(self.sock): break
            time.sleep(1)
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.s.settimeout(300)
        self.s.connect(self.sock)
    def ask(self, m):
        send(self.s, m); return recv(self.s)
    def close(self):
        try: self.s.close()
        except Exception: pass
        if os.environ.get('ASKREFINE_LOGS'):
            r = subprocess.run(['docker', 'logs', '--tail', '30', self.name], capture_output=True, text=True)
            print(r.stdout + r.stderr)
        subprocess.run(['docker', 'rm', '-f', self.name], capture_output=True)

def describe(r):
    if r is None: return 'closed'
    if r[0] == 255:
        l, i = nat(r, 1); return 'ERROR ' + r[i:i+l].decode(errors='replace')
    return {0: 'peer_info', 2: 'state_root ' + r[1:9].hex(), 7: 'work_report'}.get(r[0], f'tag {r[0]}')

def features(imgs):
    for img in imgs:
        try:
            t = Target(img)
            print(f'{img}: {show_peer(t.ask(peer_info(7)))}', flush=True)
        except Exception as e:
            print(f'{img}: {e}', flush=True)
        finally:
            try: t.close()
            except Exception: pass

def replay(sess, imgs):
    files = sorted(f for f in os.listdir(sess) if f.endswith('.bin'))
    reqs = [f for f in files if '_fuzzer_' in f]
    for img in imgs:
        print(f'== {img}', flush=True)
        try:
            t = Target(img)
            for f in reqs:
                idx = f.split('_')[0]
                exp = next(g for g in files if g.startswith(idx + '_target_'))
                want = open(os.path.join(sess, exp), 'rb').read()
                got = t.ask(open(os.path.join(sess, f), 'rb').read())
                if got is None:
                    print(f'{f}: connection closed'); break
                if f.endswith('peer_info.bin'):
                    print(f'{f}: {show_peer(got)}'); continue
                if got == want:
                    print(f'{f}: same ({describe(got)})'); continue
                post = os.path.join(sess, idx + '_post080_work_report.bin')
                if os.path.exists(post) and got == open(post, 'rb').read():
                    print(f'{f}: as the model after GP #580/#583 (model v0.8.0: {describe(want)})'); continue
                if got[0] == 7 and want[0] == 7:
                    dump = os.environ.get('ASKREFINE_DUMP')
                    if dump:
                        os.makedirs(dump, exist_ok=True)
                        open(os.path.join(dump, f), 'wb').write(got)
                    try:
                        a, b = report_fields(got[1:]), report_fields(want[1:])
                    except IndexError:
                        print(f'{f}: work reports differ; target report does not parse ({len(got)} octets: {got[:200].hex()})')
                        continue
                    diff = [k for k in a if a[k] != b[k]]
                    print(f'{f}: work reports differ in {", ".join(diff)}')
                    for k in diff: print(f'    {k}: target {a[k].hex()[:96]}  model {b[k].hex()[:96]}')
                elif got[0] == 255 and want[0] == 255:
                    print(f'{f}: both error (target: {describe(got)})')
                else:
                    print(f'{f}: target {describe(got)}, model {describe(want)}')
        except Exception as e:
            print(f'{img}: {e}')
        finally:
            try: t.close()
            except Exception: pass

if __name__ == '__main__':
    if sys.argv[1] == 'features': features(sys.argv[2:])
    elif sys.argv[1] == 'replay': replay(sys.argv[2], sys.argv[3:])
    else: raise SystemExit(__doc__)
