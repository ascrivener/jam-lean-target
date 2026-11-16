#!/usr/bin/env python3
"""Shadow mode: follow a JAM chain block by block and check every post-state root against the model.

A *feed* supplies the chain: an Initialize message (genesis header + key-values), then blocks,
each optionally with the node's verdict (imported or rejected), its post-state root and its
post-state key-values. The driver sends PeerInfo, Initialize and ImportBlock to a fuzzer-protocol
target (default: `jam-lean-target serve` on stdin/stdout) and compares our root with the node's.
Where a feed gives no root for a block, the next block's header supplies it (H_R, the parent's
posterior state root) when that block is a child of this one.

On a mismatch the driver asks the target for its state (GetState), writes both states to --out
and diffs them (scripts/diffstate.py) when the feed has the node's state. Then it stops, or with
--continue resyncs: a fresh target session initialised from the node's post-state (when the feed
has it) so later blocks are checked against the node's chain, not against our diverged one.

Feeds (see docs/shadow.md):
  session DIR   a recorded fuzzer session (jam-fuzzing fuzz-proto/examples/<v>/<name>): the
                fuzzer's requests are the chain, the recorded target responses the node's roots.
  trace DIR     a fuzz-reports trace: genesis.bin = E(header, state), NNNNNNNN.bin =
                E(pre-state, block, post-state) with NNNNNNNN.json beside it (its post-state root
                anchors the split). Without genesis.bin, --genesis-header names a session whose
                Initialize header goes with the first pre-state.
  dump DIR      a node's block dump: genesis.bin = E(header, key-values); NNNNNNNN.block = E(block);
                optional NNNNNNNN.root (32 octets) and NNNNNNNN.state = E(key-values).
Raw bytes only, apart from splitting a header off a block to hash it.
"""
import argparse, hashlib, json, os, struct, subprocess, sys, time

# ---------------------------------------------------------------- codec helpers (GP Appendix C)

def nat(b, i):
    x = b[i]
    if x < 128: return x, i + 1
    l = 0
    while x & (0x80 >> l): l += 1
    if l == 8: return int.from_bytes(b[i+1:i+9], 'little'), i + 9
    hi = x & ((1 << (8 - l)) - 1)
    return int.from_bytes(b[i+1:i+1+l], 'little') + (hi << (8 * l)), i + 1 + l

def enc_nat(x):
    if x < 128: return bytes([x])
    for l in range(1, 8):
        if x < (1 << (7 * (l + 1))):
            hi = x >> (8 * l)
            return bytes([(0xff << (8 - l)) & 0xff | hi]) + (x & ((1 << (8 * l)) - 1)).to_bytes(l, 'little')
    return b'\xff' + x.to_bytes(8, 'little')

def kvs_end(b, i):
    """End of an encoded key-value sequence (↕[(key 31, ↕value)]) starting at i."""
    n, i = nat(b, i)
    for _ in range(n):
        i += 31
        l, i = nat(b, i); i += l
    if i > len(b): raise IndexError
    return i

def kvs_dict(b, i=0):
    n, i = nat(b, i); d = {}
    for _ in range(n):
        k = b[i:i+31]; i += 31
        l, i = nat(b, i); d[k] = b[i:i+l]; i += l
    return d

def enc_kvs(d):
    out = [enc_nat(len(d))]
    for k in sorted(d): out += [k, enc_nat(len(d[k])), d[k]]
    return b''.join(out)

SPECS = {'tiny': (6, 12), 'full': (1023, 600)}  # (validators V, epoch length E)

def header_len(b, spec):
    """Length of the GP v0.8.0 header at the start of a block: H_P, H_R, H_X, H_T, H_E?, H_W?,
    H_I, H_V, H_O, H_S."""
    V, E = SPECS[spec]
    i = 32 * 3 + 4
    if b[i]:                           # epoch mark: η1', η2', ↕[(bandersnatch, ed25519)]
        n, i = nat(b, i + 65); i += 64 * n
    else: i += 1
    if b[i]: i += 1 + E * 33           # tickets mark: [(id, attempt)]
    else: i += 1
    i += 2 + 96                        # author index, entropy-yielding VRF signature
    n, i = nat(b, i); i += 32 * n      # offenders mark
    return i + 96                      # seal

def err_text(r):
    """The text of an Error response (tag 255, ↕string)."""
    try:
        n, i = nat(r, 1); return r[i:i+n].decode('utf-8', 'replace')
    except IndexError:
        return r[1:].decode('utf-8', 'replace')

def blake2b(x): return hashlib.blake2b(x, digest_size=32).digest()
def slot_of(block): return struct.unpack('<I', block[96:100])[0]

# ---------------------------------------------------------------- feeds

class Step:
    """One block of the chain. root/state: the node's post-state (None: unknown);
    rejected: the node's verdict (None: unknown, False for any block a node dump holds)."""
    def __init__(self, name, block, root=None, rejected=None, state=None, note=None):
        self.name, self.block, self.root, self.rejected, self.state, self.note = name, block, root, rejected, state, note

class Feed:
    """A chain to shadow. peer_info: a PeerInfo message to send (None: the driver's own);
    initialize: the Initialize message (tag 1 included); init_root: the node's genesis root or None;
    steps(): the blocks in import order. A node RPC feed implements the same three things."""
    peer_info = None
    init_root = None

class SessionFeed(Feed):
    def __init__(self, d):
        fs = sorted(f for f in os.listdir(d) if f.endswith('.bin'))
        rd = lambda f: open(os.path.join(d, f), 'rb').read()
        self.d, self.fs, self.rd = d, fs, rd
        self.peer_info = rd(next(f for f in fs if '_fuzzer_peer_info' in f))
        self.initialize = rd(next(f for f in fs if '_fuzzer_initialize' in f))
        r = rd(next(f for f in fs if f.startswith(next(f for f in fs if '_fuzzer_initialize' in f)[:8] + '_target_')))
        self.init_root = r[1:33] if r[0] == 2 else None
    def steps(self):
        for f in self.fs:
            if '_fuzzer_import_block' not in f: continue
            resp = [g for g in self.fs if g.startswith(f[:8] + '_target_')]
            r = self.rd(resp[0]) if resp else None
            yield Step(f[:8], self.rd(f)[1:],
                       root=r[1:33] if r and r[0] == 2 else None,
                       rejected=None if r is None else r[0] == 255,
                       note=err_text(r) if r and r[0] == 255 else None)

def split_trace_step(b, post_root):
    """E(pre-state, block, post-state) with state = (root, key-values): the post-state is the suffix
    that starts with the post-state root (from the step's .json) and parses exactly to the end."""
    pe = kvs_end(b, 32)
    j = len(b)
    while True:
        j = b.rfind(post_root, pe, j)
        if j < 0: raise ValueError('cannot split trace step')
        try:
            if kvs_end(b, j + 32) == len(b): return b[:pe], b[pe:j], b[j:]
        except IndexError:
            pass

class TraceFeed(Feed):
    """genesis.bin = E(header, state) when present (all published 0.8.0 traces have it); otherwise
    the first pre-state under a given genesis header."""
    def __init__(self, d, genesis_header, spec):
        fs = sorted(f for f in os.listdir(d) if f.endswith('.bin') and f[:8].isdigit())
        post_root = lambda f: bytes.fromhex(json.load(open(os.path.join(d, f[:-4] + '.json')))['post_state']['state_root'].removeprefix('0x'))
        self.raw = [(f[:8], *split_trace_step(open(os.path.join(d, f), 'rb').read(), post_root(f))) for f in fs]
        g = os.path.join(d, 'genesis.bin')
        if os.path.exists(g):
            g = open(g, 'rb').read(); hl = header_len(g, spec)
            self.initialize = b'\x01' + g[:hl] + g[hl+32:] + enc_nat(0)
            self.init_root = g[hl:hl+32]
        else:
            if genesis_header is None: raise SystemExit(f'{d}: no genesis.bin; give --genesis-header')
            pre = self.raw[0][1]
            self.initialize = b'\x01' + genesis_header + pre[32:] + enc_nat(0)
            self.init_root = pre[:32]
    def steps(self):
        prev_post = self.init_root
        for name, pre, block, post in self.raw:
            note = None if pre[:32] == prev_post else 'pre-state is not the previous post-state (trace is not one chain)'
            yield Step(name, block, root=post[:32], rejected=post[:32] == pre[:32],
                       state=kvs_dict(post, 32), note=note)
            prev_post = post[:32]

class DumpFeed(Feed):
    def __init__(self, d):
        self.d = d
        g = open(os.path.join(d, 'genesis.bin'), 'rb').read()
        self.initialize = b'\x01' + g + enc_nat(0)
    def steps(self):
        for f in sorted(f for f in os.listdir(self.d) if f.endswith('.block')):
            p = lambda ext: os.path.join(self.d, f[:-6] + ext)
            rd = lambda ext: open(p(ext), 'rb').read() if os.path.exists(p(ext)) else None
            st = rd('.state')
            yield Step(f[:-6], rd('.block'), root=rd('.root'), rejected=False,
                       state=kvs_dict(st) if st is not None else None)

def genesis_header_of(init_msg):
    """The header of an Initialize message (tag, header, key-values, ancestry)."""
    for hl in range(100, len(init_msg)):
        try:
            i = kvs_end(init_msg, 1 + hl)
            a, i = nat(init_msg, i)
            if i + a * 36 == len(init_msg): return init_msg[1:1+hl]
        except IndexError:
            pass
    raise SystemExit('cannot split Initialize')

# ---------------------------------------------------------------- target connection

class Target:
    def __init__(self, cmd, log):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    def ask(self, msg):
        self.p.stdin.write(struct.pack('<I', len(msg)) + msg); self.p.stdin.flush()
        h = self.p.stdout.read(4)
        if len(h) < 4: raise SystemExit('target closed the connection')
        return self.p.stdout.read(struct.unpack('<I', h)[0])
    def close(self):
        try: self.p.stdin.close()
        except OSError: pass
        self.p.wait()

OWN_PEER_INFO = (b'\x00' + bytes([1]) + struct.pack('<I', 3) + bytes([0, 8, 0]) + bytes([0, 1, 0])
                 + enc_nat(6) + b'shadow')

# ---------------------------------------------------------------- hints (docs/gp-after-0.8.0.md)

NAMES = {1:'alpha',2:'phi',3:'beta',4:'gamma',5:'psi',6:'eta',7:'iota',8:'kappa',9:'lambda',10:'rho',
         11:'tau',12:'chi',13:'pi',14:'omega',15:'xi',16:'theta',255:'delta-info'}

def components(ours, theirs):
    out = set()
    for k in set(ours) | set(theirs):
        if ours.get(k) != theirs.get(k):
            out.add(NAMES.get(k[0], 'delta-data') if k[1:].strip(b'\0') == b'' or k[0] == 255 else 'delta-data')
    return sorted(out)

def hint(kind, comps):
    """First things to check in docs/gp-after-0.8.0.md and docs/findings.md. Hints, not verdicts."""
    if kind == 'node-rejects':
        return 'block validity changed after 0.8.0? see GP #563 (F3), #567, #574, #542, #560, #562, #575'
    if kind == 'we-reject':
        return 'model rejects: check its error against GP v0.8.0; post-0.8.0 encoding changes (#562, #575, #560) also show here'
    if comps and set(comps) <= {'pi'}:
        return 'only pi: accumulation gas/statistics, see F2 (GP #533) and #564/#565'
    if comps and set(comps) <= {'pi', 'delta-data', 'delta-info', 'chi', 'phi', 'iota', 'xi', 'theta'}:
        return 'accumulation: see GP #533, #545, #558, #571, #581, #588 and findings F2'
    return 'not covered by a known post-0.8.0 change: unexplained until checked against GP v0.8.0'

# ---------------------------------------------------------------- driver

def run(feed, a):
    out = a.out; os.makedirs(out, exist_ok=True)
    tgt = Target(a.target, a.log)
    tgt.ask(feed.peer_info or OWN_PEER_INFO)
    r = tgt.ask(feed.initialize)
    stats = {'blocks': 0, 'checked': 0, 'match': 0, 'mismatch': 0, 'unchecked': 0, 'diverged': 0, 'gap': 0, 'known': 0, 'time': 0.0}
    if r[0] != 2: print(f'Initialize: {r!r}'); return stats
    if feed.init_root is not None and r[1:33] != feed.init_root:
        # Nothing after this can be compared. docs/gaps.md #2: a state holding storage cannot be
        # rebuilt from its key-values until jam-lean's storage-key stage 2.
        print(f'genesis: root {r[1:33].hex()} != node {feed.init_root.hex()}: feed skipped '
              '(state not reproduced; storage in the key-values? docs/gaps.md #2)')
        stats['skipped_feeds'] = 1; tgt.close(); return stats
    steps = list(feed.steps())
    # (slot, header hash) of the feed's ancestry and of the blocks imported, for a resync's Initialize
    g_hl = header_len(feed.initialize[1:], a.spec)
    n_anc, i = nat(feed.initialize, kvs_end(feed.initialize, 1 + g_hl))
    ancestry = [(struct.unpack('<I', feed.initialize[i+36*j:i+36*j+4])[0], feed.initialize[i+36*j+4:i+36*j+36]) for j in range(n_anc)]
    tainted = set() # headers whose post-state diverged with no resync, and their descendants
    seen = {blake2b(feed.initialize[1:1+g_hl])}  # parents the target holds a state for
    for n, st in enumerate(steps):
        hl = header_len(st.block, a.spec); hh = blake2b(st.block[:hl])
        if st.block[:32] not in seen and st.block[:32] not in tainted:
            stats['unchecked'] += 1; stats['gap'] += 1   # so its descendants are gaps too
            if not a.quiet: print(f'{st.name}: slot {slot_of(st.block)} parent {st.block[:32].hex()} not in the feed: unchecked')
            continue
        if st.block[:32] in tainted:
            tainted.add(hh); stats['unchecked'] += 1; stats['diverged'] += 1
            if not a.quiet: print(f'{st.name}: slot {slot_of(st.block)} descends from a diverged block: unchecked')
            continue
        # The node's root: the feed's, else the next block's H_R when it is a child of this one.
        node_root, src = st.root, 'feed'
        if node_root is None and st.rejected is not True:
            nxt = next((s for s in steps[n+1:] if s.block[:32] == hh), None)
            if nxt is not None: node_root, src = nxt.block[32:64], 'next H_R'
        t0 = time.perf_counter(); r = tgt.ask(b'\x03' + st.block); dt = time.perf_counter() - t0
        stats['blocks'] += 1; stats['time'] += dt
        ours = r[1:33] if r[0] == 2 else None
        err = err_text(r) if r[0] == 255 else None
        if st.note and not a.quiet: print(f'{st.name}: note: {st.note}')
        if node_root is None and not st.rejected:
            stats['unchecked'] += 1
            if not a.quiet: print(f'{st.name}: slot {slot_of(st.block)} {"root " + ours.hex() if ours else "error " + str(err)} (no node root: unchecked) {dt*1000:.0f} ms')
            continue
        stats['checked'] += 1
        if st.rejected and err is not None: ok, kind = True, None
        elif st.rejected: ok, kind = False, 'node-rejects'
        elif err is not None: ok, kind = False, 'we-reject'
        else: ok, kind = ours == node_root, 'root'
        if ok:
            stats['match'] += 1
            if not a.quiet: print(f'{st.name}: slot {slot_of(st.block)} {"rejected as the node" if err else "root " + ours.hex()} ok {dt*1000:.0f} ms')
            if err is None: ancestry.append((slot_of(st.block), hh)); seen.add(hh)
            continue
        known = a.known.get(hh.hex())
        stats['known' if known else 'mismatch'] += 1
        print(f'{st.name}: {"KNOWN " + known if known else "MISMATCH"} slot {slot_of(st.block)} header {hh.hex()}')
        print(f'  ours: {"root " + ours.hex() if ours else "rejected: " + str(err)}')
        print(f'  node: {"rejected" + (": " + st.note if st.note else "") if st.rejected else "root " + node_root.hex() + " (" + src + ")"}')
        comps = None
        if ours is not None:
            s = tgt.ask(b'\x04' + hh)
            if s[0] == 5:
                open(os.path.join(out, f'{st.name}.ours.state'), 'wb').write(s)
                if st.state is not None:
                    theirs = b'\x05' + enc_kvs(st.state)
                    open(os.path.join(out, f'{st.name}.node.state'), 'wb').write(theirs)
                    comps = components(kvs_dict(s, 1), st.state)
                    print(f'  differing components: {", ".join(comps)}')
                    sys.stdout.flush()
                    subprocess.run([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'diffstate.py'),
                                    os.path.join(out, f'{st.name}.ours.state'), os.path.join(out, f'{st.name}.node.state')])
                else:
                    print(f'  our state: {out}/{st.name}.ours.state (feed has no node state to diff)')
        if not known: print(f'  hint: {hint(kind, comps)}')
        if not a.cont: stats['stopped'] = 1; break
        if st.state is not None and not st.rejected:
            # Resync: a fresh session on the node's post-state, keyed by this header.
            tgt.close(); tgt = Target(a.target, a.log); tgt.ask(feed.peer_info or OWN_PEER_INFO)
            anc = ancestry[-24:] if a.spec == 'tiny' else ancestry[-14400:]
            init = (b'\x01' + st.block[:hl] + enc_kvs(st.state) + enc_nat(len(anc))
                    + b''.join(struct.pack('<I', s) + h for s, h in anc))
            r = tgt.ask(init)
            if r[0] == 2 and (st.root is None or r[1:33] == st.root):
                print(f'  resynced on the node post-state (root {r[1:33].hex()})')
                ancestry.append((slot_of(st.block), hh)); seen.add(hh)
            else:
                tainted.add(hh)
                print(f'  resync failed ({"root " + r[1:33].hex() + " != node root" if r[0] == 2 else err_text(r)}): its descendants go unchecked')
        elif not st.rejected:
            tainted.add(hh)
            print('  cannot resync (feed has no node post-state): its descendants go unchecked')
    tgt.close()
    return stats

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('kind', choices=['session', 'trace', 'dump']); ap.add_argument('dirs', nargs='+')
    ap.add_argument('--target', nargs='+', default=['.lake/build/bin/jam-lean-target', 'serve'],
                    help='target command speaking the protocol on stdin/stdout, given last (default: %(default)s)')
    ap.add_argument('--genesis-header', help='trace feed without genesis.bin: a session dir whose Initialize header to use')
    ap.add_argument('--spec', choices=list(SPECS), default='tiny')
    ap.add_argument('--continue', dest='cont', action='store_true', help='continue after a mismatch')
    ap.add_argument('--out', default='shadow-out', help='directory for states on mismatch')
    ap.add_argument('--quiet', action='store_true', help='print mismatches and the summary only')
    ap.add_argument('--known', help='file of known divergences: lines "HEADER-HASH LABEL" (# starts a comment line)')
    ap.add_argument('--target-log', help="file for the target's stderr (default: discarded)")
    a = ap.parse_args()
    known_file, a.known = a.known, {}
    for line in (open(known_file).read().splitlines() if known_file else []):
        line = line.split(None, 1)
        if len(line) == 2 and not line[0].startswith('#'): a.known[line[0].removeprefix('0x').lower()] = line[1].strip()
    a.log = open(a.target_log, 'ab') if a.target_log else subprocess.DEVNULL
    gh = genesis_header_of(SessionFeed(a.genesis_header).initialize) if a.genesis_header else None
    tot = {}
    for d in a.dirs:
        feed = {'session': lambda: SessionFeed(d), 'trace': lambda: TraceFeed(d, gh, a.spec), 'dump': lambda: DumpFeed(d)}[a.kind]()
        if len(a.dirs) > 1: print(f'== {d}')
        s = run(feed, a)
        for k, v in s.items(): tot[k] = tot.get(k, 0) + v
    b = tot['blocks']
    t = tot['blocks']
    print(f'{t} blocks imported, {tot["checked"]} checked: {tot["match"]} match, {tot["known"]} known divergence, '
          f'{tot["mismatch"]} unexplained mismatch; {tot["unchecked"] - tot["diverged"] - tot["gap"]} without a node root, '
          f'{tot["diverged"]} skipped as descendants of a divergence, {tot["gap"]} skipped with a parent not in the feed; {tot["time"]/max(t,1)*1000:.0f} ms/block'
          + (' (stopped at the first mismatch)' if tot.get('stopped') else '')
          + (f'; {tot["skipped_feeds"]} feed(s) skipped, genesis state not reproduced' if tot.get('skipped_feeds') else ''))
    return 1 if tot['mismatch'] else 0

if __name__ == '__main__':
    sys.exit(main())
