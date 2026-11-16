#!/usr/bin/env python3
"""Record a JAM node's best chain over JIP-2 RPC: (slot, header hash, posterior state root) for
every block from the best block back to genesis. JIP-2 has no method returning blocks or full
states, so this gives roots only (see docs/shadow.md). Needs `pip install websockets`.
  polkajam_chain.py --rpc ws://127.0.0.1:19800 --blocks 100 --timeout 1200 --out chain.json
"""
import argparse, base64, itertools, json, os, sys, time
from websockets.sync.client import connect

ids = itertools.count(1)

def call(ws, method, *params):
    i = next(ids)
    ws.send(json.dumps({'jsonrpc': '2.0', 'id': i, 'method': method, 'params': list(params)}))
    while True:
        m = json.loads(ws.recv())
        if m.get('id') == i:
            if 'error' in m: raise RuntimeError(f'{method}: {m["error"]}')
            return m['result']

def hexify(h):
    """A 32-octet hash as hex: PolkaJam sends base64; byte arrays and hex are accepted too."""
    if isinstance(h, list): return bytes(h).hex()
    if isinstance(h, str):
        if h.startswith('0x'): return h[2:]
        if len(h) == 64 and all(c in '0123456789abcdefABCDEF' for c in h): return h.lower()
        return base64.b64decode(h).hex()
    raise ValueError(f'unexpected hash encoding {h!r}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rpc', default='ws://127.0.0.1:19800')
    ap.add_argument('--blocks', type=int, default=100, help='blocks after genesis to wait for')
    ap.add_argument('--timeout', type=int, default=1200, help='seconds to wait for the chain to grow')
    ap.add_argument('--out', default='chain.json')
    ap.add_argument('--pid', type=int, help='stop early if this process (the node) exits')
    ap.add_argument('--roots-for', help='instead: write NAME.root (JIP-2 stateRoot) beside each '
                    'NAME.block in this directory (jamnp_listen.py\'s fork blocks)')
    a = ap.parse_args()
    alive = lambda: a.pid is None or os.path.exists(f'/proc/{a.pid}')
    t0 = time.time(); ws = None
    while ws is None:
        try: ws = connect(a.rpc, max_size=None)
        except OSError:
            if time.time() - t0 > a.timeout: sys.exit(f'no RPC at {a.rpc}')
            if not alive(): sys.exit('the node exited before its RPC came up (see testnet.log)')
            time.sleep(2)
    if a.roots_for:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from shadow import blake2b, header_len
        n = 0
        for f in sorted(os.listdir(a.roots_for)):
            if not f.endswith('.block'): continue
            blk = open(os.path.join(a.roots_for, f), 'rb').read()
            h = blake2b(blk[:header_len(blk, 'tiny')])
            try: root = hexify(call(ws, 'stateRoot', base64.b64encode(h).decode()))  # as JIP-2 sends hashes
            except RuntimeError as e: print(f'{f}: {e}'); continue
            open(os.path.join(a.roots_for, f[:-6] + '.root'), 'wb').write(bytes.fromhex(root)); n += 1
        print(f'{n} roots -> {a.roots_for}'); return
    print('parameters:', json.dumps(call(ws, 'parameters'))[:2000])
    # Slots are wall-clock (the first block after genesis is at the current slot), so count blocks
    # from the first block seen after genesis rather than from slot 0.
    first = None
    while True:
        best = call(ws, 'bestBlock')
        if first is None and best['slot'] > 0: first = best['slot']
        n = best['slot'] - first + 1 if first is not None else 0
        print(f'best: slot {best["slot"]} {hexify(best["header_hash"])} (~{n} blocks)', flush=True)
        if n >= a.blocks or time.time() - t0 > a.timeout or not alive(): break
        time.sleep(6)
    chain, cur = [], best
    while True:
        h = cur['header_hash']
        try: root = hexify(call(ws, 'stateRoot', h))
        except RuntimeError as e: root = f'error: {e}'
        chain.append({'slot': cur['slot'], 'header_hash': hexify(h), 'state_root': root})
        if cur['slot'] == 0: break   # genesis
        try: cur = call(ws, 'parent', h)
        except RuntimeError as e:
            print(f'parent of slot {cur["slot"]}: {e} (stop)'); break
        if cur is None: break
    chain.reverse()
    try: fin = call(ws, 'finalizedBlock'); print(f'finalized: slot {fin["slot"]}')
    except RuntimeError as e: print(e)
    json.dump(chain, open(a.out, 'w'), indent=1)
    print(f'{len(chain)} blocks, slots {chain[0]["slot"]}..{chain[-1]["slot"]} -> {a.out}')

main()
