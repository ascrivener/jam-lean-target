#!/usr/bin/env python3
"""Record a JAM node's best chain over JIP-2 RPC: (slot, header hash, posterior state root) for
every block from the best block back to genesis. JIP-2 has no method returning blocks or full
states, so this gives roots only (see docs/shadow.md). Needs `pip install websockets`.
  polkajam_chain.py --rpc ws://127.0.0.1:19800 --blocks 100 --timeout 1200 --out chain.json
"""
import argparse, itertools, json, sys, time
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
    if isinstance(h, list): return bytes(h).hex()
    if isinstance(h, str): return h.removeprefix('0x')
    raise ValueError(f'unexpected hash encoding {h!r}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--rpc', default='ws://127.0.0.1:19800')
    ap.add_argument('--blocks', type=int, default=100)
    ap.add_argument('--timeout', type=int, default=1200, help='seconds to wait for the chain to grow')
    ap.add_argument('--out', default='chain.json')
    a = ap.parse_args()
    t0 = time.time(); ws = None
    while ws is None:
        try: ws = connect(a.rpc, max_size=None)
        except OSError:
            if time.time() - t0 > a.timeout: sys.exit(f'no RPC at {a.rpc}')
            time.sleep(2)
    print('parameters:', json.dumps(call(ws, 'parameters'))[:2000])
    while True:
        best = call(ws, 'bestBlock')
        print(f'best: slot {best["slot"]} {hexify(best["header_hash"])}', flush=True)
        if best['slot'] >= a.blocks or time.time() - t0 > a.timeout: break
        time.sleep(6)
    chain, cur = [], best
    while True:
        h = cur['header_hash']
        try: root = hexify(call(ws, 'stateRoot', h))
        except RuntimeError as e: root = f'error: {e}'
        chain.append({'slot': cur['slot'], 'header_hash': hexify(h), 'state_root': root})
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
