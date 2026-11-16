#!/usr/bin/env python3
"""Record every block a JAM node announces over JAM-NP, side forks included, for scripts/shadow.py.

Opens UP 0 (block announcements) to a node and sends a handshake with the genesis as the finalized
block and no leaves. It reads the node's handshake (finalized block and leaves) and then each
announcement (header ++ finalized block). For every header hash it has not seen, including the
leaves, it fetches the block at once with a CE 128 request, while forks are still held. It writes
OUT/NAME.block (NAME = slot-hash prefix, as jamnp_blocks.py) and appends to OUT/announced.jsonl.
It runs until it is killed or --duration passes; files are written as blocks arrive.
`jamnp_blocks.py --side OUT` later adds the blocks that are not on the best chain to the dump.
  jamnp_listen.py --peer [peer-id@]HOST:PORT … --genesis GENESIS.bin --out DIR [--duration S]
"""
import argparse, asyncio, json, os, struct, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from jamnp_blocks import genesis_hash, name, request_block, with_peer
from shadow import blake2b, enc_nat, nat

async def read_msg(reader):
    n = struct.unpack('<I', await reader.readexactly(4))[0]
    return await reader.readexactly(n)

async def listen(conn, a, ghash):
    reader, writer = await conn.create_stream()
    hs = ghash + struct.pack('<I', 0) + enc_nat(0)          # Final(genesis, 0), no leaves
    writer.write(bytes([0]) + struct.pack('<I', len(hs)) + hs)
    seen, queue = set(), asyncio.Queue()
    log = open(os.path.join(a.out, 'announced.jsonl'), 'a')

    async def fetcher():
        while True:
            h, slot, how = await queue.get()
            try:
                blk = await request_block(conn, h, a.spec, a.timeout)
            except Exception as e:  # keep listening; the miss is logged
                blk = None; print(f'fetch {h.hex()[:16]}: {e!r}', flush=True)
            if blk is not None:
                open(os.path.join(a.out, name(slot, h) + '.block'), 'wb').write(blk)
            log.write(json.dumps({'hash': h.hex(), 'slot': slot, 'via': how,
                                  'parent': blk[:32].hex() if blk else None,
                                  'fetched': blk is not None}) + '\n'); log.flush()

    def note(h, slot, how):
        if h not in seen and slot > 0:
            seen.add(h); queue.put_nowait((h, slot, how))

    task = asyncio.create_task(fetcher())
    m = await read_msg(reader)                                # the node's handshake
    k, i = nat(m, 36)
    for j in range(k):
        leaf = m[i + 36 * j:i + 36 * j + 36]
        note(leaf[:32], struct.unpack('<I', leaf[32:36])[0], 'leaf')
    print(f'handshake: finalized slot {struct.unpack("<I", m[32:36])[0]}, {k} leaves', flush=True)
    t0 = time.time()
    while a.duration is None or time.time() - t0 < a.duration:
        try:
            m = await asyncio.wait_for(read_msg(reader), 30)
        except asyncio.TimeoutError:
            continue
        hdr = m[:-36]
        note(blake2b(hdr), struct.unpack('<I', hdr[96:100])[0], 'announcement')
    task.cancel()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--peer', nargs='+', required=True, help='nodes to try, [peer-id@]host:port (UDP)')
    ap.add_argument('--genesis', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--duration', type=float)
    ap.add_argument('--spec', default='tiny')
    ap.add_argument('--timeout', type=float, default=30)
    ap.add_argument('--alpn', nargs='+')
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    ghash = genesis_hash(a.genesis, a.spec)
    asyncio.run(with_peer(a, ghash, lambda conn: listen(conn, a, ghash)))

if __name__ == '__main__':
    main()
