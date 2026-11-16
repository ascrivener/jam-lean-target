#!/usr/bin/env python3
"""Fetch a chain's blocks from a JAM node over JAM-NP (JAMNP-S) and write scripts/shadow.py's dump
feed: NAME.block = E(block) and NAME.root = its posterior state root, NAME = slot-hash prefix
(so a parent sorts before its children). With --side, fork blocks recorded by jamnp_listen.py
are added too.

The chain to fetch is chain.json from scripts/polkajam_chain.py (slot, header hash, state root per
block, from genesis to the best block). For each block after genesis this sends a CE 128 block
request (header hash, direction 1 = descending inclusive, maximum 1 block). It checks that the
returned header hashes to the requested hash and names the previous block as its parent.

JAM-NP as used here: QUIC with TLS 1.3, a self-signed Ed25519 certificate whose DNS alternative
name is the peer ID ("e" + base32 of the public key read as a little-endian integer, alphabet
a-z2-7, 52 characters), ALPN "jamnp-s/0/" + the first 4 octets of the genesis header hash in hex.
A stream starts with its kind octet (128); each message is a u32 LE length and the content.
Needs `pip install aioquic`.
  jamnp_blocks.py --peer 127.0.0.1:40000 --genesis GENESIS.bin --chain chain.json --out DUMP_DIR
"""
import argparse, asyncio, contextlib, datetime, json, os, socket, ssl, struct, sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shadow import blake2b, header_len, nat

ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567'

def peer_id(pub):
    n = int.from_bytes(pub, 'little')
    return 'e' + ''.join(ALPHABET[(n >> (5 * i)) & 31] for i in range(52))

def self_signed():
    key = ed25519.Ed25519PrivateKey.generate()
    pid = peer_id(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, pid)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(pid)]), critical=False)
            .sign(key, None))
    return key, cert, pid

@contextlib.asynccontextmanager
async def connect(host, port, cfg):
    """aioquic.asyncio.connect, but on a socket of the address's own family (aioquic's always
    opens an IPv6 dual-stack socket, which fails where IPv6 is off)."""
    loop = asyncio.get_running_loop()
    fam, _, _, _, addr = (await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM))[0]
    cfg.server_name = cfg.server_name or host
    transport, proto = await loop.create_datagram_endpoint(
        lambda: QuicConnectionProtocol(QuicConnection(configuration=cfg)),
        local_addr=('0.0.0.0' if fam == socket.AF_INET else '::', 0), family=fam)
    try:
        proto.connect(addr, transmit=True)
        try:
            await asyncio.wait_for(proto.wait_connected(), 15)
        except (ConnectionError, asyncio.TimeoutError) as e:
            ev = proto._quic._close_event
            why = f'error {ev.error_code:#x} frame {ev.frame_type} "{ev.reason_phrase}"' if ev else type(e).__name__
            raise ConnectionError(f'handshake with {host}:{port} failed: {why}') from None
        yield proto
    finally:
        proto.close(); await proto.wait_closed(); transport.close()

def messages(data):
    out, i = [], 0
    while i + 4 <= len(data):
        n = struct.unpack('<I', data[i:i+4])[0]; out.append(data[i+4:i+4+n]); i += 4 + n
    if i != len(data): raise ValueError(f'trailing {len(data) - i} octets in the response')
    return out

def find_block(msgs, want, spec):
    """The requested block in the response, whether [Block] carries a length prefix or not."""
    for m in msgs:
        for off in (0, 1, 2):
            try:
                if blake2b(m[off:off + header_len(m[off:], spec)]) == want:
                    if off: n, j = nat(m, 0); assert j == off and n == 1
                    return m[off:]
            except (IndexError, AssertionError):
                pass
    return None

def alpns(ghash, given):
    """ALPNs to offer: --alpn if given, else JAMNP-S's jamnp-s/0/<first 4 genesis-hash octets>
    and its variants (full hash, other versions); the node picks the one it speaks."""
    if given: return given
    h8, h = ghash[:4].hex(), ghash.hex()
    return [f'jamnp-s/{v}/{x}' for v in (0, 1, 2) for x in (h8, h)]

def genesis_hash(path, spec):
    gen = open(path, 'rb').read()
    return blake2b(gen[:header_len(gen, spec)])

async def with_peer(a, ghash, work):
    """Run `work(conn)` on the first of a.peer ("host:port" or "peer-id@host:port", the node's
    own peer ID then being the TLS server name) that completes the handshake."""
    key, cert, pid = self_signed()
    for peer in a.peer:
        sni, _, hp = peer.rpartition('@')
        host, port = hp.rsplit(':', 1)
        cfg = QuicConfiguration(is_client=True, alpn_protocols=alpns(ghash, a.alpn),
                                verify_mode=ssl.CERT_NONE, idle_timeout=60, server_name=sni or None)
        cfg.certificate, cfg.private_key = cert, key
        print(f'connecting to {peer} as {pid}, ALPN {" ".join(cfg.alpn_protocols)}', flush=True)
        try:
            async with connect(host, int(port), cfg) as conn:
                print(f'connected, ALPN {conn._quic.tls.alpn_negotiated}', flush=True)
                return await work(conn)
        except ConnectionError as e:
            print(e, flush=True)
    sys.exit('no peer completed the handshake')

async def request_block(conn, want, spec, timeout):
    """CE 128 block request: the block whose header hashes to `want`, or None."""
    reader, writer = await conn.create_stream()
    req = want + bytes([1]) + struct.pack('<I', 1)
    writer.write(bytes([128]) + struct.pack('<I', len(req)) + req); writer.write_eof()
    data = await asyncio.wait_for(reader.read(), timeout)
    return find_block(messages(data), want, spec)

def name(slot, h):
    """Dump file stem: slot first, so parents sort before children (forks included)."""
    return f'{slot:010d}-{h.hex()[:16]}'

async def fetch(a):
    ghash = genesis_hash(a.genesis, a.spec)
    chain = json.load(open(a.chain))
    if bytes.fromhex(chain[0]['header_hash']) != ghash:
        sys.exit(f'chain.json starts at {chain[0]["header_hash"]}, not the genesis {ghash.hex()}')
    os.makedirs(a.out, exist_ok=True)
    await with_peer(a, ghash, lambda conn: fetch_chain(conn, a, chain, ghash))
    if a.side: merge_side(a, chain)

async def fetch_chain(conn, a, chain, ghash):
    prev = ghash
    for b in chain[1:]:
        want = bytes.fromhex(b['header_hash'])
        blk = await request_block(conn, want, a.spec, a.timeout)
        if blk is None:
            sys.exit(f'slot {b["slot"]}: no block hashing to {want.hex()}')
        if blk[:32] != prev:
            sys.exit(f'slot {b["slot"]}: parent {blk[:32].hex()} is not the previous block {prev.hex()}')
        stem = os.path.join(a.out, name(b['slot'], want))
        open(stem + '.block', 'wb').write(blk)
        open(stem + '.root', 'wb').write(bytes.fromhex(b['state_root']))
        prev = want
    print(f'{len(chain) - 1} best-chain blocks -> {a.out}')

def merge_side(a, chain):
    """Add the blocks of --side (jamnp_listen.py's NAME.block, with NAME.root where JIP-2 gave
    one) that are not on the best chain: the fork blocks."""
    best = {c['header_hash'] for c in chain}
    n = 0
    for f in sorted(os.listdir(a.side)):
        if not f.endswith('.block'): continue
        blk = open(os.path.join(a.side, f), 'rb').read()
        h = blake2b(blk[:header_len(blk, a.spec)])
        if h.hex() in best: continue
        stem = os.path.join(a.out, name(struct.unpack('<I', blk[96:100])[0], h))
        open(stem + '.block', 'wb').write(blk)
        r = os.path.join(a.side, f[:-6] + '.root')
        if os.path.exists(r): open(stem + '.root', 'wb').write(open(r, 'rb').read())
        n += 1
    print(f'{n} fork blocks from {a.side} -> {a.out}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--peer', nargs='+', default=['127.0.0.1:40000'],
                    help='nodes to try, [peer-id@]host:port (UDP)')
    ap.add_argument('--genesis', required=True, help='genesis.bin (E(header, key-values))')
    ap.add_argument('--chain', required=True, help='chain.json from polkajam_chain.py')
    ap.add_argument('--out', required=True)
    ap.add_argument('--spec', default='tiny')
    ap.add_argument('--timeout', type=float, default=30)
    ap.add_argument('--alpn', nargs='+', help='ALPN protocol(s) to offer instead of the defaults')
    ap.add_argument('--side', help='directory of fork blocks from jamnp_listen.py to add')
    asyncio.run(fetch(ap.parse_args()))

if __name__ == '__main__':
    main()
