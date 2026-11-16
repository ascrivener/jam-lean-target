#!/usr/bin/env python3
"""Fetch a chain's blocks from a JAM node over JAM-NP (JAMNP-S) and write scripts/shadow.py's dump
feed: NNNNNNNN.block = E(block) and NNNNNNNN.root = its posterior state root.

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

async def fetch(a):
    gen = open(a.genesis, 'rb').read()
    ghash = blake2b(gen[:header_len(gen, a.spec)])
    chain = json.load(open(a.chain))
    if bytes.fromhex(chain[0]['header_hash']) != ghash:
        sys.exit(f'chain.json starts at {chain[0]["header_hash"]}, not the genesis {ghash.hex()}')
    key, cert, pid = self_signed()
    os.makedirs(a.out, exist_ok=True)
    # Peers: "host:port" or "peer-id@host:port" (the node's own peer ID is then sent as the TLS
    # server name). The first that completes the handshake is used.
    for peer in a.peer:
        sni, _, hp = peer.rpartition('@')
        host, port = hp.rsplit(':', 1)
        cfg = QuicConfiguration(is_client=True, alpn_protocols=[f'jamnp-s/0/{ghash[:4].hex()}'],
                                verify_mode=ssl.CERT_NONE, idle_timeout=60, server_name=sni or None)
        cfg.certificate, cfg.private_key = cert, key
        print(f'connecting to {peer} as {pid}, ALPN {cfg.alpn_protocols[0]}', flush=True)
        try:
            async with connect(host, int(port), cfg) as conn:
                await fetch_chain(conn, a, chain, ghash)
            return
        except ConnectionError as e:
            print(e, flush=True)
    sys.exit('no peer completed the handshake')

async def fetch_chain(conn, a, chain, ghash):
    prev = ghash
    for n, b in enumerate(chain[1:], 1):
        want = bytes.fromhex(b['header_hash'])
        reader, writer = await conn.create_stream()
        req = want + bytes([1]) + struct.pack('<I', 1)
        writer.write(bytes([128]) + struct.pack('<I', len(req)) + req); writer.write_eof()
        data = await asyncio.wait_for(reader.read(), a.timeout)
        blk = find_block(messages(data), want, a.spec)
        if blk is None:
            sys.exit(f'slot {b["slot"]}: no block hashing to {want.hex()} in {len(data)} response octets')
        if blk[:32] != prev:
            sys.exit(f'slot {b["slot"]}: parent {blk[:32].hex()} is not the previous block {prev.hex()}')
        open(os.path.join(a.out, f'{n:08d}.block'), 'wb').write(blk)
        open(os.path.join(a.out, f'{n:08d}.root'), 'wb').write(bytes.fromhex(b['state_root']))
        prev = want
    print(f'{len(chain) - 1} blocks -> {a.out}')

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--peer', nargs='+', default=['127.0.0.1:40000'],
                    help='nodes to try, [peer-id@]host:port (UDP)')
    ap.add_argument('--genesis', required=True, help='genesis.bin (E(header, key-values))')
    ap.add_argument('--chain', required=True, help='chain.json from polkajam_chain.py')
    ap.add_argument('--out', required=True)
    ap.add_argument('--spec', default='tiny')
    ap.add_argument('--timeout', type=float, default=30)
    asyncio.run(fetch(ap.parse_args()))

if __name__ == '__main__':
    main()
