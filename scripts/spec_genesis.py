#!/usr/bin/env python3
"""genesis.bin for scripts/shadow.py's dump feed from a PolkaJam chain spec (`polkajam --chain dev
dump-spec FILE`): E(genesis_header, genesis_state as key-values sorted by key).
  spec_genesis.py SPEC.json OUT/genesis.bin
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shadow import enc_kvs

spec = json.load(open(sys.argv[1]))
h = bytes.fromhex(spec['genesis_header'].removeprefix('0x'))
kv = {bytes.fromhex(k.removeprefix('0x')): bytes.fromhex(v.removeprefix('0x')) for k, v in spec['genesis_state'].items()}
os.makedirs(os.path.dirname(os.path.abspath(sys.argv[2])), exist_ok=True)
open(sys.argv[2], 'wb').write(h + enc_kvs(kv))
print(f'{sys.argv[2]}: header {len(h)} octets, {len(kv)} key-values')
