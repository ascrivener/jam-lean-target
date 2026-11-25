# Gaps

1. **Cryptography**: now all in plain Lean (`JamCrypto`: Ed25519 ZIP-215, Bandersnatch IETF VRF,
   ring root, Ring VRF). Every fuzzer signature verifies (jam-lean #196 dropped the `$` sigil from
   its context strings; the target's stopgap is gone). The 0.8.0 `no_forks` session now matches polkajam through slot 24; slot 25 is finding F2.
2. **σ cannot be rebuilt from key-values that hold storage**: jam-lean's `ServiceAccount` keys
   storage by the unhashed key, T(σ) keeps only a hash. 52 of 89 published 0.8.0 traces start from
   such a state. Adam approved re-keying storage by the state-key hash (jam-lean
   docs/storage-key-design.md, stage 1 = jam-lean PR #200, stage 2 later).
3. **Ancestry**: `Initialize` ancestry items carry (slot, hash) only, but GP 0.8.0 eq. 11.36 also
   needs h'_R of the child header; only headers imported in the session form 𝒜.
4. **No Unix sockets in Lean core/Std**: `serve` uses stdin/stdout behind socat (or
   `scripts/bridge.py`).
5. **Tiny 𝖫 = 24** as the fuzzer protocol specifies (the GP defines only the full chain).
6. **GP v0.8.1 crypto (behind `--gp 0.8.1`), readings to confirm with 0.8.1 vectors or fuzzer
   blocks**: the 96-octet Thin VRF signature is O ⌢ R ⌢ s (GP gives 96 octets, the VRF spec
   encodes only R ⌢ s; Adam, 2026-11-25). The ring domain is fixed at 2048 for every chain, per
   Draft 35 §5 (Adam, 2026-11-25; v0.8.0 stays sized by V). The ring transcript label follows
   Draft 35's vectors (suite id), not its prose ("ring-proof"). See docs/crypto-notes.md.
