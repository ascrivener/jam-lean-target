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
