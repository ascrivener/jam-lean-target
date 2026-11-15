# Gaps

1. **Cryptography**: now all in plain Lean (`JamCrypto`: Ed25519 ZIP-215, Bandersnatch IETF VRF,
   ring root, Ring VRF). Stopgap: a leading `$` is stripped from jam-lean's context strings until
   jam-lean drops the sigil (approved by Adam, jam-lean PR pending). With it, every fuzzer signature
   verifies. The 0.8.0 `no_forks` session now matches polkajam through slot 24; slot 25 is finding F2.
2. **σ cannot be rebuilt from key-values that hold storage**: jam-lean's `ServiceAccount` keys
   storage by the unhashed key, T(σ) keeps only a hash. 52 of 89 published 0.8.0 traces start from
   such a state. A jam-lean representation change (Adam's decision).
3. **Ancestry**: `Initialize` ancestry items carry (slot, hash) only, but GP 0.8.0 eq. 11.36 also
   needs h'_R of the child header; only headers imported in the session form 𝒜.
4. **No Unix sockets in Lean core/Std**: `serve` uses stdin/stdout behind socat (or
   `scripts/bridge.py`).
5. **Tiny 𝖫 = 24** as the fuzzer protocol specifies (the GP defines only the full chain).
