# Gaps

1. **Cryptography is a stand-in** (`JamTarget/Session.lean`, `oracleCrypto`): every Ed25519,
   Bandersnatch IETF VRF and Ring VRF signature is accepted; Y is computed; the ring root
   O(**k**) is known only for key sequences seen in a state. Consequences seen so far:
   * 0.8.0 `no_forks` session: slots 1–11 match polkajam; slot 12 (first epoch change) differs
     only in γ_Z, because the Bootstrap workload reorders ι (`designate`), so γ_P' is a new key
     sequence. jamduna agrees with polkajam there.
   * 14–17 trace steps that polkajam rejects are imported (likely invalid signatures).
   Plan: Ed25519 and Bandersnatch IETF VRF, then BLS12-381 KZG ring root and Ring VRF, in Lean.
2. **σ cannot be rebuilt from key-values that hold storage**: jam-lean's `ServiceAccount` keys
   storage by the unhashed key, T(σ) keeps only a hash. 52 of 89 published 0.8.0 traces start from
   such a state. A jam-lean representation change (Adam's decision).
3. **Ancestry**: `Initialize` ancestry items carry (slot, hash) only, but GP 0.8.0 eq. 11.36 also
   needs h'_R of the child header; only headers imported in the session form 𝒜.
4. **No Unix sockets in Lean core/Std**: `serve` uses stdin/stdout behind socat (or
   `scripts/bridge.py`).
5. **Tiny 𝖫 = 24** as the fuzzer protocol specifies (the GP defines only the full chain).
