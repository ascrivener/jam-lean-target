# Gaps

1. **Cryptography**: now all in plain Lean (`JamCrypto`: Ed25519 ZIP-215, Bandersnatch IETF VRF,
   ring root, Ring VRF). Every fuzzer signature verifies (jam-lean #196 dropped the `$` sigil from
   its context strings; the target's stopgap is gone). The 0.8.0 `no_forks` session now matches polkajam through slot 24; slot 25 is finding F2.
2. **Resolved: σ from key-values that hold storage.** jam-lean's storage-key stage 2 (jam-lean
   #243) keys storage and requests by the state-key hash and carries a_i, a_o, so every state T(σ)
   can hold decodes. The decoder is jam-lean's `JAM.StateDecode` (jam-lean #247), which the target
   now uses; jam-lean's tracetest checks the T(σ) round trip on every trace state.
   Replay of the 89 published 0.8.0 traces (jam-fuzzing `fuzz-reports/0.8.0`, `jam-lean-target
   trace`, real crypto, v0.8.0 path; 2026-11-25): all 232 pre-states decode and reproduce their
   root. 119 of 232 steps as the trace; 94 rejected for a lookup anchor outside the known ancestry
   (traces without genesis.bin start mid-chain with no headers: item 3); 16 accepted where the trace
   rejects (F3, GP #563); 3 post-state roots differ, each in one 8-octet service storage value. Triage of those 3: a
   non-manager service calls `bless`, and GP v0.8.0's Ω_B returns HUH (the manager check of GP #519,
   "Restrict bless to manager", in v0.8.0; absent in v0.7.1 and v0.7.2). The traces' post-states are
   those of `bless` returning OK, the pre-#519 rule: with OK in place of HUH the model reproduces
   each value. The model follows v0.8.0 here (finding F7).
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
