# Gaps

The target follows GP v0.8.1 since 2026-11-25 (items 6 and 7). Items 1–3 record what was found
under GP v0.8.0 (the last v0.8.0 target is commit `671f256`).

1. **Cryptography**: all in plain Lean (jam-lean's `JamCrypto`). Under v0.8.0 (Ed25519 ZIP-215,
   Bandersnatch IETF VRF, ring root, Ring VRF) every fuzzer signature verified (jam-lean #196
   dropped the `$` sigil from its context strings); the 0.8.0 `no_forks` session matched polkajam
   through slot 24; slot 25 is finding F2.
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
3. **Ancestry**: `Initialize` ancestry items carry (slot, hash) only, but GP eq. 11.36 also
   needs h'_R of the child header; only headers imported in the session form 𝒜.
4. **No Unix sockets in Lean core/Std**: `serve` uses stdin/stdout behind socat (or
   `scripts/bridge.py`).
5. **Tiny 𝖫 = 24** as the fuzzer protocol specifies (the GP defines only the full chain).
6. **GP v0.8.1 crypto: assumptions, to confirm with 0.8.1 vectors or fuzzer blocks.**
   * **The VRF spec's vector reading** (`JamCrypto.Reading.vectors`; `cryptoReading` in
     `JamTarget/Session.lean`). Where Draft 35's prose and its own vectors disagree (the Z_pad of
     hash to curve, 48 octets not 128; the ring transcript label, the suite id not "ring-proof"),
     jam-lean's `JamCrypto` follows the prose by default (Adam's option A) and the target selects
     the vectors' reading: the fuzzer's blocks follow the vectors (davxy asked for it), and the
     prose reading has no oracle at all. The list of cases is in jam-lean `docs/jamcrypto.md`.
   * **The 96-octet Thin VRF signature is O ⌢ R ⌢ s.** GP gives 96 octets, the VRF spec encodes
     only R ⌢ s; davxy confirmed O ⌢ R ⌢ s (graypaper#593; spec issue
     davxy/bandersnatch-vrf-spec#30).
   * **The ring domain is fixed at 2048** for every chain, per Draft 35 §5 (Adam, 2026-11-25).
7. **Suspended until GP 0.8.1 fuzzer data exists** (as jam-lean suspends its v0.8.0 vectors):
   * the recorded 0.8.0 fuzzer sessions (`forks`, `no_forks`) and the shadow driver on them, in CI
     and in the image check: they are GP v0.8.0 chains (H_R, C(13), C(255), assurances, seals);
   * replays of the published 0.8.0 fuzz-reports traces (item 2), and the polkajam feed workflow
     (a polkajam v0.8.0 testnet; manual trigger only).
   What runs instead: the refine vectors (`vectors/refine/0.8.1-tiny`) and the block vectors
   (`vectors/blocks`), both regenerated under v0.8.1 and checked byte for byte; a crafted v0.8.1
   session (CI and the image); the official PVM vectors. The generators start from the 0.8.0
   genesis converted to v0.8.1 form (`JamTarget/Upgrade.lean`).
