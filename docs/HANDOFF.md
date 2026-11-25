# Handoff: state of jam-lean-target (2026-11-25)

Read this, README.md and the other docs/*.md first.

## What this project is
The jam-lean Lean 4 model of JAM (Gray Paper **v0.8.1**, tag v0.8.1, 2026-11-16; moved from v0.8.0
with jam-lean on 2026-11-25, the last v0.8.0 target is commit 671f256, image tag `671f256`) as a
target of the JAM conformance fuzzer (jam-conformance/jam-fuzzing, protocol v1), plus our own
generators, vectors and a shadow driver that checks a live node's chain against the model.

**Ownership (Adam, 2026-11-25):** session_01FAPLsdKXq86WuSpB5fCYVg is the single canonical parent
for jam-lean, jam-lean-target and jam (Jamzilla). The former jam-lean parent
(session_01FAPLsbixBk5ZtxHTAoNtdU) is archived. Within jam-lean, follow its own CLAUDE.md
(at most 3 parallel sessions, its standing decisions and CI rules).

## Adam's standing decisions
- Model strictly GP v0.8.1 (since 2026-11-25; strictly v0.8.0 before). Divergences caused by later
  GP changes are logged as "the process follows GP #N", not as bugs. docs/gp-after-0.8.0.md is the
  v0.8.0-era list (all its rows are in v0.8.1).
- Ed25519 acceptance: ZIP-215 (2026-11-15).
- All crypto in plain Lean (JamCrypto); crypto in jam-lean stays a parameter, the target supplies it.
- Ring domain sized by the chain's V (vectors show it; GP silent) for v0.8.0; for v0.8.1 fixed at 2048 per the cited VRF spec Draft 35 §5 (2026-11-25).
- Refine (GP v0.8.1): erasure code of GP #580, s♣ of GP #583 for a package that exports nothing,
  Refine errors first (GP #568); the bundle is read as the GP bundle encoding B (assumption, asked
  on jam-fuzzing PR #214, no answer yet). Under v0.8.0 the target used §H.3 and answered Error.
- Crypto for v0.8.1: the VRF spec's vector reading (`JamCrypto.Reading.vectors`), the Thin
  signature O ⌢ R ⌢ s (graypaper#593), ring domain 2048: docs/gaps.md item 6.
- Ancestry (2026-11-25): keep rejecting lookup anchors that are only in the `Initialize` ancestry
  (slot, hash): accepting them would skip the GP's state-root check. The only paper-exact fix is
  the fuzzer sending full headers (possible later ask on jam-fuzzing #221, Adam's call).
- Disclosure: F4–F6 stay public. Never publish per-implementation results (which node agrees or
  differs) in repos; report them to Adam. Outward-facing actions (issues, posts, contacting people,
  settings) are Adam's call.
- Lean rules: core+Std only, no sorry / partial def / implemented_by / native_decide / bv_decide /
  FFI, standard axioms only (scripts/check-forbidden.sh). The target imports only jam-lean's PVM, JAM and JamCrypto (2026-11-25: JamCrypto and the state decoder moved into jam-lean, #247 and #249).
- Git: PRs against main, squash-merge on green; never push to main.
- Keep the model an executable Gray Paper, not a node (no networking/authoring in Lean; networking
  tooling lives in Python scripts and CI).

## Where things are
- Target: Main.lean (`serve`, `session`, `trace`, `craft`, `probe`), JamTarget/ (wire codec, state
  decode, session, Refine). jam-lean pin in lakefile.lean.
- Docker image: published by .github/workflows/image.yml to **ghcr.io/ascrivener/jam-lean-target**
  (`latest` + short SHA on main, `v*` tags), public. The workflow runs the image the way jam-fuzzing's
  target.py does and replays vectors/refine/0.8.1-tiny (24/24) and a session the image's own crafter
  makes (6/6) before pushing. Tags from 671f256 back are GP v0.8.0 images.
- Crypto: jam-lean's `JamCrypto` library, GP v0.8.1 path (Ed25519 ZIP-215, Bandersnatch Thin VRF,
  Draft 35 ring root and Ring VRF, in the vectors' reading; its vectors run in jam-lean's CI, notes in
  jam-lean docs/jamcrypto.md; the target's assumptions in docs/gaps.md item 6). JIP-5 dev keys sign.
  σ from Initialize key-values: jam-lean's `JAM.StateDecode`. The ring SRS comes from jam-lean
  (`JamCryptoTest/data/`; `JAM_LEAN_SRS` overrides it). The generators (craft, probe, refinegen)
  start from the 0.8.0 genesis converted to v0.8.1 form (JamTarget/Upgrade.lean).
- PVM harness: pvmrun, tools/pvm-ref (PolkaVM 0.38.1), vectors/pvm (1,408 vectors).
- Block crafter and probes: vectors/blocks; refine vectors: vectors/refine.
- Shadow: scripts/shadow.py and docs/shadow.md; polkajam feed workflow (.github/workflows/polkajam-feed.yml)
  runs polkajam v0.8.0's testnet on Actions, fetches blocks over JAM-NP (scripts/jamnp_*.py),
  optional jamt workload with our service (tools/service). A v0.8.0 chain: suspended against the
  v0.8.1 target until a 0.8.1 polkajam release (manual trigger only).
- Findings: docs/findings.md (F0–F7). Gaps: docs/gaps.md. GP changes after v0.8.0: docs/gp-after-0.8.0.md.

## Results so far (results per implementation are kept out of the repo)
- 0.8.0 example sessions: forks 97/97; no_forks matches to slot 24, slot 25 is F2 (GP #533).
- Live testnet shadowing (polkajam feed workflow, including side forks and our service's storage and
  preimage paths): results reported to Adam, not recorded here.
- JAM Toaster (`public-30`): genesis decodes under GP v0.8.0, roots match; blocks not yet checked
  (connecting to it as a peer is Adam's call).

## Open items (2026-11-25, end of day)
- **0.8.1 conformance:** waiting for davxy's 0.8.1 fuzzer and vectors. Images: `:v0.8.1` / `:latest`
  (GP v0.8.1, f9acace), `:v0.8.0` (671f256). Announced on jam-fuzzing #221. When the data arrives:
  restore the suspended checks (gaps.md item 7), triage every divergence against GP v0.8.1.
- **Crypto readings (gaps.md item 6):** the target uses the VRF spec's vector reading. Adam asked
  davxy (privately, 2026-11-25) about the ring transcript label, Z_pad and the undefined "push R";
  no answer yet. If the vectors are confirmed as intended, make them jam-lean's default, drop the
  prose path and this assumption. Thin layout O‖R‖s confirmed by davxy on graypaper#593; he is
  adding serialization rules to the spec (davxy/bandersnatch-vrf-spec#30), cited in the next GP.
- **Upstream:** graypaper#592 (N(o) post-state undefined; jam-lean uses the input state) open.
  F7 (bless by a non-manager) public in findings.md; check whether the 0.8.1 fuzzer still expects OK.
- Ancestry gap (gaps.md item 3) for traces without genesis.bin: unchanged decision (reject).
- jam-fuzzing PR #214 (refine wire format reading B): no answer yet.
- Fellowship: Rank II referendum 687 deciding (decision deposit placed 2026-11-25); claim the
  deposit refund afterwards.
- jam-lean: Services proofs paused since c22c197 (proofs CI on demand only); see jam-lean HANDOFF.

## Environment notes
- Release assets of repos not attached to the session are blocked; container registries and git
  clone of public repos work; run node binaries in GitHub Actions instead.
