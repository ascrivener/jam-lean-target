# Handoff: state of jam-lean-target (2026-11-25)

Read this, README.md and the other docs/*.md first.

## What this project is
The jam-lean Lean 4 model of JAM (Gray Paper **v0.8.0 as released**, tag v0.8.0, 2026-06-03) as a
target of the JAM conformance fuzzer (jam-conformance/jam-fuzzing, protocol v1), plus our own
generators, vectors and a shadow driver that checks a live node's chain against the model.

**Ownership (Adam, 2026-11-25):** session_01FAPLsdKXq86WuSpB5fCYVg is the single canonical parent
for jam-lean, jam-lean-target and jam (Jamzilla). The former jam-lean parent
(session_01FAPLsbixBk5ZtxHTAoNtdU) is archived. Within jam-lean, follow its own CLAUDE.md
(at most 3 parallel sessions, its standing decisions and CI rules).

## Adam's standing decisions
- Model strictly GP v0.8.0. Divergences caused by later GP changes are logged as "the process
  follows GP #N" (docs/gp-after-0.8.0.md lists them), not as bugs. Triage every divergence there first.
- Ed25519 acceptance: ZIP-215 (2026-11-15).
- All crypto in plain Lean (JamCrypto); crypto in jam-lean stays a parameter, the target supplies it.
- Ring domain sized by the chain's V (vectors show it; GP silent).
- Refine: erasure root by GP v0.8.0 §H.3 (not GP #580); a package that exports nothing gets Error
  (undefined in v0.8.0, see GP #583); the bundle is read as the GP bundle encoding B (assumption,
  asked on jam-fuzzing PR #214, no answer yet).
- Ancestry (2026-11-25): keep rejecting lookup anchors that are only in the `Initialize` ancestry
  (slot, hash): accepting them would skip GP v0.8.0's state-root check. The only paper-exact fix is
  the fuzzer sending full headers (possible later ask on jam-fuzzing #221, Adam's call).
- Disclosure: F4–F6 stay public. Never publish per-implementation results (which node agrees or
  differs) in repos; report them to Adam. Outward-facing actions (issues, posts, contacting people,
  settings) are Adam's call.
- Lean rules: core+Std only, no sorry / partial def / implemented_by / native_decide / bv_decide /
  FFI, standard axioms only (scripts/check-forbidden.sh). The target imports only jam-lean's PVM and JAM.
- Git: PRs against main, squash-merge on green; never push to main.
- Keep the model an executable Gray Paper, not a node (no networking/authoring in Lean; networking
  tooling lives in Python scripts and CI).

## Where things are
- Target: Main.lean (`serve`, `session`, `trace`, `craft`, `probe`), JamTarget/ (wire codec, state
  decode, session, Refine). jam-lean pin in lakefile.lean.
- Docker image: published by .github/workflows/image.yml to **ghcr.io/ascrivener/jam-lean-target**
  (`latest` + short SHA on main, `v*` tags), public. The workflow runs the image the way jam-fuzzing's
  target.py does and replays the forks session (97/97) and vectors/refine (24/24) before pushing.
- Crypto: JamCrypto/ (Ed25519, Bandersnatch IETF VRF, ring root, Ring VRF, signing, JIP-5 dev keys).
- PVM harness: pvmrun, tools/pvm-ref (PolkaVM 0.38.1), vectors/pvm (1,408 vectors).
- Block crafter and probes: vectors/blocks; refine vectors: vectors/refine.
- Shadow: scripts/shadow.py and docs/shadow.md; polkajam feed workflow (.github/workflows/polkajam-feed.yml)
  runs polkajam v0.8.0's testnet on Actions, fetches blocks over JAM-NP (scripts/jamnp_*.py),
  optional jamt workload with our service (tools/service).
- Findings: docs/findings.md (F0–F6). Gaps: docs/gaps.md. GP changes after v0.8.0: docs/gp-after-0.8.0.md.

## Results so far (results per implementation are kept out of the repo)
- 0.8.0 example sessions: forks 97/97; no_forks matches to slot 24, slot 25 is F2 (GP #533).
- Live testnet shadowing (polkajam feed workflow, including side forks and our service's storage and
  preimage paths): results reported to Adam, not recorded here.
- JAM Toaster (`public-30`): genesis decodes under GP v0.8.0, roots match; blocks not yet checked
  (connecting to it as a peer is Adam's call).

## Open items
- **jam-lean storage-key stage 2** (jam-lean docs/storage-key-design.md; stage 1 = jam-lean #200):
  blocks loading `Initialize` states with storage (52 of 89 published traces). Main item for
  davxy's fuzzing. After it lands: bump the pin, replay all traces, update gaps.md.
- jam-lean (from its archived parent): add `proofs` to main's required checks (Adam, settings);
  pick the next proof step (T2 option B; check whether step 10, the vendored-blob check, was done by
  the Witness session's child on 2026-11-20).
- jam-fuzzing #221 (Adam's issue, integration of this target) and PR #214 (refine wire format): watch
  for replies Adam relays.
- Fellowship (handled by the "Rank 2 application follow-up" session): Evaluations PR #367 approved
  by davxy; referendum on track 32 pending.

## Environment notes
- Release assets of repos not attached to the session are blocked; container registries and git
  clone of public repos work; run node binaries in GitHub Actions instead.
