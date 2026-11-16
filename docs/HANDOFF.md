# Handoff: state of jam-lean-target (2026-11-16)

For a fresh parent session. Read this, README.md and the other docs/*.md first.

## What this project is
The jam-lean Lean 4 model of JAM (Gray Paper **v0.8.0 as released**, tag v0.8.0, 2026-06-03) as a
target of the JAM conformance fuzzer (jam-conformance/jam-fuzzing, protocol v1), plus our own
generators and vectors. jam-lean (ascrivener/jam-lean) is read-only for us; another parent session
(session_01FAPLsbixBk5ZtxHTAoNtdU) owns it. This parent: session_01FAPLsdKXq86WuSpB5fCYVg.

## Adam's standing decisions
- Model strictly GP v0.8.0. Divergences caused by later GP changes are logged as "the process
  follows GP #N" (docs/gp-after-0.8.0.md lists them), not as bugs. Triage every divergence there first.
- Ed25519 acceptance: ZIP-215 (2026-11-15).
- All crypto in plain Lean (JamCrypto); crypto in jam-lean stays a parameter, the target supplies it.
- Ring domain sized by the chain's V (vectors show it; GP silent).
- F4–F6 (PolkaVM vs GP) stay public. Otherwise disclosure / outward-facing actions are Adam's call:
  no issues or posts on external repos without him. Children may be started for self-contained work.
- Lean rules: core+Std only, no sorry / partial def / implemented_by / native_decide / bv_decide /
  FFI, standard axioms only (scripts/check-forbidden.sh). Import only jam-lean's PVM and JAM.
- Git: PRs against main, squash-merge on green; never push to main.
- Keep the model an executable Gray Paper, not a node (no networking/authoring in Lean).

## Where things are
- Target: Main.lean (`serve`, `session DIR`, `trace DIR…`), JamTarget/ (wire codec, state decode,
  session). Docker image (Dockerfile, scripts/entrypoint.sh, socat). jam-lean pin in lakefile.lean
  (208cc20: fast paths for Ψ_H, grow_heap, Blake2b).
- Crypto: JamCrypto/ (Ed25519, Bandersnatch IETF VRF, ring root, Ring VRF; signing in PR #13).
- PVM harness: pvmrun, tools/pvm-ref (PolkaVM 0.38.1), scripts/pvmdiff.py, docs/pvm-diff.md;
  vectors/pvm (1,408 GP v0.8.0 vectors, checked in CI).
- Scripts: bridge.py (socket ↔ serve), drive.py (replay a session against any target),
  askimpls.py (send a trace step to Docker images of other teams), diffstate.py.
- Findings: docs/findings.md (F0–F6). Gaps: docs/gaps.md. GP changes after v0.8.0:
  docs/gp-after-0.8.0.md. Crypto notes: docs/crypto-notes.md.

## Results so far
- 0.8.0 example sessions: forks 97/97 as polkajam (29 s); no_forks matches to slot 24, slot 25 is
  GP #533. Published 0.8.0 traces: 93/232 steps (rest: storage-key gap, missing ancestry, F3).
- F0, F1: jam-lean model bugs, fixed in jam-lean (#196, #195), pinned.
- F2, F3: the fuzzer/implementations follow GP #533 / #563 (post-0.8.0); not bugs. Adam posted
  jam-fuzzing#220 asking releases to pin a GP commit.
- F4–F6: PolkaVM vs GP v0.8.0. F4 reported by Adam as paritytech/polkavm#455; F5 = polkavm#429;
  F6 ~ polkavm#447. Block-level results per implementation: not published
  (Adam, 2026-11-16: don't disclose).
- Speed: jam-lean #201/#204 (profile from here) made a 693 s session run in 16 s.

## In flight
- Child "block crafter" (session_01FAPLsdan7X8ei7dbkrbKEw, branch claude/block-crafter): Lean
  signing (PR #13, merged), crafter exe emitting fuzzer messages, F4/F6 block-level probes against the
  five 0.8.0 images (jamduna, javajam, jamforge, lasair, pyjamaz), block vectors under vectors/blocks.
- Child "shadow" (session_01FAPLsZj552eofYwzgtSy1b, branch claude/shadow): driver that checks a
  node's blocks against the model; feed = a manual GitHub Actions workflow that downloads polkajam
  from polkajam-releases (this sandbox can't download GitHub release assets or run node binaries),
  runs polkajam-testnet and uploads blocks+roots as an artifact.
- Child "refine" (session_01FAPLsatdp1wPizxANsrjPM, branch claude/refine): fuzzer RefineBundle →
  WorkReport via jam-lean's Ξ; first reports the erasure-coding convention question (GP #580).
- jam-lean: storage-key re-keying (stage 1 = jam-lean #200, stage 2 later) will let the target load
  mid-chain states and replay all 89 traces.
- Forum post (Adam's, for the Fellowship Rank II application): Claude Doc "Checking JAM against an
  executable Gray Paper" — ready, not posted. Rank II evidence draft: Claude Doc "Fellowship Rank II
  evidence (draft)".

## Environment notes
- github.com release pages/assets are blocked for repos not attached to the session; git clone of
  public repos works; container registries work; start `dockerd` for Docker.
- polkajam-fuzz is not available here (Parity release assets); use recorded sessions/traces or CI.
