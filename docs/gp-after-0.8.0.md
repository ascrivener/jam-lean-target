# Gray Paper changes after v0.8.0

The model follows GP v0.8.0 as released (2026-06-03, tag `v0.8.0`, commit 07f041d); Adam's
decision. The fuzzer (polkajam-fuzz 0.1.29, "GP 0.8.0") and the 0.8.0 implementations follow
v0.8.0 plus *some* later GP changes. A divergence is first checked against this list: if a change
here explains it, it is logged as "the process follows GP #N", not as a bug.

"Seen" says what the fuzzing evidence shows about the process; blank means not yet observed either
way. "Effect" is from the PR title and diff where checked, otherwise from the title only (marked †).

| GP PR | Merged | Change | Effect on consensus | Seen |
| --- | --- | --- | --- | --- |
| #533 | 2026-07-22 | Various host-function fixes (incl. `grow_heap` out-of-gas charges all gas) | accumulation gas, stats | **followed** (F2) |
| #538 | 2026-07-22 | `grow_heap` upper boundary | PVM host call † | |
| #537 | 2026-07-22 | Work-report field order in prose/tuple | none (notation) † | |
| #541 | 2026-08-10 | Cite ZIP 215 for Ed25519 | clarifies v0.8.0 (matches Adam's ZIP-215 decision) | consistent |
| #543 | 2026-08-10 | Null validator key for Ed25519 | disputes/offenders † | |
| #545 | 2026-08-10 | `forget` dropping a preimage | accumulation † | |
| #539 | 2026-08-10 | Junior services | new protocol feature † | |
| #530 | 2026-08-19 | Hostcall for inner PVM module compilation | refine host calls † | |
| #542 | 2026-08-19 | Preimage request lengths below state-key discriminators | validity † | |
| #550 | 2026-08-24 | Bandersnatch: new VRF spec (Draft 35), Thin VRF; also changes the ring VRF and ring root | seals, tickets, entropy, γ_Z | **not followed**: fuzzer blocks verify under ark-vrf 0.1.0 IETF VRF. Implemented behind `--gp 0.8.1` (PRs #30, #31; docs/crypto-notes.md) |
| #554 | 2026-08-26 | Mask the third register of three-register instructions | PVM semantics † | |
| #559 | 2026-10-21 | Code blob and jump-table size limits; cmov gas | PVM † | |
| #560 | 2026-10-31 | Header extrinsic-hash credential encoding | header validity † | |
| #557 | 2026-11-02 | MaxAuthCodeSize 192 KiB | constant † | |
| #563 | 2026-11-02 | Bound work-report values by work-package limits (eq. `reportrefineload`) | guarantee validity | **followed** (F3) |
| #564 | 2026-11-02 | Validator statistics with variable-length naturals | state root (π) | **not followed**: model's ℰ_4 π matches polkajam's roots |
| #565 | 2026-11-02 | Type slips in accumulation dependencies, validator statistics | † | |
| #566 | 2026-11-02 | Remove "dictionary subscript implies key exists" | † | |
| #568 | 2026-11-02 | Report Refine errors before oversize/bad-exports checks | refine † | |
| #571 | 2026-11-02 | `bless` dictionary decoding | accumulation † | |
| #562 | 2026-11-02 | Remove parent hash from assurances extrinsic | block encoding † | |
| #574 | 2026-11-02 | Assurances constraint | validity † | |
| #567 | 2026-11-06 | Limit preimages count and size per block | validity † | |
| #575 | 2026-11-09 | Reorder extrinsic tuple | encoding † | |
| #558 | 2026-11-10 | Non-manager privilege holders hand over roles via `bless` | accumulation | followed by the vectors (jam-lean `knownDeviations`) |
| #583 | 2026-11-10 | Erasure root when a package exports nothing | † | |
| #581 | 2026-11-11 | Storage footprint bounds in `write`, `solicit` | accumulation † | |
| #582 | 2026-11-12 | Code-size limits on full blobs; metadata in Ψ_M | PVM invocation † | |
| #580 | 2026-11-12 | Erasure coding generator polynomial | availability † | |
| #588 | 2026-11-12 | Clear the gas-charged flag when Ψ halts or panics | PVM gas † | |

Not listed: #534, #536, #540 (auditing, typos and examples, no on-chain effect).
