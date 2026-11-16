# jam-lean-target

The [jam-lean](https://github.com/ascrivener/jam-lean) model of JAM (Gray Paper v0.8.0) as a
target of the JAM conformance fuzzer ([jam-fuzzing](https://github.com/jam-conformance/jam-fuzzing),
fuzzer protocol v1). It uses only jam-lean's `PVM` and `JAM` libraries (pinned commit in
`lakefile.lean`), toolchain Lean v4.36.0-rc1, core and Std only.

```
lake build
.lake/build/bin/jam-lean-target serve            # protocol on stdin/stdout
.lake/build/bin/jam-lean-target session DIR      # replay a recorded session (fuzz-proto/examples)
.lake/build/bin/jam-lean-target trace DIR …      # replay fuzz-reports traces step by step
.lake/build/bin/jam-lean-target craft SPEC OUTDIR      # craft valid blocks (JIP-5 dev keys) as a session
python3 scripts/bridge.py SOCK .lake/build/bin/jam-lean-target serve   # Unix-socket listener
python3 scripts/drive.py DIR --sock SOCK         # drive any target with a recorded session
```

The Docker image (`Dockerfile`) follows the standard target packaging (`JAM_FUZZ*` variables) and
binds the socket with socat, one process per fuzzer session.

* `docs/gaps.md`: what the model or the protocol cannot do yet.
* `docs/findings.md`: divergences, with GP references and verdicts.

## Rules

Model from GP v0.8.0 only; no `sorry`, `partial def`, `implemented_by`, `native_decide` or
`bv_decide` (`scripts/check-forbidden.sh`); axioms only `propext`, `Classical.choice`,
`Quot.sound`.
