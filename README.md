# jam-lean-target

The [jam-lean](https://github.com/ascrivener/jam-lean) model of JAM (Gray Paper **v0.8.1**) as a
target of the JAM conformance fuzzer ([jam-fuzzing](https://github.com/jam-conformance/jam-fuzzing),
fuzzer protocol v1). It uses only jam-lean's `PVM`, `JAM` and `JamCrypto` libraries (pinned commit in
`lakefile.lean`), toolchain Lean v4.36.0-rc1, core and Std only.

The target moved from GP v0.8.0 to v0.8.1 on 2026-11-25 (with jam-lean). The last v0.8.0 target
is commit `671f256`; its image is `ghcr.io/ascrivener/jam-lean-target:671f256`.

```
lake build
.lake/build/bin/jam-lean-target serve            # protocol on stdin/stdout
.lake/build/bin/jam-lean-target session DIR      # replay a recorded session (fuzz-proto/examples)
.lake/build/bin/jam-lean-target trace DIR …      # replay fuzz-reports traces step by step
.lake/build/bin/jam-lean-target craft SPEC OUTDIR      # craft valid blocks (JIP-5 dev keys) as a session
.lake/build/bin/jam-lean-target probe KIND INIT OUTDIR  # block-level probes of F4/F6 (vectors/blocks)
python3 scripts/askprobe.py OUTDIR IMAGE…                # send a crafted session to target images
python3 scripts/bridge.py SOCK .lake/build/bin/jam-lean-target serve   # Unix-socket listener
python3 scripts/drive.py DIR --sock SOCK         # drive any target with a recorded session
```

The Docker image (`Dockerfile`) follows the standard target packaging (`JAM_FUZZ*` variables) and
binds the socket with socat, one process per fuzzer session.

## Docker image

Published to `ghcr.io/ascrivener/jam-lean-target` (`latest` and the short commit SHA from `main`,
plus `v*` release tags; linux/amd64). `latest` and the SHA tags from this change on are GP v0.8.1;
`671f256` and earlier SHA tags are GP v0.8.0. The image is built and checked by `.github/workflows/image.yml`. It runs
like any other fuzzer target, as any user, with the socket in the mounted data directory:

```
docker pull ghcr.io/ascrivener/jam-lean-target:latest
docker run --rm --init --user "$(id -u):$(id -g)" -v /tmp/jam_fuzz:/tmp/jam_fuzz \
  -e JAM_FUZZ=1 -e JAM_FUZZ_SPEC=tiny -e JAM_FUZZ_DATA_PATH=/tmp/jam_fuzz \
  -e JAM_FUZZ_SOCK_PATH=/tmp/jam_fuzz/fuzz.sock ghcr.io/ascrivener/jam-lean-target:latest
```

* `docs/gaps.md`: what the model or the protocol cannot do yet.
* `docs/findings.md`: divergences, with GP references and verdicts.
* `docs/shadow.md`: shadow mode (`scripts/shadow.py`), following a chain block by block against the model.

## Rules

Model from GP v0.8.1 only (jam-lean's rules); no `sorry`, `partial def`, `implemented_by`, `native_decide` or
`bv_decide` (`scripts/check-forbidden.sh`); axioms only `propext`, `Classical.choice`,
`Quot.sound`.
