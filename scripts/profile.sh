#!/bin/sh
# Time the target per message and per component (docs/profiling.md).
#   scripts/profile.sh [REPS]        (needs vendor/jam-fuzzing, as CI checks it out)
#   PERF=1 scripts/profile.sh        also record a perf profile of the harness and summarise it
set -e
REPS=${1:-3}
INIT=vendor/jam-fuzzing/fuzz-proto/examples/0.8.0/no_forks/00000001_fuzzer_initialize.bin
[ -f "$INIT" ] || { echo "missing $INIT (git clone https://github.com/jam-conformance/jam-fuzzing vendor/jam-fuzzing)" >&2; exit 1; }
lake build jam-lean-target profile > /dev/null
BIN=.lake/build/bin/jam-lean-target
TMP=$(mktemp -d)
# Sessions: crafted blocks (plain, assurances, an epoch change with the ring root) and the probes
# (5 assurances making a report available; it accumulates: PVM), plus the refine vectors.
$BIN craft tests/craft/epoch.txt $TMP/craft_epoch > /dev/null
for k in control oog; do $BIN probe $k $INIT $TMP/probe_$k > /dev/null; done
# Process start to the PeerInfo reply, as the fuzzer sees it (socat starts one process per connection)
python3 - "$BIN" "$TMP/craft_epoch/00000000_fuzzer_peer_info.bin" <<'PY'
import subprocess, struct, sys, time
msg = open(sys.argv[2], 'rb').read(); t0 = time.monotonic()
p = subprocess.Popen([sys.argv[1], "serve"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
p.stdin.write(struct.pack("<I", len(msg)) + msg); p.stdin.flush()
n = struct.unpack("<I", p.stdout.read(4))[0]; p.stdout.read(n)
print(f"process start -> PeerInfo reply: {time.monotonic() - t0:.2f} s"); p.stdin.close(); p.wait()
PY
.lake/build/bin/profile -n "$REPS" --prims
.lake/build/bin/profile -n "$REPS" $TMP/craft_epoch $TMP/probe_control $TMP/probe_oog vectors/refine/0.8.1-tiny
if [ -n "${PERF:-}" ]; then
  # -D: skip Lean module initialisation (see docs/profiling.md, "Startup")
  perf record -F 999 -D 16000 --call-graph dwarf,32768 -o $TMP/perf.data \
    .lake/build/bin/profile -n "$REPS" $TMP/craft_epoch $TMP/probe_control > /dev/null 2>&1
  perf script -i $TMP/perf.data --no-inline 2>/dev/null | python3 scripts/perfcat.py 40
fi
rm -rf $TMP
