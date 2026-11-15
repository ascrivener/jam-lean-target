#!/bin/sh
# Standard target entry point: bind JAM_FUZZ_SOCK_PATH and run one `jam-lean-target serve`
# process per fuzzer connection (fresh session state for each, as the protocol requires).
set -eu
if [ -z "${JAM_FUZZ:-}" ]; then
  echo "jam-lean-target has only a fuzz mode; set JAM_FUZZ" >&2; exit 1
fi
for v in JAM_FUZZ_SPEC JAM_FUZZ_DATA_PATH JAM_FUZZ_SOCK_PATH; do
  eval "val=\${$v:-}"
  if [ -z "$val" ]; then echo "missing $v" >&2; exit 1; fi
done
mkdir -p "$JAM_FUZZ_DATA_PATH" "$(dirname "$JAM_FUZZ_SOCK_PATH")"
rm -f "$JAM_FUZZ_SOCK_PATH"
exec socat UNIX-LISTEN:"$JAM_FUZZ_SOCK_PATH",fork EXEC:"/usr/local/bin/jam-lean-target serve"
