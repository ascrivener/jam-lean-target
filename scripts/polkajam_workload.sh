#!/usr/bin/env bash
# A workload for a running PolkaJam testnet (used by .github/workflows/polkajam-feed.yml).
#   polkajam_workload.sh JAMT RPC ITEMS [SERVICE_BLOB]
# Submits ITEMS work items to the Bootstrap service (0) and one transfer, so blocks carry
# guarantees, assurances and accumulation. With SERVICE_BLOB (tools/service/build.py), it first
# creates that service, transfers 1000 to it, then sends each work item to it as well, and
# after each one records what the chain holds for it (storage keys n, k0..k3; each preimage
# request and preimage), so the log shows which state paths ran.
set -u
JAMT=$1; RPC=$2; ITEMS=$3; BLOB=${4:-}
j() { timeout 120 "$JAMT" --rpc "$RPC" "$@" 2>&1; }
SVC=
if [ -n "$BLOB" ]; then
  echo "== create-service $BLOB"
  out=$(timeout 300 "$JAMT" --rpc "$RPC" create-service --raw "$BLOB" 10000000000 2>&1)
  echo "$out"
  SVC=$(echo "$out" | tail -1 | tr -d '[:space:]')
  case "$SVC" in ''|*[!0-9a-fA-Fx]*) echo "no service id"; SVC= ;; esac
  # The preimages the service solicits and provides: "preimage <hash> <text>" from build.py.
  PREIMAGES=$(python3 "$(dirname "$0")/../tools/service/build.py" /dev/null | grep '^preimage ')
  if [ -n "$SVC" ]; then echo "== transfer 1000 to service $SVC"; j transfer "$SVC" 1000 || echo "exit $?"; fi
fi
for i in $(seq 1 "$ITEMS"); do
  echo "== item $i (bootstrap)"; j item 0 "shadow-$i" || echo "exit $?"
  [ "$i" = 2 ] && { echo "== transfer"; j transfer 0 1 || echo "exit $?"; }
  if [ -n "$SVC" ]; then
    echo "== item $i (service $SVC)"; j item "$SVC" "probe-$i" || echo "exit $?"
    sleep 6
    echo "-- slot $(j inspect slot)"
    for k in n k0 k1 k2 k3; do echo "-- storage $k: $(j inspect storage --raw "$SVC" "$k" | head -c 200)"; done
    while read -r _ h text; do
      echo "-- request ${h:0:8}: $(j inspect request "$SVC" "$text" | head -c 300)"
      echo "-- preimage ${h:0:8}: $(j inspect preimage "$SVC" "$h" | head -c 300)"
    done <<< "$PREIMAGES"
  fi
  sleep 6
done
echo "== workload done"
