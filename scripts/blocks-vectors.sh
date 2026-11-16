#!/bin/sh
# Regenerate vectors/blocks (the crafted block-level vectors) from the fuzzer's 0.8.0 genesis.
#   scripts/blocks-vectors.sh [OUT]   (default vectors/blocks; needs vendor/jam-fuzzing, see CI)
set -e
OUT=${1:-vectors/blocks}
BIN=.lake/build/bin/jam-lean-target
INIT=vendor/jam-fuzzing/fuzz-proto/examples/0.8.0/no_forks/00000001_fuzzer_initialize.bin
TMP=$(mktemp -d)
for k in control panic oog f4 f6; do
  $BIN probe $k $INIT $TMP/$k > /dev/null
  rm -rf $OUT/probe_$k && mkdir -p $OUT/probe_$k && cp $TMP/$k/trace/* $OUT/probe_$k/
done
$BIN craft tests/craft/epoch.txt $TMP/epoch > /dev/null
rm -rf $OUT/craft_epoch && mkdir -p $OUT/craft_epoch && cp $TMP/epoch/trace/* $OUT/craft_epoch/
rm -rf $TMP
