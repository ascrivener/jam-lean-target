#!/bin/sh
# Regenerate vectors/gp081-extra (block-level probes and PVM vectors, GP v0.8.1, jam-lean's results).
#   scripts/gp081-extra.sh [OUT]   (default vectors/gp081-extra; needs vendor/jam-fuzzing, see CI)
set -e
OUT=${1:-vectors/gp081-extra}
BIN=.lake/build/bin/jam-lean-target
INIT=vendor/jam-fuzzing/fuzz-proto/examples/0.8.0/no_forks/00000001_fuzzer_initialize.bin
TMP=$(mktemp -d)
for p in f4:f4_fallthrough_last f4b:f4_branch_last f6:f6_jump_table_z0; do
  k=${p%%:*}; d=${p#*:}
  $BIN probe $k $INIT $TMP/$k > /dev/null
  rm -rf $OUT/blocks/$d && mkdir -p $OUT/blocks/$d && cp $TMP/$k/trace/* $OUT/blocks/$d/
done
rm -rf $OUT/pvm && python3 tools/gp081-extra/gen_pvm.py $OUT/pvm
rm -rf $TMP
