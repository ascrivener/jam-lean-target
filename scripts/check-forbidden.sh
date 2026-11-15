#!/bin/sh
# The Lean of this repository may not use sorry, partial def, implemented_by, native_decide or
# bv_decide (see README, "Rules").
if grep -rnE '\b(sorry|partial def|implemented_by|native_decide|bv_decide)\b' --include='*.lean' --exclude-dir=.lake . ; then
  echo "forbidden construct found" >&2; exit 1
fi
echo "no forbidden constructs"
