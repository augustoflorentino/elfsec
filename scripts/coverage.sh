#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/build/coverage}
mkdir -p "$out"
clang -std=c99 -O0 -fprofile-instr-generate -fcoverage-mapping -I"$root/include" -I"$root/tests" \
    "$root"/src/*.c "$root/tests/test_elfsec.c" -o "$out/test_elfsec"
LLVM_PROFILE_FILE="$out/test.profraw" "$out/test_elfsec"
llvm-profdata merge -o "$out/test.profdata" "$out/test.profraw"
llvm-cov report "$out/test_elfsec" -instr-profile="$out/test.profdata" "$root"/src/*.c
