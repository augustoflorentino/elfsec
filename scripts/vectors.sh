#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

out=$(cd "$(dirname "$0")/.." && pwd)/tests/vectors
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
printf 'int f(int x) { return x + 1; }\n' > "$src/f.c"
so() { "$@" -O2 -shared -nostdlib -fPIC -s "$src/f.c"; }
so gcc -fcf-protection=full -o "$out/x86_64-cet.so"
so gcc -fcf-protection=none -o "$out/x86_64-nocet.so"
so gcc -m32 -fcf-protection=full -o "$out/i386-cet.so"
so gcc -fcf-protection=branch -o "$out/x86_64-ibt.so"
so zig cc -target aarch64-linux-musl -mbranch-protection=standard -o "$out/aarch64-bti-pac.so"
so zig cc -target aarch64-linux-musl -mbranch-protection=bti -o "$out/aarch64-bti.so"
so zig cc -target aarch64-linux-musl -mbranch-protection=none -o "$out/aarch64-none.so"
{ gcc --version | head -1; zig version; } > "$out/VERSIONS"
