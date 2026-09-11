#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/dist/elfsec/elfsec.h}
mkdir -p "$(dirname "$out")"

{
    cat "$root/include/elfsec/elfsec.h"
    echo
    echo "#if defined(ELFS_IMPLEMENTATION) && !defined(ELFS_IMPLEMENTATION_DONE)"
    echo "#define ELFS_IMPLEMENTATION_DONE"
    for src in "$root"/src/*.h "$root"/src/*.c; do
        [ -f "$src" ] && grep -v '^#include "' "$src"
    done
    echo "#endif"
} > "$out"
echo "$out"
