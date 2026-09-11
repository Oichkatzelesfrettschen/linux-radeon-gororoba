#!/bin/sh
# SPDX-License-Identifier: MIT
# Compile the actual packet0 function body with a CPU-only boundary fixture.
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] ||
   { [ "$#" -eq 2 ] && [ "$2" != "--self-test" ]; }; then
    echo "usage: $0 external-build-directory [--self-test]" >&2
    exit 2
fi
source_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$1"
build_root=$(CDPATH= cd -- "$1" && pwd)
case "$build_root/" in
    "$source_root/"*) echo "build directory must be outside the source tree" >&2; exit 2 ;;
esac

awk '
    /^int r100_cs_parse_packet0\(/ { copying = 1; starts++ }
    copying { print }
    copying && /^}/ { copying = 0; ends++ }
    END { if (starts != 1 || ends != 1) exit 1 }
' "$source_root/drivers/gpu/drm/radeon/r100.c" > "$build_root/r100_packet0_source.inc"
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Wno-sign-compare -I"$build_root" \
    "$source_root/scripts/calibrate_r100_packet0_bitmap_bounds.c" \
    -o "$build_root/calibrate_r100_packet0_bitmap_bounds"
"$build_root/calibrate_r100_packet0_bitmap_bounds"

if [ "${2:-}" = "--self-test" ]; then
    sed 's/) >= n)/) > n)/' "$build_root/r100_packet0_source.inc" \
        > "$build_root/r100_packet0_source_mutant.inc"
    mv "$build_root/r100_packet0_source.inc" \
        "$build_root/r100_packet0_source_good.inc"
    cp "$build_root/r100_packet0_source_mutant.inc" \
        "$build_root/r100_packet0_source.inc"
    "${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Wno-sign-compare \
        -I"$build_root" \
        "$source_root/scripts/calibrate_r100_packet0_bitmap_bounds.c" \
        -o "$build_root/calibrate_r100_packet0_bitmap_bounds_mutant"
    if "$build_root/calibrate_r100_packet0_bitmap_bounds_mutant" \
        > "$build_root/mutant.stdout" 2> "$build_root/mutant.stderr"; then
        echo "inclusive-bound mutant unexpectedly passed" >&2
        exit 1
    fi
    mv "$build_root/r100_packet0_source_good.inc" \
        "$build_root/r100_packet0_source.inc"
    grep -q 'packet0 source-body bounds: 780 cases, 260 failures' \
        "$build_root/mutant.stdout"
    echo "packet0 inclusive-bound mutant: rejected"
fi
