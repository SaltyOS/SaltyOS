#!/bin/bash
# Cross-compile hello_cpp.cpp for SaltyOS using the sysroot + libc++
# SPDX-License-Identifier: GPL-2.0-only
#
# Usage: bash tests/cross/build_cpp.sh <sysroot-path>
#
# Requires: libc++.so in sysroot (just tc build host runtimes)

set -euo pipefail

SYSROOT="${1:?Usage: build_cpp.sh <sysroot-path>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="${2:-${SCRIPT_DIR}/hello_cpp.elf}"

if [ ! -d "$SYSROOT/usr/lib" ]; then
    echo "Error: sysroot not found at $SYSROOT" >&2
    echo "Run 'just sysroot' first." >&2
    exit 1
fi

if [ ! -d "$SYSROOT/usr/include/c++/v1" ]; then
    echo "Error: C++ headers not found in sysroot." >&2
    echo "Run 'just tc build host runtimes' first." >&2
    exit 1
fi

echo "Cross-compiling hello_cpp.cpp for SaltyOS..."
echo "  Sysroot: $SYSROOT"
echo "  Output:  $OUTPUT"

clang++ \
    --target=x86_64-unknown-saltyos \
    --sysroot="$SYSROOT" \
    -fno-exceptions -fno-rtti \
    "$SCRIPT_DIR/hello_cpp.cpp" \
    -lc++ \
    -o "$OUTPUT"

echo "Success: $OUTPUT"
echo "  Verify with: readelf -d $OUTPUT | grep NEEDED"
echo "  Expected: libc++.so, libc.so, libbesalt.so"
echo "  Add hello_cpp.elf + libc++.so to initrd and boot to verify."
