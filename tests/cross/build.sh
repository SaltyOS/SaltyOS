#!/bin/bash
# Cross-compile hello.c for SaltyOS using the sysroot
# SPDX-License-Identifier: GPL-2.0-only
#
# Usage: bash tests/cross/build.sh <sysroot-path>

set -euo pipefail

SYSROOT="${1:?Usage: build.sh <sysroot-path>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT="${2:-${SCRIPT_DIR}/hello.elf}"

if [ ! -d "$SYSROOT/usr/lib" ]; then
    echo "Error: sysroot not found at $SYSROOT" >&2
    echo "Run 'just sysroot' first." >&2
    exit 1
fi

echo "Cross-compiling hello.c for SaltyOS..."
echo "  Sysroot: $SYSROOT"
echo "  Output:  $OUTPUT"

clang \
    --target=x86_64-unknown-saltyos \
    --sysroot="$SYSROOT" \
    "$SCRIPT_DIR/hello.c" \
    -o "$OUTPUT"

echo "Success: $OUTPUT"
echo "  Add to initrd and boot to verify."
