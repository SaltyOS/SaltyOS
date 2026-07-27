#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# tools/lint/asm_discipline.sh
#
# Assembly discipline lint for SaltyOS.
#
# Rules:
#   A1. Project-owned, built Rust code must not use inline assembly
#       (`asm!`, `global_asm!`, `naked_asm!`, or `#[unsafe(naked)]`).
#       Assembly must live in explicit `.S` / `.asm` translation units.
#   A2. Assembly sources must be architecture-owned: their path must include
#       `arch/x86_64/`, `arch/aarch64/`, or bootloader `arch/x86/`.
#
# `userland/core/vfs_old*` are archived, non-built trees and are intentionally
# excluded until they are deleted or revived.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

fail=0
red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'

report_fail() {
    local rule="$1"
    local hits="$2"
    printf "${red}asm_discipline: FAIL — %s${reset}\n" "$rule" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    fail=1
}

strip_comments() {
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*[^a-zA-Z_]|#)'
}

INLINE_ASM_REGEX='(::)?core::arch::(asm|global_asm|naked_asm)!|(^|[^A-Za-z0-9_])(asm|global_asm|naked_asm)!|#\[unsafe\(naked\)\]|core::arch::.*\b(asm|global_asm|naked_asm)\b'

inline_hits=$(
    find kernite lib/trona lib/basalt userland -type f -name '*.rs' \
        ! -path 'userland/core/vfs_old/*' \
        ! -path 'userland/core/vfs_old1/*' \
        -print0 \
    | xargs -0 grep -nE "$INLINE_ASM_REGEX" 2>/dev/null \
    | strip_comments || true
)
if [ -n "$inline_hits" ]; then
    report_fail "Rust inline assembly is banned; move instructions to arch-owned .S/.asm" "$inline_hits"
fi

asm_path_hits=$(
    find kernite boot lib userland -type f \( -name '*.S' -o -name '*.asm' \) \
        ! -path 'userland/core/vfs_old/*' \
        ! -path 'userland/core/vfs_old1/*' \
    | grep -vE '(^|/)arch/(x86_64|aarch64|x86)(/|$)' || true
)
if [ -n "$asm_path_hits" ]; then
    report_fail "assembly source outside an architecture-owned path" "$asm_path_hits"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
printf "${green}asm_discipline: PASS${reset}\n"
