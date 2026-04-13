#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# tools/lint/cap_discipline.sh
#
# Capability discipline lint for SaltyOS.
#
# Enforces the invariants left by the role-based startup capability
# table migration. All rules are HARD — any violation fails the lint.
# Run via `just lint-cap-discipline` (also wired into `just fmt-check`).
#
# Rules:
#   H1. No references to the removed legacy `AT_TRONA_*_EP` /
#       `AT_TRONA_*_NTFN` / `AT_TRONA_*_UNTYPED` / `AT_TRONA_*_IOPORT`
#       / `AT_TRONA_MM_EP` / `AT_TRONA_EXPAND_EP` auxv tag constants.
#   H2. No references to `ROLE_PROCMGR_EXPAND_EP` (bridge role removed
#       once the ws:24 audit confirmed no consumer existed).
#   H3. No direct reads of `__trona_cap_*` weak symbols outside the
#       substrate (where they are defined) and rtld (where they are
#       populated). Everyone else must use the `trona::caps::*()`
#       getters.
#   H4. No literal `const CAP_<WELL_KNOWN>: u64 = N` declarations in
#       userland service code. Well-known cap slots come from the
#       cap_table via `trona::caps::*()` fn getters; service-local
#       caps come from generated `svc_caps::*()` crates.
#   H5. No `fn CAP_*()` shim wrappers in userland runtime code. Call
#       sites should use `trona::caps::*()` / `svc_caps::*()` directly
#       so there is only one naming layer.
#
# Exit 0 on clean, 1 on any violation.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

fail=0
red='\033[0;31m'
green='\033[0;32m'
reset='\033[0m'

report_fail() {
    local rule="$1"
    shift
    printf "${red}cap_discipline: FAIL — %s${reset}\n" "$rule" >&2
    while IFS= read -r line; do
        printf "  %s\n" "$line" >&2
    done
    fail=1
}

# Strip comment-line hits (//, /*, * continuation, #). Hit format is
# `path:lineno:content` from `grep -rEn`.
strip_comments() {
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*[^a-zA-Z_]|#)'
}

# -----------------------------------------------------------------------------
# H1. Legacy `AT_TRONA_*_EP` / `_NTFN` / `_UNTYPED` / `_IOPORT` tag references.
# -----------------------------------------------------------------------------
H1_REGEX='AT_TRONA_(PROCMGR_EP|VFS_EP|NAMESRV_EP|SIGNAL_NTFN|RSRCSRV_EP|CONSOLE_EP|READINESS_NTFN|INITRD_UNTYPED|FB_UNTYPED|PCI_IOPORT|COM1_IOPORT|SERVICE_EP|MM_EP|EXPAND_EP)'
h1_hits=$(grep -rEn "$H1_REGEX" \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ lib/trona/ lib/basalt/ kernite/ 2>/dev/null \
    | strip_comments || true)
if [ -n "$h1_hits" ]; then
    printf '%s\n' "$h1_hits" | report_fail "legacy AT_TRONA_*_EP / _NTFN / _UNTYPED / _IOPORT tag reference"
fi

# -----------------------------------------------------------------------------
# H2. Removed `ROLE_PROCMGR_EXPAND_EP` bridge role.
# -----------------------------------------------------------------------------
h2_hits=$(grep -rEn 'ROLE_PROCMGR_EXPAND_EP' \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ lib/trona/ lib/basalt/ kernite/ 2>/dev/null \
    | strip_comments || true)
if [ -n "$h2_hits" ]; then
    printf '%s\n' "$h2_hits" | report_fail "removed ROLE_PROCMGR_EXPAND_EP bridge role reference"
fi

# -----------------------------------------------------------------------------
# H3. Raw `__trona_cap_*` weak symbol access outside substrate/rtld.
#
# The substrate defines the symbols and exposes them via
# `trona::caps::*()`. The rtld populates them from the cap_table. Any
# other consumer must read caps via the public getters.
# -----------------------------------------------------------------------------
H3_REGEX='__trona_cap_[a-z_]+'
h3_hits=$(grep -rEn "$H3_REGEX" \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ lib/basalt/ 2>/dev/null \
    | strip_comments || true)
if [ -n "$h3_hits" ]; then
    printf '%s\n' "$h3_hits" | report_fail "raw __trona_cap_* weak symbol access outside substrate/rtld"
fi

# -----------------------------------------------------------------------------
# H4. Literal `const CAP_<WELL_KNOWN>: u64 = N` in userland.
#
# Well-known names (the same ones exposed via `trona::caps::*`) must be
# fn getters that delegate to the substrate. File-local constants for
# runtime-allocated slots (e.g. notification slots, reply scratch) use
# different suffixes and are not matched by this rule.
# -----------------------------------------------------------------------------
H4_REGEX='^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?const[[:space:]]+CAP_(PROCMGR_EP|VFS_EP|NAMESRV_EP|SIGNAL_NTFN|MMSRV_EP|RSRCSRV_EP|CONSOLE_EP|READINESS_NTFN|INITRD_UNTYPED|FB_UNTYPED|PCI_IOPORT|COM1_IOPORT|SERVICE_EP|WIN32SRV_EP|MMSRV_EP_UNBADGED|RSRCSRV_EP_UNBADGED)[[:space:]]*:'
h4_hits=$(grep -rEn "$H4_REGEX" \
    --include='*.rs' \
    userland/ 2>/dev/null || true)
if [ -n "$h4_hits" ]; then
    printf '%s\n' "$h4_hits" | report_fail "literal const CAP_<well-known>: u64 = N — migrate to fn getter using trona::caps::*()"
fi

# -----------------------------------------------------------------------------
# H5. No `fn CAP_*()` wrapper shims in userland runtime code.
# -----------------------------------------------------------------------------
H5_REGEX='^[[:space:]]*(pub(\([a-z]+\))?[[:space:]]+)?fn[[:space:]]+CAP_[A-Z_]+[[:space:]]*\('
h5_hits=$(grep -rEn "$H5_REGEX" \
    --include='*.rs' \
    userland/core/procmgr/ \
    userland/core/vfs/ \
    userland/servers/ \
    userland/drivers/ \
    userland/core/mmsrv/ \
    userland/core/namesrv/ \
    userland/core/rsrcsrv/ 2>/dev/null || true)
if [ -n "$h5_hits" ]; then
    printf '%s\n' "$h5_hits" | report_fail "fn CAP_* shim wrapper in userland runtime code — call trona::caps::*() / svc_caps::*() directly"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
printf "${green}cap_discipline: PASS${reset}\n"
