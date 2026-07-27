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
#   H1. No references to removed legacy startup auxv tag constants.
#   H2. No references to `ROLE_PROCMGR_EXPAND_EP` (bridge role removed
#       once the ws:24 audit confirmed no consumer existed).
#   H3. No direct reads of `__trona_cap_*` weak symbols outside the
#       substrate (where they are defined) and rtld (where they are
#       populated). Everyone else must use the `trona::caps::*()`
#       getters.
#   H4. No literal `const CAP_<WELL_KNOWN>: u64 = N` declarations in
#       userland service code. Well-known cap slots come from the
#       cap_table via `trona::caps::*()` fn getters; service-local caps
#       come from `trona::caps::local_by_name` / `trona::local_cap!`.
#   H5. No `fn CAP_*()` shim wrappers in userland runtime code. Call
#       sites should use `trona::caps::*()` / `trona::local_cap!`
#       directly so there is only one naming layer.
#   H6. No `CAP_UNTYPED_START` references in userland outside the two
#       spawners (`core/init/` and `core/procmgr/`) that legitimately
#       maintain their own file-local constant. Everyone else must go
#       through `trona::runtime_get_bootstrap_untyped()` or
#       `SpawnConfig::for_runtime_bootstrap_untyped()` — the constant is
#       a spawner-side convention and not a child-side slot number.
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
    # NOTE: hits are passed as the second argument, not piped in. A
    # historical version used `printf '%s\n' "$hits" | report_fail ...`
    # which invoked `report_fail` inside a subshell (right side of a
    # pipe), so the `fail=1` assignment below never reached the parent
    # shell and the final `PASS` line printed even when violations
    # were reported. Keep hits as an argument to preserve the
    # assignment in the outer scope.
    local rule="$1"
    local hits="$2"
    printf "${red}cap_discipline: FAIL — %s${reset}\n" "$rule" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    fail=1
}

# Strip comment-line hits (//, /*, * continuation, #). Hit format is
# `path:lineno:content` from `grep -rEn`.
strip_comments() {
    grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*[^a-zA-Z_]|#)'
}

# -----------------------------------------------------------------------------
# H1. Legacy startup auxv tag references.
#
# Matches the 14 named auxv tags that the role-based cap-table migration
# retired (`AT_TRONA_{PROCMGR_EP, VFS_EP, NAMESRV_EP, SIGNAL_NTFN,
# RSRCSRV_EP, CONSOLE_EP, READINESS_NTFN, INITRD_UNTYPED, FB_UNTYPED,
# PCI_IOPORT, COM1_IOPORT, SERVICE_EP, MM_EP, EXPAND_EP}`). The single
# surviving tag `AT_SALTYOS_STARTUP` is the replacement pointer into
# `SaltyOSStartupLayoutV1` and is deliberately NOT matched — an earlier
# regex `AT_TRONA_[A-Z0-9_]+` was too greedy and caught the new tag
# along with the legacy ones.
# -----------------------------------------------------------------------------
H1_REGEX='AT_TRONA_(PROCMGR_EP|VFS_EP|NAMESRV_EP|SIGNAL_NTFN|RSRCSRV_EP|CONSOLE_EP|READINESS_NTFN|INITRD_UNTYPED|FB_UNTYPED|PCI_IOPORT|COM1_IOPORT|SERVICE_EP|MM_EP|EXPAND_EP)\b'
h1_hits=$(grep -rEn "$H1_REGEX" \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ lib/trona/ lib/basalt/ kernite/ 2>/dev/null \
    | strip_comments || true)
if [ -n "$h1_hits" ]; then
    report_fail "legacy startup auxv tag reference" "$h1_hits"
fi

# -----------------------------------------------------------------------------
# H2. Removed `ROLE_PROCMGR_EXPAND_EP` bridge role.
# -----------------------------------------------------------------------------
h2_hits=$(grep -rEn 'ROLE_PROCMGR_EXPAND_EP' \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ lib/trona/ lib/basalt/ kernite/ 2>/dev/null \
    | strip_comments || true)
if [ -n "$h2_hits" ]; then
    report_fail "removed ROLE_PROCMGR_EXPAND_EP bridge role reference" "$h2_hits"
fi

# -----------------------------------------------------------------------------
# H3. Raw `__trona_cap_*` weak symbol access outside substrate/rtld.
#
# The substrate defines the symbols and exposes them via
# `trona::caps::*()`. The rtld populates them from the cap_table at
# process startup. A third authorized mutator is procmgr, which
# re-publishes well-known provider caps when services re-register at
# runtime (`publish_well_known_provider` in
# `userland/core/procmgr/src/service/registry.rs`) — procmgr is the
# spawner-side counterpart of rtld's startup-time populate path and
# shares the same architectural invariant (the entity that builds the
# cap table is the one allowed to mutate it). Every other consumer
# reads caps via the public getters.
# -----------------------------------------------------------------------------
H3_REGEX='__trona_cap_[a-z_]+'
h3_hits=$(grep -rEn "$H3_REGEX" \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ lib/basalt/ 2>/dev/null \
    | grep -vE '^userland/core/procmgr/' \
    | strip_comments || true)
if [ -n "$h3_hits" ]; then
    report_fail "raw __trona_cap_* weak symbol access outside substrate/rtld/procmgr" "$h3_hits"
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
    report_fail "literal const CAP_<well-known>: u64 = N — migrate to fn getter using trona::caps::*()" "$h4_hits"
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
    report_fail "fn CAP_* shim wrapper in userland runtime code — call trona::caps::*() / trona::local_cap!() directly" "$h5_hits"
fi

# -----------------------------------------------------------------------------
# H6. `CAP_UNTYPED_START` in userland outside the two spawner crates.
#
# init (`userland/core/init/`) and procmgr (`userland/core/procmgr/`) keep
# private file-local `CAP_UNTYPED_START` constants for their own CSpace
# allocators — those are allowed. Every other userland path must resolve
# the bootstrap untyped at runtime via
# `trona::runtime_get_bootstrap_untyped()` or the higher-level
# `SpawnConfig::for_runtime_bootstrap_untyped()` factory. Hard-coding slot
# 16 into a child-side consumer lands on whatever cap the spawner chose
# to deposit there (often `fb_untyped` for display-class services), which
# silently breaks kernel-object retype.
# -----------------------------------------------------------------------------
h6_hits=$(grep -rEn 'CAP_UNTYPED_START' \
    --include='*.rs' --include='*.c' --include='*.h' \
    userland/ 2>/dev/null \
    | grep -vE '^userland/core/init/' \
    | grep -vE '^userland/core/procmgr/' \
    | strip_comments || true)
if [ -n "$h6_hits" ]; then
    report_fail "CAP_UNTYPED_START in userland outside core/init/ and core/procmgr/ — use SpawnConfig::for_runtime_bootstrap_untyped()" "$h6_hits"
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
printf "${green}cap_discipline: PASS${reset}\n"
