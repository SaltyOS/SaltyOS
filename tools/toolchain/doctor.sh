#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Validate the current SaltyOS toolchain layout and active binaries.

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tools/toolchain/env.sh
source "${script_dir}/env.sh"

status=0

ok() {
  printf '[ok] %s\n' "$1"
}

warn() {
  printf '[warn] %s\n' "$1"
}

fail() {
  printf '[fail] %s\n' "$1" >&2
  status=1
}

check_file() {
  local path="$1"
  local label="$2"
  if [[ -e "${path}" ]]; then
    ok "${label}: ${path}"
  else
    fail "${label} missing: ${path}"
  fi
}

check_exe() {
  local path="$1"
  local label="$2"
  if [[ -x "${path}" ]]; then
    ok "${label}: ${path}"
  else
    fail "${label} missing or not executable: ${path}"
  fi
}

echo "SaltyOS toolchain doctor"
echo "  Repo root         : ${SALTYOS_REPO_ROOT}"
echo "  Toolchain src root: ${SALTYOS_TOOLCHAIN_SRC_ROOT}"
echo "  Toolchain build   : ${SALTYOS_TOOLCHAIN_BUILD_ROOT}"
echo "  Prefix            : ${SALTYOS_TOOLCHAIN_PREFIX}"
echo

legacy_llvm_clang="${SALTYOS_LLVM_SRC_DIR}/build/bin/clang"
legacy_llvm_config="${SALTYOS_LLVM_SRC_DIR}/build/bin/llvm-config"
legacy_rust_stage1="${SALTYOS_RUST_SRC_DIR}/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"

check_file "${SALTYOS_LLVM_SRC_DIR}" "LLVM source tree"
check_file "${SALTYOS_RUST_SRC_DIR}" "Rust source tree"
check_exe "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" "Prefix clang"
check_exe "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" "Prefix llvm-config"
if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck" ]]; then
  ok "Prefix FileCheck: ${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck"
else
  fail "Prefix FileCheck missing or not executable: ${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck"
fi

if [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" && -x "${legacy_llvm_clang}" ]]; then
  warn "Legacy LLVM build detected at ${legacy_llvm_clang}"
  warn "Install it into the prefix with: ninja -C \"${SALTYOS_LLVM_BUILD_DIR}\" install"
fi
if [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" && -x "${legacy_llvm_config}" ]]; then
  warn "Legacy llvm-config detected at ${legacy_llvm_config}"
fi
if [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck" && -x "${SALTYOS_LLVM_BUILD_DIR}/bin/FileCheck" ]]; then
  warn "LLVM build-dir FileCheck detected, but prefix FileCheck is missing:"
  warn "  ${SALTYOS_LLVM_BUILD_DIR}/bin/FileCheck"
  warn "Rerun 'just toolchain-build-llvm' to install/link FileCheck into the prefix."
elif [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck" && -x "${legacy_llvm_clang%/clang}/FileCheck" ]]; then
  warn "Legacy FileCheck detected at ${legacy_llvm_clang%/clang}/FileCheck"
fi

if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/rustc" ]]; then
  rustc_bin="${SALTYOS_TOOLCHAIN_PREFIX}/bin/rustc"
  ok "Prefix rustc: ${rustc_bin}"
elif [[ -x "${SALTYOS_RUST_STAGE1_RUSTC}" ]]; then
  rustc_bin="${SALTYOS_RUST_STAGE1_RUSTC}"
  warn "Prefix rustc missing; using stage1 rustc directly: ${rustc_bin}"
  warn "Install it into the prefix with: just toolchain-build-rust"
else
  rustc_bin=""
  fail "No usable rustc found in prefix or stage1 build"
  if [[ -x "${legacy_rust_stage1}" ]]; then
    warn "Legacy Rust stage1 rustc detected at ${legacy_rust_stage1}"
    warn "Rebuild with --build-dir \"${SALTYOS_RUST_BUILD_DIR}\" or link legacy stage1 into the prefix temporarily"
  fi
fi

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT

if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" ]]; then
  if "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" --target=x86_64-unknown-saltyos -### -c -x c /dev/null \
      >"${tmp}" 2>&1; then
    if grep -q "x86_64-unknown-saltyos" "${tmp}"; then
      ok "clang recognizes target x86_64-unknown-saltyos"
    else
      fail "clang invocation succeeded but target triple was not visible in -### output"
    fi
  else
    fail "clang failed to compile with --target=x86_64-unknown-saltyos"
  fi
fi

if [[ -n "${rustc_bin}" ]]; then
  if "${rustc_bin}" --print target-list 2>/dev/null | grep -qx "x86_64-unknown-saltyos"; then
    ok "rustc exposes target x86_64-unknown-saltyos"
  else
    fail "rustc does not list x86_64-unknown-saltyos"
  fi
fi

if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" ]]; then
  if "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" --version >/dev/null 2>&1; then
    ok "llvm-config runs successfully"
  else
    fail "llvm-config exists but failed to run"
  fi
fi

if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" ]]; then
  clang_version=$("${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" --version 2>/dev/null \
    | sed 's/\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/')
  crt_builtins="${SALTYOS_TOOLCHAIN_PREFIX}/lib/clang/${clang_version}/lib/x86_64-unknown-saltyos/libclang_rt.builtins.a"
  check_file "${crt_builtins}" "compiler-rt builtins (saltyos)"
fi

exit "${status}"
