#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# SaltyOS toolchain environment helper.
# Source this file to export a workspace-local toolchain layout:
#   source tools/toolchain/env.sh
#
# Execute with --print to emit shell exports:
#   eval "$(tools/toolchain/env.sh --print)"

_saltyos_toolchain_is_sourced() {
  [[ "${BASH_SOURCE[0]}" != "$0" ]]
}

_saltyos_toolchain_script_dir() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P
}

_saltyos_toolchain_init() {
  local script_dir repo_root prefix_bin
  script_dir="$(_saltyos_toolchain_script_dir)"
  repo_root="$(cd -- "${script_dir}/../.." && pwd -P)"

  : "${SALTYOS_REPO_ROOT:=${repo_root}}"
  : "${SALTYOS_TOOLCHAIN_SRC_ROOT:=${SALTYOS_REPO_ROOT}/toolchain}"
  : "${SALTYOS_TOOLCHAIN_BUILD_ROOT:=${SALTYOS_REPO_ROOT}/build-toolchain}"
  : "${SALTYOS_LLVM_SRC_DIR:=${SALTYOS_TOOLCHAIN_SRC_ROOT}/llvm-project}"
  : "${SALTYOS_RUST_SRC_DIR:=${SALTYOS_TOOLCHAIN_SRC_ROOT}/rust}"
  : "${SALTYOS_LLVM_BUILD_DIR:=${SALTYOS_TOOLCHAIN_BUILD_ROOT}/llvm}"
  : "${SALTYOS_RUST_BUILD_DIR:=${SALTYOS_TOOLCHAIN_BUILD_ROOT}/rust}"
  : "${SALTYOS_TOOLCHAIN_PREFIX:=${SALTYOS_TOOLCHAIN_BUILD_ROOT}/prefix}"
  : "${SALTYOS_RUST_STAGE1_RUSTC:=${SALTYOS_RUST_BUILD_DIR}/x86_64-unknown-linux-gnu/stage1/bin/rustc}"

  prefix_bin="${SALTYOS_TOOLCHAIN_PREFIX}/bin"
  case ":${PATH-}:" in
    *":${prefix_bin}:"*) ;;
    *) PATH="${prefix_bin}${PATH:+:${PATH}}" ;;
  esac

  export PATH
  export SALTYOS_REPO_ROOT
  export SALTYOS_TOOLCHAIN_SRC_ROOT
  export SALTYOS_TOOLCHAIN_BUILD_ROOT
  export SALTYOS_LLVM_SRC_DIR
  export SALTYOS_RUST_SRC_DIR
  export SALTYOS_LLVM_BUILD_DIR
  export SALTYOS_RUST_BUILD_DIR
  export SALTYOS_TOOLCHAIN_PREFIX
  export SALTYOS_RUST_STAGE1_RUSTC
}

_saltyos_toolchain_print_exports() {
  printf 'export %s=%q\n' "SALTYOS_REPO_ROOT" "${SALTYOS_REPO_ROOT}"
  printf 'export %s=%q\n' "SALTYOS_TOOLCHAIN_SRC_ROOT" "${SALTYOS_TOOLCHAIN_SRC_ROOT}"
  printf 'export %s=%q\n' "SALTYOS_TOOLCHAIN_BUILD_ROOT" "${SALTYOS_TOOLCHAIN_BUILD_ROOT}"
  printf 'export %s=%q\n' "SALTYOS_LLVM_SRC_DIR" "${SALTYOS_LLVM_SRC_DIR}"
  printf 'export %s=%q\n' "SALTYOS_RUST_SRC_DIR" "${SALTYOS_RUST_SRC_DIR}"
  printf 'export %s=%q\n' "SALTYOS_LLVM_BUILD_DIR" "${SALTYOS_LLVM_BUILD_DIR}"
  printf 'export %s=%q\n' "SALTYOS_RUST_BUILD_DIR" "${SALTYOS_RUST_BUILD_DIR}"
  printf 'export %s=%q\n' "SALTYOS_TOOLCHAIN_PREFIX" "${SALTYOS_TOOLCHAIN_PREFIX}"
  printf 'export %s=%q\n' "SALTYOS_RUST_STAGE1_RUSTC" "${SALTYOS_RUST_STAGE1_RUSTC}"
  printf 'export PATH=%q\n' "${PATH}"
}

_saltyos_toolchain_show() {
  cat <<EOF
SaltyOS toolchain layout
  Repo root          : ${SALTYOS_REPO_ROOT}
  Toolchain sources  : ${SALTYOS_TOOLCHAIN_SRC_ROOT}
  LLVM source        : ${SALTYOS_LLVM_SRC_DIR}
  Rust source        : ${SALTYOS_RUST_SRC_DIR}
  Build root         : ${SALTYOS_TOOLCHAIN_BUILD_ROOT}
  LLVM build dir     : ${SALTYOS_LLVM_BUILD_DIR}
  Rust build dir     : ${SALTYOS_RUST_BUILD_DIR}
  Prefix             : ${SALTYOS_TOOLCHAIN_PREFIX}
  Stage1 rustc       : ${SALTYOS_RUST_STAGE1_RUSTC}

Usage
  source tools/toolchain/env.sh
  eval "\$(tools/toolchain/env.sh --print)"
EOF
}

_saltyos_toolchain_main() {
  _saltyos_toolchain_init

  case "${1-}" in
    "" )
      if _saltyos_toolchain_is_sourced; then
        return 0
      fi
      _saltyos_toolchain_show
      ;;
    --print)
      _saltyos_toolchain_print_exports
      ;;
    --show)
      _saltyos_toolchain_show
      ;;
    -h|--help|help)
      _saltyos_toolchain_show
      ;;
    *)
      echo "unknown option: $1" >&2
      return 2
      ;;
  esac
}

_saltyos_toolchain_main "${@}"
