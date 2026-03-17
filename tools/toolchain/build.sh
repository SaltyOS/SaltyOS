#!/usr/bin/env bash
# tools/toolchain/build.sh — SaltyOS unified toolchain builder
# SPDX-License-Identifier: GPL-2.0-only
#
# Usage:
#   bash tools/toolchain/build.sh <command> [args...]
#   SALTYOS_MESON_BUILDDIR=build bash tools/toolchain/build.sh <command>
#
# Commands:
#   setup                    Create toolchain directories
#   build host llvm          Build host Clang/LLD + compiler-rt
#   build host rust          Build host rustc
#   build cross llvm         Cross-compile Clang/LLD for SaltyOS
#   build cross rust         Cross-compile rustc for SaltyOS
#   sysroot                  Generate cross-compilation sysroot (includes libc++ via Meson)
#   doctor                   Validate toolchain
#   all                      setup → host llvm → host rust → doctor
#   self-host                sysroot → cross llvm → cross rust

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=tools/toolchain/env.sh
# Pass "" so env.sh's _saltyos_toolchain_main sees no args and detects it is
# being sourced (BASH_SOURCE[0] != $0), instead of inheriting build.sh's $@.
source "${SCRIPT_DIR}/env.sh" ""

# Build directory passed from justfile (default: build)
: "${SALTYOS_MESON_BUILDDIR:=build}"

SYSROOT="$SALTYOS_REPO_ROOT/$SALTYOS_MESON_BUILDDIR/sysroot"

# =============================================================================
# Helpers
# =============================================================================

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat >&2 <<'EOF'
Usage: bash tools/toolchain/build.sh <command> [args...]

Commands:
  setup                    Create toolchain directories
  build host llvm          Build host Clang/LLD + compiler-rt (~30 min)
  build host rust          Build host rustc (~20 min)
  build cross llvm         Cross-compile Clang/LLD for SaltyOS
  build cross rust         Cross-compile rustc for SaltyOS
  sysroot                  Generate cross-compilation sysroot (includes libc++ via Meson)
  doctor                   Validate toolchain
  all                      Run: setup → host llvm → host rust → doctor
  self-host                Run: sysroot → cross llvm → cross rust
EOF
  exit 1
}

# Doctor status tracking (reset per invocation)
_doctor_status=0

_ok()        { printf '[ok]   %s\n' "$1"; }
_warn()      { printf '[warn] %s\n' "$1"; }
_fail()      { printf '[fail] %s\n' "$1" >&2; _doctor_status=1; }
_check_file() { [[ -e "$1" ]] && _ok "${2}: $1" || _fail "${2} missing: $1"; }
_check_exe()  { [[ -x "$1" ]] && _ok "${2}: $1" || _fail "${2} missing or not executable: $1"; }

# =============================================================================
# cmd_setup
# =============================================================================

cmd_setup() {
  mkdir -p \
    "$SALTYOS_LLVM_BUILD_DIR" \
    "$SALTYOS_RUST_BUILD_DIR" \
    "$SALTYOS_TOOLCHAIN_PREFIX/bin"

  echo "Initialized toolchain directories:"
  echo "  LLVM build : $SALTYOS_LLVM_BUILD_DIR"
  echo "  Rust build : $SALTYOS_RUST_BUILD_DIR"
  echo "  Prefix     : $SALTYOS_TOOLCHAIN_PREFIX"
  echo
  echo "Next:"
  echo "  just tc build host llvm"
  echo "  just tc build host rust"
}

# =============================================================================
# cmd_build_host_llvm
# =============================================================================

cmd_build_host_llvm() {
  mkdir -p "$SALTYOS_LLVM_BUILD_DIR" "$SALTYOS_TOOLCHAIN_PREFIX"

  cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" -B "$SALTYOS_LLVM_BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DLLVM_ENABLE_PROJECTS="clang;lld" \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    -DLLVM_INSTALL_UTILS=ON \
    -DLLVM_ENABLE_RUNTIMES=compiler-rt \
    -DLLVM_RUNTIME_TARGETS="default;x86_64-unknown-saltyos" \
    -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_C_FLAGS="-ffreestanding" \
    -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_CXX_FLAGS="-ffreestanding" \
    -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_C_COMPILER_FORCED=ON \
    -DRUNTIMES_x86_64-unknown-saltyos_CMAKE_CXX_COMPILER_FORCED=ON \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_BUILTINS=ON \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_SANITIZERS=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_XRAY=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_LIBFUZZER=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_PROFILE=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_MEMPROF=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_ORC=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_GWP_ASAN=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILD_CTX_PROFILE=OFF \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BUILTINS_ENABLE_PIC=ON \
    -DRUNTIMES_x86_64-unknown-saltyos_COMPILER_RT_BAREMETAL_BUILD=ON \
    -DCMAKE_INSTALL_PREFIX="$SALTYOS_TOOLCHAIN_PREFIX"

  ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$(nproc)"
  ninja -C "$SALTYOS_LLVM_BUILD_DIR" install
}

# =============================================================================
# cmd_build_host_rust
# =============================================================================

cmd_build_host_rust() {
  mkdir -p \
    "$SALTYOS_RUST_BUILD_DIR" \
    "$SALTYOS_TOOLCHAIN_BUILD_ROOT" \
    "$SALTYOS_TOOLCHAIN_PREFIX/bin"

  local llvm_config_path="$SALTYOS_TOOLCHAIN_PREFIX/bin/llvm-config"
  if [ ! -x "$llvm_config_path" ]; then
    die "Missing llvm-config in prefix: $llvm_config_path
Run 'just tc build host llvm' first (or set SALTYOS_TOOLCHAIN_PREFIX to an existing install)."
  fi

  local filecheck_path="$SALTYOS_TOOLCHAIN_PREFIX/bin/FileCheck"
  if [ ! -x "$filecheck_path" ]; then
    die "Missing FileCheck in prefix: $filecheck_path
Run 'just tc build host llvm' first (it installs/links FileCheck into the prefix)."
  fi

  local config_path="$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml"
  {
    echo '[build]'
    echo 'target = ["x86_64-unknown-linux-gnu"]'
    echo ''
    echo '[install]'
    echo "prefix = \"$SALTYOS_TOOLCHAIN_PREFIX\""
    echo 'sysconfdir = "etc"'
    echo ''
    echo '[llvm]'
    echo 'download-ci-llvm = false'
    echo ''
    echo '[rust]'
    echo 'use-lld = true'
    echo ''
    echo '[target.x86_64-unknown-linux-gnu]'
    echo "llvm-config = \"$llvm_config_path\""
    echo "llvm-filecheck = \"$filecheck_path\""
  } > "$config_path"

  python3 "$SALTYOS_RUST_SRC_DIR/x.py" install \
    --src "$SALTYOS_RUST_SRC_DIR" \
    --build-dir "$SALTYOS_RUST_BUILD_DIR" \
    --config "$config_path" \
    --stage 1 \
    compiler/rustc library/std src

  echo "Installed stage1 rustc into prefix: $SALTYOS_TOOLCHAIN_PREFIX"
}

# =============================================================================
# cmd_sysroot
# =============================================================================

cmd_sysroot() {
  # Ensure build outputs (libc.so, libbesalt.so, libc++.so, ...) are up to date
  # before collecting them into the sysroot.
  if [ ! -d "$SALTYOS_MESON_BUILDDIR" ]; then
    die "Build directory not found: $SALTYOS_MESON_BUILDDIR
Run 'just setup && just build' first."
  fi
  meson compile -C "$SALTYOS_MESON_BUILDDIR"

  python3 tools/mksysroot \
    --build-dir "$SALTYOS_MESON_BUILDDIR" \
    --output "$SYSROOT" \
    --clean -v
}

# =============================================================================
# cmd_build_cross_llvm
# =============================================================================

cmd_build_cross_llvm() {
  if [ ! -d "$SYSROOT/usr/lib" ]; then
    die "sysroot not found at $SYSROOT
Run 'just sysroot' first."
  fi

  if [ ! -f "$SYSROOT/usr/lib/libc++.so" ] && [ ! -L "$SYSROOT/usr/lib/libc++.so" ]; then
    die "libc++.so not found in sysroot.
Run 'just sysroot' first (requires build_libcxx=auto|true and toolchain/llvm-project present)."
  fi

  local build_root="$SALTYOS_TOOLCHAIN_BUILD_ROOT/llvm-saltyos"
  local install_prefix="/usr"

  # Prefer installed tablegen; fall back to build-dir binaries
  local llvm_tblgen="$SALTYOS_TOOLCHAIN_PREFIX/bin/llvm-tblgen"
  local clang_tblgen="$SALTYOS_TOOLCHAIN_PREFIX/bin/clang-tblgen"
  [ -x "$llvm_tblgen"  ] || llvm_tblgen="$SALTYOS_LLVM_BUILD_DIR/bin/llvm-tblgen"
  [ -x "$clang_tblgen" ] || clang_tblgen="$SALTYOS_LLVM_BUILD_DIR/bin/clang-tblgen"

  [ -x "$llvm_tblgen" ] || die "llvm-tblgen not found.
Run 'just tc build host llvm' first."

  echo "Cross-compiling LLVM/Clang/LLD for SaltyOS..."
  echo "  Source:       $SALTYOS_LLVM_SRC_DIR"
  echo "  Build:        $build_root"
  echo "  Sysroot:      $SYSROOT"
  echo "  Toolchain:    $SALTYOS_TOOLCHAIN_PREFIX"
  echo "  llvm-tblgen:  $llvm_tblgen"
  echo "  clang-tblgen: $clang_tblgen"

  mkdir -p "$build_root"

  cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" \
    -B "$build_root" \
    -G Ninja \
    -DCMAKE_C_COMPILER="$SALTYOS_TOOLCHAIN_PREFIX/bin/clang" \
    -DCMAKE_CXX_COMPILER="$SALTYOS_TOOLCHAIN_PREFIX/bin/clang++" \
    -DCMAKE_AR="$SALTYOS_TOOLCHAIN_PREFIX/bin/llvm-ar" \
    -DCMAKE_RANLIB="$SALTYOS_TOOLCHAIN_PREFIX/bin/llvm-ranlib" \
    -DCMAKE_C_COMPILER_TARGET=x86_64-unknown-saltyos \
    -DCMAKE_CXX_COMPILER_TARGET=x86_64-unknown-saltyos \
    -DCMAKE_SYSROOT="$SYSROOT" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$install_prefix" \
    -DCMAKE_CROSSCOMPILING=TRUE \
    -DCMAKE_SYSTEM_NAME=SaltyOS \
    -DCMAKE_MODULE_PATH="$SALTYOS_REPO_ROOT/tools/cmake" \
    \
    -DLLVM_ENABLE_PROJECTS="clang;lld" \
    -DLLVM_TARGETS_TO_BUILD="X86" \
    -DLLVM_HOST_TRIPLE=x86_64-unknown-saltyos \
    -DLLVM_DEFAULT_TARGET_TRIPLE=x86_64-unknown-saltyos \
    \
    -DLLVM_ENABLE_EH=OFF \
    -DLLVM_ENABLE_RTTI=OFF \
    -DLLVM_ENABLE_THREADS=ON \
    -DLLVM_ENABLE_ZLIB=OFF \
    -DLLVM_ENABLE_ZSTD=OFF \
    -DLLVM_ENABLE_TERMINFO=OFF \
    -DLLVM_ENABLE_LIBXML2=OFF \
    -DLLVM_ENABLE_LIBEDIT=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF \
    -DLLVM_INCLUDE_DOCS=OFF \
    -DCMAKE_DISABLE_PRECOMPILE_HEADERS=ON \
    \
    -DLLVM_TABLEGEN="$llvm_tblgen" \
    -DCLANG_TABLEGEN="$clang_tblgen" \
    \
    -DCMAKE_C_FLAGS="--target=x86_64-unknown-saltyos --sysroot=$SYSROOT" \
    -DCMAKE_CXX_FLAGS="--target=x86_64-unknown-saltyos --sysroot=$SYSROOT -fno-exceptions -fno-rtti -nostdinc++ -I$SYSROOT/usr/include/c++/v1" \
    -DCMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -nostdlib -nostartfiles -L$SYSROOT/usr/lib $SYSROOT/usr/lib/crt_start.o -lc++ -lc -lbesalt $SYSROOT/usr/lib/core.o $SYSROOT/usr/lib/compiler_builtins.o -T $SYSROOT/usr/lib/saltyos-pie.ld -z max-page-size=4096" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -nostdlib -nostartfiles -L$SYSROOT/usr/lib -lc++ -lc -lbesalt -z max-page-size=4096" \
    -DCMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -nostdlib -nostartfiles -L$SYSROOT/usr/lib -lc++ -lc -lbesalt -z max-page-size=4096" \
    \
    -DHAVE_CXX_ATOMICS_WITHOUT_LIB=ON \
    -DHAVE_CXX_ATOMICS64_WITHOUT_LIB=ON

  ninja -C "$build_root" -j"$(nproc)"

  echo
  echo "LLVM/Clang/LLD cross-compiled for SaltyOS successfully."
  echo "  Binaries: $build_root/bin/"
  echo "  Verify: readelf -d $build_root/bin/clang | grep NEEDED"
  echo "  Expected: libc++.so, libc.so, libbesalt.so"
}

# =============================================================================
# cmd_build_cross_rust
# =============================================================================

cmd_build_cross_rust() {
  if [ ! -d "$SYSROOT/usr/lib" ]; then
    die "sysroot not found at $SYSROOT
Run 'just sysroot' first."
  fi

  local llvm_config="$SALTYOS_TOOLCHAIN_PREFIX/bin/llvm-config"
  if [ ! -x "$llvm_config" ]; then
    die "llvm-config not found at $llvm_config
Run 'just tc build host llvm' first."
  fi

  local build_root="$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-saltyos"
  mkdir -p "$build_root"

  echo "Cross-compiling rustc for SaltyOS..."
  echo "  Rust source:  $SALTYOS_RUST_SRC_DIR"
  echo "  Build:        $build_root"
  echo "  Sysroot:      $SYSROOT"
  echo "  llvm-config:  $llvm_config"

  # Generate cross-bootstrap config
  local config_path="$build_root/config.toml"
  cat > "$config_path" << EOF
[build]
host = ["x86_64-unknown-linux-gnu"]
target = ["x86_64-unknown-saltyos"]
docs = false
extended = false

[install]
prefix = "/usr"
sysconfdir = "etc"

[llvm]
download-ci-llvm = false

[rust]
use-lld = true

[target.x86_64-unknown-linux-gnu]
llvm-config = "$llvm_config"

[target.x86_64-unknown-saltyos]
cc = "$SALTYOS_TOOLCHAIN_PREFIX/bin/clang"
cxx = "$SALTYOS_TOOLCHAIN_PREFIX/bin/clang++"
linker = "$SALTYOS_TOOLCHAIN_PREFIX/bin/clang"
llvm-config = "$llvm_config"
EOF

  echo "Generated config: $config_path"
  echo
  echo "Building stage 1 rustc for x86_64-unknown-saltyos..."

  python3 "$SALTYOS_RUST_SRC_DIR/x.py" build \
    --src "$SALTYOS_RUST_SRC_DIR" \
    --build-dir "$build_root" \
    --config "$config_path" \
    --stage 1 \
    --target x86_64-unknown-saltyos \
    compiler/rustc library/std

  echo
  echo "rustc cross-compiled for SaltyOS successfully."
  echo "  Build dir: $build_root"
}

# =============================================================================
# cmd_doctor
# =============================================================================

cmd_doctor() {
  _doctor_status=0

  local legacy_llvm_clang="${SALTYOS_LLVM_SRC_DIR}/build/bin/clang"
  local legacy_llvm_config="${SALTYOS_LLVM_SRC_DIR}/build/bin/llvm-config"
  local legacy_rust_stage1="${SALTYOS_RUST_SRC_DIR}/build/x86_64-unknown-linux-gnu/stage1/bin/rustc"

  echo "SaltyOS toolchain doctor"
  echo "  Repo root         : ${SALTYOS_REPO_ROOT}"
  echo "  Toolchain src root: ${SALTYOS_TOOLCHAIN_SRC_ROOT}"
  echo "  Toolchain build   : ${SALTYOS_TOOLCHAIN_BUILD_ROOT}"
  echo "  Prefix            : ${SALTYOS_TOOLCHAIN_PREFIX}"
  echo

  _check_file "${SALTYOS_LLVM_SRC_DIR}" "LLVM source tree"
  _check_file "${SALTYOS_RUST_SRC_DIR}" "Rust source tree"
  _check_exe  "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang"       "Prefix clang"
  _check_exe  "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" "Prefix llvm-config"

  if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck" ]]; then
    _ok "Prefix FileCheck: ${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck"
  else
    _fail "Prefix FileCheck missing or not executable: ${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck"
  fi

  if [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" && -x "${legacy_llvm_clang}" ]]; then
    _warn "Legacy LLVM build detected at ${legacy_llvm_clang}"
    _warn "Install it into the prefix with: ninja -C \"${SALTYOS_LLVM_BUILD_DIR}\" install"
  fi
  if [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" && -x "${legacy_llvm_config}" ]]; then
    _warn "Legacy llvm-config detected at ${legacy_llvm_config}"
  fi
  if [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck" && -x "${SALTYOS_LLVM_BUILD_DIR}/bin/FileCheck" ]]; then
    _warn "LLVM build-dir FileCheck detected, but prefix FileCheck is missing:"
    _warn "  ${SALTYOS_LLVM_BUILD_DIR}/bin/FileCheck"
    _warn "Rerun 'just tc build host llvm' to install/link FileCheck into the prefix."
  elif [[ ! -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck" && -x "${legacy_llvm_clang%/clang}/FileCheck" ]]; then
    _warn "Legacy FileCheck detected at ${legacy_llvm_clang%/clang}/FileCheck"
  fi

  local rustc_bin
  if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/rustc" ]]; then
    rustc_bin="${SALTYOS_TOOLCHAIN_PREFIX}/bin/rustc"
    _ok "Prefix rustc: ${rustc_bin}"
  elif [[ -x "${SALTYOS_RUST_STAGE1_RUSTC}" ]]; then
    rustc_bin="${SALTYOS_RUST_STAGE1_RUSTC}"
    _warn "Prefix rustc missing; using stage1 rustc directly: ${rustc_bin}"
    _warn "Install it into the prefix with: just tc build host rust"
  else
    rustc_bin=""
    _fail "No usable rustc found in prefix or stage1 build"
    if [[ -x "${legacy_rust_stage1}" ]]; then
      _warn "Legacy Rust stage1 rustc detected at ${legacy_rust_stage1}"
      _warn "Rebuild with --build-dir \"${SALTYOS_RUST_BUILD_DIR}\" or link legacy stage1 into the prefix temporarily"
    fi
  fi

  local tmp
  tmp="$(mktemp)"
  trap 'rm -f "${tmp}"' EXIT

  if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" ]]; then
    if "${SALTYOS_TOOLCHAIN_PREFIX}/bin/clang" --target=x86_64-unknown-saltyos -### -c -x c /dev/null \
        >"${tmp}" 2>&1; then
      if grep -q "x86_64-unknown-saltyos" "${tmp}"; then
        _ok "clang recognizes target x86_64-unknown-saltyos"
      else
        _fail "clang invocation succeeded but target triple was not visible in -### output"
      fi
    else
      _fail "clang failed to compile with --target=x86_64-unknown-saltyos"
    fi
  fi

  if [[ -n "${rustc_bin}" ]]; then
    if "${rustc_bin}" --print target-list 2>/dev/null | grep -qx "x86_64-unknown-saltyos"; then
      _ok "rustc exposes target x86_64-unknown-saltyos"
    else
      _fail "rustc does not list x86_64-unknown-saltyos"
    fi
  fi

  if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" ]]; then
    if "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" --version >/dev/null 2>&1; then
      _ok "llvm-config runs successfully"
    else
      _fail "llvm-config exists but failed to run"
    fi
  fi

  if [[ -x "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" ]]; then
    local clang_version
    clang_version=$("${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config" --version 2>/dev/null \
      | sed 's/\([0-9]*\.[0-9]*\.[0-9]*\).*/\1/')
    local crt_builtins="${SALTYOS_TOOLCHAIN_PREFIX}/lib/clang/${clang_version}/lib/x86_64-unknown-saltyos/libclang_rt.builtins.a"
    _check_file "${crt_builtins}" "compiler-rt builtins (saltyos)"
  fi

  exit "${_doctor_status}"
}

# =============================================================================
# cmd_all / cmd_self_host
# =============================================================================

cmd_all() {
  cmd_setup
  cmd_build_host_llvm
  cmd_build_host_rust
  cmd_doctor
}

cmd_self_host() {
  # libc++ is built as part of the Meson build (just build) and installed
  # into the sysroot by cmd_sysroot. No separate runtimes step needed.
  cmd_sysroot
  cmd_build_cross_llvm
  cmd_build_cross_rust
}

# =============================================================================
# cmd_build (2-level dispatch)
# =============================================================================

cmd_build() {
  local target="${1:-}"
  local component="${2:-}"
  case "$target/$component" in
    host/llvm)  cmd_build_host_llvm ;;
    host/rust)  cmd_build_host_rust ;;
    cross/llvm) cmd_build_cross_llvm ;;
    cross/rust) cmd_build_cross_rust ;;
    *) die "Usage: build {host|cross} {llvm|rust}" ;;
  esac
}

# =============================================================================
# Main dispatch
# =============================================================================

case "${1:-help}" in
  setup)     cmd_setup ;;
  build)     cmd_build "${@:2}" ;;
  sysroot)   cmd_sysroot ;;
  doctor)    cmd_doctor ;;
  all)       cmd_all ;;
  self-host) cmd_self_host ;;
  help|-h|--help) usage ;;
  *) die "Unknown command: $1. Run 'bash tools/toolchain/build.sh help' for usage." ;;
esac
