# Building the SaltyOS Toolchain

SaltyOS uses custom `x86_64-unknown-saltyos` and `aarch64-unknown-saltyos` targets registered in patched forks of LLVM/Clang and Rust. This document describes the recommended local layout and build flow for that toolchain.

## Layout Model (Source vs Build vs Prefix)

Use three separate locations:

| Role | Default path | Purpose |
|------|--------------|---------|
| Toolchain sources | `toolchain/` | LLVM/Rust fork submodules only |
| Toolchain build outputs | `build-toolchain/` | CMake/x.py build directories |
| Toolchain prefix | `build-toolchain/prefix/` | Active `clang`/`lld`/`llvm-config`/`rustc` on `PATH` |

Recommended defaults in this repo:

```text
toolchain/llvm-project          # source submodule
toolchain/rust                  # source submodule
build-toolchain/llvm            # LLVM CMake build dir
build-toolchain/rust            # Rust x.py build dir
build-toolchain/prefix          # installed/active host toolchain prefix
```

## Quick Start (just recipes)

The fastest way to build the entire toolchain:

```bash
just tc setup                    # Create directories
just tc build host llvm          # Build host Clang/LLD (~30 min)
just tc build host rust          # Build host rustc (~20 min)
just tc doctor                   # Validate toolchain

# Or all at once:
just tc all                      # setup → host llvm → host rust → doctor
```

For aarch64 (the `arch=` prefix applies to all `tc` commands):

```bash
just arch=aarch64 tc all
```

## Toolchain Helper Scripts

SaltyOS includes helper scripts for this layout:

- `tools/toolchain/env.sh` — exports the recommended local paths and prepends the prefix `bin/` to `PATH`
- `tools/toolchain/doctor.sh` — validates that `clang`, `llvm-config`, and `rustc` recognize the SaltyOS targets
- `tools/toolchain/build.sh` — unified build script invoked by `just tc`

Usage:

```bash
# Recommended (source into current shell)
source tools/toolchain/env.sh

# Or print exports for eval (same effect)
eval "$(just toolchain-env)"

# Quick validation
just tc doctor
```

`tools/toolchain/env.sh` auto-detects and exports `SALTYOS_HOST_TRIPLE` from the active host (`uname -s` + `uname -m`). Typical values are `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`. When writing manual `x.py` configs below, use `${SALTYOS_HOST_TRIPLE}` instead of hardcoding a Linux host triple.

## Overview

The SaltyOS targets encode OS-specific defaults so that every compilation does not need many repeated flags:

| Default | Value |
|---------|-------|
| Linker | `ld.lld` |
| PIC/PIE | enabled |
| Math errno | disabled |
| Runtime lib | compiler-rt |
| Dynamic linker | `/lib/ld-trona.so` |
| Page size | 4096 |
| Hash style | GNU |
| Preprocessor | `__saltyos__`, `__SaltyOS__`, `__ELF__` |

Both `x86_64-unknown-saltyos` and `aarch64-unknown-saltyos` share these defaults. The patched sources live as git submodules under `toolchain/`:

```text
toolchain/
├── llvm-project/   # SaltyOS/llvm-project fork
└── rust/           # SaltyOS/rust fork
```

## Prerequisites

Building the toolchain requires significant disk space and time:

| Component | Disk | Time (8-core) |
|-----------|------|---------------|
| LLVM/Clang/LLD | ~30 GB | 30-90 min |
| Rust (stage 1) | ~20 GB | 30-60 min |

Required host tools:

```bash
# Arch Linux
sudo pacman -S cmake ninja python3 clang lld

# Ubuntu/Debian
sudo apt install cmake ninja-build python3 clang lld

# Fedora
sudo dnf install cmake ninja-build python3 clang lld
```

## Step 1: Initialize Submodules

```bash
git submodule update --init --depth=1 toolchain/llvm-project
git submodule update --init --depth=1 toolchain/rust
```

Use `--depth=1` for a shallow clone to save disk space and time.

## Step 2: Initialize Local Toolchain Paths

From the SaltyOS repository root:

```bash
source tools/toolchain/env.sh
mkdir -p "$SALTYOS_LLVM_BUILD_DIR" "$SALTYOS_RUST_BUILD_DIR" "$SALTYOS_TOOLCHAIN_PREFIX"
```

Equivalent `just` command:

```bash
just tc setup
```

If you prefer a shared global prefix, override only the prefix before sourcing:

```bash
export SALTYOS_TOOLCHAIN_PREFIX="$HOME/.local/saltyos-toolchain"
source tools/toolchain/env.sh
```

This keeps sources and build dirs local to the repo while allowing a shared install prefix.

## Step 3: Build LLVM/Clang/LLD

Recommended shortcut:

```bash
just tc build host llvm
```

Manual steps (equivalent):

```bash
source tools/toolchain/env.sh
HOST_JOBS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"

cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" -B "$SALTYOS_LLVM_BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="AArch64;X86" \
  -DLLVM_INSTALL_UTILS=ON \
  -C "$SALTYOS_REPO_ROOT/tools/toolchain/cmake/saltyos-builtins-target-cache.cmake" \
  -DLLVM_ENABLE_RUNTIMES=compiler-rt \
  -DLLVM_BUILTIN_TARGETS="default;x86_64-unknown-saltyos;aarch64-unknown-saltyos" \
  -DCMAKE_INSTALL_PREFIX="$SALTYOS_TOOLCHAIN_PREFIX"

ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$HOST_JOBS"
ninja -C "$SALTYOS_LLVM_BUILD_DIR" install
```

The host LLVM build includes both `X86` and `AArch64` backends, and bootstraps compiler-rt builtins for both `x86_64-unknown-saltyos` and `aarch64-unknown-saltyos`.

SaltyOS uses a dedicated compiler-rt builtins cache at `tools/toolchain/cmake/saltyos-builtins-target-cache.cmake` so the host LLVM build also bootstraps SaltyOS builtins without relying on legacy `LLVM_RUNTIME_TARGETS` wiring.

### Build options

| Option | Effect |
|--------|--------|
| `-DCMAKE_BUILD_TYPE=Release` | Optimized build (recommended) |
| `-DCMAKE_BUILD_TYPE=RelWithDebInfo` | Optimized + debug symbols |
| `-DLLVM_TARGETS_TO_BUILD="AArch64;X86"` | Both architecture backends |
| `-C tools/toolchain/cmake/saltyos-builtins-target-cache.cmake` | Load the SaltyOS compiler-rt builtins cache |
| `-DLLVM_ENABLE_RUNTIMES=compiler-rt` | Build compiler-rt alongside LLVM |
| `-DLLVM_BUILTIN_TARGETS="default;x86_64-unknown-saltyos;aarch64-unknown-saltyos"` | Build compiler-rt builtins for both SaltyOS targets |
| `-DLLVM_USE_LINKER=lld` | Use LLD to link LLVM itself (faster) |
| `-DLLVM_PARALLEL_LINK_JOBS=2` | Limit link parallelism (saves RAM) |

### Verify

```bash
source tools/toolchain/env.sh

# Preprocessor defines (x86_64)
echo | clang --target=x86_64-unknown-saltyos -E -dM - | grep -i salty
# Expected:
#   #define __SaltyOS__ 1
#   #define __saltyos__ 1

# Preprocessor defines (aarch64)
echo | clang --target=aarch64-unknown-saltyos -E -dM - | grep -i salty
# Expected: same as above

# Driver defaults (ld.lld, -pie, dynamic linker)
clang --target=x86_64-unknown-saltyos -### /dev/null 2>&1 \
  | grep -oE '(ld\.lld|pie|ld-trona\.so)'
# Expected: ld.lld, -pie, /lib/ld-trona.so
```

## Step 4: Build and Install Rust (Stage 1)

Rust bootstrap needs the patched LLVM via `llvm-config`, and the key belongs under the detected host target table (`[target.${SALTYOS_HOST_TRIPLE}]` after sourcing `env.sh`), not under `[llvm]`.

Recommended shortcut:

```bash
just tc build host rust
```

Manual steps (equivalent):

```bash
source tools/toolchain/env.sh

mkdir -p "$SALTYOS_TOOLCHAIN_BUILD_ROOT"
cat > "$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml" <<EOF
[build]
target = ["${SALTYOS_HOST_TRIPLE}"]

[install]
prefix = "${SALTYOS_TOOLCHAIN_PREFIX}"
sysconfdir = "etc"

[llvm]
download-ci-llvm = false

[rust]
use-lld = true

[target.${SALTYOS_HOST_TRIPLE}]
llvm-config = "${SALTYOS_TOOLCHAIN_PREFIX}/bin/llvm-config"
llvm-filecheck = "${SALTYOS_TOOLCHAIN_PREFIX}/bin/FileCheck"
EOF

python3 "$SALTYOS_RUST_SRC_DIR/x.py" install \
  --src "$SALTYOS_RUST_SRC_DIR" \
  --build-dir "$SALTYOS_RUST_BUILD_DIR" \
  --config "$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml" \
  --stage 1 \
  compiler/rustc library/std src
```

Notes:

- `x.py install` copies the stage1 compiler, standard libraries, and rust-src into the prefix — no symlinks needed.
- `x.py` may download the stage0 toolchain on first use (network access required).
- Using `--build-dir "$SALTYOS_RUST_BUILD_DIR"` avoids placing Rust build artifacts under `toolchain/rust/build/`.
- On macOS, if `llvm-config --link-static --system-libs` reports `-lzstd`, export `LIBRARY_PATH="$(brew --prefix zstd)/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"` before running `x.py` manually. `tools/toolchain/build.sh` now does this automatically when it detects a Homebrew `zstd`.

### Verify

```bash
source tools/toolchain/env.sh

# rustc is a real binary in the prefix (not a symlink)
file "$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc"

# Sysroot resolves to the prefix
"$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc" --print sysroot

# Both targets are registered
"$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc" --print target-list | grep saltyos
# Expected:
#   x86_64-unknown-saltyos
#   aarch64-unknown-saltyos

# rust-src is available (needed by Meson for core library cross-compilation)
ls "$SALTYOS_TOOLCHAIN_PREFIX/lib/rustlib/src/rust/library/core/src/lib.rs"
```

## Step 5: Validate Toolchain

Run the toolchain doctor to verify the prefix is complete:

```bash
just tc doctor
```

The doctor checks:
- `clang` recognizes both `x86_64-unknown-saltyos` and `aarch64-unknown-saltyos`
- `rustc` lists both SaltyOS targets
- compiler-rt builtins exist for both targets
- `llvm-config`, `lld`, and `FileCheck` are present in the prefix

## Step 6: Build SaltyOS

With the local prefix active:

```bash
source tools/toolchain/env.sh

just distclean
just setup
just build

# For aarch64
just arch=aarch64 setup
just arch=aarch64 build
```

### Full verification

```bash
just build                      # Must succeed with no new warnings
just run                        # Boot in QEMU — no KERNEL PANIC
just run --smp 2                # 2-CPU test — no deadlocks
just run --smp 4                # 4-CPU stress test
just fmt-check                  # Formatting check
```

Watch serial output for `test_runner` PASS/FAIL lines.

## Target Architecture

### Kernel vs Userland Targets

SaltyOS defines two target types per architecture:

| | Kernel | Userland |
|--|--------|----------|
| **x86_64** | `kernite/x86_64-kernite.json` | `x86_64-unknown-saltyos` (built-in) |
| **aarch64** | `kernite/aarch64-kernite.json` | `aarch64-unknown-saltyos` (built-in) |

The kernel uses custom JSON target specs because it needs different settings:

| Property | Kernel | Userland |
|----------|--------|----------|
| SSE/FPU | disabled (soft-float) | enabled (SSE2 / NEON) |
| Code model | kernel | small |
| Relocation | PIC | PIC |
| Red zone | disabled | allowed |

The `core` library is built twice per architecture: once with the kernel JSON target (soft-float, kernel code model) and once with the userland built-in target (SSE2/NEON, small code model). This ensures each binary links against a `core` compiled with matching ABI and target settings.

### What the target implies

When you pass `--target=x86_64-unknown-saltyos` (or `aarch64-unknown-saltyos`) to clang, these defaults are automatically applied:

```text
-fPIC                   (position-independent code)
-fuse-ld=lld            (LLD linker)
-pie                    (position-independent executable)
--dynamic-linker=/lib/ld-trona.so
-z max-page-size=4096
--hash-style=gnu
--build-id
```

Flags you still need to pass explicitly:

```text
-ffreestanding          (for freestanding runtime/kernel components)
-nostdinc               (no system include search)
-nostdlib               (no default libraries)
-mno-red-zone           (kernel/interrupt-safe code)
```

## Cross-Compilation for Self-Hosting

SaltyOS can cross-compile its own toolchain (Clang/LLD and rustc) to run natively on SaltyOS:

```bash
# Generate sysroot from the built userland
just sysroot

# Cross-compile Clang/LLD for SaltyOS
just tc build cross llvm

# Cross-compile rustc for SaltyOS
just tc build cross rust

# Package for rootfs
just tc package

# Or all at once:
just self-host                   # sysroot → cross llvm → cross rust → package
```

For aarch64 self-hosting:

```bash
just arch=aarch64 self-host
```

The cross-compiled toolchain is packaged and included in the rootfs image.

## Updating the Toolchain

The submodules track specific commits of the forks. To update:

```bash
git -C toolchain/llvm-project pull origin main
git -C toolchain/rust pull origin main

git add toolchain/llvm-project toolchain/rust
git commit --no-gpg-sign -m "chore(toolchain): update llvm and rust submodules"

source tools/toolchain/env.sh
HOST_JOBS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$HOST_JOBS"
ninja -C "$SALTYOS_LLVM_BUILD_DIR" install
python3 "$SALTYOS_RUST_SRC_DIR/x.py" install \
  --src "$SALTYOS_RUST_SRC_DIR" \
  --build-dir "$SALTYOS_RUST_BUILD_DIR" \
  --config "$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml" \
  --stage 1 \
  compiler/rustc library/std src
```

## Troubleshooting

### "unknown target triple 'x86_64-unknown-saltyos'" (or aarch64)

You are using upstream `clang` or `rustc` instead of the patched versions. Run `just tc doctor` and check `which clang`, `which rustc`.

### LLVM build runs out of memory

Limit link parallelism:

```bash
cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" -B "$SALTYOS_LLVM_BUILD_DIR" -G Ninja \
  ... \
  -DLLVM_PARALLEL_LINK_JOBS=1
```

Each LLD link of a large LLVM library can use 4-8 GB of RAM.

### `nproc: command not found`

macOS and some minimal userlands do not ship GNU `nproc`. Use a portable job-count helper instead:

```bash
HOST_JOBS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.logicalcpu 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$HOST_JOBS"
```

### Rust build fails with "LLVM version mismatch"

Ensure `config.toml` uses:

- `[llvm] download-ci-llvm = false`
- `[target.${SALTYOS_HOST_TRIPLE}] llvm-config = ".../bin/llvm-config"`

Also verify `llvm-config` points to the patched LLVM in your active prefix.

### Rust bootstrap panics: `FileCheck ... does not exist`

Rust bootstrap sanity checks require `FileCheck` when using an external LLVM.

- `just tc build host llvm` now configures `-DLLVM_INSTALL_UTILS=ON`
- It also links `FileCheck` into the prefix if LLVM did not install it

### Rust bootstrap on macOS fails to link `-lzstd`

This usually means your external LLVM was linked against Homebrew `zstd`, but `x.py` cannot see that library path.

```bash
brew install zstd
export LIBRARY_PATH="$(brew --prefix zstd)/lib${LIBRARY_PATH:+:$LIBRARY_PATH}"
```

`tools/toolchain/build.sh build host rust` now probes `llvm-config --link-static --system-libs` and prepends the Homebrew `zstd` library directory automatically when needed.

## See Also

- [BUILDING.md](BUILDING.md) — General SaltyOS build instructions
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture overview
