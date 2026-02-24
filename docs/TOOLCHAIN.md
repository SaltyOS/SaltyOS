# Building the SaltyOS Toolchain

SaltyOS uses a custom `x86_64-unknown-saltyos` target registered in patched forks of LLVM/Clang and Rust. This document describes the recommended local layout and build flow for that toolchain.

## Layout Model (Source vs Build vs Prefix)

Use three separate locations:

| Role | Default path | Purpose |
|------|--------------|---------|
| Toolchain sources | `toolchain/` | LLVM/Rust fork submodules only |
| Toolchain build outputs | `build-toolchain/` | CMake/x.py build directories |
| Toolchain prefix | `build-toolchain/prefix/` | Active `clang`/`lld`/`llvm-config`/`rustc` on `PATH` |

This avoids the current ambiguity where Rust often appears to "live inside the subtree" (`toolchain/rust/build/...`) while Clang is often installed somewhere else (for example `~/.local/...`).

Recommended defaults in this repo:

```text
toolchain/llvm-project          # source submodule
toolchain/rust                  # source submodule
build-toolchain/llvm            # LLVM CMake build dir
build-toolchain/rust            # Rust x.py build dir
build-toolchain/prefix          # installed/active host toolchain prefix
```

## Toolchain Helper Scripts

SaltyOS now includes helper scripts for this layout:

- `tools/toolchain/env.sh` — exports the recommended local paths and prepends the prefix `bin/` to `PATH`
- `tools/toolchain/doctor.sh` — validates that `clang`, `llvm-config`, and `rustc` recognize the SaltyOS target

Usage:

```bash
# Recommended (source into current shell)
source tools/toolchain/env.sh

# Or print exports for eval (same effect)
eval "$(tools/toolchain/env.sh --print)"

# Quick validation
tools/toolchain/doctor.sh

# just wrappers
eval "$(just toolchain-env)"
just toolchain-doctor
just toolchain-setup
```

## Overview

The `x86_64-unknown-saltyos` target encodes OS-specific defaults so that every compilation does not need many repeated flags. The target provides:

| Default | Value |
|---------|-------|
| Linker | `ld.lld` |
| PIC/PIE | enabled |
| Math errno | disabled |
| Runtime lib | compiler-rt |
| Dynamic linker | `/lib/ld-salty.so` |
| Page size | 4096 |
| Hash style | GNU |
| Preprocessor | `__saltyos__`, `__SaltyOS__`, `__ELF__` |

The patched sources live as git submodules under `toolchain/`:

```text
toolchain/
├── llvm-project/   # SaltyOS/llvm-project fork
└── rust/           # SaltyOS/rust fork
```

## Prerequisites

Building the toolchain requires significant disk space and time:

| Component | Disk | Time (8-core) |
|-----------|------|---------------|
| LLVM/Clang/LLD | ~30 GB | 30–90 min |
| Rust (stage 1) | ~20 GB | 30–60 min |

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
just toolchain-setup
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
just toolchain-build-llvm
```

Manual steps (equivalent):

```bash
source tools/toolchain/env.sh

cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" -B "$SALTYOS_LLVM_BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="clang;lld" \
  -DLLVM_TARGETS_TO_BUILD="X86" \
  -DLLVM_INSTALL_UTILS=ON \
  -DCMAKE_INSTALL_PREFIX="$SALTYOS_TOOLCHAIN_PREFIX"

ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$(nproc)"
ninja -C "$SALTYOS_LLVM_BUILD_DIR" install
```

### Build options

| Option | Effect |
|--------|--------|
| `-DCMAKE_BUILD_TYPE=Release` | Optimized build (recommended) |
| `-DCMAKE_BUILD_TYPE=RelWithDebInfo` | Optimized + debug symbols |
| `-DLLVM_TARGETS_TO_BUILD="X86"` | Only x86 backend (faster build) |
| `-DLLVM_USE_LINKER=lld` | Use LLD to link LLVM itself (faster) |
| `-DLLVM_PARALLEL_LINK_JOBS=2` | Limit link parallelism (saves RAM) |

### Verify

```bash
source tools/toolchain/env.sh

# Preprocessor defines
echo | clang --target=x86_64-unknown-saltyos -E -dM - | grep -i salty
# Expected:
#   #define __SaltyOS__ 1
#   #define __saltyos__ 1

# Driver defaults (ld.lld, -pie, dynamic linker)
clang --target=x86_64-unknown-saltyos -### /dev/null 2>&1 \
  | grep -oE '(ld\.lld|pie|ld-salty\.so)'
# Expected: ld.lld, -pie, /lib/ld-salty.so
```

## Step 4: Build and Install Rust (Stage 1)

Rust bootstrap needs the patched LLVM via `llvm-config`, and the key belongs under the host target table (`[target.x86_64-unknown-linux-gnu]`), not under `[llvm]`.

Recommended shortcut:

```bash
just toolchain-build-rust
```

Manual steps (equivalent):

```bash
source tools/toolchain/env.sh

mkdir -p "$SALTYOS_TOOLCHAIN_BUILD_ROOT"
cat > "$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml" <<EOF
[build]
target = ["x86_64-unknown-linux-gnu"]

[install]
prefix = "${SALTYOS_TOOLCHAIN_PREFIX}"
sysconfdir = "etc"

[llvm]
download-ci-llvm = false

[rust]
use-lld = true

[target.x86_64-unknown-linux-gnu]
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

### Verify

```bash
source tools/toolchain/env.sh

# rustc is a real binary in the prefix (not a symlink)
file "$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc"

# Sysroot resolves to the prefix
"$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc" --print sysroot

# Target is registered
"$SALTYOS_TOOLCHAIN_PREFIX/bin/rustc" --print target-list | grep saltyos
# Expected: x86_64-unknown-saltyos

# rust-src is available (needed by Meson for core library cross-compilation)
ls "$SALTYOS_TOOLCHAIN_PREFIX/lib/rustlib/src/rust/library/core/src/lib.rs"
```

## Step 5: Validate Toolchain

Run the toolchain doctor to verify the prefix is complete:

```bash
tools/toolchain/doctor.sh
```

## Step 6: Build SaltyOS

With the local prefix active:

```bash
source tools/toolchain/env.sh
tools/toolchain/doctor.sh

just distclean
just setup
just build
```

### Full verification

```bash
just build          # Must succeed with no new warnings
just run            # Boot in QEMU — no KERNEL PANIC
just run-smp        # 2-CPU test — no deadlocks
just run-smp4       # 4-CPU stress test
just fmt-check      # Formatting check
```

Watch serial output for `test_runner` PASS/FAIL lines.

## Target Architecture

### Kernel vs Userland

The `x86_64-unknown-saltyos` target is for **userland** code. The kernel uses a separate JSON target spec (`kernel/x86_64-saltyos.json`) because it needs:

| Property | Kernel | Userland |
|----------|--------|----------|
| SSE/FPU | disabled (soft-float) | enabled (SSE2) |
| Code model | kernel | small |
| Relocation | PIC | PIC |
| Red zone | disabled | allowed |

The `core` library is built twice: once with the kernel JSON target (soft-float, kernel code model) and once with `x86_64-unknown-saltyos` (SSE2, small code model). This ensures each binary links against a `core` compiled with matching ABI and target settings.

### What the target implies

When you pass `--target=x86_64-unknown-saltyos` to clang, these defaults are automatically applied:

```text
-fPIC                   (position-independent code)
-fuse-ld=lld            (LLD linker)
-pie                    (position-independent executable)
--dynamic-linker=/lib/ld-salty.so
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

## Updating the Toolchain

The submodules track specific commits of the forks. To update:

```bash
git -C toolchain/llvm-project pull origin main
git -C toolchain/rust pull origin main

git add toolchain/llvm-project toolchain/rust
git commit --no-gpg-sign -m "chore(toolchain): update llvm and rust submodules"

source tools/toolchain/env.sh
ninja -C "$SALTYOS_LLVM_BUILD_DIR" -j"$(nproc)"
ninja -C "$SALTYOS_LLVM_BUILD_DIR" install
python3 "$SALTYOS_RUST_SRC_DIR/x.py" install \
  --src "$SALTYOS_RUST_SRC_DIR" \
  --build-dir "$SALTYOS_RUST_BUILD_DIR" \
  --config "$SALTYOS_TOOLCHAIN_BUILD_ROOT/rust-bootstrap.toml" \
  --stage 1 \
  compiler/rustc library/std src
```

## Troubleshooting

### "unknown target triple 'x86_64-unknown-saltyos'"

You are using upstream `clang` or `rustc` instead of the patched versions. Run `tools/toolchain/doctor.sh` and check `which clang`, `which rustc`.

### LLVM build runs out of memory

Limit link parallelism:

```bash
cmake -S "$SALTYOS_LLVM_SRC_DIR/llvm" -B "$SALTYOS_LLVM_BUILD_DIR" -G Ninja \
  ... \
  -DLLVM_PARALLEL_LINK_JOBS=1
```

Each LLD link of a large LLVM library can use 4–8 GB of RAM.

### Rust build fails with "LLVM version mismatch"

Ensure `config.toml` uses:

- `[llvm] download-ci-llvm = false`
- `[target.x86_64-unknown-linux-gnu] llvm-config = ".../bin/llvm-config"`

Also verify `llvm-config` points to the patched LLVM in your active prefix.

### Rust bootstrap panics: `FileCheck ... does not exist`

Rust bootstrap sanity checks require `FileCheck` when using an external LLVM.

- `just toolchain-build-llvm` now configures `-DLLVM_INSTALL_UTILS=ON`
- It also links `FileCheck` into the prefix if LLVM did not install it

## See Also

- [BUILDING.md](BUILDING.md) — General SaltyOS build instructions
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture overview
