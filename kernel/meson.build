# SaltyOS Kernel Build
# SPDX-License-Identifier: GPL-2.0-only

# =============================================================================
# Inherited from parent:
#   cc_cmd, rustc, rust_target, c_kernel_args
# =============================================================================

kernel_src = files('src/lib.rs')
kernel_ld = meson.current_source_dir() / 'kernel.ld'

# Step 1: Compile Rust to object file
kernel_obj = custom_target('kernel_obj',
  input: kernel_src,
  output: 'kernel.o',
  command: [
    rustc,
    '--edition=2024',
    '--emit=obj',
    '--crate-name=saltyos_kernel',
    '--target=' + rust_target,
    '-C', 'panic=abort',
    '-C', 'opt-level=2',
    '-C', 'debuginfo=2',
    '-C', 'code-model=kernel',
    '-C', 'relocation-model=static',
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

# Step 2: Link object file into ELF executable (via clang driver)
kernel = custom_target('kernel',
  input: kernel_obj,
  output: 'kernel.elf',
  command: [
    cc_cmd,
    '-nostdlib',
    '-static',
    '-fuse-ld=lld',
    '-Wl,--no-pie',
    '-Wl,-n',
    '-Wl,-T,' + kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
