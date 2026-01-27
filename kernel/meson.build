# SaltyOS Kernel Build
# SPDX-License-Identifier: GPL-2.0-only

# Kernel is built using rustc directly (not Meson's Rust support)
# because we need freestanding no_std build

kernel_src = files(
  'src/lib.rs',
)

# Linker script
kernel_ld = meson.current_source_dir() / 'kernel.ld'

# Use built-in x86_64-unknown-none target (has prebuilt core)
rust_target = 'x86_64-unknown-none'

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
  install: false,
)

# Step 2: Link object file into ELF executable
kernel = custom_target('kernel',
  input: kernel_obj,
  output: 'kernel.elf',
  command: [
    ld,
    '-n',                           # Don't page align sections
    '-nostdlib',                    # No standard library
    '-T', kernel_ld,                # Use linker script
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
  install: false,
)

# Make kernel available to parent
kernel_dep = declare_dependency(
  sources: kernel,
)
