# SaltyOS - Unix-like Microkernel Operating System
# SPDX-License-Identifier: GPL-2.0-only

project('saltyos', ['c'],
  version: '0.1.0',
  license: 'GPL-2.0-only',
  meson_version: '>=1.1',
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=false',
    'b_staticpic=false',
    'b_pie=false',
  ])

# =============================================================================
# Build Configuration
# =============================================================================

arch = get_option('arch')
build_boot = get_option('build_boot')
build_kernel = get_option('build_kernel')
build_userland = get_option('build_userland')

message('Target architecture: ' + arch)
message('Build bootloader: ' + build_boot.to_string())
message('Build kernel: ' + build_kernel.to_string())
message('Build userland: ' + build_userland.to_string())

# =============================================================================
# Toolchain Detection
# =============================================================================

# Find required tools
rustc = find_program('rustc', required: build_kernel)
nasm = find_program('nasm', required: build_boot)
ld = find_program('ld', required: true)

# Architecture-specific settings
if arch == 'x86_64'
  rust_target = 'x86_64-unknown-none'
  asm_format = 'elf64'
  kernel_base = '0xFFFFFFFF80000000'  # Higher half
elif arch == 'aarch64'
  rust_target = 'aarch64-unknown-none'
  asm_format = 'elf64'
  kernel_base = '0xFFFF000000000000'
else
  error('Unsupported architecture: ' + arch)
endif

# =============================================================================
# Compiler Flags
# =============================================================================

# Freestanding C flags (no libc, no standard library)
c_freestanding_args = [
  '-ffreestanding',
  '-fno-stack-protector',
  '-fno-pic',
  '-fno-pie',
  '-mno-red-zone',
  '-nostdlib',
  '-nostdinc',
]

# Architecture-specific C flags
if arch == 'x86_64'
  c_freestanding_args += [
    '-mcmodel=kernel',
    '-mno-sse',
    '-mno-mmx',
    '-mno-sse2',
    '-mno-3dnow',
    '-mno-avx',
  ]
endif

# Rust flags for kernel
rust_kernel_args = [
  '--edition=2024',
  '--target=' + rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=kernel',
  '-C', 'relocation-model=static',
  '-C', 'soft-float',
]

# =============================================================================
# Subdirectories
# =============================================================================

if build_boot
  subdir('boot')
endif

if build_kernel
  subdir('kernel')
endif

if build_userland
  subdir('userland')
endif

# =============================================================================
# Image Generation
# =============================================================================

mkimage = find_program('tools/mkimage.py', required: false)

if mkimage.found() and build_boot and build_kernel
  disk_image = custom_target('disk_image',
    input: [mbr, stage2, stage3, kernel],
    output: 'saltyos.img',
    command: [mkimage,
      '--arch', arch,
      '--mbr', '@INPUT0@',
      '--stage2', '@INPUT1@',
      '--stage3', '@INPUT2@',
      '--kernel', '@INPUT3@',
      '--output', '@OUTPUT@',
      '--size', '8',
    ],
    build_by_default: true,
  )
endif

# =============================================================================
# Summary
# =============================================================================

summary({
  'Architecture': arch,
  'Build Bootloader': build_boot,
  'Build Kernel': build_kernel,
  'Build Userland': build_userland,
  'Rust Target': rust_target,
}, section: 'Configuration')

summary({
  'rustc': rustc.found() ? rustc.full_path() : 'not found',
  'nasm': nasm.found() ? nasm.full_path() : 'not found',
}, section: 'Tools')
