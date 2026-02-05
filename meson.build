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
# Build Options
# =============================================================================

arch = get_option('arch')
build_boot = get_option('build_boot')
build_kernel = get_option('build_kernel')
build_userland = get_option('build_userland')

# =============================================================================
# Toolchain (clang/lld required, nightly rustc required)
# =============================================================================

# C Compiler: must be clang
cc = meson.get_compiler('c', native: false)
if cc.get_id() != 'clang'
  error('SaltyOS requires clang. Got: ' + cc.get_id())
endif
cc_cmd = cc.cmd_array()

# Assembler
nasm = find_program('nasm', required: build_boot)

# Binary tools
objcopy = find_program('llvm-objcopy', required: build_boot)
lld_link = find_program('lld-link', required: build_boot)

# Rust: must be nightly (required for building core library)
rustc = find_program('rustc', required: build_kernel)

fs = import('fs')

if build_kernel
  # Verify nightly toolchain
  rustc_version = run_command(rustc, '--version', capture: true, check: true).stdout().strip()
  if not rustc_version.contains('nightly')
    error('SaltyOS requires nightly rustc for building core library.\n' +
          'Got: ' + rustc_version + '\n' +
          'Fix: rustup default nightly, or add nightly bin to PATH')
  endif

  # Get rust-src path from sysroot
  rustc_sysroot = run_command(rustc, '--print', 'sysroot', capture: true, check: true).stdout().strip()
  rust_lib_src = rustc_sysroot / 'lib/rustlib/src/rust/library'

  # Verify rust-src component is installed
  if not fs.is_file(rust_lib_src / 'core/src/lib.rs')
    error('rust-src component not found.\n' +
          'Expected: ' + rust_lib_src + '\n' +
          'Fix: rustup component add rust-src')
  endif
endif

# =============================================================================
# Architecture Configuration
# =============================================================================

if arch == 'x86_64'
  rust_target = 'x86_64-unknown-none'
  efi_target = 'x86_64-unknown-uefi'
elif arch == 'aarch64'
  rust_target = 'aarch64-unknown-none'
  efi_target = 'aarch64-unknown-uefi'
else
  error('Unsupported architecture: ' + arch)
endif

# =============================================================================
# Compiler Flags
# =============================================================================

# Base freestanding flags (shared across boot components)
c_freestanding_args = [
  '-ffreestanding',
  '-fno-builtin',
  '-fcf-protection=none',
  '-fno-stack-protector',
  '-fno-pic',
  '-fno-pie',
  '-mno-red-zone',
  '-nostdlib',
]

# EFI-specific flags (PE/COFF via clang UEFI target)
c_efi_args = c_freestanding_args + [
  '-target', efi_target,
  '-fshort-wchar',
  '-DEFI_BUILD',
]

# Stage3 flags (loaded at 0x10000, small code model sufficient)
c_stage3_args = c_freestanding_args + [
  '-m64',
  '-mcmodel=small',
]

# Kernel flags (higher half)
if arch == 'x86_64'
  c_kernel_args = c_freestanding_args + [
    '-mcmodel=kernel',
    '-mno-sse',
    '-mno-mmx',
    '-mno-sse2',
    '-mno-3dnow',
    '-mno-avx',
  ]
else
  c_kernel_args = c_freestanding_args
endif

# Rust flags
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
  # Build core library and compiler_builtins first
  subdir('rust')
  subdir('kernel')
endif

if build_userland
  subdir('userland')
endif

# =============================================================================
# Initrd Generation (CPIO archive with init.elf)
# =============================================================================

mkcpio = find_program('tools/mkcpio.py', required: false)
initrd_args = []
initrd_inputs = []
initrd_target = []

if build_userland and mkcpio.found()
  initrd = custom_target('initrd',
    input: [init_elf],
    output: 'initrd.cpio',
    command: [mkcpio,
      '--output', '@OUTPUT@',
      'init.elf=@INPUT0@',
    ],
    build_by_default: true,
  )
  initrd_args = ['--initrd', initrd.full_path()]
  initrd_inputs = [initrd]
  initrd_target = [initrd]
endif

# =============================================================================
# Disk Image Generation
# =============================================================================

mkimage = find_program('tools/mkimage.py', required: false)

if mkimage.found() and build_boot and build_kernel

  # BIOS disk image
  disk_image = custom_target('disk_image',
    input: [mbr, stage2, stage3, kernel] + initrd_inputs,
    output: 'saltyos.img',
    command: [mkimage,
      '--build-dir', meson.project_build_root(),
      '--output', '@OUTPUT@',
      '--size', '8',
    ] + initrd_args,
    build_by_default: true,
  )

  # UEFI disk image
  if arch == 'x86_64'
    uefi_image = custom_target('uefi_image',
      input: [efi, stage2_efi, stage3_uefi, kernel] + initrd_inputs,
      output: 'saltyos-uefi.img',
      command: [mkimage,
        '--efi',
        '--build-dir', meson.project_build_root(),
        '--output', '@OUTPUT@',
        '--size', '64',
      ] + initrd_args,
      build_by_default: false,
    )
  endif

endif

# =============================================================================
# Summary
# =============================================================================

summary({
  'Architecture': arch,
  'Bootloader': build_boot,
  'Kernel': build_kernel,
  'Userland': build_userland,
}, section: 'Build')

summary({
  'C Compiler': cc.get_id() + ' ' + cc.version(),
  'Rust': rustc.found() ? rustc_version : 'not found',
  'NASM': nasm.found() ? nasm.full_path() : 'not found',
}, section: 'Toolchain')

summary({
  'Rust Target': rust_target,
  'Rust Lib Src': build_kernel ? rust_lib_src : 'N/A',
  'EFI Target': efi_target,
}, section: 'Targets')
