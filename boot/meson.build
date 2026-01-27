# SaltyOS Bootloader Build
# SPDX-License-Identifier: GPL-2.0-only

# Common includes
boot_inc = include_directories('common')

# Freestanding C flags for bootloader
boot_c_args = [
  '-ffreestanding',
  '-fno-stack-protector',
  '-fno-pic',
  '-mno-red-zone',
  '-nostdlib',
  '-nostdinc',
  '-I' + meson.current_source_dir() / 'common',
]

# =============================================================================
# Stage 1: MBR
# =============================================================================

if arch == 'x86_64'
  mbr = custom_target('mbr',
    input: 'stage1/bios/mbr.asm',
    output: 'mbr.bin',
    command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  vbr = custom_target('vbr',
    input: 'stage1/bios/vbr.asm',
    output: 'vbr.bin',
    command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endif

# =============================================================================
# Stage 2: Real mode → Long mode transition
# =============================================================================

# Stage 2 is pure assembly, outputs flat binary
stage2 = custom_target('stage2',
  input: 'stage2/entry.asm',
  output: 'stage2.bin',
  command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
  build_by_default: true,
)

# =============================================================================
# Stage 3: Kernel loader (64-bit C code)
# =============================================================================

stage3_ld = meson.current_source_dir() / 'stage3/stage3.ld'

# Compile Stage 3 assembly entry stub
stage3_entry_obj = custom_target('stage3_entry_obj',
  input: 'stage3/entry.asm',
  output: 'stage3_entry.o',
  command: [nasm, '-f', 'elf64', '-o', '@OUTPUT@', '@INPUT@'],
)

# Compile Stage 3 C files to object files
stage3_main_obj = custom_target('stage3_main_obj',
  input: 'stage3/main.c',
  output: 'stage3_main.o',
  command: [
    find_program('gcc'),
    boot_c_args,
    '-m64',
    '-mcmodel=large',
    '-c', '@INPUT@',
    '-o', '@OUTPUT@',
  ],
)

stage3_elf_obj = custom_target('stage3_elf_obj',
  input: 'stage3/elf.c',
  output: 'stage3_elf.o',
  command: [
    find_program('gcc'),
    boot_c_args,
    '-m64',
    '-mcmodel=large',
    '-c', '@INPUT@',
    '-o', '@OUTPUT@',
  ],
)

# Link Stage 3 into flat binary (entry stub must be first)
stage3 = custom_target('stage3',
  input: [stage3_entry_obj, stage3_main_obj, stage3_elf_obj],
  output: 'stage3.bin',
  command: [
    ld,
    '-T', stage3_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
