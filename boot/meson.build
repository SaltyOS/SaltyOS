# SaltyOS Bootloader Build Configuration
# SPDX-License-Identifier: GPL-2.0-only

# =============================================================================
# Common Sources
# =============================================================================

boot_common_src = files(
  'common/string.c',
  'common/print.c',
  'common/udiv64.c',
  'common/fb_console.c',
  'common/font_8x16.c',
)

# =============================================================================
# Stage 1: MBR (BIOS x86)
# =============================================================================

if build_bios_boot
  mbr = custom_target('mbr',
    input: 'stage1/arch/x86/bios/mbr.asm',
    output: 'mbr.bin',
    command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endif

# =============================================================================
# Stage 1: UEFI (all architectures — UEFI APIs are arch-neutral)
# =============================================================================

# UEFI compilation flags: clang --target=<arch>-unknown-uefi produces COFF objects
# directly, with the appropriate calling convention. No ELF->PE conversion needed.
uefi_c_args = c_efi_args + [
  '-I' + meson.current_source_dir(),
]

# Common UEFI print utility
uefi_common_src = files(
  'common/efi/print.c',
)

# Stage 1 UEFI source (same entry.c works for both x86_64 and aarch64)
stage1_uefi_c_src = files(
  'stage1/arch/x86/uefi/entry.c',
) + uefi_common_src

# Compile Stage 1 UEFI C files (produces COFF .obj)
stage1_uefi_c_objs = []
foreach src : stage1_uefi_c_src
  src_name = fs.name(src)
  obj_name = src_name.replace('.c', '.obj')
  dep_name = 'stage1_uefi_' + src_name.replace('.c', '.d')
  stage1_uefi_c_objs += custom_target('stage1_uefi_' + obj_name,
    input: src,
    output: 'stage1_uefi_' + obj_name,
    depfile: dep_name,
    command: cc_cmd + uefi_c_args + ['-MMD', '-MF', '@DEPFILE@', '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endforeach

# Link Stage 1 UEFI as PE/COFF EFI application directly via lld-link
efi = custom_target('efi',
  input: stage1_uefi_c_objs,
  output: efi_binary_name,
  command: [lld_link,
            '-subsystem:efi_application',
            '-nodefaultlib',
            '-dll',
            '-entry:efi_main',
            '-out:@OUTPUT@',
            '@INPUT@'],
  build_by_default: true,
)

# =============================================================================
# Stage 2: BIOS x86 (32-bit protected mode with BTX/V86)
# =============================================================================

if build_bios_boot
  # Stage 2 entry assembly (16-bit -> 32-bit protected mode)
  stage2_entry_asm = custom_target('stage2_entry_asm',
    input: 'stage2/arch/x86/bios/entry.asm',
    output: 'stage2_entry.o',
    command: [nasm, '-f', 'elf32',
              '-I', meson.current_source_dir() / 'stage2/arch/x86/bios/',
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Stage 2 BTX/V86 kernel (V86 mode for BIOS calls from protected mode)
  stage2_btx_asm = custom_target('stage2_btx_asm',
    input: 'common/arch/x86/bios/btx.asm',
    output: 'stage2_btx.o',
    command: [nasm, '-f', 'elf32',
              '-I', meson.current_source_dir() / 'common/arch/x86/bios/',
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Stage 2 C sources (32-bit)
  stage2_c_src = files(
    'common/arch/x86/bios/v86.c',
  )

  stage2_c_args = c_freestanding_args + [
    '--target=i686-unknown-none-elf',
    '-march=i686',
    '-I' + meson.current_source_dir(),
  ]

  # Compile Stage 2 C files
  stage2_c_objs = []
  foreach src : stage2_c_src + boot_common_src
    src_name = fs.name(src)
    obj_name = src_name.replace('.c', '.o')
    dep_name = 'stage2_' + src_name.replace('.c', '.d')
    stage2_c_objs += custom_target('stage2_' + obj_name,
      input: src,
      output: 'stage2_' + obj_name,
      depfile: dep_name,
      command: cc_cmd + stage2_c_args + ['-MMD', '-MF', '@DEPFILE@', '-c', '-o', '@OUTPUT@', '@INPUT@'],
      build_by_default: true,
    )
  endforeach

  # Stage 2 linker script
  stage2_ld_script = meson.current_source_dir() / 'stage2/arch/x86/bios/stage2.ld'

  # Link Stage 2
  stage2_elf = custom_target('stage2_elf',
    input: [stage2_entry_asm, stage2_btx_asm] + stage2_c_objs,
    output: 'stage2.elf',
    command: ['ld.lld', '-m', 'elf_i386', '-nostdlib', '-static',
              '-T', stage2_ld_script,
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Convert to binary
  stage2 = custom_target('stage2',
    input: stage2_elf,
    output: 'stage2.bin',
    command: [objcopy, '-O', 'binary', '@INPUT@', '@OUTPUT@'],
    build_by_default: true,
  )
endif

# =============================================================================
# Stage 2: UEFI (all architectures — same C code, different UEFI target)
# =============================================================================

# Stage 2 UEFI source
stage2_uefi_c_src = files(
  'stage2/arch/x86/uefi/main.c',
) + uefi_common_src

# Compile Stage 2 UEFI C files (produces COFF .obj)
stage2_uefi_c_objs = []
foreach src : stage2_uefi_c_src
  src_name = fs.name(src)
  obj_name = src_name.replace('.c', '.obj')
  dep_name = 'stage2_uefi_' + src_name.replace('.c', '.d')
  stage2_uefi_c_objs += custom_target('stage2_uefi_' + obj_name,
    input: src,
    output: 'stage2_uefi_' + obj_name,
    depfile: dep_name,
    command: cc_cmd + uefi_c_args + ['-MMD', '-MF', '@DEPFILE@', '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endforeach

# Link Stage 2 UEFI as PE/COFF EFI application directly via lld-link
stage2_efi = custom_target('stage2_efi',
  input: stage2_uefi_c_objs,
  output: 'stage2.efi',
  command: [lld_link,
            '-subsystem:efi_application',
            '-nodefaultlib',
            '-dll',
            '-entry:efi_main',
            '-out:@OUTPUT@',
            '@INPUT@'],
  build_by_default: true,
)

# =============================================================================
# Stage 3: Kernel Loader (32-bit BIOS, transitions to 64-bit at end)
# =============================================================================

if build_bios_boot
  # Stage 3 entry assembly (32-bit entry point)
  stage3_entry_asm = custom_target('stage3_entry_asm',
    input: 'stage3/arch/x86/bios/entry.asm',
    output: 'stage3_entry.o',
    command: [nasm, '-f', 'elf32',
              '-I', meson.current_source_dir() / 'stage3/',
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Stage 3 mode switch assembly (32->64 bit)
  stage3_mode_switch_asm = custom_target('stage3_mode_switch_asm',
    input: 'stage3/arch/x86/bios/mode_switch.asm',
    output: 'stage3_mode_switch.o',
    command: [nasm, '-f', 'elf32',
              '-I', meson.current_source_dir() / 'stage3/',
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Stage 3 BTX/V86 support (for BIOS calls from Stage 3)
  # Stage 3 has its own copy since it's a separate binary
  stage3_btx_asm = custom_target('stage3_btx_asm',
    input: 'common/arch/x86/bios/btx.asm',
    output: 'stage3_btx.o',
    command: [nasm, '-f', 'elf32',
              '-I', meson.current_source_dir() / 'common/arch/x86/bios/',
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Stage 3 V86 wrapper sources
  stage3_v86_src = files(
    'common/arch/x86/bios/v86.c',
  )

  stage3_c_src = files(
    'stage3/main.c',
    'stage3/bios_main.c',
    'stage3/boot_alloc.c',
    'stage3/elf.c',
    'stage3/arch/x86/paging.c',
    'stage3/handoff.c',
    'stage3/disk/bios_disk.c',
    'stage3/disk/memory_disk.c',
    'stage3/fs/raw.c',
    'stage3/fs/fat32.c',
    'stage3/fs/saltyfs.c',
  )

  # Stage 3 is 32-bit code
  stage3_c_args = c_freestanding_args + [
    '--target=i686-unknown-none-elf',
    '-march=i686',
    '-I' + meson.current_source_dir(),
  ]

  stage3_ld_script = meson.current_source_dir() / 'stage3/arch/x86/bios/stage3.ld'

  # Compile Stage 3 C files
  stage3_c_objs = []
  foreach src : stage3_c_src + stage3_v86_src + boot_common_src
    src_name = fs.name(src)
    obj_name = src_name.replace('.c', '.o')
    dep_name = 'stage3_' + src_name.replace('.c', '.d')
    stage3_c_objs += custom_target('stage3_' + obj_name,
      input: src,
      output: 'stage3_' + obj_name,
      depfile: dep_name,
      command: cc_cmd + stage3_c_args + ['-MMD', '-MF', '@DEPFILE@', '-c', '-o', '@OUTPUT@', '@INPUT@'],
      build_by_default: true,
    )
  endforeach

  # Link Stage 3 ELF (32-bit)
  stage3_elf = custom_target('stage3_elf',
    input: [stage3_entry_asm, stage3_mode_switch_asm, stage3_btx_asm] + stage3_c_objs,
    output: 'stage3.elf',
    command: ['ld.lld', '-m', 'elf_i386', '-nostdlib', '-static',
              '-T', stage3_ld_script,
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Convert to binary
  stage3 = custom_target('stage3',
    input: stage3_elf,
    output: 'stage3.bin',
    command: [objcopy, '-O', 'binary', '@INPUT@', '@OUTPUT@'],
    build_by_default: true,
  )
endif

# =============================================================================
# Stage 3: UEFI Kernel Loader (64-bit, loaded by UEFI Stage 2)
# =============================================================================

# Architecture-specific entry assembly and paging
if arch == 'x86_64'
  stage3_uefi_entry_asm = custom_target('stage3_uefi_entry_asm',
    input: 'stage3/arch/x86/uefi/entry_uefi.asm',
    output: 'stage3_uefi_entry.o',
    command: [nasm, '-f', 'elf64',
              '-I', meson.current_source_dir() / 'stage3/',
              '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stage3_paging_src = files('stage3/arch/x86/paging.c')
  stage3_uefi_ld_script = meson.current_source_dir() / 'stage3/arch/x86/uefi/stage3.ld'
elif arch == 'aarch64'
  stage3_uefi_entry_asm = custom_target('stage3_uefi_entry_asm',
    input: 'stage3/arch/aarch64/uefi/entry_uefi.S',
    output: 'stage3_uefi_entry.o',
    command: [cc_cmd, '--target=' + asm_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
    build_by_default: true,
  )
  stage3_paging_src = files('stage3/arch/aarch64/paging.c')
  stage3_uefi_ld_script = meson.current_source_dir() / 'stage3/arch/aarch64/uefi/stage3.ld'
endif

# Stage 3 UEFI C sources (shared across architectures)
stage3_uefi_c_src = files(
  'stage3/main.c',
  'stage3/uefi_main.c',
  'stage3/boot_alloc.c',
  'stage3/elf.c',
  'stage3/handoff.c',
) + stage3_paging_src

# Stage 3 UEFI common sources (string, print, fb - no udiv64 needed for 64-bit)
stage3_uefi_common_src = files(
  'common/string.c',
  'common/print.c',
  'common/fb_console.c',
  'common/font_8x16.c',
)

stage3_uefi_c_args = c_stage3_args + [
  '-DSTAGE3_UEFI',
  '-I' + meson.current_source_dir(),
]

# Compile Stage 3 UEFI C files
stage3_uefi_c_objs = []
foreach src : stage3_uefi_c_src + stage3_uefi_common_src
  src_name = fs.name(src)
  obj_name = src_name.replace('.c', '.o')
  dep_name = 'stage3_uefi_' + src_name.replace('.c', '.d')
  stage3_uefi_c_objs += custom_target('stage3_uefi_' + obj_name,
    input: src,
    output: 'stage3_uefi_' + obj_name,
    depfile: dep_name,
    command: cc_cmd + stage3_uefi_c_args + ['-MMD', '-MF', '@DEPFILE@', '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endforeach

# Link Stage 3 UEFI ELF (64-bit)
stage3_uefi_elf = custom_target('stage3_uefi_elf',
  input: [stage3_uefi_entry_asm] + stage3_uefi_c_objs,
  output: 'stage3_uefi.elf',
  command: ['ld.lld', '-m', kernel_link_emulation, '-nostdlib', '-static',
            '-T', stage3_uefi_ld_script,
            '-o', '@OUTPUT@', '@INPUT@'],
  build_by_default: true,
)

# Convert to binary
stage3_uefi = custom_target('stage3_uefi',
  input: stage3_uefi_elf,
  output: 'stage3_uefi.bin',
  command: [objcopy, '-O', 'binary', '@INPUT@', '@OUTPUT@'],
  build_by_default: true,
)

# =============================================================================
# Summary
# =============================================================================

boot_summary = {}
if build_bios_boot
  boot_summary += {
    'MBR': mbr.full_path(),
    'Stage 2 (BIOS)': stage2.full_path(),
    'Stage 3': stage3.full_path(),
  }
endif
boot_summary += {
  'Stage 3 (UEFI)': stage3_uefi.full_path(),
  efi_binary_name: efi.full_path(),
  'Stage 2 (UEFI)': stage2_efi.full_path(),
}
summary(boot_summary, section: 'Bootloader')
