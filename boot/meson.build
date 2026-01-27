# SaltyOS Bootloader Build System
# SPDX-License-Identifier: GPL-2.0-only

# =============================================================================
# Inherited from parent:
#   cc, cc_cmd, nasm
#   c_freestanding_args, c_efi_args, c_stage3_args
#   arch, efi_target
# =============================================================================

# Targets exported to parent
mbr = []
vbr = []
efi = []
stage2 = []
stage2_efi = []
stage3 = []

# Paths
dir_boot = meson.current_source_dir()
dir_common = dir_boot / 'common'
dir_stage2 = dir_boot / 'stage2'

# Include paths
inc_common = ['-I' + dir_common]
inc_stage2 = ['-I' + dir_stage2]

# =============================================================================
# Stage 1: Boot Sector (BIOS + EFI)
# =============================================================================

if arch == 'x86_64'

  # --- BIOS: MBR ---
  mbr = custom_target('mbr',
    input: 'stage1/bios/mbr.asm',
    output: 'mbr.bin',
    command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # --- BIOS: VBR ---
  vbr = custom_target('vbr',
    input: 'stage1/bios/vbr.asm',
    output: 'vbr.bin',
    command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # --- EFI: BOOTX64.EFI ---
  s1_efi_src = [
    'stage1/efi/main.c',
    'common/print.c',
  ]
  s1_efi_objs = []
  foreach src : s1_efi_src
    s1_efi_objs += custom_target('s1_efi_' + src.underscorify(),
      input: src,
      output: 's1_efi_@BASENAME@.o',
      command: [cc_cmd, c_efi_args, inc_common, '-c', '@INPUT@', '-o', '@OUTPUT@'],
    )
  endforeach

  # Link via clang driver (handles PE/COFF automatically)
  # Note: We disable DYNAMIC_BASE and HIGH_ENTROPY_VA because:
  # 1. x86_64 code uses RIP-relative addressing (position-independent by default)
  # 2. Without actual relocations in .reloc section, these flags cause UEFI to fail
  # 3. ImageBase=0 matches gnu-efi/EDK2 convention for fully PIC binaries
  # LLD-link uses MSVC-style options: /option:value instead of --option
  efi = custom_target('bootx64_efi',
    input: s1_efi_objs,
    output: 'BOOTX64.EFI',
    command: [
      cc_cmd,
      '-target', efi_target,
      '-nostdlib',
      '-Wl,-entry:efi_main',
      '-Wl,-subsystem:efi_application',
      '-Wl,-dynamicbase:no',
      '-Wl,-highentropyva:no',
      '-Wl,-nxcompat:no',
      '-Wl,-base:0',
      '-fuse-ld=lld',
      '-o', '@OUTPUT@',
      '@INPUT@',
    ],
    build_by_default: true,
  )

endif

# =============================================================================
# Stage 2: Loader (BIOS + EFI)
# =============================================================================

# --- BIOS: stage2.bin ---
stage2 = custom_target('stage2_bios',
  input: 'stage2/bios/entry.asm',
  output: 'stage2.bin',
  command: [nasm, '-f', 'bin', '-o', '@OUTPUT@', '@INPUT@'],
  build_by_default: true,
)

# --- EFI: stage2.efi (PE/COFF application) ---
if arch == 'x86_64'

  s2_efi_src = [
    'stage2/efi/entry.c',
    'stage2/efi/file.c',
    'stage2/efi/memory.c',
    'stage2/efi/fb.c',
    'stage2/efi/acpi.c',
    'stage2/common/main.c',
    'stage2/common/bootinfo.c',
    'common/memory.c',
    'common/print.c',
  ]
  s2_efi_objs = []
  foreach src : s2_efi_src
    s2_efi_objs += custom_target('s2_efi_' + src.underscorify(),
      input: src,
      output: 's2_efi_' + src.underscorify() + '.o',
      command: [cc_cmd, c_efi_args, inc_common, inc_stage2, '-c', '@INPUT@', '-o', '@OUTPUT@'],
    )
  endforeach

  # Link PE/COFF EFI application directly
  stage2_efi = custom_target('stage2_efi',
    input: s2_efi_objs,
    output: 'stage2.efi',
    command: [
      cc_cmd,
      '-target', efi_target,
      '-nostdlib',
      '-Wl,-entry:stage2_efi_main',
      '-Wl,-subsystem:efi_application',
      '-Wl,-dynamicbase',
      '-Wl,-highentropyva:no',
      '-Wl,-nxcompat',
      '-Wl,-base:0',
      '-fuse-ld=lld',
      '-o', '@OUTPUT@',
      '@INPUT@',
    ],
    build_by_default: true,
  )

endif

# =============================================================================
# Stage 3: Kernel Loader
# =============================================================================

# Entry point (assembly)
s3_entry = custom_target('s3_entry',
  input: 'stage3/entry.asm',
  output: 's3_entry.o',
  command: [nasm, '-f', 'elf64', '-o', '@OUTPUT@', '@INPUT@'],
)

# C sources
s3_src = [
  'stage3/main.c',
  'stage3/elf.c',
  'stage3/disk.c',
  'stage3/fs/saltyfs.c',
  'common/print.c',
  'common/memory.c',
]
s3_objs = []
foreach src : s3_src
  s3_objs += custom_target('s3_' + src.underscorify(),
    input: src,
    output: 's3_' + src.underscorify() + '.o',
    command: [cc_cmd, c_stage3_args, inc_common, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  )
endforeach

# Link stage3.elf first, then convert to flat binary
stage3_elf = custom_target('stage3_elf',
  input: [s3_entry] + s3_objs,
  output: 'stage3.elf',
  command: [
    cc_cmd,
    '-nostdlib',
    '-static',
    '-fuse-ld=lld',
    '-Wl,--no-pie',
    '-Wl,-T,' + dir_boot / 'stage3/stage3.ld',
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: false,
)

stage3 = custom_target('stage3_bin',
  input: stage3_elf,
  output: 'stage3.bin',
  command: [objcopy, '-O', 'binary', '@INPUT@', '@OUTPUT@'],
  build_by_default: true,
)
