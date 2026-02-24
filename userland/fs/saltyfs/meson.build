# SaltyOS SaltyFS Server Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

saltyfs_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'

# Step 1: Rust -> .o
saltyfs_obj = custom_target('saltyfs_obj',
  input: files('src/main.rs'),
  output: 'saltyfs.o',
  depfile: 'saltyfs.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=saltyfs',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
saltyfs_elf = custom_target('saltyfs_elf',
  input: [saltyfs_obj],
  output: 'saltyfs.elf',
  depends: [libsalty_so, libc_so],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-T', saltyfs_link,
    '-L', libsalty_build_dir,
    '-L', meson.project_build_root() / 'lib/saltyc',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lsalty', '-lc',
  ],
  build_by_default: true,
)
