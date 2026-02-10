# SaltyOS VFS Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

vfs_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'

# Step 1: Rust -> .o
vfs_obj = custom_target('vfs_obj',
  input: files('src/main.rs'),
  output: 'vfs.o',
  command: [rustc,
    rust_userland_args,
    '--emit=obj',
    '--crate-name=vfs',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
vfs_elf = custom_target('vfs_elf',
  input: [vfs_obj],
  output: 'vfs.elf',
  depends: [libsalty_so, libc_so],
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', vfs_link,
    '-Wl,--dynamic-linker,/lib/ld-salty.so',
    '-L', libsalty_build_dir,
    '-L', meson.project_build_root() / 'lib/saltyc',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lsalty', '-lc',
  ],
  build_by_default: true,
)
