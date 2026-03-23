# SaltyOS VFS Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

vfs_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'
libbesalt_build_dir = meson.project_build_root() / 'lib/besalt/lib'

# Step 1: Rust -> .o
vfs_obj = custom_target('vfs_obj',
  input: files('src/main.rs'),
  output: 'vfs.o',
  depfile: 'vfs.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=vfs',
    '--crate-type=lib',
    '--extern', 'besalt=' + libbesalt_build_dir / 'libbesalt.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libbesalt_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
vfs_elf = custom_target('vfs_elf',
  input: [vfs_obj],
  output: 'vfs.elf',
  depends: [libbesalt_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', vfs_link,
    '-L', libbesalt_build_dir,
    '-L', besaltc_build_dir,
    '-o', '@OUTPUT@',
    besaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
