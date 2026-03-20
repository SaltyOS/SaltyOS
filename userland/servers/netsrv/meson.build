# SaltyOS Network Stack Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

netsrv_link = meson.current_source_dir() / 'link.ld'
libbesalt_build_dir = meson.project_build_root() / 'lib/besalt/lib'

# Step 1: Rust -> .o
netsrv_obj = custom_target('netsrv_obj',
  input: files('src/main.rs'),
  output: 'netsrv.o',
  depfile: 'netsrv.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=netsrv',
    '--crate-type=lib',
    '--extern', 'besalt=' + libbesalt_build_dir / 'libbesalt.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libbesalt_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
netsrv_elf = custom_target('netsrv_elf',
  input: [netsrv_obj],
  output: 'netsrv.elf',
  depends: [libbesalt_so, libc_so],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', netsrv_link,
    '-Wl,--dynamic-linker,/lib/ld-besalt.so',
    '-L', libbesalt_build_dir,
    '-L', meson.project_build_root() / 'lib/besalt/c',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
