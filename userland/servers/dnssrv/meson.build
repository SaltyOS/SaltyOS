# SaltyOS DNS Resolver Service Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

dnssrv_link = meson.current_source_dir() / 'link.ld'
libbesalt_build_dir = meson.project_build_root() / 'lib/besalt/lib'

# Step 1: Rust -> .o
dnssrv_obj = custom_target('dnssrv_obj',
  input: files('src/main.rs'),
  output: 'dnssrv.o',
  depfile: 'dnssrv.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=dnssrv',
    '--crate-type=lib',
    '--extern', 'besalt=' + libbesalt_build_dir / 'libbesalt.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libbesalt_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
dnssrv_elf = custom_target('dnssrv_elf',
  input: [dnssrv_obj],
  output: 'dnssrv.elf',
  depends: [libbesalt_so, libc_so],
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', dnssrv_link,
    '-Wl,--dynamic-linker,/lib/ld-besalt.so',
    '-L', libbesalt_build_dir,
    '-L', meson.project_build_root() / 'lib/besalt/c',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
