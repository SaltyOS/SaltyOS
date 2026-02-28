# SaltyOS PCI Enumeration Server Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

pcisrv_link = meson.current_source_dir() / 'link.ld'
libbesalt_build_dir = meson.project_build_root() / 'lib/besalt/lib'

# Step 1: Rust -> .o
pcisrv_obj = custom_target('pcisrv_obj',
  input: files('src/main.rs'),
  output: 'pcisrv.o',
  depfile: 'pcisrv.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=pcisrv',
    '--crate-type=lib',
    '--extern', 'besalt=' + libbesalt_build_dir / 'libbesalt.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libbesalt_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
pcisrv_elf = custom_target('pcisrv_elf',
  input: [pcisrv_obj],
  output: 'pcisrv.elf',
  depends: [libbesalt_so, libc_so],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-T', pcisrv_link,
    '-L', libbesalt_build_dir,
    '-L', meson.project_build_root() / 'lib/besalt/c',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
