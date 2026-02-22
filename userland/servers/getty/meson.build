# SaltyOS Getty Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

getty_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'
saltyc_build_dir = meson.project_build_root() / 'lib/saltyc'

# Step 1: Rust -> .o
getty_obj = custom_target('getty_obj',
  input: files('src/main.rs'),
  output: 'getty.o',
  depfile: 'getty.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=getty',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
getty_elf = custom_target('getty_elf',
  input: [getty_obj],
  output: 'getty.elf',
  depends: [libsalty_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', getty_link,
    '-Wl,--dynamic-linker,/lib/ld-salty.so',
    '-L', libsalty_build_dir,
    '-L', saltyc_build_dir,
    '-o', '@OUTPUT@',
    saltyc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-lsalty', '-lc',
  ],
  build_by_default: true,
)
