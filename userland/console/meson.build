# SaltyOS Console Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

console_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'

# Step 1: Rust -> .o
console_obj = custom_target('console_obj',
  input: files('src/main.rs'),
  output: 'console.o',
  command: [rustc,
    rust_userland_args,
    '--emit=obj',
    '--crate-name=console',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
console_elf = custom_target('console_elf',
  input: [console_obj],
  output: 'console.elf',
  depends: [libsalty_so, libc_so],
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', console_link,
    '-Wl,--dynamic-linker,/lib/ld-salty.so',
    '-L', libsalty_build_dir,
    '-L', meson.project_build_root() / 'lib/saltyc',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lsalty', '-lc',
  ],
  build_by_default: true,
)
