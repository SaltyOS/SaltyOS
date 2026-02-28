# SaltyOS Getty Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

getty_link = meson.current_source_dir() / 'link.ld'

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
    '--extern', 'besalt=' + libbesalt_build_dir / 'libbesalt.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libbesalt_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
getty_elf = custom_target('getty_elf',
  input: [getty_obj],
  output: 'getty.elf',
  depends: [libbesalt_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-T', getty_link,
    '-L', libbesalt_build_dir,
    '-L', besaltc_build_dir,
    '-o', '@OUTPUT@',
    besaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
