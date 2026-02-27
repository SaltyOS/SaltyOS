# SaltyOS Hello World (C, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

hello_link = meson.current_source_dir() / 'link.ld'
libbesalt_build_dir = meson.project_build_root() / 'lib/besalt/lib'
saltyc_build_dir = meson.project_build_root() / 'lib/besalt/c'

# C source -> .elf (compile + link in one step)
hello_elf = custom_target('hello_elf',
  input: files('main.c'),
  output: 'hello.elf',
  depends: [libbesalt_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdinc', '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-I', saltyc_inc_dir,
    '-T', hello_link,
    '-L', libbesalt_build_dir,
    '-L', saltyc_build_dir,
    '-o', '@OUTPUT@',
    saltyc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
