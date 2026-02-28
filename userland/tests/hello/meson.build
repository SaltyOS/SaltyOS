# SaltyOS Hello World (C, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

hello_link = meson.current_source_dir() / 'link.ld'

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
    '-I', besaltc_inc_dir,
    '-T', hello_link,
    '-L', libbesalt_build_dir,
    '-L', besaltc_build_dir,
    '-o', '@OUTPUT@',
    besaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-lbesalt', '-lc',
  ],
  build_by_default: true,
)
