# SaltyOS Hello World (C, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

hello_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'
saltyc_build_dir = meson.project_build_root() / 'lib/saltyc'

# C source -> .elf (compile + link in one step)
hello_elf = custom_target('hello_elf',
  input: files('main.c'),
  output: 'hello.elf',
  depends: [libsalty_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '-nostdinc', '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-I', saltyc_inc_dir,
    '-T', hello_link,
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
