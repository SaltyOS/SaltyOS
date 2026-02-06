# SaltyOS Hello Test Program Build
# SPDX-License-Identifier: GPL-2.0-only

hello_src = files('main.c')
hello_link = meson.current_source_dir() / 'link.ld'

hello_elf = custom_target('hello_elf',
    input: [hello_src],
    output: 'hello.elf',
    depends: [libsalty_so, libc_so],
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', hello_link,
        '-Wl,--dynamic-linker,/lib/ld-salty.so',
        '-L', meson.project_build_root() / 'lib/libsalty',
        '-L', meson.project_build_root() / 'lib/libc',
        '-o', '@OUTPUT@',
        '@INPUT@',
        '-lsalty', '-lc',
    ],
    build_by_default: true,
)
