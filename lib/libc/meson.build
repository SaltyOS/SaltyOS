# libc.so - SaltyOS Minimal C Library
# SPDX-License-Identifier: GPL-2.0-only

libc_link = meson.current_source_dir() / 'libc.ld'

libc_so = custom_target('libc_so',
    input: files('string.c'),
    output: 'libc.so',
    command: [cc_cmd,
        '-fPIC', '-shared',
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-Wl,-soname,libc.so',
        '-Wl,--hash-style=gnu',
        '-I', meson.current_source_dir(),
        '-T', libc_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
