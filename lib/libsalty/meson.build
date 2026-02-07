# libsalty.so - SaltyOS System Call Library
# SPDX-License-Identifier: GPL-2.0-only

libsalty_link = meson.current_source_dir() / 'libsalty.ld'

libsalty_so = custom_target('libsalty_so',
    input: files('salty_impl.c', 'fork.S'),
    output: 'libsalty.so',
    command: [cc_cmd,
        '-fPIC', '-shared',
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-Wl,-soname,libsalty.so',
        '-Wl,--hash-style=gnu',
        '-I', meson.current_source_dir(),
        '-T', libsalty_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
