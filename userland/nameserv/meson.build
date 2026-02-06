# SaltyOS Name Server Build
# SPDX-License-Identifier: GPL-2.0-only

nameserv_src = files('main.c')
nameserv_link = meson.current_source_dir() / 'link.ld'

nameserv_elf = custom_target('nameserv_elf',
    input: [nameserv_src, '../../lib/libc/string.c'],
    output: 'nameserv.elf',
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie', '-shared',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-DSALTY_STATIC',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', nameserv_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
