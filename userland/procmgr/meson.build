# SaltyOS Process Manager Build
# SPDX-License-Identifier: GPL-2.0-only

procmgr_src = files('main.c')
procmgr_link = meson.current_source_dir() / 'link.ld'

procmgr_elf = custom_target('procmgr_elf',
    input: [procmgr_src, '../../lib/libc/string.c'],
    output: 'procmgr.elf',
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie', '-shared',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-DSALTY_STATIC',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', procmgr_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
