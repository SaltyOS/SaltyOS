# SaltyOS VFS Server Build
# SPDX-License-Identifier: GPL-2.0-only

vfs_src = files('main.c')
vfs_link = meson.current_source_dir() / 'link.ld'

vfs_elf = custom_target('vfs_elf',
    input: [vfs_src, '../../lib/libc/string.c'],
    output: 'vfs.elf',
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie', '-shared',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-DSALTY_STATIC',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', vfs_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
