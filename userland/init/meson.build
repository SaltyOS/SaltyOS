# SaltyOS Init Process Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds init.elf as a PIE (ET_DYN) ELF64 binary.
# Uses libsalty (header-only syscall wrappers) and libc (string functions).

init_src = files('main.c')
init_link = meson.current_source_dir() / 'link.ld'

init_elf = custom_target('init_elf',
    input: [init_src, '../../lib/libc/string.c'],
    output: 'init.elf',
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie', '-shared',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-DSALTY_STATIC',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', init_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
