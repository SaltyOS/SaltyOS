# SaltyOS Console Server Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds console.elf as a PIE (ET_DYN) ELF64 binary.

console_src = files('main.c')
console_link = meson.current_source_dir() / 'link.ld'

console_elf = custom_target('console_elf',
    input: [console_src, '../../lib/libc/string.c'],
    output: 'console.elf',
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie', '-shared',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', console_link,
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
