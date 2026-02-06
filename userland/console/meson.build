# SaltyOS Console Server Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds console.elf as a dynamically-linked PIE (ET_DYN) ELF64 binary.
# Links against libsalty.so and libc.so via the runtime linker ld-salty.so.

console_src = files('main.c')
console_link = meson.current_source_dir() / 'link.ld'

console_elf = custom_target('console_elf',
    input: [console_src],
    output: 'console.elf',
    depends: [libsalty_so, libc_so],
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', console_link,
        '-Wl,--dynamic-linker,/lib/ld-salty.so',
        '-L', meson.project_build_root() / 'lib/libsalty',
        '-L', meson.project_build_root() / 'lib/libc',
        '-o', '@OUTPUT@',
        '@INPUT@',
        '-lsalty', '-lc',
    ],
    build_by_default: true,
)
