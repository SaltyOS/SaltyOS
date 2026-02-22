# SaltyOS Runtime Dynamic Linker Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds ld-salty.so as a static PIE with no external dependencies.

rtld_sources = files(
    'rtld_main.c',
    'rtld_elf.c',
    'rtld_symbol.c',
    'rtld_reloc.c',
    'rtld_resolve.S',
)
rtld_link_script = meson.current_source_dir() / 'rtld.ld'

ld_salty_so = custom_target('ld_salty_so',
    input: rtld_sources,
    output: 'ld-salty.so',
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.current_source_dir(),
        '-T', rtld_link_script,
        '-Wl,-soname,ld-salty.so',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
