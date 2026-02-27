# SaltyOS Runtime Dynamic Linker Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds ld-besalt.so as a static PIE with no external dependencies.

rtld_sources = files(
    'rtld_main.c',
    'rtld_elf.c',
    'rtld_symbol.c',
    'rtld_reloc.c',
    'rtld_resolve.S',
)
rtld_link_script = meson.current_source_dir() / 'rtld.ld'

ld_besalt_so = custom_target('ld_besalt_so',
    input: rtld_sources,
    output: 'ld-besalt.so',
    command: [cc_cmd,
        '--target=' + c_target,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fno-plt', '-Wl,-Bsymbolic',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.current_source_dir(),
        '-T', rtld_link_script,
        '-Wl,-soname,ld-besalt.so',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
