# SaltyOS mmap_test Build
# SPDX-License-Identifier: GPL-2.0-only

mmap_test_src = files('main.c')
mmap_test_link = meson.current_source_dir() / 'link.ld'

mmap_test_elf = custom_target('mmap_test_elf',
    input: [mmap_test_src],
    output: 'mmap_test.elf',
    depends: [libsalty_so, libc_so],
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', mmap_test_link,
        '-Wl,--dynamic-linker,/lib/ld-salty.so',
        '-L', meson.project_build_root() / 'lib/libsalty',
        '-L', meson.project_build_root() / 'lib/libc',
        '-o', '@OUTPUT@',
        '@INPUT@',
        '-lsalty', '-lc',
    ],
    build_by_default: true,
)
