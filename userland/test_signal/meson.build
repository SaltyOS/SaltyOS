# SaltyOS test_signal Build
# SPDX-License-Identifier: GPL-2.0-only

test_signal_src = files('main.c')
test_signal_link = meson.current_source_dir() / 'link.ld'

test_signal_elf = custom_target('test_signal_elf',
    input: [test_signal_src],
    output: 'test_signal.elf',
    depends: [libsalty_so, libc_so],
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', test_signal_link,
        '-Wl,--dynamic-linker,/lib/ld-salty.so',
        '-L', meson.project_build_root() / 'lib/libsalty',
        '-L', meson.project_build_root() / 'lib/libc',
        '-o', '@OUTPUT@',
        '@INPUT@',
        '-lsalty', '-lc',
    ],
    build_by_default: true,
)
