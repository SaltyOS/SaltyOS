# SaltyOS VFS Server Build
# SPDX-License-Identifier: GPL-2.0-only

vfs_src = files('main.c')
vfs_link = meson.current_source_dir() / 'link.ld'

vfs_elf = custom_target('vfs_elf',
    input: [vfs_src],
    output: 'vfs.elf',
    depends: [libsalty_so, libc_so],
    command: [cc_cmd,
        '-nostdlib', '-nostartfiles', '-ffreestanding',
        '-fPIE', '-pie',
        '-fno-stack-protector',
        '-mno-red-zone',
        '-I', meson.project_source_root() / 'lib/libsalty',
        '-I', meson.project_source_root() / 'lib/libc',
        '-T', vfs_link,
        '-Wl,--dynamic-linker,/lib/ld-salty.so',
        '-L', meson.project_build_root() / 'lib/libsalty',
        '-L', meson.project_build_root() / 'lib/libc',
        '-o', '@OUTPUT@',
        '@INPUT@',
        '-lsalty', '-lc',
    ],
    build_by_default: true,
)
