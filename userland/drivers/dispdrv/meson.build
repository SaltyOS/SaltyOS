# SaltyOS Display Driver Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

dispdrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'dispdrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
dispdrv_obj = custom_target('dispdrv_obj',
  input: files('src/main.rs'),
  output: 'dispdrv.o',
  depfile: 'dispdrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=dispdrv',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust, trona_posix],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
dispdrv_elf = custom_target('dispdrv_elf',
  input: [dispdrv_obj],
  output: 'dispdrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', dispdrv_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
