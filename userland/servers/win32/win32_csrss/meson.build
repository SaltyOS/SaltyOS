# SaltyOS Win32 CSRSS Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

win32_csrss_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'win32_csrss' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
win32_csrss_obj = custom_target('win32_csrss_obj',
  input: files('src/main.rs'),
  output: 'win32_csrss.o',
  depfile: 'win32_csrss.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=win32_csrss',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
win32_csrss_elf = custom_target('win32_csrss_elf',
  input: [win32_csrss_obj],
  output: 'win32_csrss.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', win32_csrss_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
