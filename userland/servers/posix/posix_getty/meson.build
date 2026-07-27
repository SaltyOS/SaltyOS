# SaltyOS POSIX Getty Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

posix_getty_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'posix_getty' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
posix_getty_obj = custom_target('posix_getty_obj',
  input: files('src/main.rs'),
  output: 'posix_getty.o',
  depfile: 'posix_getty.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=posix_getty',
    '--crate-type=lib',
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_runtime=' + trona_runtime_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '--extern', 'trona_server=' + trona_server_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'basaltc=' + basaltc_build_dir / 'basaltc.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, basaltc_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
posix_getty_elf = custom_target('posix_getty_elf',
  input: [posix_getty_obj],
  output: 'posix_getty.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', posix_getty_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
