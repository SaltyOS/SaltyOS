# SaltyOS Name Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

namesrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'namesrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
namesrv_obj = custom_target('namesrv_obj',
  input: files('src/main.rs'),
  output: 'namesrv.o',
  depfile: 'namesrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=namesrv',
    '--crate-type=lib',
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_runtime=' + trona_runtime_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '--extern', 'trona_server=' + trona_server_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel, trona_protocol, trona_server, trona_runtime, trona_posix],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
namesrv_elf = custom_target('namesrv_elf',
  input: [namesrv_obj],
  output: 'namesrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', namesrv_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
