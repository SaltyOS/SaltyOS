# SaltyOS Network Stack Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

netsrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'netsrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
netsrv_obj = custom_target('netsrv_obj',
  input: files('src/main.rs'),
  output: 'netsrv.o',
  depfile: 'netsrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=netsrv',
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
netsrv_elf = custom_target('netsrv_elf',
  input: [netsrv_obj],
  output: 'netsrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-fuse-ld=lld',
    '-T', netsrv_link,
    '-Wl,--dynamic-linker,/lib/ldtrona-elf.so',
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
