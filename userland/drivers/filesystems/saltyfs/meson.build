# SaltyOS SaltyFS Server Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

saltyfs_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'saltyfs' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
saltyfs_obj = custom_target('saltyfs_obj',
  input: files('src/main.rs'),
  output: 'saltyfs.o',
  depfile: 'saltyfs.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=saltyfs',
    '--crate-type=lib',
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_runtime=' + trona_runtime_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '--extern', 'trona_server=' + trona_server_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_kernel, trona_protocol, trona_server, trona_runtime],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
saltyfs_elf = custom_target('saltyfs_elf',
  input: [saltyfs_obj],
  output: 'saltyfs.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', saltyfs_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
