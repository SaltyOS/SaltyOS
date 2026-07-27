# SaltyOS Init Process Build (Rust, statically linked)
# SPDX-License-Identifier: GPL-2.0-only

init_link = meson.project_source_root() / 'lib/trona/trona-static-pie.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'init' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
init_obj = custom_target('init_obj',
  input: files('src/main.rs'),
  output: 'init.o',
  depfile: 'init.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=init',
    '--crate-type=lib',
    '--extern', 'uapi=' + trona_uapi_rmeta,
    '--extern', 'trona_kernel=' + trona_kernel_rmeta,
    '--extern', 'trona_runtime=' + trona_runtime_rmeta,
    '--extern', 'trona_protocol=' + trona_protocol_rmeta,
    '--extern', 'trona_server=' + trona_server_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'trona_loader=' + trona_loader_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, trona_uapi, trona_kernel, trona_protocol, trona_server, trona_runtime, trona_posix, trona_loader],
  build_by_default: true,
)

# Step 2: crt_start.o + init.o + static libc/libtrona -> init.elf (static)
init_elf = custom_target('init_elf',
  input: [crt_start_obj, init_obj, libc_a, libtrona_a],
  output: 'init.elf',
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-shared',
    '-fno-plt', '-Wl,-Bsymbolic',
    '-fno-stack-protector',
    '-T', init_link,
    '-o', '@OUTPUT@',
    '-Wl,--undefined=main',
    '-Wl,--start-group',
    '@INPUT@',
    '-Wl,--end-group',
  ],
  build_by_default: true,
)

# Step 3: stripped init ELF for boot image/initrd (keep init.elf for debugging)
init_boot_elf = custom_target('init_boot_elf',
  input: [crt_start_obj, init_obj, libc_a, libtrona_a],
  output: 'init.boot.elf',
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-shared',
    '-fno-plt', '-Wl,-Bsymbolic',
    '-fno-stack-protector',
    '-Wl,-S',
    '-T', init_link,
    '-o', '@OUTPUT@',
    '-Wl,--undefined=main',
    '-Wl,--start-group',
    '@INPUT@',
    '-Wl,--end-group',
  ],
  build_by_default: true,
)
