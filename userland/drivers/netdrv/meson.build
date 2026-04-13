# SaltyOS virtio-net Driver Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

netdrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'netdrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# -----------------------------------------------------------------------------
# Step 0a: Generate per-service `svc_caps` Rust crate from `netdrv.service`.
# -----------------------------------------------------------------------------
netdrv_svc_caps_rs = custom_target('netdrv_svc_caps_rs',
  input: files('../../services/netdrv.service'),
  output: 'netdrv_svc_caps.rs',
  command: [py_prog, files('../../../tools/svc_caps_gen.py'),
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--crate-name', 'netdrv_svc_caps',
            '--data-file', role_map_data_py],
  depends: [role_map_gen],
  build_by_default: true,
)

# -----------------------------------------------------------------------------
# Step 0b: Compile the generated crate.
# -----------------------------------------------------------------------------
netdrv_svc_caps = custom_target('netdrv_svc_caps',
  input: netdrv_svc_caps_rs,
  output: ['libnetdrv_svc_caps.o', 'libnetdrv_svc_caps.rmeta'],
  depfile: 'libnetdrv_svc_caps.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=netdrv_svc_caps',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)
netdrv_svc_caps_obj = netdrv_svc_caps[0]
netdrv_svc_caps_rmeta = meson.current_build_dir() / 'libnetdrv_svc_caps.rmeta'

# Step 1: Rust -> .o
netdrv_obj = custom_target('netdrv_obj',
  input: files('src/main.rs'),
  output: 'netdrv.o',
  depfile: 'netdrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=netdrv',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'svc_caps=' + netdrv_svc_caps_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust, trona_posix, netdrv_svc_caps],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
netdrv_elf = custom_target('netdrv_elf',
  input: [netdrv_obj, netdrv_svc_caps_obj],
  output: 'netdrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', netdrv_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
