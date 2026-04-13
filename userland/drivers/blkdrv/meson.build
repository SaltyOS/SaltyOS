# SaltyOS virtio-blk Driver Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

blkdrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'blkdrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# -----------------------------------------------------------------------------
# Step 0a: Generate per-service `svc_caps` Rust crate from `blkdrv.service`.
# -----------------------------------------------------------------------------
blkdrv_svc_caps_rs = custom_target('blkdrv_svc_caps_rs',
  input: files('../../services/blkdrv.service'),
  output: 'blkdrv_svc_caps.rs',
  command: [py_prog, files('../../../tools/svc_caps_gen.py'),
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--crate-name', 'blkdrv_svc_caps',
            '--data-file', role_map_data_py],
  depends: [role_map_gen],
  build_by_default: true,
)

# -----------------------------------------------------------------------------
# Step 0b: Compile the generated crate.
# -----------------------------------------------------------------------------
blkdrv_svc_caps = custom_target('blkdrv_svc_caps',
  input: blkdrv_svc_caps_rs,
  output: ['libblkdrv_svc_caps.o', 'libblkdrv_svc_caps.rmeta'],
  depfile: 'libblkdrv_svc_caps.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=blkdrv_svc_caps',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)
blkdrv_svc_caps_obj = blkdrv_svc_caps[0]
blkdrv_svc_caps_rmeta = meson.current_build_dir() / 'libblkdrv_svc_caps.rmeta'

# Step 1: Rust -> .o
blkdrv_obj = custom_target('blkdrv_obj',
  input: files('src/main.rs'),
  output: 'blkdrv.o',
  depfile: 'blkdrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=blkdrv',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'svc_caps=' + blkdrv_svc_caps_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust, trona_posix, blkdrv_svc_caps],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
blkdrv_elf = custom_target('blkdrv_elf',
  input: [blkdrv_obj, blkdrv_svc_caps_obj],
  output: 'blkdrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', blkdrv_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
