# SaltyOS Display Driver Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

dispdrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'dispdrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# -----------------------------------------------------------------------------
# Step 0a: Generate per-service `svc_caps` Rust crate from `dispdrv.service`.
# `svc_caps_gen.py` parses the `Require=` lines and emits a small crate that
# exposes service-local cap getters. System roles like `Require=namesrv` /
# `Require=mmsrv` / `Require=fb_untyped` are skipped — those are reachable
# through the substrate `trona::caps::*` getters. dispdrv has no service-local
# requires today, but the crate is still generated for pattern consistency.
# -----------------------------------------------------------------------------
dispdrv_svc_caps_rs = custom_target('dispdrv_svc_caps_rs',
  input: files('../../services/dispdrv.service'),
  output: 'dispdrv_svc_caps.rs',
  command: [py_prog, files('../../../tools/svc_caps_gen.py'),
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--crate-name', 'dispdrv_svc_caps',
            '--data-file', role_map_data_py],
  depends: [role_map_gen],
  build_by_default: true,
)

# -----------------------------------------------------------------------------
# Step 0b: Compile the generated `dispdrv_svc_caps.rs` into a standalone rlib
# (object + metadata) so the main `dispdrv_obj` rustc invocation can link it
# via `--extern svc_caps=...`.
# -----------------------------------------------------------------------------
dispdrv_svc_caps = custom_target('dispdrv_svc_caps',
  input: dispdrv_svc_caps_rs,
  output: ['libdispdrv_svc_caps.o', 'libdispdrv_svc_caps.rmeta'],
  depfile: 'libdispdrv_svc_caps.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=dispdrv_svc_caps',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)
dispdrv_svc_caps_obj = dispdrv_svc_caps[0]
dispdrv_svc_caps_rmeta = meson.current_build_dir() / 'libdispdrv_svc_caps.rmeta'

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
    '--extern', 'svc_caps=' + dispdrv_svc_caps_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust, trona_posix, dispdrv_svc_caps],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
dispdrv_elf = custom_target('dispdrv_elf',
  input: [dispdrv_obj, dispdrv_svc_caps_obj],
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
