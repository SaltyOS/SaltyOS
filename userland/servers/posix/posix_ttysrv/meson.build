# SaltyOS POSIX TTY Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

posix_ttysrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'posix_ttysrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# -----------------------------------------------------------------------------
# Step 0a: Generate per-service `svc_caps` Rust crate from `posix_ttysrv.service`.
# `svc_caps_gen.py` parses the `Require=` lines and emits a small crate that
# exposes service-local cap getters (e.g. `svc_caps::dispdrv_ep()`). System
# roles like `Require=namesrv` are skipped — those are reachable through the
# substrate `trona::caps::*` getters.
# -----------------------------------------------------------------------------
posix_ttysrv_svc_caps_rs = custom_target('posix_ttysrv_svc_caps_rs',
  input: files('../../../services/posix_ttysrv.service'),
  output: 'posix_ttysrv_svc_caps.rs',
  command: [py_prog, files('../../../../tools/svc_caps_gen.py'),
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--crate-name', 'posix_ttysrv_svc_caps',
            '--data-file', role_map_data_py],
  depends: [role_map_gen],
  build_by_default: true,
)

# -----------------------------------------------------------------------------
# Step 0b: Compile the generated `posix_ttysrv_svc_caps.rs` into a standalone
# rlib (object + metadata) so the main `posix_ttysrv_obj` rustc invocation can
# link it via `--extern svc_caps=...`.
# -----------------------------------------------------------------------------
posix_ttysrv_svc_caps = custom_target('posix_ttysrv_svc_caps',
  input: posix_ttysrv_svc_caps_rs,
  output: ['libposix_ttysrv_svc_caps.o', 'libposix_ttysrv_svc_caps.rmeta'],
  depfile: 'libposix_ttysrv_svc_caps.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=posix_ttysrv_svc_caps',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)
posix_ttysrv_svc_caps_obj = posix_ttysrv_svc_caps[0]
posix_ttysrv_svc_caps_rmeta = meson.current_build_dir() / 'libposix_ttysrv_svc_caps.rmeta'

# Step 1: Rust -> .o
posix_ttysrv_obj = custom_target('posix_ttysrv_obj',
  input: files('src/main.rs'),
  output: 'posix_ttysrv.o',
  depfile: 'posix_ttysrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=posix_ttysrv',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'basaltc=' + basaltc_build_dir / 'basaltc.rmeta',
    '--extern', 'svc_caps=' + posix_ttysrv_svc_caps_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, basaltc_rust, posix_ttysrv_svc_caps],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
posix_ttysrv_elf = custom_target('posix_ttysrv_elf',
  input: [posix_ttysrv_obj, posix_ttysrv_svc_caps_obj],
  output: 'posix_ttysrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', posix_ttysrv_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
