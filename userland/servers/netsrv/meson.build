# SaltyOS Network Stack Server Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

netsrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'netsrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# -----------------------------------------------------------------------------
# Step 0a: Generate per-service `svc_caps` Rust crate from `netsrv.service`.
# `svc_caps_gen.py` parses the `Require=` lines and emits a small crate that
# exposes service-local cap getters (e.g. `svc_caps::netdrv_ep()`). System
# roles like `Require=namesrv` are skipped — those are reachable through the
# substrate `trona::caps::*` getters.
# -----------------------------------------------------------------------------
netsrv_svc_caps_rs = custom_target('netsrv_svc_caps_rs',
  input: files('../../services/netsrv.service'),
  output: 'netsrv_svc_caps.rs',
  command: [py_prog, files('../../../tools/svc_caps_gen.py'),
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--crate-name', 'netsrv_svc_caps',
            '--data-file', role_map_data_py],
  depends: [role_map_gen],
  build_by_default: true,
)

# -----------------------------------------------------------------------------
# Step 0b: Compile the generated `netsrv_svc_caps.rs` into a standalone rlib
# (object + metadata) so the main `netsrv_obj` rustc invocation can link it
# via `--extern svc_caps=...`.
# -----------------------------------------------------------------------------
netsrv_svc_caps = custom_target('netsrv_svc_caps',
  input: netsrv_svc_caps_rs,
  output: ['libnetsrv_svc_caps.o', 'libnetsrv_svc_caps.rmeta'],
  depfile: 'libnetsrv_svc_caps.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=netsrv_svc_caps',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)
netsrv_svc_caps_obj = netsrv_svc_caps[0]
netsrv_svc_caps_rmeta = meson.current_build_dir() / 'libnetsrv_svc_caps.rmeta'

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
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'svc_caps=' + netsrv_svc_caps_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust, trona_posix, netsrv_svc_caps],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
netsrv_elf = custom_target('netsrv_elf',
  input: [netsrv_obj, netsrv_svc_caps_obj],
  output: 'netsrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-fuse-ld=lld',
    '-T', netsrv_link,
    '-Wl,--dynamic-linker,/lib/ld-trona.so',
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
