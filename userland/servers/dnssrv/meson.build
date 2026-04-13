# SaltyOS DNS Resolver Service Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

dnssrv_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'dnssrv' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# -----------------------------------------------------------------------------
# Step 0a: Generate per-service `svc_caps` Rust crate from `dnssrv.service`.
# -----------------------------------------------------------------------------
dnssrv_svc_caps_rs = custom_target('dnssrv_svc_caps_rs',
  input: files('../../services/dnssrv.service'),
  output: 'dnssrv_svc_caps.rs',
  command: [py_prog, files('../../../tools/svc_caps_gen.py'),
            '--input', '@INPUT@',
            '--output', '@OUTPUT@',
            '--crate-name', 'dnssrv_svc_caps',
            '--data-file', role_map_data_py],
  depends: [role_map_gen],
  build_by_default: true,
)

# -----------------------------------------------------------------------------
# Step 0b: Compile the generated crate.
# -----------------------------------------------------------------------------
dnssrv_svc_caps = custom_target('dnssrv_svc_caps',
  input: dnssrv_svc_caps_rs,
  output: ['libdnssrv_svc_caps.o', 'libdnssrv_svc_caps.rmeta'],
  depfile: 'libdnssrv_svc_caps.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=dnssrv_svc_caps',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust],
  build_by_default: true,
)
dnssrv_svc_caps_obj = dnssrv_svc_caps[0]
dnssrv_svc_caps_rmeta = meson.current_build_dir() / 'libdnssrv_svc_caps.rmeta'

# Step 1: Rust -> .o
dnssrv_obj = custom_target('dnssrv_obj',
  input: files('src/main.rs'),
  output: 'dnssrv.o',
  depfile: 'dnssrv.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=dnssrv',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'svc_caps=' + dnssrv_svc_caps_rmeta,
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libtrona_rust, trona_posix, dnssrv_svc_caps],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
dnssrv_elf = custom_target('dnssrv_elf',
  input: [dnssrv_obj, dnssrv_svc_caps_obj],
  output: 'dnssrv.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-fuse-ld=lld',
    '-T', dnssrv_link,
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
