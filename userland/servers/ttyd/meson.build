# SaltyOS TTY Daemon Build (Rust)
# SPDX-License-Identifier: GPL-2.0-only

ttyd_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

# Per-program debug override
_prog_rust_args = rust_userland_args
if 'ttyd' in userland_debug_list
  _prog_rust_args = _prog_rust_args + ['--cfg', 'ulog_debug']
endif

# Step 1: Rust -> .o
ttyd_obj = custom_target('ttyd_obj',
  input: files('src/main.rs'),
  output: 'ttyd.o',
  depfile: 'ttyd.d',
  command: [rustc,
    _prog_rust_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=ttyd',
    '--crate-type=lib',
    '--extern', 'trona=' + trona_rmeta,
    '--extern', 'trona_posix=' + trona_posix_rmeta,
    '--extern', 'basaltc=' + basaltc_build_dir / 'basaltc.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, basaltc_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
ttyd_elf = custom_target('ttyd_elf',
  input: [ttyd_obj],
  output: 'ttyd.elf',
  depends: [libtrona_so, libc_so, crt_start_obj],
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-T', ttyd_link,
    '-L', libtrona_build_dir,
    '-L', basaltc_build_dir,
    '-o', '@OUTPUT@',
    basaltc_build_dir / 'crt_start.o',
    '@INPUT@',
    '-ltrona', '-lc',
  ],
  build_by_default: true,
)
