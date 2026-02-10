# SaltyOS Test Runner Build (Rust, dynamically linked)
# SPDX-License-Identifier: GPL-2.0-only

test_runner_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'

# Step 1: Rust -> .o
test_runner_obj = custom_target('test_runner_obj',
  input: files('src/main.rs'),
  output: 'test_runner.o',
  command: [rustc,
    rust_userland_args,
    '--emit=obj',
    '--crate-name=test_runner',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

# Step 2: .o -> .elf (dynamic linking)
test_runner_elf = custom_target('test_runner_elf',
  input: [test_runner_obj],
  output: 'test_runner.elf',
  depends: [libsalty_so, libc_so],
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIE', '-pie',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', test_runner_link,
    '-Wl,--dynamic-linker,/lib/ld-salty.so',
    '-L', libsalty_build_dir,
    '-L', meson.project_build_root() / 'lib/saltyc',
    '-o', '@OUTPUT@',
    '@INPUT@',
    '-lsalty', '-lc',
  ],
  build_by_default: true,
)
