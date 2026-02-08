# libsalty.so - SaltyOS System Call Library (Rust)
# SPDX-License-Identifier: GPL-2.0-only

libsalty_link = meson.current_source_dir() / 'libsalty.ld'
rust_build_dir = meson.project_build_root() / 'rust'

# Common rustc flags for userland (PIC, small code model)
rust_userland_args = [
  '--edition=2024',
  '--target=' + rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
  '--sysroot=/dev/null',
  '--extern', 'core=' + rust_build_dir / 'libcore.rmeta',
  '--extern', 'compiler_builtins=' + rust_build_dir / 'libcompiler_builtins.rmeta',
  '-L', rust_build_dir,
]

# Rust source files (listed as depend_files for rebuild tracking)
libsalty_rust_sources = files(
  'src/lib.rs',
  'src/consts.rs',
  'src/types.rs',
  'src/syscall.rs',
  'src/ipc.rs',
  'src/invoke.rs',
  'src/serial.rs',
  'src/posix.rs',
  'src/posix_mm.rs',
  'src/signals.rs',
  'src/cpio.rs',
  'src/elf_loader.rs',
  'src/elf_dynamic.rs',
)

# Step 1: Rust -> .o + .rmeta
libsalty_rust = custom_target('libsalty_rust',
  input: files('src/lib.rs'),
  depend_files: libsalty_rust_sources,
  output: ['libsalty.o', 'libsalty.rmeta'],
  command: [rustc,
    rust_userland_args,
    '--emit=obj,metadata',
    '--crate-name=salty',
    '--crate-type=lib',
    '--out-dir', '@OUTDIR@',
    '-o', '@OUTPUT0@',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins],
  build_by_default: true,
)

libsalty_obj = libsalty_rust[0]
libsalty_rmeta = libsalty_rust[1]

# Step 2: fork.S -> fork.o
fork_obj = custom_target('fork_asm',
  input: files('fork.S'),
  output: 'fork.o',
  command: [cc_cmd, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# Step 3: libsalty.o + fork.o + core.o -> libsalty.so
libsalty_so = custom_target('libsalty_so',
  input: [libsalty_obj, fork_obj, core_obj, compiler_builtins_obj],
  output: 'libsalty.so',
  command: [cc_cmd,
    '-fPIC', '-shared',
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-Wl,-soname,libsalty.so',
    '-Wl,--hash-style=gnu',
    '-T', libsalty_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
