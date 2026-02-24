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

# SSE2-accelerated saltyc routines — auto-enabled on x86_64 (ISA baseline).
if get_option('arch') == 'x86_64'
  rust_userland_args += ['--cfg=saltyc_sse2',
    '-C', 'target-feature=+sse,+sse2,-soft-float']
endif

# fork.S compile-time feature flags
fork_asm_args = []
if get_option('arch') == 'x86_64'
  fork_asm_args += ['-DSALTY_X86_SIMD=1']
endif

# Step 1: Rust -> .o + .rmeta
libsalty_rust = custom_target('libsalty_rust',
  input: files('src/lib.rs'),
  output: ['libsalty.o', 'libsalty.rmeta'],
  depfile: 'libsalty.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=salty',
    '--crate-type=lib',
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
  command: [cc_cmd, '--target=' + c_target, fork_asm_args, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# Step 3: libsalty.o + fork.o + core.o -> libsalty.so
libsalty_so = custom_target('libsalty_so',
  input: [libsalty_obj, fork_obj, core_obj, compiler_builtins_obj],
  output: 'libsalty.so',
  command: [cc_cmd,
    '--target=' + c_target,
    '-shared',
    '-nostdlib', '-nostartfiles',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-Wl,-soname,libsalty.so',
    '-T', libsalty_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
