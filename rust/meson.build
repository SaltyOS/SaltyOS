# SaltyOS Rust Infrastructure
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds core library and compiler_builtins from rust-src.
# This is required for freestanding Rust kernel development.
#
# =============================================================================
# Inherited from parent:
#   rustc, rust_target, rust_lib_src
# =============================================================================

# Core library configuration
# Disable floating-point formatting to reduce code size and avoid FP intrinsics
core_cfgs = ['no_fp_fmt_parse']

core_cfg_args = []
foreach cfg : core_cfgs
  core_cfg_args += ['--cfg', cfg]
endforeach

# Common rustc flags for building core/compiler_builtins
rust_core_args = [
  '--edition=2024',
  '--target=' + rust_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
]

# Step 1: Build core library from rust-src
core_src = rust_lib_src / 'core/src/lib.rs'

core = custom_target('core',
  input: [],
  output: ['core.o', 'libcore.rmeta'],
  command: [
    rustc,
    rust_core_args,
    core_cfg_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=core',
    '--crate-type=lib',
    core_src,
  ],
  build_by_default: true,
)

core_obj = core[0]
core_rmeta = core[1]

# Step 2: Build compiler_builtins
compiler_builtins_src = files('compiler_builtins.rs')

compiler_builtins = custom_target('compiler_builtins',
  input: compiler_builtins_src,
  output: ['compiler_builtins.o', 'libcompiler_builtins.rmeta'],
  command: [
    rustc,
    rust_core_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=compiler_builtins',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + meson.current_build_dir() / 'libcore.rmeta',
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [core],
  build_by_default: true,
)

compiler_builtins_obj = compiler_builtins[0]
compiler_builtins_rmeta = compiler_builtins[1]
