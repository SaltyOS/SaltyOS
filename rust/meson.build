# SaltyOS Rust Infrastructure
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds core library and compiler_builtins from rust-src.
# x86_64 uses separate kernel/userland targets, so we may build two sets.
#
# =============================================================================
# Inherited from parent:
#   rustc, rust_target, rust_kernel_target,
#   rust_kernel_target_needs_unstable, rust_lib_src, build_kernel, build_userland
# =============================================================================

rust_kernel_target_file = files('../kernel/' + arch + '-saltyos.json')

# Core library configuration
# Disable floating-point formatting to reduce code size and avoid FP intrinsics
core_cfgs = ['no_fp_fmt_parse']

core_cfg_args = []
foreach cfg : core_cfgs
  core_cfg_args += ['--cfg', cfg]
endforeach

# Common rustc flags for building core/compiler_builtins.
rust_core_common_args = [
  '--edition=2024',
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
]

# Userland core/builtins follow the OS target (e.g. x86_64-unknown-saltyos).
rust_userland_core_args = rust_core_common_args + [
  '--target=' + rust_target,
]

# Kernel core/builtins must match the kernel crate target exactly (JSON on x86_64)
# so rustc accepts the rmeta objects during kernel compilation.
rust_kernel_core_args = rust_core_common_args + [
  '--target=' + rust_kernel_target,
]
if rust_kernel_target_needs_unstable
  rust_kernel_core_args += ['-Z', 'unstable-options']
endif

core_src = rust_lib_src / 'core/src/lib.rs'
compiler_builtins_src = files('compiler_builtins.rs')

# Userland set (generic names used by lib/ and userland/ subdirs)
if build_userland
  core = custom_target('core_userland',
    input: [],
    output: ['core.o', 'libcore.rmeta'],
    command: [
      rustc,
      rust_userland_core_args,
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

  compiler_builtins = custom_target('compiler_builtins_userland',
    input: compiler_builtins_src,
    output: ['compiler_builtins.o', 'libcompiler_builtins.rmeta'],
    command: [
      rustc,
      rust_userland_core_args,
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
endif

# Kernel set (explicit names used by kernel/meson.build)
if build_kernel
  if build_userland and rust_kernel_target == rust_target
    core_kernel = core
    core_kernel_obj = core_obj
    core_kernel_rmeta = core_rmeta
    compiler_builtins_kernel = compiler_builtins
    compiler_builtins_kernel_obj = compiler_builtins_obj
    compiler_builtins_kernel_rmeta = compiler_builtins_rmeta
  else
    # rustc emits crate-name-based intermediate object filenames in the current
    # build dir. When building both userland and kernel copies of `core` /
    # `compiler_builtins` in parallel, those temp files can collide.
    # Serialize the duplicate crate-name invocations when both sets exist.
    core_kernel_deps = []
    if build_userland
      core_kernel_deps += [core]
    endif

    core_kernel = custom_target('core_kernel',
      input: [],
      output: ['core-kernel.o', 'libcore-kernel.rmeta'],
      depend_files: rust_kernel_target_file,
      command: [
        rustc,
        rust_kernel_core_args,
        core_cfg_args,
        '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
        '--crate-name=core',
        '--crate-type=lib',
        core_src,
      ],
      depends: core_kernel_deps,
      build_by_default: true,
    )

    core_kernel_obj = core_kernel[0]
    core_kernel_rmeta = core_kernel[1]

    compiler_builtins_kernel_deps = [core_kernel]
    if build_userland
      compiler_builtins_kernel_deps += [compiler_builtins]
    endif

    compiler_builtins_kernel = custom_target('compiler_builtins_kernel',
      input: compiler_builtins_src,
      output: ['compiler_builtins-kernel.o', 'libcompiler_builtins-kernel.rmeta'],
      depend_files: rust_kernel_target_file,
      command: [
        rustc,
        rust_kernel_core_args,
        '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
        '--crate-name=compiler_builtins',
        '--crate-type=lib',
        '--sysroot=/dev/null',
        '--extern', 'core=' + meson.current_build_dir() / 'libcore-kernel.rmeta',
        '-L', meson.current_build_dir(),
        '@INPUT@',
      ],
      depends: compiler_builtins_kernel_deps,
      build_by_default: true,
    )

    compiler_builtins_kernel_obj = compiler_builtins_kernel[0]
    compiler_builtins_kernel_rmeta = compiler_builtins_kernel[1]
  endif
endif
