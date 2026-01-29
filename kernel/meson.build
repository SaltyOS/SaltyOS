# SaltyOS Kernel Build
# SPDX-License-Identifier: GPL-2.0-only

# =============================================================================
# Inherited from parent:
#   cc_cmd, rustc, rust_target, c_kernel_args
# Inherited from rust/:
#   core_obj, core_rmeta, compiler_builtins_obj, compiler_builtins_rmeta
# =============================================================================

# Find all Rust source files for proper change tracking
# lib.rs is the crate root (input), other modules are dependencies for change detection
all_rs_files = run_command(
  'find', 'src', '-name', '*.rs',
  capture: true,
  check: true
).stdout().strip()

# Split into crate root and module dependencies
kernel_crate_root = files('src/lib.rs')
module_deps = files(all_rs_files.split('\n'))
kernel_ld = meson.current_source_dir() / 'kernel.ld'

# Paths to core and compiler_builtins metadata (built in rust/)
rust_build_dir = meson.project_build_root() / 'rust'

# Step 1: Compile Rust kernel to object file
# Uses custom-built core library instead of sysroot
kernel_obj = custom_target('kernel_obj',
  input: kernel_crate_root,
  depend_files: module_deps,
  output: 'kernel.o',
  command: [
    rustc,
    '--edition=2024',
    '--emit=obj',
    '--crate-name=saltyos_kernel',
    '--target=' + rust_target,
    '-C', 'panic=abort',
    '-C', 'opt-level=2',
    '-C', 'debuginfo=2',
    '-C', 'code-model=kernel',
    '-C', 'relocation-model=static',
    '--sysroot=/dev/null',
    '--extern', 'core=' + rust_build_dir / 'libcore.rmeta',
    '--extern', 'compiler_builtins=' + rust_build_dir / 'libcompiler_builtins.rmeta',
    '-L', rust_build_dir,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins],
  build_by_default: true,
)

# Step 2: Link kernel object with core and compiler_builtins into ELF executable
kernel = custom_target('kernel',
  input: [kernel_obj, core_obj, compiler_builtins_obj],
  output: 'kernel.elf',
  command: [
    cc_cmd,
    '-nostdlib',
    '-static',
    '-fuse-ld=lld',
    '-Wl,--no-pie',
    '-Wl,-n',
    '-Wl,-T,' + kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
