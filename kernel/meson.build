# SaltyOS Kernel Build
# SPDX-License-Identifier: GPL-2.0-only

# =============================================================================
# Inherited from parent:
#   cc_cmd, rustc, rust_target, c_kernel_args
# Inherited from rust/:
#   core_obj, core_rmeta, compiler_builtins_obj, compiler_builtins_rmeta
# =============================================================================

# Find all assembly source files
all_asm_files = run_command(
  'find', 'src', '-name', '*.S',
  capture: true,
  check: true
).stdout().strip()

kernel_crate_root = files('src/lib.rs')
kernel_ld = meson.current_source_dir() / 'kernel.ld'

# Paths to core and compiler_builtins metadata (built in rust/)
rust_build_dir = meson.project_build_root() / 'rust'

# Compile assembly files to object files
asm_objs = []
if all_asm_files != ''
  asm_files = all_asm_files.split('\n')
  foreach asm_file : asm_files
    asm_obj = custom_target(
      'asm_' + asm_file.underscorify(),
      input: files(asm_file),
      output: asm_file.underscorify() + '.o',
      command: [cc_cmd, '-c', '@INPUT@', '-o', '@OUTPUT@'],
      build_by_default: true,
    )
    asm_objs += asm_obj
  endforeach
endif

# Compile-time log-level cfg flags for the kernel.
# These enable the ktrace!/kdebug! macros in lib.rs at zero runtime cost when off.
log_level = get_option('kernel_log_level')
if log_level == 'trace'
  rust_log_cfgs = ['--cfg', 'klog_trace', '--cfg', 'klog_debug', '--cfg', 'klog_info', '--cfg', 'klog_warn']
elif log_level == 'debug'
  rust_log_cfgs = ['--cfg', 'klog_debug', '--cfg', 'klog_info', '--cfg', 'klog_warn']
elif log_level == 'info'
  rust_log_cfgs = ['--cfg', 'klog_info', '--cfg', 'klog_warn']
elif log_level == 'warn'
  rust_log_cfgs = ['--cfg', 'klog_warn']
else  # 'error' or unrecognized
  rust_log_cfgs = []
endif

# Step 1: Compile Rust kernel to object file
# Uses custom-built core library instead of sysroot
kernel_obj = custom_target('kernel_obj',
  input: kernel_crate_root,
  output: 'kernel.o',
  depfile: 'kernel.d',
  command: [
    rustc,
    '--edition=2024',
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=saltyos_kernel',
    '--target=' + rust_target,
    '-C', 'panic=abort',
    '-C', 'opt-level=2',
    '-C', 'debuginfo=2',
    '-C', 'code-model=small',
    '-C', 'relocation-model=pic',
    '--sysroot=/dev/null',
    '--extern', 'core=' + rust_build_dir / 'libcore.rmeta',
    '--extern', 'compiler_builtins=' + rust_build_dir / 'libcompiler_builtins.rmeta',
    '-L', rust_build_dir,
  ] + rust_log_cfgs + [
    '@INPUT@',
  ],
  depends: [core, compiler_builtins],
  build_by_default: true,
)

# Step 2: Link kernel object with core, compiler_builtins, and assembly objects into ELF executable
kernel = custom_target('kernel',
  input: [kernel_obj, core_obj, compiler_builtins_obj] + asm_objs,
  output: 'kernel.elf',
  command: [
    cc_cmd,
    '-nostdlib',
    '-fuse-ld=lld',
    '-Wl,--pie',
    '-Wl,--no-dynamic-linker',
    '-Wl,-n',
    '-Wl,-T,' + kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

# Step 3: Link boot image kernel ELF with debug sections stripped.
# Keep kernel.elf unchanged for local debugging/symbol work.
kernel_boot = custom_target('kernel_boot',
  input: [kernel_obj, core_obj, compiler_builtins_obj] + asm_objs,
  output: 'kernel.boot.elf',
  command: [
    cc_cmd,
    '-nostdlib',
    '-fuse-ld=lld',
    '-Wl,--pie',
    '-Wl,--no-dynamic-linker',
    '-Wl,-n',
    '-Wl,-S',
    '-Wl,-T,' + kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
