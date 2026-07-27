# Kernite — SaltyOS Kernel Build
# SPDX-License-Identifier: GPL-2.0-only

# =============================================================================
# Inherited from parent:
#   cc_cmd, rustc, rust_lib_src, rust_kernel_target,
#   rust_kernel_target_needs_unstable, rust_kernel_args, rust_target, c_kernel_args
# =============================================================================

# Find assembly source files, excluding the other architecture's directory
exclude_arch = arch == 'x86_64' ? 'aarch64' : 'x86_64'
all_asm_files = run_command(
  'find', 'src', '-name', '*.S', '-not', '-path', '*/arch/' + exclude_arch + '/*',
  capture: true,
  check: true
).stdout().strip()

kernel_crate_root = files('src/lib.rs')
kernel_target_spec = files(arch + '-kernite.json')
kernel_ld = meson.current_source_dir() / 'arch' / arch + '.ld'
kernel_link_target = '--target=' + asm_target
kernel_ld_lld = find_program('ld.lld', required: true)
kernel_llvm_nm = find_program('llvm-nm', required: true)
kernel_llvm_readelf = find_program('llvm-readelf', required: true)
kernel_symbol_demangler = find_program('rustfilt', required: false)
if not kernel_symbol_demangler.found()
  kernel_symbol_demangler = find_program('llvm-cxxfilt', required: true)
endif
core_src = rust_lib_src / 'core/src/lib.rs'
core_kernel_rmeta_path = meson.current_build_dir() / 'libcore-kernel.rmeta'
compiler_builtins_kernel_rmeta_path = meson.current_build_dir() / 'libcompiler_builtins-kernel.rmeta'

core_kernel_support_args = [
  '--edition=2024',
  '--target=' + rust_kernel_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'code-model=small',
  '-C', 'relocation-model=pic',
  '-C', 'force-frame-pointers=yes',
  '-C', 'force-unwind-tables=yes',
]
if get_option('debug_symbols')
  core_kernel_support_args += ['-C', 'debuginfo=2']
endif
if rust_kernel_target_needs_unstable
  core_kernel_support_args += ['-Z', 'unstable-options']
endif

core_kernel = custom_target('core_kernel',
  input: [],
  output: ['core-kernel.o', 'libcore-kernel.rmeta'],
  depend_files: kernel_target_spec,
  command: [
    rustc,
    core_kernel_support_args,
    '--cfg', 'no_fp_fmt_parse',
    # Disambiguate rustc's intermediate CGU filenames (`core.core.<hash>-cgu.*.rcgu.o`)
    # from parallel `--crate-name=core` builds in `lib/trona/` so a single top-level
    # build directory can host all three `core` rebuilds without filename collisions.
    '-C', 'extra-filename=-kernel',
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=core',
    '--crate-type=lib',
    core_src,
  ],
  build_by_default: true,
)

core_kernel_obj = core_kernel[0]
core_kernel_rmeta = core_kernel[1]

compiler_builtins_kernel = custom_target('compiler_builtins_kernel',
  input: files('compiler_builtins.rs'),
  output: ['compiler_builtins-kernel.o', 'libcompiler_builtins-kernel.rmeta'],
  depend_files: kernel_target_spec,
  command: [
    rustc,
    core_kernel_support_args,
    '--cfg', 'trona_mem_builtins',
    # Same intermediate-filename disambiguation rationale as `core_kernel` above.
    '-C', 'extra-filename=-kernel',
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=compiler_builtins',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + core_kernel_rmeta_path,
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [core_kernel],
  build_by_default: true,
)

compiler_builtins_kernel_obj = compiler_builtins_kernel[0]
compiler_builtins_kernel_rmeta = compiler_builtins_kernel[1]

# UAPI rmeta (kernel target) — compiles the bindgen-generated `uapi.rs`
# (top-level `meson/` fragment) against the kernel rustc target spec.
uapi_kernel = custom_target('uapi_kernel',
  input: uapi_bindgen_rs,
  output: ['uapi-kernel.o', 'libuapi-kernel.rmeta'],
  depend_files: kernel_target_spec,
  command: [
    rustc,
    core_kernel_support_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@',
    '--crate-name=uapi',
    '-C', 'extra-filename=-kernel',
    '--crate-type=lib',
    '--sysroot=/dev/null',
    '--extern', 'core=' + core_kernel_rmeta_path,
    '--extern', 'compiler_builtins=' + compiler_builtins_kernel_rmeta_path,
    '-L', meson.current_build_dir(),
    '@INPUT@',
  ],
  depends: [core_kernel, compiler_builtins_kernel, uapi_bindgen],
  build_by_default: true,
)

uapi_kernel_obj = uapi_kernel[0]
uapi_kernel_rmeta = uapi_kernel[1]
uapi_kernel_rmeta_path = meson.current_build_dir() / 'libuapi-kernel.rmeta'

# Compile assembly files to object files
asm_objs = []
if all_asm_files != ''
  asm_files = all_asm_files.split('\n')
  foreach asm_file : asm_files
    asm_obj = custom_target(
      'asm_' + asm_file.underscorify(),
      input: files(asm_file),
      output: asm_file.underscorify() + '.o',
      command: [cc_cmd, kernel_link_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
      build_by_default: true,
    )
    asm_objs += asm_obj
  endforeach
endif

# Compile-time log-level cfg flags for the kernel.
# These enable the ktrace!/kdebug! macros in lib.rs at zero runtime cost when off.
log_level = get_option('kernel_log_level')
rust_log_cfg_names = []
if log_level == 'trace'
  rust_log_cfgs = ['--cfg', 'klog_trace', '--cfg', 'klog_debug', '--cfg', 'klog_info', '--cfg', 'klog_warn']
  rust_log_cfg_names += ['klog_trace', 'klog_debug', 'klog_info', 'klog_warn']
elif log_level == 'debug'
  rust_log_cfgs = ['--cfg', 'klog_debug', '--cfg', 'klog_info', '--cfg', 'klog_warn']
  rust_log_cfg_names += ['klog_debug', 'klog_info', 'klog_warn']
elif log_level == 'info'
  rust_log_cfgs = ['--cfg', 'klog_info', '--cfg', 'klog_warn']
  rust_log_cfg_names += ['klog_info', 'klog_warn']
elif log_level == 'warn'
  rust_log_cfgs = ['--cfg', 'klog_warn']
  rust_log_cfg_names += ['klog_warn']
else  # 'error' or unrecognized
  rust_log_cfgs = []
endif

# Global serial output kill switch. When debug_serial=false, all locked serial
# output and debug syscalls become no-ops. Panic/crash raw output is unaffected.
if not get_option('debug_serial')
  rust_log_cfgs += ['--cfg', 'no_serial_output']
  rust_log_cfg_names += ['no_serial_output']
endif

# Per-module debug flags. When kernel_debug_modules='mm,ipc', generate
# --cfg klog_mod_mm --cfg klog_mod_ipc so that kdebug!(mm, ...) compiles
# in even when the global kernel_log_level is below 'debug'.
kernel_debug_mods = get_option('kernel_debug_modules')
if kernel_debug_mods != ''
  foreach mod : kernel_debug_mods.split(',')
    mod_cfg = 'klog_mod_' + mod.strip()
    rust_log_cfgs += ['--cfg', mod_cfg]
    rust_log_cfg_names += [mod_cfg]
  endforeach
endif

kernel_profile = get_option('buildtype') == 'release' ? 'release' : 'debug'
kernel_cfg_list = ','.join(rust_log_cfg_names)
kernel_virt_base = arch == 'x86_64' ? '0xffffffff80000000' : '0xffff800000000000'

kernel_build_info_asm = custom_target('kernel_build_info_asm',
  input: [],
  output: 'kernite_build_info.S',
  depend_files: [kernel_target_spec, files('arch/' + arch + '.ld')],
  command: [
    py_prog,
    meson.project_source_root() / 'tools/kernite-build-info.py',
    '--source-root', meson.project_source_root(),
    '--arch', arch,
    '--rustc-version', rustc_version,
    '--profile', kernel_profile,
    '--kernel-log-level', get_option('kernel_log_level'),
    '--kernel-debug-modules', get_option('kernel_debug_modules'),
    '--debug-serial', get_option('debug_serial') ? 'true' : 'false',
    '--debug-symbols', get_option('debug_symbols') ? 'true' : 'false',
    '--max-cpus', get_option('max_cpus').to_string(),
    '--kernel-stack-size', get_option('kernel_stack_size').to_string(),
    '--target-json', kernel_target_spec,
    '--linker-script', kernel_ld,
    '--rust-cfg-list', kernel_cfg_list,
    '--output', '@OUTPUT@',
  ],
  build_by_default: true,
)

kernel_build_info_obj = custom_target('kernel_build_info_obj',
  input: kernel_build_info_asm,
  output: 'kernite_build_info.o',
  command: [cc_cmd, kernel_link_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# Step 1: Compile Rust kernel to object file
# Uses custom-built core library instead of sysroot
kernel_obj = custom_target('kernel_obj',
  input: kernel_crate_root,
  output: 'kernel.o',
  depfile: 'kernel.d',
  depend_files: kernel_target_spec,
  command: [
    rustc,
    rust_kernel_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=kernite',
    '--sysroot=/dev/null',
    '--extern', 'core=' + core_kernel_rmeta.full_path(),
    '--extern', 'compiler_builtins=' + compiler_builtins_kernel_rmeta.full_path(),
    '--extern', 'uapi=' + uapi_kernel_rmeta.full_path(),
    '-L', meson.current_build_dir(),
  ] + rust_log_cfgs + [
    '@INPUT@',
  ],
  depends: [core_kernel, compiler_builtins_kernel, uapi_kernel],
  build_by_default: true,
)

# Step 2: Preliminary link without kallsyms.  Diagnostic tables are placed in
# read-only data so adding them for the final link does not perturb .text.
kernel_pre = custom_target('kernel_pre',
  input: [kernel_obj, core_kernel_obj, compiler_builtins_kernel_obj, uapi_kernel_obj, kernel_build_info_obj] + asm_objs,
  output: 'kernite.pre.elf',
  command: [
    kernel_ld_lld,
    '-m', kernel_link_emulation,
    '-nostdlib',
    '-pie',
    '--no-dynamic-linker',
    '-n',
    '-T', kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

kernel_pre_nm = custom_target('kernel_pre_nm',
  input: kernel_pre,
  output: 'kernite.pre.nm',
  command: [kernel_llvm_nm, '-S', '-n', '--defined-only', '--format=posix', '@INPUT@'],
  capture: true,
  build_by_default: true,
)

kernel_pre_sections = custom_target('kernel_pre_sections',
  input: kernel_pre,
  output: 'kernite.pre.sections',
  command: [kernel_llvm_readelf, '-S', '@INPUT@'],
  capture: true,
  build_by_default: true,
)

kallsyms_asm = custom_target('kallsyms_asm',
  input: [kernel_pre_nm, kernel_pre_sections],
  output: 'kallsyms.S',
  command: [
    py_prog,
    meson.project_source_root() / 'tools/kernite-kallsyms.py',
    '--nm', '@INPUT0@',
    '--sections', '@INPUT1@',
    '--virt-base', kernel_virt_base,
    '--demangler', kernel_symbol_demangler.full_path(),
    '--output', '@OUTPUT@',
  ],
  build_by_default: true,
)

kallsyms_obj = custom_target('kallsyms_obj',
  input: kallsyms_asm,
  output: 'kallsyms.o',
  command: [cc_cmd, kernel_link_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# The unwind tool records the exact eh_frame bounds from the preliminary image
# for review/debugging.  The kernel unwinder reads the preserved .eh_frame
# section directly from the final image.
kernel_unwind_manifest = custom_target('kernel_unwind_manifest',
  input: [kernel_pre, kernel_pre_sections],
  output: 'kernite_unwind_manifest.S',
  command: [
    py_prog,
    meson.project_source_root() / 'tools/kernite-unwind.py',
    '--elf', '@INPUT0@',
    '--sections', '@INPUT1@',
    '--output', '@OUTPUT@',
  ],
  build_by_default: true,
)

kernel_unwind_manifest_obj = custom_target('kernel_unwind_manifest_obj',
  input: kernel_unwind_manifest,
  output: 'kernite_unwind_manifest.o',
  command: [cc_cmd, kernel_link_target, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# Step 3: Link final kernel object with core, compiler_builtins, assembly
# objects, build identity, kallsyms, and unwind metadata into ELF executable.
kernel = custom_target('kernel',
  input: [kernel_obj, core_kernel_obj, compiler_builtins_kernel_obj, uapi_kernel_obj, kernel_build_info_obj, kallsyms_obj, kernel_unwind_manifest_obj] + asm_objs,
  output: 'kernite.elf',
  command: [
    kernel_ld_lld,
    '-m', kernel_link_emulation,
    '-nostdlib',
    '-pie',
    '--no-dynamic-linker',
    '-n',
    '-T', kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

# Step 4: Link boot image kernel ELF with debug sections stripped.
# Keep kernite.elf unchanged for local debugging/symbol work.
kernel_boot = custom_target('kernel_boot',
  input: [kernel_obj, core_kernel_obj, compiler_builtins_kernel_obj, uapi_kernel_obj, kernel_build_info_obj, kallsyms_obj, kernel_unwind_manifest_obj] + asm_objs,
  output: 'kernite.boot.elf',
  command: [
    kernel_ld_lld,
    '-m', kernel_link_emulation,
    '-nostdlib',
    '-pie',
    '--no-dynamic-linker',
    '-n',
    '-S',
    '-T', kernel_ld,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
