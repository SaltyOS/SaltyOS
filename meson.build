# SaltyOS - Unix-like Microkernel Operating System
# SPDX-License-Identifier: GPL-2.0-only

project('saltyos', ['c'],
  version: '0.1.0',
  license: 'GPL-2.0-only',
  meson_version: '>=1.1',
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=false',
    'b_staticpic=false',
    'b_pie=false',
  ])

# =============================================================================
# Build Options
# =============================================================================

arch = get_option('arch')
build_boot = get_option('build_boot')
build_kernel = get_option('build_kernel')
build_userland = get_option('build_userland')

# =============================================================================
# Toolchain (clang/lld required, nightly rustc required)
# =============================================================================

# C Compiler: must be clang
cc = meson.get_compiler('c', native: false)
if cc.get_id() != 'clang'
  error('SaltyOS requires clang. Got: ' + cc.get_id())
endif
cc_cmd = cc.cmd_array()

# Assembler
nasm = find_program('nasm', required: build_boot)

# Binary tools
objcopy = find_program('llvm-objcopy', required: build_boot)
lld_link = find_program('lld-link', required: build_boot)
llvm_strip = find_program('llvm-strip', required: false)
if not llvm_strip.found()
  llvm_strip = find_program('strip', required: build_userland)
endif

# Rust: must be nightly (required for building core library)
rustc = find_program('rustc', required: build_kernel or build_userland)
rustc_version = 'not checked'
rust_lib_src = 'N/A'

fs = import('fs')

if build_kernel or build_userland
  # Record version for summary/errors.
  rustc_version = run_command(rustc, '--version', capture: true, check: true).stdout().strip()

  # Functional check: we need a compiler that accepts unstable options (-Z),
  # which covers nightly and self-built dev rustc.
  rustc_unstable_probe = run_command(rustc, '-Z', 'unstable-options', '--version',
    capture: true, check: false)
  if rustc_unstable_probe.returncode() != 0
    error('SaltyOS requires a rustc that supports unstable options (-Z) for core/custom-target builds.\n' +
          'rustc: ' + rustc.full_path() + '\n' +
          'Got: ' + rustc_version + '\n' +
          'Fix: use rustup nightly or the patched stage1 rustc from just toolchain-build-rust.')
  endif

  # Get rust-src path from sysroot
  rustc_sysroot = run_command(rustc, '--print', 'sysroot', capture: true, check: true).stdout().strip()
  rust_lib_src = rustc_sysroot / 'lib/rustlib/src/rust/library'

  # Verify rust-src component is installed
  if not fs.is_file(rust_lib_src / 'core/src/lib.rs')
    error('rust-src component not found.\n' +
          'Expected: ' + rust_lib_src + '\n' +
          'Fix: rustup component add rust-src')
  endif
endif

# =============================================================================
# Architecture Configuration (single source of truth)
# =============================================================================

if arch == 'x86_64'
  rust_target            = 'x86_64-unknown-saltyos'
  c_target               = 'x86_64-unknown-saltyos'
  efi_target             = 'x86_64-unknown-uefi'
  rust_kernel_target     = meson.project_source_root() / 'kernite/x86_64-kernite.json'
  rust_kernel_target_needs_unstable = true
  kernel_link_emulation  = 'elf_x86_64'
  asm_target             = 'x86_64-unknown-none-elf'
  c_kernel_extra_args    = ['-mcmodel=kernel', '-mno-sse', '-mno-mmx', '-mno-sse2', '-mno-3dnow', '-mno-avx']
  build_bios_boot        = true
  efi_binary_name        = 'BOOTX64.EFI'
elif arch == 'aarch64'
  rust_target            = 'aarch64-unknown-saltyos'
  c_target               = 'aarch64-unknown-saltyos'
  efi_target             = 'aarch64-unknown-windows'
  rust_kernel_target     = meson.project_source_root() / 'kernite/aarch64-kernite.json'
  rust_kernel_target_needs_unstable = true
  kernel_link_emulation  = 'aarch64elf'
  asm_target             = 'aarch64-unknown-none-elf'
  c_kernel_extra_args    = ['-mgeneral-regs-only']
  build_bios_boot        = false
  efi_binary_name        = 'BOOTAA64.EFI'
else
  error('Unsupported architecture: ' + arch)
endif

# Userland builds require rustc to provide the configured built-in target.
if build_userland
  rust_target_list = run_command(rustc, '--print', 'target-list', capture: true, check: true).stdout()
  if not rust_target_list.contains(rust_target)
    error('Selected rustc does not provide target "' + rust_target + '".\n' +
          'rustc: ' + rustc.full_path() + '\n' +
          'Fix: use the patched stage1 rustc (e.g. just toolchain-build-rust),\n' +
          'then rerun setup with SALTYOS_TOOLCHAIN_PREFIX or RUSTC set accordingly.')
  endif
endif

# =============================================================================
# Compiler Flags
# =============================================================================

# Base freestanding flags (shared across boot components)
c_freestanding_args = [
  '-ffreestanding',
  '-fno-builtin',
  '-fno-stack-protector',
  '-fno-pic',
  '-fno-pie',
  '-nostdlib',
]
if arch == 'x86_64'
  c_freestanding_args += ['-fcf-protection=none', '-mno-red-zone']
endif

# EFI-specific flags (PE/COFF via clang UEFI target)
c_efi_args = c_freestanding_args + [
  '-target', efi_target,
  '-fshort-wchar',
  '-DEFI_BUILD',
]

# Stage3 flags (loaded at 0x10000, small code model sufficient)
c_stage3_args = c_freestanding_args + [
  '--target=' + asm_target,
  '-mcmodel=small',
]

# Kernel flags (higher half)
c_kernel_args = c_freestanding_args + c_kernel_extra_args

# Rust flags (x86_64 kernel uses JSON spec for soft-float/kernel code model)
rust_kernel_args = [
  '--edition=2024',
  '--target=' + rust_kernel_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
]
if get_option('debug_symbols')
  rust_kernel_args += ['-C', 'debuginfo=2']
endif
if rust_kernel_target_needs_unstable
  rust_kernel_args += ['-Z', 'unstable-options']
endif

# =============================================================================
# Subdirectories
# =============================================================================

if build_boot
  subdir('boot')
endif

if build_kernel or build_userland
  # Build core library and compiler_builtins (shared by kernel and userland)
  subdir('rust')
endif

if build_kernel
  subdir('kernite')
endif

if build_userland
  subdir('lib')
  subdir('userland')
endif

# Port host tools — only when ports are enabled (requires host std for rustc)
if get_option('build_ports')
  subdir('tools/port')
  subdir('tools/pkg')
endif

# Generate cross-compilation sysroot from build outputs.
# Ports depend on this to find headers, libraries, and linker scripts.
if build_userland
  mksysroot_prog = find_program('tools/mksysroot')
  sysroot_target = custom_target('sysroot',
    output: 'sysroot.stamp',
    depends: [core, compiler_builtins, libtrona_so, libc_so, crt_start_obj, ld_trona_so],
    depend_files: basaltc_header_files + [files('lib/trona/trona-pie.ld')],
    command: [
      mksysroot_prog,
      '--build-dir', meson.project_build_root(),
      '--output', meson.project_build_root() / 'sysroot',
      '-v',
      '--stamp', '@OUTPUT@',
    ],
    build_by_default: true,
  )
endif

# Ports metadata/targets — only when ports are enabled.
if build_userland and get_option('build_ports')
  subdir('ports')
endif
if not is_variable('port_depends')
  port_depends = []
endif

# =============================================================================
# Initrd Generation (CPIO archive with extensionless runtime names)
# =============================================================================

mkcpio = find_program('tools/mkcpio.py', required: false)
initrd_args = []
initrd_inputs = []
initrd_target = []

if build_userland and mkcpio.found()
  # Strip all initrd payload binaries to minimize low-memory footprint.
  initrd_init_elf = custom_target('initrd_init_elf',
    input: init_boot_elf,
    output: 'init.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_console_elf = custom_target('initrd_console_elf',
    input: console_elf,
    output: 'console.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_rtld_so = custom_target('initrd_rtld_so',
    input: ld_trona_so,
    output: 'ld-trona.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_pe_rtld_so = custom_target('initrd_pe_rtld_so',
    input: ld_trona_pe_so,
    output: 'ld-trona-pe.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_libtrona_so = custom_target('initrd_libtrona_so',
    input: libtrona_so,
    output: 'libtrona.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_libc_so = custom_target('initrd_libc_so',
    input: libc_so,
    output: 'libc.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_libcxx_so = custom_target('initrd_libcxx_so',
    input: libcxx_so,
    output: 'libc++.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_kernel32_dll = custom_target('initrd_kernel32_dll',
    input: kernel32_dll,
    output: 'kernel32.initrd.dll',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_namesrv_elf = custom_target('initrd_namesrv_elf',
    input: namesrv_elf,
    output: 'namesrv.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_procmgr_elf = custom_target('initrd_procmgr_elf',
    input: procmgr_elf,
    output: 'procmgr.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_vfs_elf = custom_target('initrd_vfs_elf',
    input: vfs_elf,
    output: 'vfs.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  # Keep late userspace services in both initrd and rootfs.
  # This preserves the renamed service set while avoiding a boot-time
  # dependency on the root underlay being mounted before spawn.
  stripped_dispdrv_elf = custom_target('stripped_dispdrv_elf',
    input: dispdrv_elf,
    output: 'dispdrv.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_posix_ttysrv_elf = custom_target('stripped_posix_ttysrv_elf',
    input: posix_ttysrv_elf,
    output: 'posix_ttysrv.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_test_runner_elf = custom_target('stripped_test_runner_elf',
    input: test_runner_elf,
    output: 'test_runner.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_vfs_stress_elf = custom_target('stripped_vfs_stress_elf',
    input: vfs_stress_elf_elf,
    output: 'vfs_stress_elf.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_posix_getty_elf = custom_target('stripped_posix_getty_elf',
    input: posix_getty_elf,
    output: 'posix_getty.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_posix_login_elf = custom_target('stripped_posix_login_elf',
    input: posix_login_elf,
    output: 'posix_login.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_netdrv_elf = custom_target('stripped_netdrv_elf',
    input: netdrv_elf,
    output: 'netdrv.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_netsrv_elf = custom_target('stripped_netsrv_elf',
    input: netsrv_elf,
    output: 'netsrv.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_dnssrv_elf = custom_target('stripped_dnssrv_elf',
    input: dnssrv_elf,
    output: 'dnssrv.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_mmsrv_elf = custom_target('initrd_mmsrv_elf',
    input: mmsrv_elf,
    output: 'mmsrv.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_rsrcsrv_elf = custom_target('initrd_rsrcsrv_elf',
    input: rsrcsrv_elf,
    output: 'rsrcsrv.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_pcidrv_elf = custom_target('initrd_pcidrv_elf',
    input: pcidrv_elf,
    output: 'pcidrv.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_blkdrv_elf = custom_target('initrd_blkdrv_elf',
    input: blkdrv_elf,
    output: 'blkdrv.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_saltyfs_elf = custom_target('initrd_saltyfs_elf',
    input: saltyfs_elf,
    output: 'saltyfs.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_win32_csrss_elf = custom_target('initrd_win32_csrss_elf',
    input: win32_csrss_elf,
    output: 'win32_csrss.initrd.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_hello_pe_exe = custom_target('stripped_hello_pe_exe',
    input: hello_pe_exe,
    output: 'hello_pe.stripped.exe',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_vfs_stress_pe_exe = custom_target('stripped_vfs_stress_pe_exe',
    input: vfs_stress_pe_exe,
    output: 'vfs_stress_pe.stripped.exe',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_console_stress_pe_exe = custom_target('stripped_console_stress_pe_exe',
    input: console_stress_pe_exe,
    output: 'console_stress_pe.stripped.exe',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )

  # Service definition files
  svc_console = files('userland/services/console.service')
  svc_namesrv = files('userland/services/namesrv.service')
  svc_mmsrv = files('userland/services/mmsrv.service')
  svc_rsrcsrv = files('userland/services/rsrcsrv.service')
  svc_rsrcsrv_target = files('userland/services/rsrcsrv.target')
  svc_vfs = files('userland/services/vfs.service')
  svc_procmgr = files('userland/services/procmgr.service')
  svc_procmgr_target = files('userland/services/procmgr.target')
  svc_dispdrv = files('userland/services/dispdrv.service')
  svc_posix_ttysrv = files('userland/services/posix_ttysrv.service')
  svc_test_runner = files('userland/services/test_runner.service')
  svc_posix_getty = files('userland/services/posix_getty.service')
  svc_pcidrv = files('userland/services/pcidrv.service')
  svc_blkdrv = files('userland/services/blkdrv.service')
  svc_saltyfs = files('userland/services/saltyfs.service')
  svc_netdrv = files('userland/services/netdrv.service')
  svc_netsrv = files('userland/services/netsrv.service')
  svc_dnssrv = files('userland/services/dnssrv.service')
  svc_win32_csrss = files('userland/services/win32_csrss.service')
  svc_hello_pe = files('userland/services/hello_pe.service')

  # Initrd CPIO from manifest — the manifest references build output filenames
  # resolved via --port-dir, and service files via repo-relative paths.
  mkcpio_script = files('tools/mkcpio.py')
  initramfs_manifest = files('images/initramfs.manifest')

  initrd = custom_target('initrd',
    input: [initrd_rtld_so, initrd_pe_rtld_so, initrd_libtrona_so, initrd_libc_so,
          initrd_libcxx_so, initrd_kernel32_dll,
          initrd_init_elf, initrd_console_elf, initrd_namesrv_elf,
          initrd_procmgr_elf, initrd_vfs_elf, initrd_mmsrv_elf,
          initrd_rsrcsrv_elf,
          initrd_pcidrv_elf, initrd_blkdrv_elf, initrd_saltyfs_elf,
          initrd_win32_csrss_elf,
          stripped_dispdrv_elf, stripped_posix_ttysrv_elf, stripped_posix_getty_elf,
          stripped_test_runner_elf, stripped_netdrv_elf, stripped_netsrv_elf,
          stripped_dnssrv_elf, stripped_hello_pe_exe],
    depend_files: [mkcpio_script, initramfs_manifest,
          svc_console, svc_namesrv, svc_mmsrv, svc_rsrcsrv, svc_rsrcsrv_target,
          svc_vfs, svc_procmgr, svc_procmgr_target, svc_dispdrv,
          svc_posix_ttysrv, svc_test_runner, svc_posix_getty,
          svc_pcidrv, svc_blkdrv, svc_saltyfs, svc_netdrv, svc_netsrv,
          svc_dnssrv, svc_win32_csrss, svc_hello_pe],
    output: 'initrd.cpio',
    command: [mkcpio,
      '--output', '@OUTPUT@',
      '--manifest', initramfs_manifest,
      '--port-dir', meson.project_build_root(),
      '--permissions', meson.project_source_root() / 'images' / 'rootfs.permissions',
    ],
    build_by_default: true,
  )
  initrd_args = ['--initrd', initrd.full_path()]
  initrd_inputs = [initrd]
  initrd_target = [initrd]
endif

# =============================================================================
# Rootfs Image Generation (optional — embed SaltyFS rootfs into disk image)
#
# Three independent layers, each optional:
#   1. Binaries  (always)  — non-initrd userland ELFs
#   2. Toolchain (optional) — cross-compiled LLVM, present after `just tc package`
#   3. Ports     (optional) — bash, coreutils, etc., present when build_ports=true
# =============================================================================

mkrootfs = find_program('tools/mkrootfs', required: false)
mkrootfs_script = files('tools/mkrootfs')
mksaltyfs_script = files('tools/mksaltyfs.py')

rootfs_inputs = []
rootfs_args = []
if mkrootfs.found() and build_userland
  # Stripped shared libraries for rootfs (separate from initrd targets)
  rootfs_rtld_so = custom_target('rootfs_rtld_so',
    input: ld_trona_so,
    output: 'ld-trona.rootfs.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: false,
  )
  rootfs_pe_rtld_so = custom_target('rootfs_pe_rtld_so',
    input: ld_trona_pe_so,
    output: 'ld-trona-pe.rootfs.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: false,
  )
  rootfs_libtrona_so = custom_target('rootfs_libtrona_so',
    input: libtrona_so,
    output: 'libtrona.rootfs.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: false,
  )
  rootfs_libc_so = custom_target('rootfs_libc_so',
    input: libc_so,
    output: 'libc.rootfs.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: false,
  )
  rootfs_libcxx_so = custom_target('rootfs_libcxx_so',
    input: libcxx_so,
    output: 'libc++.rootfs.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: false,
  )
  rootfs_kernel32_dll = custom_target('rootfs_kernel32_dll',
    input: kernel32_dll,
    output: 'kernel32.rootfs.dll',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: false,
  )

  # Layer 1 (always): stripped shared libraries + stripped userland binaries
  rootfs_binaries_manifest = custom_target('rootfs_binaries_manifest',
    input: [rootfs_rtld_so, rootfs_pe_rtld_so, rootfs_libtrona_so,
            rootfs_libc_so, rootfs_libcxx_so, rootfs_kernel32_dll,
            stripped_dispdrv_elf, stripped_posix_ttysrv_elf, stripped_posix_getty_elf,
            stripped_posix_login_elf, stripped_test_runner_elf,
            stripped_netdrv_elf, stripped_netsrv_elf, stripped_dnssrv_elf,
            stripped_vfs_stress_elf, stripped_vfs_stress_pe_exe,
            stripped_console_stress_pe_exe],
    output: 'rootfs-binaries.manifest',
    command: [find_program('python3'), '-c',
      'import sys; f=open(sys.argv[1],"w"); [f.write(e+chr(10)) for e in sys.argv[2:]]',
      '@OUTPUT@',
      '/lib/ld-trona.so=@INPUT0@',
      '/lib/ld-trona-pe.so=@INPUT1@',
      '/lib/libtrona.so=@INPUT2@',
      '/lib/libc.so=@INPUT3@',
      '/lib/libc++.so=@INPUT4@',
      '/lib/kernel32.dll=@INPUT5@',
      '/bin/dispdrv=@INPUT6@',
      '/bin/posix_ttysrv=@INPUT7@',
      '/bin/posix_getty=@INPUT8@',
      '/bin/login=@INPUT9@',
      '/bin/test_runner=@INPUT10@',
      '/bin/netdrv=@INPUT11@',
      '/bin/netsrv=@INPUT12@',
      '/bin/dnssrv=@INPUT13@',
      '/bin/vfs_stress_elf=@INPUT14@',
      '/bin/vfs_stress_pe=@INPUT15@',
      '/bin/console_stress_pe=@INPUT16@',
    ],
    build_by_default: false,
  )

  rootfs_permissions = files('images/rootfs.permissions')
  _rootfs_cmd = [mkrootfs, '--output', '@OUTPUT@', '--size', '1G',
                 '--manifest', rootfs_binaries_manifest,
                 '--permissions', meson.project_source_root() / 'images' / 'rootfs.permissions']
  _rootfs_deps = [rootfs_binaries_manifest]
  _rootfs_dep_files = [mkrootfs_script, mksaltyfs_script, rootfs_permissions]

  # Layer 2 (optional): LLVM toolchain — present after `just tc package`
  # tc-package/ lives inside the build directory so distclean cleans it.
  # The manifest references meson build outputs directly for OS libraries,
  # eliminating stale-copy bugs.
  _tc_package_dir = meson.project_build_root() / 'tc-package'
  _tc_manifest = _tc_package_dir / 'rootfs.manifest'
  _rootfs_cmd += ['--manifest-optional', _tc_manifest]
  # Legacy fallback: support old location during transition
  _legacy_stripped_dir = 'build-toolchain' / 'llvm-' + arch + '-stripped'
  _legacy_manifest = meson.project_source_root() / _legacy_stripped_dir / 'rootfs.manifest'
  _rootfs_cmd += ['--manifest-optional', _legacy_manifest]

  # Layer 3 (optional): ports — only when build_ports=true
  if get_option('build_ports') and is_variable('pkg_tool')
    rootfs_packages = files('images/rootfs.packages')[0]
    rootfs_port_targets = []
    foreach _line : fs.read(rootfs_packages).split('\n')
      _pkg = _line.strip()
      if _pkg == '' or _pkg.startswith('#')
        continue
      endif
      _var = 'port_' + _pkg.underscorify()
      if is_variable(_var)
        rootfs_port_targets += [get_variable(_var)]
      else
        warning('rootfs package list references unknown port: ' + _pkg)
      endif
    endforeach

    rootfs_ports_manifest = custom_target('rootfs_ports_manifest',
      depends: rootfs_port_targets + [pkg_tool],
      depend_files: [rootfs_packages],
      output: 'rootfs-ports.manifest',
      command: [pkg_tool,
        'install',
        '--repo', meson.project_build_root() / 'pkgrepo',
        '--root', meson.project_build_root() / 'rootfs-pkgroot',
        '--packages-file', rootfs_packages,
        '--manifest-out', '@OUTPUT@',
        '--clean-root',
      ],
      build_by_default: false,
    )
    _rootfs_cmd += ['--manifest', rootfs_ports_manifest]
    _rootfs_deps += [rootfs_ports_manifest]
  endif

  rootfs_image = custom_target('rootfs_image',
    input: [],
    depends: _rootfs_deps,
    depend_files: _rootfs_dep_files,
    output: 'rootfs.img',
    command: _rootfs_cmd,
    build_by_default: false,
  )
  rootfs_inputs = [rootfs_image]
  rootfs_args = ['--rootfs', rootfs_image]
endif

# =============================================================================
# Disk Image Generation
# =============================================================================

mkimage = find_program('tools/mkimage.py', required: false)

mkimage_script = files('tools/mkimage.py')

if mkimage.found() and build_boot and build_kernel

  # BIOS disk image (x86_64 only)
  if build_bios_boot
    disk_image = custom_target('disk_image',
      input: [mbr, stage2, stage3, kernel_boot] + initrd_inputs + rootfs_inputs,
      depend_files: mkimage_script,
      output: 'saltyos.img',
      command: [mkimage,
        '--build-dir', meson.project_build_root(),
        '--kernel', kernel_boot.full_path(),
        '--output', '@OUTPUT@',
        '--size', '16',
      ] + initrd_args + rootfs_args,
      build_by_default: true,
    )
  endif

  # UEFI disk image (all architectures)
  uefi_image = custom_target('uefi_image',
    input: [efi, stage2_efi, stage3_uefi, kernel_boot] + initrd_inputs + rootfs_inputs,
    depend_files: mkimage_script,
    output: 'saltyos-uefi.img',
    command: [mkimage,
      '--efi',
      '--arch', arch,
      '--build-dir', meson.project_build_root(),
      '--kernel', kernel_boot.full_path(),
      '--output', '@OUTPUT@',
      '--size', '64',
    ] + initrd_args + rootfs_args,
    build_by_default: not build_bios_boot,
  )

endif

# =============================================================================
# Summary
# =============================================================================

summary({
  'Architecture': arch,
  'Bootloader': build_boot,
  'BIOS Boot': build_bios_boot,
  'Kernel': build_kernel,
  'Userland': build_userland,
}, section: 'Build')

summary({
  'C Compiler': cc.get_id() + ' ' + cc.version(),
  'Rust': rustc.found() ? rustc_version : 'not found',
  'NASM': nasm.found() ? nasm.full_path() : 'not found',
}, section: 'Toolchain')

summary({
  'Rust Target': rust_target,
  'Rust Lib Src': build_kernel ? rust_lib_src : 'N/A',
  'EFI Target': efi_target,
  'EFI Binary': efi_binary_name,
  'ASM Target': asm_target,
  'Kernel Link Emulation': kernel_link_emulation,
}, section: 'Targets')
