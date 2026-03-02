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
# Architecture Configuration
# =============================================================================

if arch == 'x86_64'
  rust_target = 'x86_64-unknown-saltyos'
  c_target = 'x86_64-unknown-saltyos'
  efi_target = 'x86_64-unknown-uefi'
  rust_kernel_target = meson.project_source_root() / 'kernel/x86_64-saltyos.json'
  rust_kernel_target_needs_unstable = true
elif arch == 'aarch64'
  rust_target = 'aarch64-unknown-none'
  c_target = 'aarch64-unknown-none'
  efi_target = 'aarch64-unknown-uefi'
  rust_kernel_target = rust_target
  rust_kernel_target_needs_unstable = false
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
  '-fcf-protection=none',
  '-fno-stack-protector',
  '-fno-pic',
  '-fno-pie',
  '-mno-red-zone',
  '-nostdlib',
]

# EFI-specific flags (PE/COFF via clang UEFI target)
c_efi_args = c_freestanding_args + [
  '-target', efi_target,
  '-fshort-wchar',
  '-DEFI_BUILD',
]

# Stage3 flags (loaded at 0x10000, small code model sufficient)
c_stage3_args = c_freestanding_args + [
  '-m64',
  '-mcmodel=small',
]

# Kernel flags (higher half)
if arch == 'x86_64'
  c_kernel_args = c_freestanding_args + [
    '-mcmodel=kernel',
    '-mno-sse',
    '-mno-mmx',
    '-mno-sse2',
    '-mno-3dnow',
    '-mno-avx',
  ]
else
  c_kernel_args = c_freestanding_args
endif

# Rust flags (x86_64 kernel uses JSON spec for soft-float/kernel code model)
rust_kernel_args = [
  '--edition=2024',
  '--target=' + rust_kernel_target,
  '-C', 'panic=abort',
  '-C', 'opt-level=2',
  '-C', 'debuginfo=2',
]
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
  subdir('kernel')
endif

if build_userland
  subdir('lib')
  subdir('userland')
endif

# Port host tool — always built with userland (needed by `just port`)
if build_userland
  subdir('tools/port')
  subdir('tools/pkg')
endif

# Generate cross-compilation sysroot from build outputs.
# Ports depend on this to find headers, libraries, and linker scripts.
if build_userland
  mksysroot_prog = find_program('tools/mksysroot')
  sysroot_target = custom_target('sysroot',
    output: 'sysroot.stamp',
    depends: [core, compiler_builtins, libbesalt_so, libc_so, crt_start_obj, ld_besalt_so],
    depend_files: besaltc_header_files + [files('userland/tests/hello/link.ld')],
    command: [
      mksysroot_prog,
      '--build-dir', meson.project_build_root(),
      '--output', meson.project_build_root() / 'sysroot',
      '--clean', '-v',
      '--stamp', '@OUTPUT@',
    ],
    build_by_default: false,
  )
endif

# Ports metadata/targets are always defined with userland. Individual port
# targets are only built by default when -Dbuild_ports=true, but rootfs/image
# targets may depend on specific runtime ports (e.g. bash).
if build_userland
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
    input: ld_besalt_so,
    output: 'ld-besalt.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_libbesalt_so = custom_target('initrd_libbesalt_so',
    input: libbesalt_so,
    output: 'libbesalt.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_libc_so = custom_target('initrd_libc_so',
    input: libc_so,
    output: 'libc.initrd.so',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  initrd_nameserv_elf = custom_target('initrd_nameserv_elf',
    input: nameserv_elf,
    output: 'nameserv.initrd.elf',
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
  # Non-boot-critical binaries: stripped for rootfs, NOT included in initrd.
  stripped_display_elf = custom_target('stripped_display_elf',
    input: display_elf,
    output: 'display.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_ttyd_elf = custom_target('stripped_ttyd_elf',
    input: ttyd_elf,
    output: 'ttyd.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_test_runner_elf = custom_target('stripped_test_runner_elf',
    input: test_runner_elf,
    output: 'test_runner.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_hello_elf = custom_target('stripped_hello_elf',
    input: hello_elf,
    output: 'hello.stripped.elf',
    command: [llvm_strip, '--strip-all', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
  stripped_getty_elf = custom_target('stripped_getty_elf',
    input: getty_elf,
    output: 'getty.stripped.elf',
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
  initrd_pcisrv_elf = custom_target('initrd_pcisrv_elf',
    input: pcisrv_elf,
    output: 'pcisrv.initrd.elf',
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

  # Service definition files
  svc_console = files('userland/services/console.service')
  svc_nameserv = files('userland/services/nameserv.service')
  svc_mmsrv = files('userland/services/mmsrv.service')
  svc_vfs = files('userland/services/vfs.service')
  svc_procmgr = files('userland/services/procmgr.service')
  svc_display = files('userland/services/display.service')
  svc_ttyd = files('userland/services/ttyd.service')
  svc_test_runner = files('userland/services/test_runner.service')
  svc_hello = files('userland/services/hello.service')
  svc_getty = files('userland/services/getty.service')
  svc_pcisrv = files('userland/services/pcisrv.service')
  svc_blkdrv = files('userland/services/blkdrv.service')
  svc_saltyfs = files('userland/services/saltyfs.service')
  svc_netdrv = files('userland/services/netdrv.service')
  svc_netsrv = files('userland/services/netsrv.service')
  svc_dnssrv = files('userland/services/dnssrv.service')

  # Shared libraries first for minimal library-window mapping.
  mkcpio_script = files('tools/mkcpio.py')
  # Boot-critical binaries only (non-critical moved to rootfs).
  initrd = custom_target('initrd',
    input: [initrd_rtld_so, initrd_libbesalt_so, initrd_libc_so,
            initrd_init_elf, initrd_console_elf, initrd_nameserv_elf,
            initrd_procmgr_elf, initrd_vfs_elf, initrd_mmsrv_elf,
            initrd_pcisrv_elf, initrd_blkdrv_elf, initrd_saltyfs_elf,
            svc_console, svc_nameserv, svc_mmsrv,
            svc_vfs, svc_procmgr, svc_display,
            svc_ttyd, svc_test_runner, svc_hello, svc_getty,
            svc_pcisrv, svc_blkdrv, svc_saltyfs, svc_netdrv, svc_netsrv,
            svc_dnssrv],
    depend_files: mkcpio_script,
    output: 'initrd.cpio',
    command: [mkcpio,
      '--output', '@OUTPUT@',
      ] + [
      # Shared libraries (inputs 0-2)
      'ld-besalt.so=@INPUT0@',
      'libbesalt.so=@INPUT1@',
      'libc.so=@INPUT2@',
      # Boot-critical services (inputs 3-11)
      'init=@INPUT3@',
      'console=@INPUT4@',
      'nameserv=@INPUT5@',
      'procmgr=@INPUT6@',
      'vfs=@INPUT7@',
      'mmsrv=@INPUT8@',
      'pcisrv=@INPUT9@',
      'blkdrv=@INPUT10@',
      'saltyfs=@INPUT11@',
      # Service definitions (inputs 12-27)
      'services/console.service=@INPUT12@',
      'services/nameserv.service=@INPUT13@',
      'services/mmsrv.service=@INPUT14@',
      'services/vfs.service=@INPUT15@',
      'services/procmgr.service=@INPUT16@',
      'services/display.service=@INPUT17@',
      'services/ttyd.service=@INPUT18@',
      'services/test_runner.service=@INPUT19@',
      'services/hello.service=@INPUT20@',
      'services/getty.service=@INPUT21@',
      'services/pcisrv.service=@INPUT22@',
      'services/blkdrv.service=@INPUT23@',
      'services/saltyfs.service=@INPUT24@',
      'services/netdrv.service=@INPUT25@',
      'services/netsrv.service=@INPUT26@',
      'services/dnssrv.service=@INPUT27@',
    ],
    build_by_default: true,
  )
  initrd_args = ['--initrd', initrd.full_path()]
  initrd_inputs = [initrd]
  initrd_target = [initrd]
endif

# =============================================================================
# Rootfs Image Generation (optional — embed SaltyFS rootfs into disk image)
# =============================================================================

mkrootfs = find_program('tools/mkrootfs', required: false)
mkrootfs_script = files('tools/mkrootfs')
mksaltyfs_script = files('tools/mksaltyfs.py')
rootfs_manifest = files('images/rootfs.manifest')[0]
rootfs_packages = files('images/rootfs.packages')[0]

rootfs_inputs = []
rootfs_args = []
if mkrootfs.found() and build_userland
  if not is_variable('pkg_tool')
    error('rootfs package assembly requires pkg_tool target (tools/pkg)')
  endif
  rootfs_port_targets = []
  foreach _line : fs.read(rootfs_packages).split('\n')
    _pkg = _line.strip()
    if _pkg == '' or _pkg.startswith('#')
      continue
    endif
    _var = 'port_' + _pkg.underscorify()
    if not is_variable(_var)
      error('rootfs package list references unknown port: ' + _pkg)
    endif
    rootfs_port_targets += [get_variable(_var)]
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

  rootfs_image = custom_target('rootfs_image',
    input: [stripped_display_elf, stripped_ttyd_elf, stripped_getty_elf,
            stripped_test_runner_elf, stripped_hello_elf,
            stripped_netdrv_elf, stripped_netsrv_elf, stripped_dnssrv_elf],
    depends: [rootfs_ports_manifest],
    depend_files: [mkrootfs_script, mksaltyfs_script, rootfs_manifest, rootfs_packages],
    output: 'rootfs.img',
    command: [mkrootfs,
      '--output', '@OUTPUT@',
      '--size', '512M',
      '--manifest', rootfs_manifest,
      '--manifest', rootfs_ports_manifest,
    ],
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

  # BIOS disk image
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

  # UEFI disk image
  if arch == 'x86_64'
    uefi_image = custom_target('uefi_image',
      input: [efi, stage2_efi, stage3_uefi, kernel_boot] + initrd_inputs + rootfs_inputs,
      depend_files: mkimage_script,
      output: 'saltyos-uefi.img',
      command: [mkimage,
        '--efi',
        '--build-dir', meson.project_build_root(),
        '--kernel', kernel_boot.full_path(),
        '--output', '@OUTPUT@',
        '--size', '64',
      ] + initrd_args + rootfs_args,
      build_by_default: false,
    )
  endif

endif

# =============================================================================
# Summary
# =============================================================================

summary({
  'Architecture': arch,
  'Bootloader': build_boot,
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
}, section: 'Targets')
