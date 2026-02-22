# SaltyOS Init Process Build (Rust, statically linked)
# SPDX-License-Identifier: GPL-2.0-only

init_link = meson.current_source_dir() / 'link.ld'
libsalty_build_dir = meson.project_build_root() / 'lib/libsalty'

# Step 1: Rust -> .o
init_obj = custom_target('init_obj',
  input: files('src/main.rs'),
  output: 'init.o',
  depfile: 'init.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT@,dep-info=@DEPFILE@',
    '--crate-name=init',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

# Step 2: .o + libsalty.o + fork.o + core.o + compiler_builtins.o + string.c -> init.elf (static)
init_elf = custom_target('init_elf',
  input: [init_obj, libsalty_obj, fork_obj, core_obj, compiler_builtins_obj,
          meson.project_source_root() / 'lib/libc/string.c'],
  output: 'init.elf',
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIC', '-shared',
    '-fno-plt', '-Wl,-Bsymbolic',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-T', init_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

# Step 3: stripped init ELF for boot image/initrd (keep init.elf for debugging)
init_boot_elf = custom_target('init_boot_elf',
  input: [init_obj, libsalty_obj, fork_obj, core_obj, compiler_builtins_obj,
          meson.project_source_root() / 'lib/libc/string.c'],
  output: 'init.boot.elf',
  command: [cc_cmd,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fPIC', '-shared',
    '-fno-plt', '-Wl,-Bsymbolic',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-Wl,-S',
    '-T', init_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
