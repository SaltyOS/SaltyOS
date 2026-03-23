# SaltyOS Init Process Build (Rust, statically linked)
# SPDX-License-Identifier: GPL-2.0-only

init_link = meson.current_source_dir() / 'arch' / arch / 'link.ld'

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
    '--extern', 'besalt=' + libbesalt_build_dir / 'libbesalt.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libbesalt_rust],
  build_by_default: true,
)

# Step 2: .o + libbesalt.o + fork.o + core.o + compiler_builtins.o + string.c -> init.elf (static)
init_elf = custom_target('init_elf',
  input: [init_obj, libbesalt_obj, fork_obj, core_obj, compiler_builtins_obj,
          meson.project_source_root() / 'lib/besalt/c/src/string.c'],
  output: 'init.elf',
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-shared',
    '-fno-plt', '-Wl,-Bsymbolic',
    '-fno-stack-protector',
    '-T', init_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)

# Step 3: stripped init ELF for boot image/initrd (keep init.elf for debugging)
init_boot_elf = custom_target('init_boot_elf',
  input: [init_obj, libbesalt_obj, fork_obj, core_obj, compiler_builtins_obj,
          meson.project_source_root() / 'lib/besalt/c/src/string.c'],
  output: 'init.boot.elf',
  command: [cc_cmd,
    '--target=' + c_target,
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-shared',
    '-fno-plt', '-Wl,-Bsymbolic',
    '-fno-stack-protector',
    '-Wl,-S',
    '-T', init_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
