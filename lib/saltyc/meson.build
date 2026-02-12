# saltyc — SaltyOS C Standard Library (Rust + ASM → libc.so)
# SPDX-License-Identifier: GPL-2.0-only

saltyc_link = meson.current_source_dir() / 'saltyc.ld'
rust_build_dir = meson.project_build_root() / 'rust'
libsalty_build_dir = meson.project_build_root() / 'lib' / 'libsalty'

# Step 1: Rust -> .o + .rmeta (depends on libsalty for --extern salty)
saltyc_rust = custom_target('saltyc_rust',
  input: files('src/lib.rs'),
  output: ['saltyc.o', 'saltyc.rmeta'],
  depfile: 'saltyc.d',
  command: [rustc,
    rust_userland_args,
    '--emit=obj=@OUTPUT0@,metadata=@OUTPUT1@,dep-info=@DEPFILE@',
    '--crate-name=saltyc',
    '--crate-type=lib',
    '--extern', 'salty=' + libsalty_build_dir / 'libsalty.rmeta',
    '@INPUT@',
  ],
  depends: [core, compiler_builtins, libsalty_rust],
  build_by_default: true,
)

saltyc_obj = saltyc_rust[0]

# Step 2: crt_start.S -> crt_start.o
crt_start_obj = custom_target('crt_start_asm',
  input: files('crt_start.S'),
  output: 'crt_start.o',
  command: [cc_cmd, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# Step 3: setjmp.S -> setjmp.o
setjmp_obj = custom_target('setjmp_asm',
  input: files('setjmp.S'),
  output: 'setjmp.o',
  command: [cc_cmd, '-c', '@INPUT@', '-o', '@OUTPUT@'],
  build_by_default: true,
)

# Step 4: saltyc.o + setjmp.o + core.o -> libc.so
# NOTE: crt_start_obj is NOT linked into libc.so — it is a separate static
# object that C programs link directly, so that libc.so does not carry an
# unresolved reference to main().
libc_so = custom_target('libc_so',
  input: [saltyc_obj, setjmp_obj, core_obj, compiler_builtins_obj],
  output: 'libc.so',
  command: [cc_cmd,
    '-fPIC', '-shared',
    '-nostdlib', '-nostartfiles', '-ffreestanding',
    '-fno-stack-protector',
    '-mno-red-zone',
    '-fuse-ld=lld',
    '-Wl,-soname,libc.so',
    '-Wl,--hash-style=gnu',
    '-T', saltyc_link,
    '-o', '@OUTPUT@',
    '@INPUT@',
  ],
  build_by_default: true,
)
