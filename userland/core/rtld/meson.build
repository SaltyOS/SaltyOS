# SaltyOS Runtime Dynamic Linker Build
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds ld-besalt.so as a static PIE with no external dependencies.
# C sources are compiled individually with depfiles so that header
# changes (e.g. rtld_internal.h) trigger recompilation.

rtld_c_sources = files(
    'rtld_main.c',
    'rtld_elf.c',
    'rtld_symbol.c',
    'rtld_reloc.c',
)
rtld_link_script = meson.current_source_dir() / 'arch' / arch / 'rtld.ld'

# Enable verbose rtld output at debug/trace log levels
rtld_extra_args = []
if get_option('userland_log_level') in ['debug', 'trace']
  rtld_extra_args += ['-DRTLD_DEBUG']
endif

rtld_c_args = [
    '--target=' + c_target,
    '-ffreestanding',
    '-fPIC',
    '-fno-plt',
    '-fno-stack-protector',
    '-I', meson.current_source_dir(),
] + rtld_extra_args

# Step 1: Compile each C source with depfile for header tracking
rtld_objs = []
foreach src : rtld_c_sources
  src_name = fs.name(src)
  obj_name = 'rtld_' + src_name.replace('.c', '.o')
  dep_name = 'rtld_' + src_name.replace('.c', '.d')
  rtld_objs += custom_target(obj_name,
    input: src,
    output: obj_name,
    depfile: dep_name,
    command: [cc_cmd, rtld_c_args, '-MMD', '-MF', '@DEPFILE@',
             '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
  )
endforeach

# Step 2: Assemble arch-specific resolve trampoline
rtld_resolve_obj = custom_target('rtld_resolve_asm',
    input: files('arch' / arch / 'rtld_resolve.S'),
    output: 'rtld_resolve.o',
    command: [cc_cmd, '--target=' + c_target, '-c', '-o', '@OUTPUT@', '@INPUT@'],
    build_by_default: true,
)

# Step 3: Link ld-besalt.so
ld_besalt_so = custom_target('ld_besalt_so',
    input: rtld_objs + [rtld_resolve_obj],
    output: 'ld-besalt.so',
    command: [cc_cmd,
        '--target=' + c_target,
        '-nostdlib', '-nostartfiles',
        '-fno-stack-protector',
        '-Wl,-Bsymbolic',
        '-T', rtld_link_script,
        '-Wl,-soname,ld-besalt.so',
        '-o', '@OUTPUT@',
        '@INPUT@',
    ],
    build_by_default: true,
)
