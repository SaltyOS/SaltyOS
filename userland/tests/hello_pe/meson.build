# SaltyOS Win32 PE test program
# SPDX-License-Identifier: GPL-2.0-only
#
# Builds hello_pe.exe — a minimal PE/COFF executable that imports from
# kernel32.dll.  Follows the same clang → lld-link pipeline as
# lib/trona/meson.build (kernel32.dll build).

if arch == 'x86_64'
  hello_pe_target  = 'x86_64-w64-windows-gnu'
  hello_pe_machine = 'amd64'
elif arch == 'aarch64'
  hello_pe_target  = 'aarch64-w64-windows-gnu'
  hello_pe_machine = 'arm64'
else
  error('Unsupported arch for hello_pe: ' + arch)
endif

# Step 1: Compile C → COFF object
hello_pe_obj = custom_target('hello_pe_obj',
  input: files('hello_pe.c'),
  output: 'hello_pe.obj',
  depfile: 'hello_pe.d',
  command: cc_cmd + [
    '--target=' + hello_pe_target,
    '-ffreestanding',
    '-fno-stack-protector',
    '-fno-builtin',
    '-MMD', '-MF', '@DEPFILE@',
    '-c', '-o', '@OUTPUT@', '@INPUT@',
  ],
  build_by_default: true,
)

# Step 2: Link PE executable against kernel32.lib (import library)
#
# lld-link produces kernel32.lib alongside kernel32.dll automatically.
# The import library lives in the libtrona build directory.
hello_pe_exe = custom_target('hello_pe_exe',
  input: [hello_pe_obj],
  output: 'hello_pe.exe',
  depends: [kernel32_dll],
  command: [lld_link,
    '-subsystem:console',
    '-nodefaultlib',
    '-machine:' + hello_pe_machine,
    '-entry:mainCRTStartup',
    '-out:@OUTPUT@',
    '@INPUT0@',
    libtrona_build_dir / 'kernel32.lib',
  ],
  build_by_default: true,
)
