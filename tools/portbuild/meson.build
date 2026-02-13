# portbuild — SaltyOS ports build tool
# SPDX-License-Identifier: GPL-2.0-only
#
# Compiled as a native host tool (runs on developer machine, not SaltyOS).

portbuild_src = files('main.rs')

portbuild = custom_target('portbuild',
  input: portbuild_src,
  output: 'portbuild',
  depend_files: files(
    'parser.rs',
    'vars.rs',
    'fetch.rs',
    'extract.rs',
    'build.rs',
    'config.rs',
    'deps.rs',
    'stamps.rs',
  ),
  command: [rustc, '--edition=2024',
    '-o', '@OUTPUT@', '@INPUT@'],
  build_by_default: true,
)
