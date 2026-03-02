# pkg — SaltyOS package tool (host-side)
# SPDX-License-Identifier: GPL-2.0-only
#
# Compiled as a native host tool (runs on developer machine, not SaltyOS).

pkg_src = files('main.rs')

pkg_tool = custom_target('pkg_tool',
  input: pkg_src,
  output: 'pkg',
  command: [rustc, '--edition=2024',
    '-o', '@OUTPUT@', '@INPUT@'],
  build_by_default: true,
)
