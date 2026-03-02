# SaltyOS Ports Build — Auto-Discovery
# SPDX-License-Identifier: GPL-2.0-only
#
# Discovers ports by scanning for <name>/<name>.port files.
# Parses [depends] sections from each port file for build ordering.
# Port manifests are consumed by mkrootfs/rootfs profile assembly.
#
# Two-pass approach:
#   Pass 1: discover ports, parse [depends] build deps
#   Pass 2: create custom_targets, resolving deps to target objects

fs_mod = import('fs')

# Auto-discover: look for <name>/<name>.port pattern
_ls = run_command('ls', '-1', meson.current_source_dir(), check: true)
port_names = []
foreach candidate : _ls.stdout().strip().split('\n')
  if fs_mod.is_file(meson.current_source_dir() / candidate / candidate + '.port')
    port_names += candidate
  endif
endforeach

port_depends = []

# Pass 1: parse metadata from each port file
foreach pname : port_names
  port_file = pname / pname + '.port'
  port_content = fs_mod.read(port_file)
  lines = port_content.strip().split('\n')

  # Parse [depends] section for build dependencies
  _in_depends = false
  _build_deps = []
  foreach line : lines
    _s = line.strip()
    if _s == '[depends]'
      _in_depends = true
      continue
    endif
    if _s.startswith('[')
      _in_depends = false
      continue
    endif
    if not _in_depends or _s == '' or _s.startswith('#')
      continue
    endif
    if _s.startswith('build')
      _dparts = _s.split('=')
      if _dparts.length() > 1
        foreach _dep : _dparts[1].strip().split(',')
          _d = _dep.strip()
          if _d != ''
            _build_deps += _d
          endif
        endforeach
      endif
    endif
  endforeach

  set_variable('_port_deps_' + pname.underscorify(), _build_deps)
endforeach

# Pass 2: create targets in dependency order.
# Build ordered list: ports without deps first, then ports with deps.
# This ensures dependencies are available when dependents are processed.
_ordered_ports = []
foreach pname : port_names
  _deps = get_variable('_port_deps_' + pname.underscorify())
  if _deps.length() == 0
    _ordered_ports += pname
  endif
endforeach
foreach pname : port_names
  _deps = get_variable('_port_deps_' + pname.underscorify())
  if _deps.length() > 0
    _ordered_ports += pname
  endif
endforeach

foreach pname : _ordered_ports
  port_file = pname / pname + '.port'
  _dep_names = get_variable('_port_deps_' + pname.underscorify())

  _extra_deps = []
  foreach _dep : _dep_names
    _varname = 'port_' + _dep.underscorify()
    if is_variable(_varname)
      _extra_deps += [get_variable(_varname)]
    else
      warning('Port ' + pname + ' depends on unknown port: ' + _dep)
    endif
  endforeach

  _pt = custom_target('port_' + pname,
    output: [pname + '.manifest'],
    depends: [port_tool, libbesalt_so, libc_so, crt_start_obj, sysroot_target] + _extra_deps,
    depend_files: files(port_file) + besaltc_header_files,
    command: [port_tool, 'build',
      meson.current_source_dir() / pname,
      '-o', '@OUTDIR@',
      '-b', meson.project_build_root()],
    console: true,
    build_always_stale: true,
    build_by_default: get_option('build_ports'),
  )

  set_variable('port_' + pname.underscorify(), _pt)
  port_depends += _pt
endforeach

message('Discovered ports: ' + ', '.join(port_names))
