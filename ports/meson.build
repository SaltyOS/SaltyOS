# SaltyOS Ports Build — Auto-Discovery
# SPDX-License-Identifier: GPL-2.0-only
#
# Discovers ports by scanning for <name>/<name>.port files.
# Parses [install] section to determine output filenames.
# Port outputs + manifests are consumed by mkcpio.py via --manifest.

fs_mod = import('fs')

# Auto-discover: look for <name>/<name>.port pattern
_ls = run_command('ls', '-1', meson.current_source_dir(), check: true)
port_names = []
foreach candidate : _ls.stdout().strip().split('\n')
  if fs_mod.is_file(meson.current_source_dir() / candidate / candidate + '.port')
    port_names += candidate
  endif
endforeach

port_manifest_args = []
port_depends = []

foreach pname : port_names
  port_file = pname / pname + '.port'
  port_content = fs_mod.read(port_file)
  lines = port_content.strip().split('\n')

  # Parse [install] section to extract output filenames
  _in_install = false
  _outputs = []
  foreach line : lines
    _s = line.strip()
    if _s == '[install]'
      _in_install = true
      continue
    endif
    if _s.startswith('[')
      _in_install = false
      continue
    endif
    if not _in_install or _s == '' or _s.startswith('#')
      continue
    endif
    # Each line: initrd_path = artifact_ref
    # Split on '=' to get initrd_path (left side)
    _parts = _s.split('=')
    _key = _parts[0].strip()
    # Flatten: "bin/echo" -> "echo.elf", "bash.elf" -> "bash.elf"
    _segs = _key.split('/')
    _last = _segs[_segs.length() - 1]
    if not _last.endswith('.elf')
      _last = _last + '.elf'
    endif
    _outputs += _last
  endforeach

  _pt = custom_target('port_' + pname,
    output: _outputs,
    depends: [portbuild, libsalty_so, libc_so, crt_start_obj],
    depend_files: files(port_file) + saltyc_header_files,
    command: [portbuild, 'build',
      meson.current_source_dir() / pname,
      '-o', '@OUTDIR@',
      '-b', meson.project_build_root()],
    console: true,
    build_always_stale: true,
    build_by_default: true,
  )

  set_variable('port_' + pname.underscorify(), _pt)
  port_depends += _pt
  port_manifest_args += ['--manifest',
    meson.project_build_root() / 'ports' / pname + '.manifest']
endforeach

message('Discovered ports: ' + ', '.join(port_names))
