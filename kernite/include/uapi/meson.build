# SPDX-License-Identifier: GPL-2.0-only
#
# UAPI bindings fragment — kernite/include/uapi/*.h → bindgen → uapi.rs.
#
# kernite/include/uapi/ is the authoritative kernel ABI surface. Every
# value that crosses the kernel/userland boundary (KERNITE_OBJ_*,
# KERNITE_INV_*, KERNITE_ERR_*, KERNITE_STATE_*, KERNITE_FAULT_*, struct
# layouts, ABI version) lives in those C headers. This fragment runs
# bindgen once and exposes the generated `uapi.rs` to every consumer:
#
#   * kernite (kernel target) — uapi-kernel.rmeta
#   * lib/trona (saltyos userland target) — libuapi.rmeta
#   * lib/trona/win32 (PE target, kernel32.dll) — libuapi-pe.rmeta
#
# All three rmeta builds compile the same generated source against
# their own rustc target spec; symbol drift is impossible.

bindgen = find_program('bindgen', required: true)

_uapi_dir = meson.current_source_dir()
uapi_bindgen_header = files('bindgen.h')
uapi_bindgen_aliases = _uapi_dir / 'bindgen_aliases.rs'

uapi_headers = files(
  'bindgen.h',
  'bindgen_aliases.rs',
  'kernite.h',
  'version.h',
  'syscall.h',
  'error.h',
  'rights.h',
  'object.h',
  'invoke.h',
  'vmem.h',
  'event.h',
  'ipc.h',
  'fault.h',
  'boot.h',
  'startup.h',
)

bindgen_clang_target = arch == 'aarch64' ? 'aarch64-unknown-none' : 'x86_64-unknown-none'

uapi_bindgen = custom_target('uapi_bindgen',
  input: uapi_bindgen_header,
  output: 'uapi.rs',
  depend_files: uapi_headers,
  command: [
    bindgen,
    '--use-core',
    '--no-prepend-enum-name',
    '--merge-extern-blocks',
    '--default-macro-constant-type=unsigned',
    '--no-layout-tests',
    '--blocklist-type', 'int_(least|fast).*|uint_(least|fast).*|intmax_t|uintmax_t',
    '--allowlist-type', 'kernite_.*',
    '--allowlist-type', 'SaltyOS.*',
    '--allowlist-var', 'kernite_bindgen_u64_.*',
    '--allowlist-var', 'AT_SALTYOS_STARTUP',
    '--allowlist-var', 'SALTYOS_.*',
    '--allowlist-var', 'KERNITE_ABI_(MAJOR|MINOR|PATCH|VERSION_STR)',
    '--allowlist-var', 'KERNITE_RIGHT_.*',
    '--allowlist-var', 'KERNITE_EVENT_(TYPE|STATUS)_.*',
    '--allowlist-var', 'KERNITE_IPC_(MSG_REGS|MAX_CAPS|BUFFER_SIZE|RESERVED_.*)',
    '--allowlist-var', 'KERNITE_MP_RECORD_.*',
    '--allowlist-var', 'KERNITE_BOOTINFO_TAG_.*',
    '--allowlist-var', 'KERNITE_MEM_KIND_.*',
    '--raw-line', '#![no_std]',
    '--raw-line', '#![allow(nonstandard_style, dead_code, unsafe_op_in_unsafe_fn)]',
    '--raw-line', 'include!("' + uapi_bindgen_aliases + '");',
    '--output', '@OUTPUT@',
    '@INPUT@',
    '--',
    '-target', bindgen_clang_target,
    '-ffreestanding',
  ],
  build_by_default: true,
)

uapi_bindgen_rs = uapi_bindgen[0]
