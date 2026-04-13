#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
#
# Generate a per-service `svc_caps` Rust crate from a `.service` file.
#
# Reads the `[Capabilities]` section of the input `.service`, collects
# every `Require=` declaration, and emits a Rust source file containing:
#
#   - One `#[linkage = "weak"]` `static mut __svc_cap_<alias>` per
#     service-local require (`Require=<provider>:<alias>`).
#   - An inline `pub fn <alias>() -> Cap` getter for each weak symbol.
#   - A strong-override `__trona_svc_caps_install` C-ABI function that
#     walks the incoming `TronaCapTableV1` and stores each service-local
#     role's slot into the matching weak symbol.
#
# System roles (`Require=procmgr`, `Require=mmsrv:authority_raw`, ...)
# do NOT produce svc_caps output — they are already reachable through
# the public `trona::caps::*()` getters or, for raw authority, through
# the procmgr-private helper.
#
# The role-id resolution here must stay in lock-step with
# `system_role_lookup` / `parse_require_list` in
# `userland/core/init/src/ini.rs`. Both use the same djb2 hash and the
# same LOCAL_ROLE_BASE.
#
# Usage:
#
#   svc_caps_gen.py --input netsrv.service \
#                   --output build/netsrv_svc_caps.rs \
#                   --crate-name netsrv_svc_caps
#
# On collision (two local roles in the same service hashing to the same
# role id) or malformed input the script exits non-zero with a message.

import argparse
import importlib.util
import sys
from pathlib import Path

# Map .service short name -> Rust constant name (looked up in
# ROLE_IDS from the generated role_map_data module).
SYSTEM_ROLE_NAMES = {
    "procmgr": "ROLE_PROCMGR_CONTROL",
    "service": "ROLE_SERVICE_EP",
    "namesrv": "ROLE_NAMESRV_CLIENT",
    "vfs": "ROLE_VFS_CLIENT",
    "mmsrv": "ROLE_MMSRV_CLIENT",
    "rsrcsrv": "ROLE_RSRCSRV_CLIENT",
    "console": "ROLE_CONSOLE_CLIENT",
    "signal": "ROLE_SIGNAL_NTFN",
    "readiness": "ROLE_READINESS_NTFN",
    "initrd_untyped": "ROLE_INITRD_UNTYPED",
    "fb_untyped": "ROLE_FB_UNTYPED",
    "pci_ioport": "ROLE_PCI_IOPORT",
    "com1_ioport": "ROLE_COM1_IOPORT",
    "win32srv": "ROLE_WIN32SRV_CLIENT",
    "cspace_ntfn": "ROLE_CSPACE_NTFN",
    "sc_cap": "ROLE_SC_CAP",
}

# Map (short name, attribute suffix) -> Rust constant name.
# The attribute-carrying system roles are privileged (`raw=True`).
SYSTEM_ATTR_ROLE_NAMES = {
    ("mmsrv", "authority_raw"): "ROLE_MMSRV_AUTHORITY_RAW",
    ("rsrcsrv", "authority_raw"): "ROLE_RSRCSRV_AUTHORITY_RAW",
}
RAW_ATTR_ROLE_CONSTS = {
    "ROLE_MMSRV_AUTHORITY_RAW",
    "ROLE_RSRCSRV_AUTHORITY_RAW",
}


def die(msg: str) -> None:
    sys.stderr.write(f"svc_caps_gen: {msg}\n")
    sys.exit(1)


def load_role_map_data(path: Path):
    """
    Import the meson-generated `role_map_data.py` from `path` and return
    a dict with LOCAL_ROLE_BASE, LOCAL_ROLE_MOD, and ROLE_IDS. Validates
    that every constant referenced by SYSTEM_ROLE_NAMES /
    SYSTEM_ATTR_ROLE_NAMES is present — drift between svc_caps_gen.py
    and kernel.rs is caught here.
    """
    spec = importlib.util.spec_from_file_location("role_map_data", path)
    if spec is None or spec.loader is None:
        die(f"cannot load role_map_data from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    for attr in ("LOCAL_ROLE_BASE", "LOCAL_ROLE_MOD", "ROLE_IDS"):
        if not hasattr(module, attr):
            die(f"role_map_data missing required attribute {attr!r}")
    role_ids = module.ROLE_IDS
    for short, const in SYSTEM_ROLE_NAMES.items():
        if const not in role_ids:
            die(
                f"SYSTEM_ROLE_NAMES[{short!r}] -> {const!r} is absent from "
                f"ROLE_IDS; svc_caps_gen.py out of sync with kernel.rs"
            )
    for (short, attr), const in SYSTEM_ATTR_ROLE_NAMES.items():
        if const not in role_ids:
            die(
                f"SYSTEM_ATTR_ROLE_NAMES[({short!r},{attr!r})] -> {const!r} "
                f"is absent from ROLE_IDS; svc_caps_gen.py out of sync"
            )
    return {
        "LOCAL_ROLE_BASE": module.LOCAL_ROLE_BASE,
        "LOCAL_ROLE_MOD": module.LOCAL_ROLE_MOD,
        "ROLE_IDS": role_ids,
    }


# Populated by `main()` after the --data-file has been loaded.
_ROLE_MAP = None


def djb2_hash(b: bytes) -> int:
    """32-bit djb2 hash — must match Rust `djb2_hash` in init ini.rs."""
    h = 5381
    for byte in b:
        h = ((h * 33) + byte) & 0xFFFFFFFF
    return h


def local_role_id(provider: str, alias: str) -> int:
    if _ROLE_MAP is None:
        die("role_map_data not loaded — internal invariant broken")
    key = f"{provider}:{alias}".encode("ascii")
    return _ROLE_MAP["LOCAL_ROLE_BASE"] + (
        djb2_hash(key) % _ROLE_MAP["LOCAL_ROLE_MOD"]
    )


def parse_require_token(token: str):
    """
    Classify one Require= token as either a system role or a
    service-local role. Returns a dict describing the entry:

      kind:     "system" | "local"
      provider: str                      (token name)
      suffix:   str | None               (attribute for system, alias for local)
      badged:   bool
      raw:      bool                     (True iff system + AUTHORITY_RAW)
      role_id:  int                      (resolved numeric role id)
      role_const: str | None             (Rust ROLE_* constant name for system)
    """
    parts = token.split(":")
    if not parts or not parts[0]:
        die(f"empty Require= token: {token!r}")
    name = parts[0]
    suffix = parts[1] if len(parts) >= 2 else ""
    badged = False
    if len(parts) >= 3:
        if parts[2] != "badge":
            die(f"unknown trailing flag in Require={token!r}: {parts[2]!r}")
        badged = True
    if len(parts) > 3:
        die(f"too many ':'-separated fields in Require={token!r}")

    # System role with attribute?
    if suffix and (name, suffix) in SYSTEM_ATTR_ROLE_NAMES:
        role_const = SYSTEM_ATTR_ROLE_NAMES[(name, suffix)]
        raw = role_const in RAW_ATTR_ROLE_CONSTS
        return {
            "kind": "system",
            "provider": name,
            "suffix": suffix,
            "badged": badged,
            "raw": raw,
            "role_id": _ROLE_MAP["ROLE_IDS"][role_const],
            "role_const": role_const,
        }
    # Bare system role?
    if not suffix and name in SYSTEM_ROLE_NAMES:
        role_const = SYSTEM_ROLE_NAMES[name]
        return {
            "kind": "system",
            "provider": name,
            "suffix": "",
            "badged": badged,
            "raw": False,
            "role_id": _ROLE_MAP["ROLE_IDS"][role_const],
            "role_const": role_const,
        }
    # Service-local role.
    if not suffix:
        die(f"unknown system role and no alias in Require={token!r}")
    if not suffix.replace("_", "").isalnum() or not suffix[0].isalpha():
        die(f"service-local alias must be a Rust identifier: {suffix!r}")
    role_id = local_role_id(name, suffix)
    return {
        "kind": "local",
        "provider": name,
        "suffix": suffix,
        "badged": badged,
        "raw": False,
        "role_id": role_id,
        "role_const": None,
    }


def parse_service_file(path: Path):
    """
    Return a list of dicts (see parse_require_token) for every token on
    every Require= line in the [Capabilities] section.
    """
    section = None
    out = []
    with path.open("r", encoding="utf-8") as fp:
        for raw_line in fp:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                section = line[1:-1].strip()
                continue
            if section != "Capabilities":
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            # Allow `Require[amd64]=...` arch-qualified keys like the
            # Rust parser does; match prefix before `[`.
            bare_key = key.split("[", 1)[0].strip()
            if bare_key != "Require":
                continue
            for token in value.strip().split():
                out.append(parse_require_token(token))
    return out


def emit_rust(crate_name: str, requires, input_path: Path) -> str:
    locals_ = [r for r in requires if r["kind"] == "local"]

    # Collision check among local roles within this service.
    seen = {}
    for r in locals_:
        rid = r["role_id"]
        if rid in seen:
            die(
                "service-local role id 0x{:04x} collision between "
                "Require={}:{} and Require={}:{}".format(
                    rid,
                    seen[rid]["provider"],
                    seen[rid]["suffix"],
                    r["provider"],
                    r["suffix"],
                )
            )
        seen[rid] = r

    lines = []
    lines.append(
        "// GENERATED by tools/svc_caps_gen.py from {} — do not edit.".format(
            input_path.name
        )
    )
    lines.append("// SPDX-License-Identifier: GPL-2.0-only")
    lines.append("")
    lines.append("#![no_std]")
    lines.append("#![allow(internal_features)]")
    lines.append("#![feature(linkage)]")
    lines.append("")
    lines.append("use trona::cap_table;")
    lines.append("use trona::types::{Cap, TronaCapTableV1};")
    lines.append("")

    if not locals_:
        # No service-local roles: keep the crate empty (the substrate's
        # default `__trona_svc_caps_install` no-op hook is sufficient).
        lines.append(
            "// No service-local `Require=provider:alias` declarations — "
            "this crate is intentionally empty."
        )
        lines.append("")
        return "\n".join(lines) + "\n"

    lines.append("pub mod roles {")
    for r in locals_:
        name_upper = r["suffix"].upper()
        lines.append(
            "    /// `Require={}:{}`".format(r["provider"], r["suffix"])
        )
        lines.append(
            "    pub const LOCAL_{}: u32 = 0x{:04X};".format(
                name_upper, r["role_id"]
            )
        )
    lines.append("}")
    lines.append("")

    for r in locals_:
        alias = r["suffix"]
        lines.append("/// Weak symbol backing `{}()` getter.".format(alias))
        lines.append("#[unsafe(no_mangle)]")
        lines.append('#[linkage = "weak"]')
        lines.append("pub static mut __svc_cap_{}: u64 = 0;".format(alias))
        lines.append("")
        lines.append("/// Slot for `Require={}:{}` (role id 0x{:04X}).".format(
            r["provider"], alias, r["role_id"]
        ))
        lines.append("#[inline]")
        lines.append("pub fn {}() -> Cap {{".format(alias))
        lines.append(
            "    unsafe {{ core::ptr::read_volatile(&raw const __svc_cap_{}) }}".format(
                alias
            )
        )
        lines.append("}")
        lines.append("")

    lines.append("/// Strong override of the substrate's weak hook. Called by")
    lines.append("/// `cap_table::install_well_known_caps` after the system")
    lines.append("/// role sweep completes.")
    lines.append("#[unsafe(no_mangle)]")
    lines.append(
        "pub extern \"C\" fn __trona_svc_caps_install("
        "table_ptr: *const TronaCapTableV1) {"
    )
    for r in locals_:
        alias = r["suffix"]
        name_upper = alias.upper()
        lines.append(
            "    if let Some(e) = cap_table::lookup(table_ptr, roles::LOCAL_{}) {{".format(
                name_upper
            )
        )
        lines.append("        unsafe {")
        lines.append(
            "            core::ptr::write_volatile("
            "&raw mut __svc_cap_{}, e.slot as u64);".format(alias)
        )
        lines.append("        }")
        lines.append("    }")
    lines.append("}")
    lines.append("")

    # Suppress the "crate-name does not match" warning when the file is
    # embedded via `include!` from another crate. Generator-emitted code
    # is invoked as a standalone crate by meson's custom_target, so the
    # actual rustc `--crate-name` is passed explicitly; the crate_name
    # arg here is informational.
    _ = crate_name
    return "\n".join(lines) + "\n"


def main() -> None:
    global _ROLE_MAP
    ap = argparse.ArgumentParser(description="svc_caps generator")
    ap.add_argument("--input", required=True, help="path to .service file")
    ap.add_argument("--output", required=True, help="path to output .rs file")
    ap.add_argument(
        "--crate-name",
        required=True,
        help="target crate name (informational; rustc sets it separately)",
    )
    ap.add_argument(
        "--data-file",
        required=True,
        help="path to generated role_map_data.py (from role_map_gen.py)",
    )
    args = ap.parse_args()

    data_path = Path(args.data_file)
    if not data_path.is_file():
        die(f"role_map_data.py not found at {data_path}")
    _ROLE_MAP = load_role_map_data(data_path)

    input_path = Path(args.input)
    if not input_path.is_file():
        die(f"input .service does not exist: {input_path}")
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    requires = parse_service_file(input_path)
    rust = emit_rust(args.crate_name, requires, input_path)
    output_path.write_text(rust, encoding="utf-8")


if __name__ == "__main__":
    main()
