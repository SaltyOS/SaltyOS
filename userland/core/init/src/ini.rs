//! INI parser for .service files
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! no_std, no heap - everything on stack with fixed-size arrays.

pub const MAX_SERVICE_NAME: usize = 32;
pub const MAX_BINARY_NAME: usize = 48;
pub const MAX_DEPS: usize = 8;
pub const MAX_CAP_COPIES: usize = 6;
pub const MAX_EP_NEEDS: usize = 8;
pub const MAX_EP_INJECTS: usize = 2;
pub const MAX_CREATE_EPS: usize = 2;
pub const MAX_SPAWN_ARGS_BYTES: usize = 96;
pub const MAX_SPAWN_ARGS: usize = 6;

// `Require=` machinery — re-exported from uapi so the parser, the spawner,
// and procmgr all share the same on-wire layout. The local alias
// `RequireDef = TronaRequireDefV1` keeps the existing call sites readable
// without inventing a separate parser-only struct.
pub use trona::types::core::{
    TronaRequireDefV1 as RequireDef, MAX_REQUIRES, MAX_REQUIRE_ALIAS, MAX_REQUIRE_PROVIDER,
    REQUIRE_KIND_LOCAL, REQUIRE_KIND_SYSTEM,
};

#[derive(Clone, Copy)]
pub struct CapCopyDef {
    pub src_slot: u64,
    pub dst_slot: u64,
}

#[derive(Clone, Copy)]
pub struct EpNeedDef {
    pub service: [u8; MAX_SERVICE_NAME],
    pub service_len: u8,
    pub dst_slot: u64,
    pub badged: bool,
    pub late: bool,
}

// `RequireDef` is a type alias to `trona::types::core::TronaRequireDefV1`
// (see top-of-file `pub use`). The full doc-comment for the syntax it
// represents lives on the uapi struct; init's parser sets the fields by
// hand and emits the resolved `role_id` so procmgr can consume the entries
// without re-parsing.

#[derive(Clone, Copy)]
pub struct EpInjectDef {
    pub target: [u8; MAX_SERVICE_NAME],
    pub target_len: u8,
    pub target_slot: u64,
}

#[derive(Clone, Copy)]
pub struct CreateEpDef {
    pub dst_slot: u64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ServiceType {
    Simple,
    Notify,
    Target,
}

#[derive(Clone, Copy, PartialEq)]
pub enum TargetActivation {
    Passive,
    Event,
}

#[derive(Clone, Copy, PartialEq)]
pub enum RestartPolicy {
    No,
    Always,
    OnFailure,
}

#[derive(Clone, Copy)]
pub struct ServiceDef {
    pub name: [u8; MAX_SERVICE_NAME],
    pub name_len: u8,
    pub binary: [u8; MAX_BINARY_NAME],
    pub binary_len: u8,
    pub svc_type: ServiceType,
    pub target_activation: TargetActivation,
    pub restart: RestartPolicy,
    pub after: [[u8; MAX_SERVICE_NAME]; MAX_DEPS],
    pub after_count: u8,
    pub before: [[u8; MAX_SERVICE_NAME]; MAX_DEPS],
    pub before_count: u8,
    /// Memory budget in KiB (0 = system default).
    pub memory_kb: u16,
    /// Service startup ready timeout in nanoseconds (0 = auto).
    pub timeout_start_ns: u64,
    pub cnode_bits: u8,
    pub map_initrd: bool,
    pub pre_procmgr: bool,
    pub caps: [CapCopyDef; MAX_CAP_COPIES],
    pub cap_count: u8,
    pub ep_needs: [EpNeedDef; MAX_EP_NEEDS],
    pub ep_need_count: u8,
    pub requires: [RequireDef; MAX_REQUIRES],
    pub require_count: u8,
    pub ep_injects: [EpInjectDef; MAX_EP_INJECTS],
    pub ep_inject_count: u8,
    pub create_eps: [CreateEpDef; MAX_CREATE_EPS],
    pub create_ep_count: u8,
    /// NUL-separated argv entries appended after argv[0] by procmgr spawn path.
    pub spawn_args: [u8; MAX_SPAWN_ARGS_BYTES],
    pub spawn_args_len: u8,
    pub spawn_argc: u8,
    /// Service role declaration. The only currently honored value is
    /// "authority", which selects init's bootstrap-class spawn path
    /// (direct retype, untyped hand-off at the end of spawn). Anything
    /// else (or empty) means a normal Service-class spawn.
    pub role: [u8; 16],
    pub role_len: u8,
    /// If set, init promotes this service's spawn badge to the bootstrap
    /// authority's privileged caller set right after spawn, so it can
    /// allocate kernel objects on behalf of arbitrary owner ids.
    pub bootstrap_privileged: bool,
    /// If set, init copies its preloaded shared-library frame caps into
    /// the child's CNode at spawn. Required for any service that runs
    /// before the regular per-process shared-lib cache is available
    /// (i.e. services that spawn before procmgr is up).
    pub copy_shared_lib_caps: bool,
}

impl ServiceDef {
    pub const fn zeroed() -> Self {
        ServiceDef {
            name: [0; MAX_SERVICE_NAME],
            name_len: 0,
            binary: [0; MAX_BINARY_NAME],
            binary_len: 0,
            svc_type: ServiceType::Simple,
            target_activation: TargetActivation::Passive,
            restart: RestartPolicy::No,
            after: [[0; MAX_SERVICE_NAME]; MAX_DEPS],
            after_count: 0,
            before: [[0; MAX_SERVICE_NAME]; MAX_DEPS],
            before_count: 0,
            memory_kb: 0,
            timeout_start_ns: 0,
            cnode_bits: 0,
            map_initrd: false,
            pre_procmgr: false,
            caps: [CapCopyDef {
                src_slot: 0,
                dst_slot: 0,
            }; MAX_CAP_COPIES],
            cap_count: 0,
            ep_needs: [EpNeedDef {
                service: [0; MAX_SERVICE_NAME],
                service_len: 0,
                dst_slot: 0,
                badged: false,
                late: false,
            }; MAX_EP_NEEDS],
            ep_need_count: 0,
            requires: [RequireDef::zeroed(); MAX_REQUIRES],
            require_count: 0,
            ep_injects: [EpInjectDef {
                target: [0; MAX_SERVICE_NAME],
                target_len: 0,
                target_slot: 0,
            }; MAX_EP_INJECTS],
            ep_inject_count: 0,
            create_eps: [CreateEpDef { dst_slot: 0 }; MAX_CREATE_EPS],
            create_ep_count: 0,
            spawn_args: [0; MAX_SPAWN_ARGS_BYTES],
            spawn_args_len: 0,
            spawn_argc: 0,
            role: [0; 16],
            role_len: 0,
            bootstrap_privileged: false,
            copy_shared_lib_caps: false,
        }
    }

    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    pub fn binary_bytes(&self) -> &[u8] {
        &self.binary[..self.binary_len as usize]
    }

    pub fn after_name(&self, idx: usize) -> &[u8] {
        let mut len = 0;
        while len < MAX_SERVICE_NAME && self.after[idx][len] != 0 {
            len += 1;
        }
        &self.after[idx][..len]
    }

    pub fn before_name(&self, idx: usize) -> &[u8] {
        let mut len = 0;
        while len < MAX_SERVICE_NAME && self.before[idx][len] != 0 {
            len += 1;
        }
        &self.before[idx][..len]
    }

    pub fn role_bytes(&self) -> &[u8] {
        &self.role[..self.role_len as usize]
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Section {
    None,
    Service,
    Dependencies,
    Capabilities,
}

fn trim_start(data: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < data.len() && (data[i] == b' ' || data[i] == b'\t') {
        i += 1;
    }
    &data[i..]
}

fn trim_end(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && (data[end - 1] == b' ' || data[end - 1] == b'\t' || data[end - 1] == b'\r') {
        end -= 1;
    }
    &data[..end]
}

fn trim(data: &[u8]) -> &[u8] {
    trim_end(trim_start(data))
}

fn bytes_eq_ci(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        let ca = if a[i] >= b'A' && a[i] <= b'Z' {
            a[i] + 32
        } else {
            a[i]
        };
        let cb = if b[i] >= b'A' && b[i] <= b'Z' {
            b[i] + 32
        } else {
            b[i]
        };
        if ca != cb {
            return false;
        }
    }
    true
}

fn key_matches_current_arch(key: &[u8], base: &[u8]) -> bool {
    if bytes_eq_ci(key, base) {
        return true;
    }
    if key.len() <= base.len() + 1 {
        return false;
    }
    if key[base.len()] != b'.' || !bytes_eq_ci(&key[..base.len()], base) {
        return false;
    }
    arch_suffix_matches(&key[base.len() + 1..])
}

fn arch_suffix_matches(suffix: &[u8]) -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        bytes_eq_ci(suffix, b"aarch64")
    }
    #[cfg(target_arch = "x86_64")]
    {
        bytes_eq_ci(suffix, b"x86_64")
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = suffix;
        false
    }
}

fn copy_to_buf(src: &[u8], dst: &mut [u8]) -> u8 {
    let len = if src.len() < dst.len() {
        src.len()
    } else {
        dst.len()
    };
    for i in 0..len {
        dst[i] = src[i];
    }
    for i in len..dst.len() {
        dst[i] = 0;
    }
    len as u8
}

/// Parse space-separated names from `value` into `deps` array.
/// Returns count of names parsed.
fn parse_dep_list(value: &[u8], deps: &mut [[u8; MAX_SERVICE_NAME]; MAX_DEPS]) -> u8 {
    let mut count: u8 = 0;
    let mut i = 0;
    let val = trim(value);

    while i < val.len() && (count as usize) < MAX_DEPS {
        // Skip whitespace
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        // Find end of word
        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }

        let word = &val[start..i];
        if !word.is_empty() {
            copy_to_buf(word, &mut deps[count as usize]);
            count += 1;
        }
    }
    count
}

fn parse_decimal_u16(data: &[u8]) -> u16 {
    let mut val: u16 = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            val = val.wrapping_mul(10).wrapping_add((b - b'0') as u16);
        } else {
            break;
        }
    }
    val
}

fn parse_decimal_u64(data: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in data {
        if b >= b'0' && b <= b'9' {
            val = val.wrapping_mul(10).wrapping_add((b - b'0') as u64);
        } else {
            break;
        }
    }
    val
}

/// Parse systemd-style timeout value into nanoseconds.
///
/// Supported forms:
/// - `10` / `10s` / `10sec` / `10seconds`
/// - `500ms`
/// - `200us`
/// - `2m` / `2min` / `2minutes`
/// - `1h` / `1hr` / `1hour`
/// - `infinity` (treated as 0 = auto/no fixed timeout)
fn parse_duration_ns(data: &[u8]) -> u64 {
    let v = trim(data);
    if v.is_empty() {
        return 0;
    }
    if bytes_eq_ci(v, b"infinity") {
        return 0;
    }

    let mut num_end = 0usize;
    while num_end < v.len() && v[num_end] >= b'0' && v[num_end] <= b'9' {
        num_end += 1;
    }
    if num_end == 0 {
        return 0;
    }

    let n = parse_decimal_u64(&v[..num_end]);
    let unit = trim(&v[num_end..]);

    let scale = if unit.is_empty()
        || bytes_eq_ci(unit, b"s")
        || bytes_eq_ci(unit, b"sec")
        || bytes_eq_ci(unit, b"secs")
        || bytes_eq_ci(unit, b"second")
        || bytes_eq_ci(unit, b"seconds")
    {
        1_000_000_000u64
    } else if bytes_eq_ci(unit, b"ms") || bytes_eq_ci(unit, b"msec") || bytes_eq_ci(unit, b"msecs")
    {
        1_000_000u64
    } else if bytes_eq_ci(unit, b"us") || bytes_eq_ci(unit, b"usec") || bytes_eq_ci(unit, b"usecs")
    {
        1_000u64
    } else if bytes_eq_ci(unit, b"m")
        || bytes_eq_ci(unit, b"min")
        || bytes_eq_ci(unit, b"mins")
        || bytes_eq_ci(unit, b"minute")
        || bytes_eq_ci(unit, b"minutes")
    {
        60 * 1_000_000_000u64
    } else if bytes_eq_ci(unit, b"h")
        || bytes_eq_ci(unit, b"hr")
        || bytes_eq_ci(unit, b"hrs")
        || bytes_eq_ci(unit, b"hour")
        || bytes_eq_ci(unit, b"hours")
    {
        60 * 60 * 1_000_000_000u64
    } else {
        // Unknown suffix: keep systemd-like default of seconds.
        1_000_000_000u64
    };

    n.saturating_mul(scale)
}

fn parse_cap_copies(value: &[u8], caps: &mut [CapCopyDef; MAX_CAP_COPIES]) -> u8 {
    let mut count: u8 = 0;
    let mut i = 0;
    let val = trim(value);

    while i < val.len() && (count as usize) < MAX_CAP_COPIES {
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }

        let token = &val[start..i];
        let mut colon = 0;
        let mut found = false;
        for j in 0..token.len() {
            if token[j] == b':' {
                colon = j;
                found = true;
                break;
            }
        }
        if found {
            caps[count as usize] = CapCopyDef {
                src_slot: parse_decimal_u64(&token[..colon]),
                dst_slot: parse_decimal_u64(&token[colon + 1..]),
            };
            count += 1;
        }
    }
    count
}

fn parse_ep_needs(value: &[u8], needs: &mut [EpNeedDef; MAX_EP_NEEDS]) -> u8 {
    let mut count: u8 = 0;
    let mut i = 0;
    let val = trim(value);

    while i < val.len() && (count as usize) < MAX_EP_NEEDS {
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }

        let token = &val[start..i];
        let mut first_colon = 0;
        let mut found = false;
        for j in 0..token.len() {
            if token[j] == b':' {
                first_colon = j;
                found = true;
                break;
            }
        }
        if found {
            let name = &token[..first_colon];
            let rest = &token[first_colon + 1..];

            // Look for second colon separating slot from :badge flag
            let mut second_colon = 0;
            let mut found_second = false;
            for j in 0..rest.len() {
                if rest[j] == b':' {
                    second_colon = j;
                    found_second = true;
                    break;
                }
            }

            let mut entry = EpNeedDef {
                service: [0; MAX_SERVICE_NAME],
                service_len: 0,
                dst_slot: 0,
                badged: false,
                late: false,
            };
            entry.service_len = copy_to_buf(name, &mut entry.service);

            if found_second {
                // Parse slot from rest[..second_colon], then parse any colon-
                // separated flags such as `badge` / `late`.
                entry.dst_slot = parse_decimal_u64(&rest[..second_colon]);
                let mut flags = &rest[second_colon + 1..];
                while !flags.is_empty() {
                    let mut split = flags.len();
                    for j in 0..flags.len() {
                        if flags[j] == b':' {
                            split = j;
                            break;
                        }
                    }
                    let flag = &flags[..split];
                    if bytes_eq_ci(flag, b"badge") {
                        entry.badged = true;
                    } else if bytes_eq_ci(flag, b"late") {
                        entry.late = true;
                    }
                    if split >= flags.len() {
                        break;
                    }
                    flags = &flags[split + 1..];
                }
            } else {
                // No second colon, just parse slot
                entry.dst_slot = parse_decimal_u64(rest);
                entry.badged = false;
                entry.late = false;
            }

            needs[count as usize] = entry;
            count += 1;
        }
    }
    count
}

fn parse_ep_injects(value: &[u8], injects: &mut [EpInjectDef; MAX_EP_INJECTS]) -> u8 {
    let mut count: u8 = 0;
    let mut i = 0;
    let val = trim(value);

    while i < val.len() && (count as usize) < MAX_EP_INJECTS {
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }

        let token = &val[start..i];
        let mut colon = 0;
        let mut found = false;
        for j in 0..token.len() {
            if token[j] == b':' {
                colon = j;
                found = true;
                break;
            }
        }
        if found {
            let name = &token[..colon];
            let mut entry = EpInjectDef {
                target: [0; MAX_SERVICE_NAME],
                target_len: 0,
                target_slot: 0,
            };
            entry.target_len = copy_to_buf(name, &mut entry.target);
            entry.target_slot = parse_decimal_u64(&token[colon + 1..]);
            injects[count as usize] = entry;
            count += 1;
        }
    }
    count
}

/// djb2 string hash used to deterministically assign role IDs to
/// service-local `Require=provider:alias` declarations.
/// Must match `djb2_hash` in `tools/svc_caps_gen.py` exactly.
fn djb2_hash(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    for &b in bytes {
        hash = hash.wrapping_mul(33).wrapping_add(b as u32);
    }
    hash
}

/// Resolve a `NeedEP=` provider name to the matching `ROLE_*`
/// identifier and its default cap_table flags, taking the `badged`
/// flag into account for roles that have a raw-authority variant.
///
/// For most system roles the `badged` flag is ignored — both badged
/// and unbadged `NeedEP=namesrv` entries map to `ROLE_NAMESRV_CLIENT`.
/// The exception is mmsrv and rsrcsrv: **unbadged** entries resolve to
/// the `*_AUTHORITY_RAW` variants (used by procmgr-private cap_table
/// lookups via `procmgr_caps`), while **badged** entries resolve to
/// the client variants that flow through `trona::caps::*`. This lets
/// `procmgr.service` declare `NeedEP=mmsrv:67:badge mmsrv:68` and have
/// init place each slot under the correct role.
///
/// Returns `None` if `name` is not a known system role.
pub fn system_role_for_needep(name: &[u8], badged: bool) -> Option<(u32, u32)> {
    use trona::consts::kernel::{
        CAP_TBL_FLAG_BADGED, CAP_TBL_FLAG_DEVICE_UT, CAP_TBL_FLAG_IO_PORT,
        CAP_TBL_FLAG_NOTIFICATION, CAP_TBL_FLAG_RAW, CAP_TBL_FLAG_UNTYPED, ROLE_COM1_IOPORT,
        ROLE_CONSOLE_CLIENT, ROLE_CSPACE_NTFN, ROLE_FB_UNTYPED, ROLE_INITRD_UNTYPED,
        ROLE_MMSRV_AUTHORITY_RAW, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT, ROLE_PCI_IOPORT,
        ROLE_PROCMGR_CONTROL, ROLE_READINESS_NTFN, ROLE_RSRCSRV_AUTHORITY_RAW, ROLE_RSRCSRV_CLIENT,
        ROLE_SC_CAP, ROLE_SERVICE_EP, ROLE_SIGNAL_NTFN, ROLE_VFS_CLIENT, ROLE_WIN32SRV_CLIENT,
    };
    // mmsrv / rsrcsrv split: unbadged → raw authority, badged → client.
    if bytes_eq_ci(name, b"mmsrv") {
        return Some(if badged {
            (ROLE_MMSRV_CLIENT, CAP_TBL_FLAG_BADGED)
        } else {
            (ROLE_MMSRV_AUTHORITY_RAW, CAP_TBL_FLAG_RAW)
        });
    }
    if bytes_eq_ci(name, b"rsrcsrv") {
        return Some(if badged {
            (ROLE_RSRCSRV_CLIENT, CAP_TBL_FLAG_BADGED)
        } else {
            (ROLE_RSRCSRV_AUTHORITY_RAW, CAP_TBL_FLAG_RAW)
        });
    }
    let (role_id, _raw) = system_role_lookup(name, &[])?;
    let flags = match role_id {
        ROLE_PROCMGR_CONTROL => CAP_TBL_FLAG_BADGED,
        ROLE_SIGNAL_NTFN | ROLE_READINESS_NTFN | ROLE_CSPACE_NTFN => CAP_TBL_FLAG_NOTIFICATION,
        ROLE_INITRD_UNTYPED | ROLE_FB_UNTYPED => CAP_TBL_FLAG_UNTYPED | CAP_TBL_FLAG_DEVICE_UT,
        ROLE_PCI_IOPORT | ROLE_COM1_IOPORT => CAP_TBL_FLAG_IO_PORT,
        ROLE_VFS_CLIENT | ROLE_NAMESRV_CLIENT | ROLE_CONSOLE_CLIENT | ROLE_SERVICE_EP
        | ROLE_SC_CAP | ROLE_WIN32SRV_CLIENT => 0,
        _ => 0,
    };
    Some((role_id, flags))
}

/// Resolve a `Require=` name (+ optional attribute suffix) to a
/// system-role `ROLE_*` id. Returns `None` if the name is not a known
/// system role — callers then fall through to the service-local path.
///
/// `attr` is the suffix after the first `:` (if any). For plain system
/// roles (`Require=namesrv`) it is empty. For raw authority roles
/// (`Require=mmsrv:authority_raw`) it is `b"authority_raw"`.
fn system_role_lookup(name: &[u8], attr: &[u8]) -> Option<(u32, bool /* raw */)> {
    use trona::consts::kernel::{
        ROLE_COM1_IOPORT, ROLE_CONSOLE_CLIENT, ROLE_CSPACE_NTFN, ROLE_FB_UNTYPED,
        ROLE_INITRD_UNTYPED, ROLE_MMSRV_AUTHORITY_RAW, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT,
        ROLE_PCI_IOPORT, ROLE_PROCMGR_CONTROL, ROLE_READINESS_NTFN, ROLE_RSRCSRV_AUTHORITY_RAW,
        ROLE_RSRCSRV_CLIENT, ROLE_SC_CAP, ROLE_SERVICE_EP, ROLE_SIGNAL_NTFN, ROLE_VFS_CLIENT,
        ROLE_WIN32SRV_CLIENT,
    };
    let has_attr = !attr.is_empty();
    // mmsrv / rsrcsrv support the `authority_raw` attribute, everything
    // else only accepts a bare name.
    if bytes_eq_ci(name, b"mmsrv") {
        if has_attr && bytes_eq_ci(attr, b"authority_raw") {
            return Some((ROLE_MMSRV_AUTHORITY_RAW, true));
        } else if !has_attr {
            return Some((ROLE_MMSRV_CLIENT, false));
        }
        return None;
    }
    if bytes_eq_ci(name, b"rsrcsrv") {
        if has_attr && bytes_eq_ci(attr, b"authority_raw") {
            return Some((ROLE_RSRCSRV_AUTHORITY_RAW, true));
        } else if !has_attr {
            return Some((ROLE_RSRCSRV_CLIENT, false));
        }
        return None;
    }
    if has_attr {
        return None;
    }
    if bytes_eq_ci(name, b"procmgr") {
        Some((ROLE_PROCMGR_CONTROL, false))
    } else if bytes_eq_ci(name, b"service") {
        Some((ROLE_SERVICE_EP, false))
    } else if bytes_eq_ci(name, b"namesrv") {
        Some((ROLE_NAMESRV_CLIENT, false))
    } else if bytes_eq_ci(name, b"vfs") {
        Some((ROLE_VFS_CLIENT, false))
    } else if bytes_eq_ci(name, b"console") {
        Some((ROLE_CONSOLE_CLIENT, false))
    } else if bytes_eq_ci(name, b"signal") {
        Some((ROLE_SIGNAL_NTFN, false))
    } else if bytes_eq_ci(name, b"readiness") {
        Some((ROLE_READINESS_NTFN, false))
    } else if bytes_eq_ci(name, b"initrd_untyped") {
        Some((ROLE_INITRD_UNTYPED, false))
    } else if bytes_eq_ci(name, b"fb_untyped") {
        Some((ROLE_FB_UNTYPED, false))
    } else if bytes_eq_ci(name, b"pci_ioport") {
        Some((ROLE_PCI_IOPORT, false))
    } else if bytes_eq_ci(name, b"com1_ioport") {
        Some((ROLE_COM1_IOPORT, false))
    } else if bytes_eq_ci(name, b"win32srv") {
        Some((ROLE_WIN32SRV_CLIENT, false))
    } else if bytes_eq_ci(name, b"cspace_ntfn") {
        Some((ROLE_CSPACE_NTFN, false))
    } else if bytes_eq_ci(name, b"sc_cap") {
        Some((ROLE_SC_CAP, false))
    } else {
        None
    }
}

/// Parse a whitespace-separated `Require=` value into `requires`.
///
/// Each token has one of these shapes:
///
/// ```text
/// <name>                       # bare system role
/// <name>:<suffix>              # system role with attribute, OR
///                              #   service-local with empty-flag alias
/// <name>:<suffix>:badge        # as above, with badged flag
/// ```
///
/// A token is classified as a system role first (via
/// [`system_role_lookup`]); on miss it falls through to the
/// service-local path, where the role id is
/// `LOCAL_ROLE_BASE + djb2("<name>:<suffix>") % 0xF00`.
fn parse_require_list(value: &[u8], out: &mut [RequireDef; MAX_REQUIRES]) -> u8 {
    use trona::consts::kernel::LOCAL_ROLE_BASE;

    let mut count: u8 = 0;
    let mut i = 0;
    let val = trim(value);

    while i < val.len() && (count as usize) < MAX_REQUIRES {
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }
        let token = &val[start..i];
        if token.is_empty() {
            continue;
        }

        // Split on first ':'.
        let mut first_colon = 0;
        let mut has_first = false;
        for j in 0..token.len() {
            if token[j] == b':' {
                first_colon = j;
                has_first = true;
                break;
            }
        }
        let name = if has_first {
            &token[..first_colon]
        } else {
            token
        };
        let rest = if has_first {
            &token[first_colon + 1..]
        } else {
            &[][..]
        };

        // Split rest on optional second ':' — everything after is the
        // trailing flag (`badge` today).
        let mut second_colon = 0;
        let mut has_second = false;
        for j in 0..rest.len() {
            if rest[j] == b':' {
                second_colon = j;
                has_second = true;
                break;
            }
        }
        let suffix = if has_second {
            &rest[..second_colon]
        } else {
            rest
        };
        let flag = if has_second {
            &rest[second_colon + 1..]
        } else {
            &[][..]
        };
        let badged = bytes_eq_ci(flag, b"badge");

        let mut entry = RequireDef::zeroed();
        entry.badged = if badged { 1 } else { 0 };
        entry.provider_len = copy_to_buf(name, &mut entry.provider);

        if let Some((role_id, raw)) = system_role_lookup(name, suffix) {
            entry.kind = REQUIRE_KIND_SYSTEM;
            entry.role_id = role_id;
            entry.raw = if raw { 1 } else { 0 };
            // Store the attribute suffix (if any) so diagnostics can
            // render the original token.
            entry.alias_len = copy_to_buf(suffix, &mut entry.alias);
        } else if has_first && !suffix.is_empty() {
            // Service-local role: hash "<provider>:<alias>".
            entry.kind = REQUIRE_KIND_LOCAL;
            entry.alias_len = copy_to_buf(suffix, &mut entry.alias);
            let mut key = [0u8; MAX_SERVICE_NAME + 1 + MAX_REQUIRE_ALIAS];
            let mut k = 0usize;
            for &b in name {
                if k >= key.len() {
                    break;
                }
                key[k] = b;
                k += 1;
            }
            if k < key.len() {
                key[k] = b':';
                k += 1;
            }
            for &b in suffix {
                if k >= key.len() {
                    break;
                }
                key[k] = b;
                k += 1;
            }
            let hash = djb2_hash(&key[..k]);
            entry.role_id = LOCAL_ROLE_BASE + (hash % 0x0F00);
        } else {
            // Malformed token (e.g. bare unknown name without a
            // service-local alias). Skip it — parser does not hard-fail
            // the whole .service, but init's validate pass can flag it.
            continue;
        }

        out[count as usize] = entry;
        count += 1;
    }
    count
}

fn parse_create_eps(value: &[u8], create_eps: &mut [CreateEpDef; MAX_CREATE_EPS]) -> u8 {
    let mut count: u8 = 0;
    let mut i = 0;
    let val = trim(value);

    while i < val.len() && (count as usize) < MAX_CREATE_EPS {
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }

        let token = &val[start..i];
        if !token.is_empty() {
            create_eps[count as usize] = CreateEpDef {
                dst_slot: parse_decimal_u64(token),
            };
            count += 1;
        }
    }

    count
}

fn parse_spawn_args(value: &[u8], out: &mut [u8; MAX_SPAWN_ARGS_BYTES]) -> (u8, u8) {
    let val = trim(value);
    let mut i = 0usize;
    let mut out_len = 0usize;
    let mut argc = 0u8;

    while i < val.len() && (argc as usize) < MAX_SPAWN_ARGS {
        while i < val.len() && (val[i] == b' ' || val[i] == b'\t') {
            i += 1;
        }
        if i >= val.len() {
            break;
        }

        let start = i;
        while i < val.len() && val[i] != b' ' && val[i] != b'\t' {
            i += 1;
        }
        let tok = &val[start..i];
        if tok.is_empty() {
            continue;
        }
        if out_len + tok.len() + 1 > out.len() {
            break;
        }

        for &b in tok {
            out[out_len] = b;
            out_len += 1;
        }
        out[out_len] = 0;
        out_len += 1;
        argc = argc.saturating_add(1);
    }

    for b in out.iter_mut().skip(out_len) {
        *b = 0;
    }

    (out_len as u8, argc)
}

/// Parse a .service INI file from raw bytes.
/// Returns true on success.
pub fn parse_service(data: &[u8], out: &mut ServiceDef) -> bool {
    *out = ServiceDef::zeroed();
    let mut section = Section::None;
    let mut line_start = 0;

    while line_start < data.len() {
        // Find end of line
        let mut line_end = line_start;
        while line_end < data.len() && data[line_end] != b'\n' {
            line_end += 1;
        }

        let line = trim(&data[line_start..line_end]);

        // Skip empty lines and comments
        if !line.is_empty() && line[0] != b'#' && line[0] != b';' {
            // Section header
            if line[0] == b'[' {
                if line.len() > 2 && line[line.len() - 1] == b']' {
                    let section_name = &line[1..line.len() - 1];
                    if bytes_eq_ci(section_name, b"Service") {
                        section = Section::Service;
                    } else if bytes_eq_ci(section_name, b"Dependencies") {
                        section = Section::Dependencies;
                    } else if bytes_eq_ci(section_name, b"Capabilities") {
                        section = Section::Capabilities;
                    } else {
                        section = Section::None;
                    }
                }
            } else {
                // Key=Value pair
                let mut eq_pos = 0;
                let mut found_eq = false;
                for i in 0..line.len() {
                    if line[i] == b'=' {
                        eq_pos = i;
                        found_eq = true;
                        break;
                    }
                }

                if found_eq {
                    let key = trim(&line[..eq_pos]);
                    let value = trim(&line[eq_pos + 1..]);

                    match section {
                        Section::Service => {
                            if key_matches_current_arch(key, b"Name") {
                                out.name_len = copy_to_buf(value, &mut out.name);
                            } else if key_matches_current_arch(key, b"Binary") {
                                out.binary_len = copy_to_buf(value, &mut out.binary);
                                if out.binary_len > 0 && out.binary[0] != b'/' {
                                    trona::uerror!(|_lb| {
                                        _lb.str(b"[INIT] Binary= must be absolute path: ");
                                        _lb.bytes(&out.binary[..out.binary_len as usize]);
                                        _lb.str(b"\n");
                                    });
                                    out.binary_len = 0;
                                }
                            } else if key_matches_current_arch(key, b"Type") {
                                if bytes_eq_ci(value, b"simple") {
                                    out.svc_type = ServiceType::Simple;
                                } else if bytes_eq_ci(value, b"notify") {
                                    out.svc_type = ServiceType::Notify;
                                } else if bytes_eq_ci(value, b"target") {
                                    out.svc_type = ServiceType::Target;
                                }
                            } else if key_matches_current_arch(key, b"Activation") {
                                if bytes_eq_ci(value, b"event") {
                                    out.target_activation = TargetActivation::Event;
                                } else {
                                    out.target_activation = TargetActivation::Passive;
                                }
                            } else if key_matches_current_arch(key, b"MemoryKB") {
                                out.memory_kb = parse_decimal_u16(value);
                            } else if key_matches_current_arch(key, b"TimeoutStartSec")
                                || key_matches_current_arch(key, b"TimeoutSec")
                            {
                                out.timeout_start_ns = parse_duration_ns(value);
                            } else if key_matches_current_arch(key, b"CNodeBits") {
                                out.cnode_bits = parse_decimal_u16(value) as u8;
                            } else if key_matches_current_arch(key, b"MapInitrd") {
                                out.map_initrd = bytes_eq_ci(value, b"yes");
                            } else if key_matches_current_arch(key, b"PreProcmgr") {
                                out.pre_procmgr = bytes_eq_ci(value, b"yes");
                            } else if key_matches_current_arch(key, b"Args") {
                                let (args_len, argc) = parse_spawn_args(value, &mut out.spawn_args);
                                out.spawn_args_len = args_len;
                                out.spawn_argc = argc;
                            } else if key_matches_current_arch(key, b"Role") {
                                out.role_len = copy_to_buf(value, &mut out.role);
                            } else if key_matches_current_arch(key, b"Restart") {
                                if bytes_eq_ci(value, b"no") {
                                    out.restart = RestartPolicy::No;
                                } else if bytes_eq_ci(value, b"always") {
                                    out.restart = RestartPolicy::Always;
                                } else if bytes_eq_ci(value, b"on-failure") {
                                    out.restart = RestartPolicy::OnFailure;
                                }
                            }
                        }
                        Section::Dependencies => {
                            if key_matches_current_arch(key, b"After") {
                                out.after_count = parse_dep_list(value, &mut out.after);
                            } else if key_matches_current_arch(key, b"Before") {
                                out.before_count = parse_dep_list(value, &mut out.before);
                            } else if key_matches_current_arch(key, b"Requires") {
                                out.ep_need_count = parse_ep_needs(value, &mut out.ep_needs);
                            }
                        }
                        Section::Capabilities => {
                            if key_matches_current_arch(key, b"CopyCap") {
                                out.cap_count = parse_cap_copies(value, &mut out.caps);
                            } else if key_matches_current_arch(key, b"NeedEP") {
                                out.ep_need_count = parse_ep_needs(value, &mut out.ep_needs);
                            } else if key_matches_current_arch(key, b"Require") {
                                out.require_count = parse_require_list(value, &mut out.requires);
                            } else if key_matches_current_arch(key, b"InjectEP") {
                                out.ep_inject_count = parse_ep_injects(value, &mut out.ep_injects);
                            } else if key_matches_current_arch(key, b"CreateEP") {
                                out.create_ep_count = parse_create_eps(value, &mut out.create_eps);
                            } else if key_matches_current_arch(key, b"BootstrapPrivileged") {
                                out.bootstrap_privileged = bytes_eq_ci(value, b"yes");
                            } else if key_matches_current_arch(key, b"CopySharedLibCaps") {
                                out.copy_shared_lib_caps = bytes_eq_ci(value, b"yes");
                            }
                        }
                        Section::None => {}
                    }
                }
            }
        }

        line_start = line_end + 1;
    }

    out.name_len > 0 && (out.svc_type == ServiceType::Target || out.binary_len > 0)
}
