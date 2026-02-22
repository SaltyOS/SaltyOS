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
pub const MAX_SPAWN_ARGS_BYTES: usize = 96;
pub const MAX_SPAWN_ARGS: usize = 6;

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
}

#[derive(Clone, Copy)]
pub struct EpInjectDef {
    pub target: [u8; MAX_SERVICE_NAME],
    pub target_len: u8,
    pub target_slot: u64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum ServiceType {
    Simple,
    Notify,
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
    pub ep_injects: [EpInjectDef; MAX_EP_INJECTS],
    pub ep_inject_count: u8,
    /// NUL-separated argv entries appended after argv[0] by procmgr spawn path.
    pub spawn_args: [u8; MAX_SPAWN_ARGS_BYTES],
    pub spawn_args_len: u8,
    pub spawn_argc: u8,
}

impl ServiceDef {
    pub const fn zeroed() -> Self {
        ServiceDef {
            name: [0; MAX_SERVICE_NAME],
            name_len: 0,
            binary: [0; MAX_BINARY_NAME],
            binary_len: 0,
            svc_type: ServiceType::Simple,
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
            caps: [CapCopyDef { src_slot: 0, dst_slot: 0 }; MAX_CAP_COPIES],
            cap_count: 0,
            ep_needs: [EpNeedDef { service: [0; MAX_SERVICE_NAME], service_len: 0, dst_slot: 0, badged: false }; MAX_EP_NEEDS],
            ep_need_count: 0,
            ep_injects: [EpInjectDef { target: [0; MAX_SERVICE_NAME], target_len: 0, target_slot: 0 }; MAX_EP_INJECTS],
            ep_inject_count: 0,
            spawn_args: [0; MAX_SPAWN_ARGS_BYTES],
            spawn_args_len: 0,
            spawn_argc: 0,
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
        let ca = if a[i] >= b'A' && a[i] <= b'Z' { a[i] + 32 } else { a[i] };
        let cb = if b[i] >= b'A' && b[i] <= b'Z' { b[i] + 32 } else { b[i] };
        if ca != cb {
            return false;
        }
    }
    true
}

fn copy_to_buf(src: &[u8], dst: &mut [u8]) -> u8 {
    let len = if src.len() < dst.len() { src.len() } else { dst.len() };
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
    } else if bytes_eq_ci(unit, b"ms")
        || bytes_eq_ci(unit, b"msec")
        || bytes_eq_ci(unit, b"msecs")
    {
        1_000_000u64
    } else if bytes_eq_ci(unit, b"us")
        || bytes_eq_ci(unit, b"usec")
        || bytes_eq_ci(unit, b"usecs")
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
        if i >= val.len() { break; }

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
        if i >= val.len() { break; }

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
            };
            entry.service_len = copy_to_buf(name, &mut entry.service);

            if found_second {
                // Parse slot from rest[..second_colon], check for "badge" flag
                entry.dst_slot = parse_decimal_u64(&rest[..second_colon]);
                let flag = &rest[second_colon + 1..];
                entry.badged = bytes_eq_ci(flag, b"badge");
            } else {
                // No second colon, just parse slot
                entry.dst_slot = parse_decimal_u64(rest);
                entry.badged = false;
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
        if i >= val.len() { break; }

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
            let mut entry = EpInjectDef { target: [0; MAX_SERVICE_NAME], target_len: 0, target_slot: 0 };
            entry.target_len = copy_to_buf(name, &mut entry.target);
            entry.target_slot = parse_decimal_u64(&token[colon + 1..]);
            injects[count as usize] = entry;
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
                            if bytes_eq_ci(key, b"Name") {
                                out.name_len = copy_to_buf(value, &mut out.name);
                            } else if bytes_eq_ci(key, b"Binary") {
                                out.binary_len = copy_to_buf(value, &mut out.binary);
                            } else if bytes_eq_ci(key, b"Type") {
                                if bytes_eq_ci(value, b"simple") {
                                    out.svc_type = ServiceType::Simple;
                                } else if bytes_eq_ci(value, b"notify") {
                                    out.svc_type = ServiceType::Notify;
                                }
                            } else if bytes_eq_ci(key, b"MemoryKB") {
                                out.memory_kb = parse_decimal_u16(value);
                            } else if bytes_eq_ci(key, b"TimeoutStartSec")
                                || bytes_eq_ci(key, b"TimeoutSec")
                            {
                                out.timeout_start_ns = parse_duration_ns(value);
                            } else if bytes_eq_ci(key, b"CNodeBits") {
                                out.cnode_bits = parse_decimal_u16(value) as u8;
                            } else if bytes_eq_ci(key, b"MapInitrd") {
                                out.map_initrd = bytes_eq_ci(value, b"yes");
                            } else if bytes_eq_ci(key, b"PreProcmgr") {
                                out.pre_procmgr = bytes_eq_ci(value, b"yes");
                            } else if bytes_eq_ci(key, b"Args") {
                                let (args_len, argc) = parse_spawn_args(value, &mut out.spawn_args);
                                out.spawn_args_len = args_len;
                                out.spawn_argc = argc;
                            } else if bytes_eq_ci(key, b"Restart") {
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
                            if bytes_eq_ci(key, b"After") {
                                out.after_count = parse_dep_list(value, &mut out.after);
                            } else if bytes_eq_ci(key, b"Before") {
                                out.before_count = parse_dep_list(value, &mut out.before);
                            } else if bytes_eq_ci(key, b"Requires") {
                                out.ep_need_count = parse_ep_needs(value, &mut out.ep_needs);
                            }
                        }
                        Section::Capabilities => {
                            if bytes_eq_ci(key, b"CopyCap") {
                                out.cap_count = parse_cap_copies(value, &mut out.caps);
                            } else if bytes_eq_ci(key, b"NeedEP") {
                                out.ep_need_count = parse_ep_needs(value, &mut out.ep_needs);
                            } else if bytes_eq_ci(key, b"InjectEP") {
                                out.ep_inject_count = parse_ep_injects(value, &mut out.ep_injects);
                            }
                        }
                        Section::None => {}
                    }
                }
            }
        }

        line_start = line_end + 1;
    }

    out.name_len > 0 && out.binary_len > 0
}
