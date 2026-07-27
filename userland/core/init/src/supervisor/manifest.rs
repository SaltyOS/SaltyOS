// SPDX-License-Identifier: GPL-2.0-only
//
//! systemd-style manifest store for SaltyOS init.
//!
//! Four unit types live under `/services/` in the initrd:
//!
//! - `*.service`  — runnable service unit (lifecycle + capabilities + dependencies)
//! - `*.cap`      — policy/hardware capability source declaration
//! - `*.socket`   — provider's namesrv publish endpoint declaration
//! - `*.target`   — milestone / dependency aggregation point
//!
//! Boot reads them all, parses each by extension into the matching
//! `*Def` type, links them into the manifest, validates the graph
//! (interface match, cycle detection, missing references), and the
//! supervisor's unit_mgr drives dispatch from the result. The whole
//! manifest is owner-thread-only — no locking.

use core::cmp::min;

use trona_runtime::spawn::stack_consts::{
    MAX_STACK_GUARD_KIB, MAX_STACK_PREFAULT_KIB, MAX_STACK_RESERVE_KIB, MIN_STACK_GUARD_KIB,
    MIN_STACK_PREFAULT_KIB, MIN_STACK_RESERVE_KIB, STACK_PAGE_KIB,
};
use trona_runtime::spawn::stack_plan::StackLayoutSpec;

pub const MAX_SERVICES: usize = 64;
pub const MAX_CAPS: usize = 16;
pub const MAX_SOCKETS: usize = 32;
pub const MAX_TARGETS: usize = 8;

pub const MAX_DEPENDENCIES_PER_SERVICE: usize = 16;
pub const MAX_PROVIDES_PER_SERVICE: usize = 8;
pub const MAX_REQUIRES_PER_SERVICE: usize = 16;
pub const MAX_UNIT_REQUIRES_PER_SERVICE: usize = 16;
pub const MAX_EXPORTS_PER_SERVICE: usize = 8;
pub const MAX_INTERFACE_FLAGS_PER_SERVICE: usize = 8;
pub const MAX_FLAG_TOKENS_PER_INTERFACE: usize = 6;

pub const MAX_NAME_BYTES: usize = 32;
pub const MAX_BINARY_BYTES: usize = 64;

/// Maximum byte length of a `<provider>:<alias>` interface key.
pub const MAX_IFACE_KEY_BYTES: usize = MAX_NAME_BYTES + 1 + 32;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ServiceType {
    /// Plain process — `_start` runs to completion or until killed.
    Simple,
    /// Long-lived server — init expects it to register itself with
    /// namesrv and signal readiness, never to exit.
    Server,
    /// One-shot task; readiness = process exit (status=0).
    Oneshot,
    /// Leaf service with no namesrv-published endpoint. Readiness =
    /// child invokes `INIT_NOTIFY_READY` on its init control endpoint.
    /// systemd `Type=notify` equivalent (transport: init control MP).
    Notify,
    /// Publishing service — readiness = `NAMESRV_REGISTER` succeeds.
    /// systemd `Type=dbus` equivalent (broker = namesrv, not D-Bus,
    /// to avoid name collision with POSIX userspace dbus).
    Broker,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    Never,
    OnFailure,
    Always,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TargetActivation {
    /// `Activation=event` — target fires when its dependencies are ready.
    Event,
    /// No `Activation=` line — passive milestone (default).
    Passive,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IfaceKey {
    bytes: [u8; MAX_IFACE_KEY_BYTES],
    len: u8,
}

impl IfaceKey {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_IFACE_KEY_BYTES],
            len: 0,
        }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut k = Self::empty();
        let n = min(s.len(), MAX_IFACE_KEY_BYTES);
        k.bytes[..n].copy_from_slice(&s[..n]);
        k.len = n as u8;
        k
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy)]
pub struct NameStr {
    bytes: [u8; MAX_NAME_BYTES],
    len: u8,
}

impl NameStr {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_NAME_BYTES],
            len: 0,
        }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut n = Self::empty();
        let len = min(s.len(), MAX_NAME_BYTES);
        n.bytes[..len].copy_from_slice(&s[..len]);
        n.len = len as u8;
        n
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy)]
pub struct BinaryStr {
    bytes: [u8; MAX_BINARY_BYTES],
    len: u8,
}

impl BinaryStr {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_BINARY_BYTES],
            len: 0,
        }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut b = Self::empty();
        let len = min(s.len(), MAX_BINARY_BYTES);
        b.bytes[..len].copy_from_slice(&s[..len]);
        b.len = len as u8;
        b
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy)]
pub struct DependencyEntry {
    pub target: NameStr,
    /// Other-service-must-be-ready-before-this. `before == false`
    /// means "After=", i.e. wait for `target` before spawning self.
    pub before: bool,
}

#[derive(Clone, Copy)]
pub struct ProvidesEntry {
    pub iface: IfaceKey,
    /// Optional role id from `[Capabilities] InterfaceRole=<iface>:ROLE_*`.
    /// Zero means metadata-only interface with no startup cap-table slot.
    pub role_id: u32,
}

#[derive(Clone, Copy)]
pub struct RequiresEntry {
    pub iface: IfaceKey,
    pub optional: bool,
}

#[derive(Clone, Copy)]
pub struct InterfaceFlagsEntry {
    pub iface: IfaceKey,
    pub tokens: [NameStr; MAX_FLAG_TOKENS_PER_INTERFACE],
    pub tokens_len: u8,
}

impl InterfaceFlagsEntry {
    pub const fn empty() -> Self {
        Self {
            iface: IfaceKey::empty(),
            tokens: [NameStr::empty(); MAX_FLAG_TOKENS_PER_INTERFACE],
            tokens_len: 0,
        }
    }
}

/// A single token inside a `[Dependencies] Requires=...` line, classified
/// by its file extension or shape.
#[derive(Clone, Copy)]
pub enum UnitRef {
    /// Empty slot.
    None,
    /// `foo.cap` — policy/hardware cap unit. install_caps resolves
    /// `SourceSlot` from the matching `CapDef`.
    Cap(NameStr),
    /// `foo.socket` — provider's namesrv publish endpoint. Wait for
    /// the provider service's readiness + register event.
    Socket(NameStr),
    /// `foo.target` — milestone unit. Wait for the target's transitive
    /// dependencies.
    Target(NameStr),
    /// `foo.service` or bare `foo` — direct service dependency.
    Service(NameStr),
    /// `provider:alias` — service-local consumer. Provider's
    /// `Exports=` must contain `alias`. install_caps attaches the
    /// resolved cap at spawn time.
    LocalAlias { provider: NameStr, alias: NameStr },
}

#[derive(Clone, Copy)]
pub struct ServiceDef {
    pub name: NameStr,
    pub binary: BinaryStr,
    pub service_type: ServiceType,
    pub restart: RestartPolicy,
    pub bootstrap_privileged: bool,
    pub deps: [DependencyEntry; MAX_DEPENDENCIES_PER_SERVICE],
    pub deps_len: u8,
    /// `[Capabilities] ProvidesInterface=` interfaces with optional
    /// `InterfaceRole=` mappings. Interfaces without a role are provider-local
    /// metadata for dependency validation and do not consume cap-table slots.
    pub provides: [ProvidesEntry; MAX_PROVIDES_PER_SERVICE],
    pub provides_len: u8,
    /// `[Dependencies] RequiresInterface=` entries. Iface key is
    /// `provider:iface_name`.
    pub requires: [RequiresEntry; MAX_REQUIRES_PER_SERVICE],
    pub requires_len: u8,
    /// `[Dependencies] Requires=` tokens (hard), classified by `UnitRef`.
    /// Hard: dependency miss = not-ready (block) or spawn fail. Edge
    /// participates in cycle detection (validate SCC).
    pub unit_requires: [UnitRef; MAX_UNIT_REQUIRES_PER_SERVICE],
    pub unit_requires_len: u8,
    /// `[Dependencies] Wants=` tokens (soft), classified by `UnitRef`.
    /// Soft: dependency miss/fail = best-effort, this service still
    /// proceeds. Excluded from cycle detection. Cap/LocalAlias forms
    /// are rejected at parse time (only Service/Socket/Target valid).
    pub unit_wants: [UnitRef; MAX_UNIT_REQUIRES_PER_SERVICE],
    pub unit_wants_len: u8,
    /// Set by `parse_service` when a `Wants=` token names a `.cap` or
    /// `provider:alias` (rejected — those forms must be `Requires=`).
    /// `validate` raises `ParseErr::InvalidWants` so the manifest fails
    /// loud at boot rather than silently dropping the line.
    pub wants_invalid: bool,
    /// `[Capabilities] Exports=` aliases consumed by other services
    /// via `<this>:<alias>` in their `Requires=` line.
    pub exports: [NameStr; MAX_EXPORTS_PER_SERVICE],
    pub exports_len: u8,
    /// `[Capabilities] InterfaceFlags=` mapping per interface.
    pub interface_flags: [InterfaceFlagsEntry; MAX_INTERFACE_FLAGS_PER_SERVICE],
    pub interface_flags_len: u8,
    /// Set when an `InterfaceRole=` line is malformed or names an
    /// unknown/zero role. Omitting `InterfaceRole=` is valid for
    /// metadata-only interfaces.
    pub interface_role_invalid: bool,
    /// Stable policy id for namesrv badge mint
    /// (badge bit 47-32; see authz.rs).
    pub policy_id: u16,
    /// `[Memory] StackReserveKiB=`. Zero means use substrate default.
    pub stack_reserve_kib: u32,
    /// `[Memory] StackPrefaultKiB=`. Zero means use substrate default.
    pub stack_prefault_kib: u16,
    /// `[Memory] StackGuardKiB=`. Zero means use substrate default.
    pub stack_guard_kib: u16,
}

impl ServiceDef {
    pub const fn empty() -> Self {
        Self {
            name: NameStr::empty(),
            binary: BinaryStr::empty(),
            service_type: ServiceType::Simple,
            restart: RestartPolicy::Never,
            bootstrap_privileged: false,
            deps: [DependencyEntry {
                target: NameStr::empty(),
                before: false,
            }; MAX_DEPENDENCIES_PER_SERVICE],
            deps_len: 0,
            provides: [ProvidesEntry {
                iface: IfaceKey::empty(),
                role_id: 0,
            }; MAX_PROVIDES_PER_SERVICE],
            provides_len: 0,
            requires: [RequiresEntry {
                iface: IfaceKey::empty(),
                optional: false,
            }; MAX_REQUIRES_PER_SERVICE],
            requires_len: 0,
            unit_requires: [UnitRef::None; MAX_UNIT_REQUIRES_PER_SERVICE],
            unit_requires_len: 0,
            unit_wants: [UnitRef::None; MAX_UNIT_REQUIRES_PER_SERVICE],
            unit_wants_len: 0,
            wants_invalid: false,
            exports: [NameStr::empty(); MAX_EXPORTS_PER_SERVICE],
            exports_len: 0,
            interface_flags: [InterfaceFlagsEntry::empty(); MAX_INTERFACE_FLAGS_PER_SERVICE],
            interface_flags_len: 0,
            interface_role_invalid: false,
            policy_id: 0,
            stack_reserve_kib: 0,
            stack_prefault_kib: 0,
            stack_guard_kib: 0,
        }
    }

    /// `empty()` plus a stamped name. Used by the lifecycle pipeline
    /// when a process arrives without a manifest entry (e.g. fork —
    /// the child inherits the parent's name; exec replaces the name
    /// with the new image's manifest entry).
    pub fn empty_named(name: NameStr) -> Self {
        let mut s = Self::empty();
        s.name = name;
        s
    }

    /// Readiness source predicate. Each `ServiceType` answers via a
    /// distinct hook in `UnitGraph`:
    /// - `Broker`/`Server`: `on_namesrv_register` (NAMESRV_REGISTER seen).
    /// - `Notify`: `on_init_notify_ready` (child INIT_NOTIFY_READY call).
    /// - `Oneshot`: `on_oneshot_exit` (lifecycle handler on exit(0)).
    /// - `Simple`: no readiness wait — dispatched once spawned.
    pub fn readiness_source(&self) -> ReadinessSource {
        match self.service_type {
            ServiceType::Broker | ServiceType::Server => ReadinessSource::NamesrvRegister,
            ServiceType::Notify => ReadinessSource::InitNotifyReady,
            ServiceType::Oneshot => ReadinessSource::OneshotExit,
            ServiceType::Simple => ReadinessSource::Immediate,
        }
    }

    pub fn stack_layout_spec(&self) -> StackLayoutSpec {
        StackLayoutSpec::from_manifest_or_default(
            self.stack_reserve_kib,
            self.stack_prefault_kib,
            self.stack_guard_kib,
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ReadinessSource {
    NamesrvRegister,
    InitNotifyReady,
    OneshotExit,
    Immediate,
}

#[derive(Clone, Copy)]
pub struct CapDef {
    pub name: NameStr,
    pub source_slot: u64,
}

impl CapDef {
    pub const fn empty() -> Self {
        Self {
            name: NameStr::empty(),
            source_slot: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SocketDef {
    pub name: NameStr,
    pub provider: NameStr,
    pub alias: NameStr,
}

impl SocketDef {
    pub const fn empty() -> Self {
        Self {
            name: NameStr::empty(),
            provider: NameStr::empty(),
            alias: NameStr::empty(),
        }
    }
}

#[derive(Clone, Copy)]
pub struct TargetDef {
    pub name: NameStr,
    pub activation: TargetActivation,
    pub deps: [DependencyEntry; MAX_DEPENDENCIES_PER_SERVICE],
    pub deps_len: u8,
}

impl TargetDef {
    pub const fn empty() -> Self {
        Self {
            name: NameStr::empty(),
            activation: TargetActivation::Passive,
            deps: [DependencyEntry {
                target: NameStr::empty(),
                before: false,
            }; MAX_DEPENDENCIES_PER_SERVICE],
            deps_len: 0,
        }
    }
}

pub struct ServiceManifest {
    pub services: [ServiceDef; MAX_SERVICES],
    pub count: usize,
    pub caps: [CapDef; MAX_CAPS],
    pub caps_count: usize,
    pub sockets: [SocketDef; MAX_SOCKETS],
    pub sockets_count: usize,
    pub targets: [TargetDef; MAX_TARGETS],
    pub targets_count: usize,
    /// Indices into `services`, topologically sorted. Valid after
    /// `topo_sort()` returns true.
    pub spawn_order: [u8; MAX_SERVICES],
    pub spawn_order_valid: bool,
    /// Monotonic counter for stable policy ids assigned at parse time.
    next_policy_id: u16,
}

impl ServiceManifest {
    pub const fn new() -> Self {
        Self {
            services: [ServiceDef::empty(); MAX_SERVICES],
            count: 0,
            caps: [CapDef::empty(); MAX_CAPS],
            caps_count: 0,
            sockets: [SocketDef::empty(); MAX_SOCKETS],
            sockets_count: 0,
            targets: [TargetDef::empty(); MAX_TARGETS],
            targets_count: 0,
            spawn_order: [0; MAX_SERVICES],
            spawn_order_valid: false,
            next_policy_id: 1,
        }
    }

    pub fn find_index_by_name(&self, name: &[u8]) -> Option<usize> {
        for (i, s) in self.services[..self.count].iter().enumerate() {
            if s.name.as_bytes() == name {
                return Some(i);
            }
        }
        None
    }

    pub fn find_cap_by_name(&self, name: &[u8]) -> Option<&CapDef> {
        self.caps[..self.caps_count]
            .iter()
            .find(|c| c.name.as_bytes() == name)
    }

    pub fn find_socket_by_name(&self, name: &[u8]) -> Option<&SocketDef> {
        self.sockets[..self.sockets_count]
            .iter()
            .find(|s| s.name.as_bytes() == name)
    }

    pub fn find_target_by_name(&self, name: &[u8]) -> Option<&TargetDef> {
        self.targets[..self.targets_count]
            .iter()
            .find(|t| t.name.as_bytes() == name)
    }

    /// Parse one `.service` file and append the resulting `ServiceDef`.
    /// Returns the new index on success.
    pub fn parse_and_add(&mut self, content: &[u8]) -> Result<usize, ParseErr> {
        if self.count >= MAX_SERVICES {
            return Err(ParseErr::ManifestFull);
        }
        let mut def = ServiceDef::empty();
        let mut state = ParseState::Top;
        for line in content.split(|b| *b == b'\n') {
            let line = trim(line);
            if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
                continue;
            }
            if line.starts_with(b"[") && line.ends_with(b"]") {
                let section = &line[1..line.len() - 1];
                state = match section {
                    b"Service" => ParseState::Service,
                    b"Dependencies" => ParseState::Dependencies,
                    b"Capabilities" => ParseState::Capabilities,
                    b"Memory" => ParseState::Memory,
                    b"Quotas" => ParseState::Skip,
                    _ => ParseState::Skip,
                };
                continue;
            }
            let Some((key, value)) = split_kv(line) else {
                continue;
            };
            match state {
                ParseState::Service => apply_service_kv(&mut def, key, value),
                ParseState::Dependencies => apply_dep_kv(&mut def, key, value),
                ParseState::Capabilities => apply_capabilities_kv(&mut def, key, value),
                ParseState::Memory => apply_memory_kv(&mut def, key, value),
                _ => {}
            }
        }
        if def.name.as_bytes().is_empty() || def.binary.as_bytes().is_empty() {
            return Err(ParseErr::MissingNameOrBinary);
        }
        def.policy_id = self.next_policy_id;
        self.next_policy_id = self.next_policy_id.wrapping_add(1);
        if self.next_policy_id == 0 {
            self.next_policy_id = 1;
        }
        let idx = self.count;
        self.services[idx] = def;
        self.count += 1;
        self.spawn_order_valid = false;
        Ok(idx)
    }

    /// Parse one `.cap` file.
    pub fn parse_cap_and_add(
        &mut self,
        file_name: &[u8],
        content: &[u8],
    ) -> Result<usize, ParseErr> {
        if self.caps_count >= MAX_CAPS {
            return Err(ParseErr::ManifestFull);
        }
        let mut def = CapDef::empty();
        // Strip leading `/services/` and use the file name as the
        // canonical cap name. Caller passes the raw cpio entry name.
        let bare = strip_services_prefix(file_name);
        def.name = NameStr::from_bytes(bare);
        let mut state = ParseState::Top;
        for line in content.split(|b| *b == b'\n') {
            let line = trim(line);
            if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
                continue;
            }
            if line.starts_with(b"[") && line.ends_with(b"]") {
                let section = &line[1..line.len() - 1];
                state = match section {
                    b"Capability" => ParseState::Capability,
                    b"Unit" => ParseState::Unit,
                    _ => ParseState::Skip,
                };
                continue;
            }
            let Some((key, value)) = split_kv(line) else {
                continue;
            };
            match state {
                ParseState::Capability => apply_cap_kv(&mut def, key, value),
                ParseState::Unit => apply_unit_kv_for_cap(&mut def, key, value),
                _ => {}
            }
        }
        if def.name.as_bytes().is_empty() {
            return Err(ParseErr::MissingNameOrBinary);
        }
        let idx = self.caps_count;
        self.caps[idx] = def;
        self.caps_count += 1;
        Ok(idx)
    }

    /// Parse one `.socket` file.
    pub fn parse_socket_and_add(
        &mut self,
        file_name: &[u8],
        content: &[u8],
    ) -> Result<usize, ParseErr> {
        if self.sockets_count >= MAX_SOCKETS {
            return Err(ParseErr::ManifestFull);
        }
        let mut def = SocketDef::empty();
        let bare = strip_services_prefix(file_name);
        def.name = NameStr::from_bytes(bare);
        let mut state = ParseState::Top;
        for line in content.split(|b| *b == b'\n') {
            let line = trim(line);
            if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
                continue;
            }
            if line.starts_with(b"[") && line.ends_with(b"]") {
                let section = &line[1..line.len() - 1];
                state = match section {
                    b"Socket" => ParseState::Socket,
                    b"Unit" => ParseState::Unit,
                    _ => ParseState::Skip,
                };
                continue;
            }
            let Some((key, value)) = split_kv(line) else {
                continue;
            };
            match state {
                ParseState::Socket => apply_socket_kv(&mut def, key, value),
                ParseState::Unit => apply_unit_kv_for_socket(&mut def, key, value),
                _ => {}
            }
        }
        if def.name.as_bytes().is_empty() || def.provider.as_bytes().is_empty() {
            return Err(ParseErr::MissingNameOrBinary);
        }
        let idx = self.sockets_count;
        self.sockets[idx] = def;
        self.sockets_count += 1;
        Ok(idx)
    }

    /// Parse one `.target` file.
    pub fn parse_target_and_add(
        &mut self,
        file_name: &[u8],
        content: &[u8],
    ) -> Result<usize, ParseErr> {
        if self.targets_count >= MAX_TARGETS {
            return Err(ParseErr::ManifestFull);
        }
        let mut def = TargetDef::empty();
        let bare = strip_services_prefix(file_name);
        def.name = NameStr::from_bytes(bare);
        let mut state = ParseState::Top;
        for line in content.split(|b| *b == b'\n') {
            let line = trim(line);
            if line.is_empty() || line.starts_with(b"#") || line.starts_with(b";") {
                continue;
            }
            if line.starts_with(b"[") && line.ends_with(b"]") {
                let section = &line[1..line.len() - 1];
                state = match section {
                    b"Service" => ParseState::Service,
                    b"Dependencies" => ParseState::Dependencies,
                    _ => ParseState::Skip,
                };
                continue;
            }
            let Some((key, value)) = split_kv(line) else {
                continue;
            };
            match state {
                ParseState::Service => apply_target_service_kv(&mut def, key, value),
                ParseState::Dependencies => apply_target_dep_kv(&mut def, key, value),
                _ => {}
            }
        }
        if def.name.as_bytes().is_empty() {
            return Err(ParseErr::MissingNameOrBinary);
        }
        let idx = self.targets_count;
        self.targets[idx] = def;
        self.targets_count += 1;
        Ok(idx)
    }

    /// Validate cross-references between unit types. Run after every
    /// unit file has been parsed and before `topo_sort`.
    pub fn validate(&self) -> Result<(), ParseErr> {
        for s in &self.services[..self.count] {
            if s.wants_invalid {
                return Err(ParseErr::InvalidWants);
            }
            if s.interface_role_invalid {
                return Err(ParseErr::InvalidInterfaceRole);
            }
            for u in 0..s.unit_requires_len as usize {
                match s.unit_requires[u] {
                    UnitRef::None => {}
                    UnitRef::Cap(name) => {
                        if self.find_cap_by_name(name.as_bytes()).is_none() {
                            return Err(ParseErr::UnknownCap);
                        }
                    }
                    UnitRef::Socket(name) => {
                        let sock = match self.find_socket_by_name(name.as_bytes()) {
                            Some(s) => s,
                            None => return Err(ParseErr::UnknownSocket),
                        };
                        if self.find_index_by_name(sock.provider.as_bytes()).is_none() {
                            return Err(ParseErr::UnknownService);
                        }
                    }
                    UnitRef::Target(name) => {
                        if self.find_target_by_name(name.as_bytes()).is_none() {
                            return Err(ParseErr::UnknownTarget);
                        }
                    }
                    UnitRef::Service(name) => {
                        if self.find_index_by_name(name.as_bytes()).is_none() {
                            return Err(ParseErr::UnknownService);
                        }
                    }
                    UnitRef::LocalAlias { provider, alias } => {
                        let p = match self.find_index_by_name(provider.as_bytes()) {
                            Some(i) => &self.services[i],
                            None => return Err(ParseErr::UnknownService),
                        };
                        let mut found = false;
                        for e in 0..p.exports_len as usize {
                            if p.exports[e].as_bytes() == alias.as_bytes() {
                                found = true;
                                break;
                            }
                        }
                        if !found {
                            return Err(ParseErr::UnknownAlias);
                        }
                    }
                }
            }
            for r in 0..s.requires_len as usize {
                let key = s.requires[r].iface.as_bytes();
                let Some(colon) = key.iter().position(|c| *c == b':') else {
                    return Err(ParseErr::MalformedInterface);
                };
                let provider = &key[..colon];
                let iface = &key[colon + 1..];
                let p = match self.find_index_by_name(provider) {
                    Some(i) => &self.services[i],
                    None if s.requires[r].optional => continue,
                    None => return Err(ParseErr::UnknownService),
                };
                let mut found = false;
                for q in 0..p.provides_len as usize {
                    if p.provides[q].iface.as_bytes() == iface {
                        found = true;
                        break;
                    }
                }
                if !found && !s.requires[r].optional {
                    return Err(ParseErr::UnknownInterface);
                }
            }
        }
        self.detect_cycle_hard()?;
        Ok(())
    }

    /// Iterative DFS over the hard-dependency graph (`Requires=` /
    /// `RequiresInterface=` / `After=` / sibling `Before=` rewrites).
    /// Soft `Wants=` edges are excluded so soft-loop manifests still
    /// boot. Three-color DFS detects back-edges (cycles).
    fn detect_cycle_hard(&self) -> Result<(), ParseErr> {
        let mut color = [0u8; MAX_SERVICES]; // 0=white, 1=gray, 2=black
        let mut stack_idx = [0usize; MAX_SERVICES];
        let mut stack_iter = [0u32; MAX_SERVICES];
        for root in 0..self.count {
            if color[root] != 0 {
                continue;
            }
            let mut sp = 0usize;
            stack_idx[sp] = root;
            stack_iter[sp] = 0;
            color[root] = 1;
            sp += 1;
            while sp > 0 {
                let cur = stack_idx[sp - 1];
                let it = stack_iter[sp - 1] as usize;
                if let Some(next) = self.nth_hard_edge(cur, it) {
                    stack_iter[sp - 1] = (it + 1) as u32;
                    match color[next] {
                        1 => return Err(ParseErr::Cycle),
                        0 => {
                            color[next] = 1;
                            stack_idx[sp] = next;
                            stack_iter[sp] = 0;
                            sp += 1;
                        }
                        _ => {}
                    }
                } else {
                    color[cur] = 2;
                    sp -= 1;
                }
            }
        }
        Ok(())
    }

    /// Returns the `it`-th hard outgoing edge (a service index this
    /// service depends on) or `None` when exhausted. Edge order is
    /// `unit_requires` → `requires_iface` → own `After=` → sibling
    /// `Before=` rewrites. `Wants=` excluded.
    fn nth_hard_edge(&self, cur: usize, it: usize) -> Option<usize> {
        let svc = &self.services[cur];
        let mut k = 0usize;
        for u in 0..svc.unit_requires_len as usize {
            match svc.unit_requires[u] {
                UnitRef::Service(name) => {
                    if let Some(t) = self.find_index_by_name(name.as_bytes()) {
                        if k == it {
                            return Some(t);
                        }
                        k += 1;
                    }
                }
                UnitRef::Socket(name) => {
                    if let Some(t) = self
                        .find_socket_by_name(name.as_bytes())
                        .and_then(|s| self.find_index_by_name(s.provider.as_bytes()))
                    {
                        if k == it {
                            return Some(t);
                        }
                        k += 1;
                    }
                }
                UnitRef::LocalAlias { provider, .. } => {
                    if let Some(t) = self.find_index_by_name(provider.as_bytes()) {
                        if k == it {
                            return Some(t);
                        }
                        k += 1;
                    }
                }
                UnitRef::Target(name) => {
                    // Targets are virtual milestones — expand to every
                    // service the target hard-depends on so cycles
                    // through targets surface in SCC instead of slipping
                    // into the unit_mgr depth-limit guard at runtime.
                    if let Some(target) = self.find_target_by_name(name.as_bytes()) {
                        for d in 0..target.deps_len as usize {
                            let dep = target.deps[d];
                            if dep.before {
                                continue;
                            }
                            if let Some(t) = self.find_index_by_name(dep.target.as_bytes()) {
                                if k == it {
                                    return Some(t);
                                }
                                k += 1;
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        for r in 0..svc.requires_len as usize {
            let key = svc.requires[r].iface.as_bytes();
            if let Some(colon) = key.iter().position(|c| *c == b':') {
                let provider = &key[..colon];
                if let Some(t) = self.find_index_by_name(provider) {
                    if k == it {
                        return Some(t);
                    }
                    k += 1;
                }
            }
        }
        for d in 0..svc.deps_len as usize {
            let dep = svc.deps[d];
            if dep.before {
                continue;
            }
            if let Some(t) = self.find_index_by_name(dep.target.as_bytes()) {
                if k == it {
                    return Some(t);
                }
                k += 1;
            }
        }
        for j in 0..self.count {
            if j == cur {
                continue;
            }
            let other = &self.services[j];
            for d in 0..other.deps_len as usize {
                let dep = other.deps[d];
                if !dep.before {
                    continue;
                }
                if let Some(t) = self.find_index_by_name(dep.target.as_bytes()) {
                    if t == cur {
                        if k == it {
                            return Some(j);
                        }
                        k += 1;
                    }
                }
            }
        }
        None
    }

    /// Kahn's-algorithm topological sort. Reads `After=` edges only —
    /// `Before=` is rewritten into the corresponding `After=` on the
    /// other service before sorting.
    pub fn topo_sort(&mut self) -> Result<(), ParseErr> {
        // First, propagate `Before=X` on service A to `After=A` on service X.
        let mut after_count = [0u8; MAX_SERVICES];
        let mut after_edges: [[u8; MAX_DEPENDENCIES_PER_SERVICE]; MAX_SERVICES] =
            [[0; MAX_DEPENDENCIES_PER_SERVICE]; MAX_SERVICES];

        for i in 0..self.count {
            let svc = &self.services[i];
            for d in 0..svc.deps_len as usize {
                let dep = svc.deps[d];
                let target_idx = match self.find_index_by_name(dep.target.as_bytes()) {
                    Some(t) => t,
                    None => continue, // missing dep — treated as already satisfied
                };
                let (consumer, producer) = if dep.before {
                    (target_idx, i)
                } else {
                    (i, target_idx)
                };
                let n = after_count[consumer] as usize;
                if n >= MAX_DEPENDENCIES_PER_SERVICE {
                    return Err(ParseErr::TooManyDeps);
                }
                after_edges[consumer][n] = producer as u8;
                after_count[consumer] = (n + 1) as u8;
            }
        }

        // Compute in-degree.
        let mut indegree = [0u8; MAX_SERVICES];
        for c in 0..self.count {
            indegree[c] = after_count[c];
        }

        let mut queue: [u8; MAX_SERVICES] = [0; MAX_SERVICES];
        let mut qhead = 0;
        let mut qtail = 0;
        for i in 0..self.count {
            if indegree[i] == 0 {
                queue[qtail] = i as u8;
                qtail += 1;
            }
        }

        let mut out_idx = 0;
        while qhead < qtail {
            let cur = queue[qhead] as usize;
            qhead += 1;
            self.spawn_order[out_idx] = cur as u8;
            out_idx += 1;
            // Decrement in-degree of every consumer that depended on
            // `cur` becoming ready.
            for c in 0..self.count {
                let n = after_count[c] as usize;
                for e in 0..n {
                    if after_edges[c][e] as usize == cur && indegree[c] > 0 {
                        indegree[c] -= 1;
                        if indegree[c] == 0 {
                            queue[qtail] = c as u8;
                            qtail += 1;
                        }
                    }
                }
            }
        }

        if out_idx != self.count {
            return Err(ParseErr::Cycle);
        }
        self.spawn_order_valid = true;
        Ok(())
    }

    pub fn spawn_order_slice(&self) -> &[u8] {
        if self.spawn_order_valid {
            &self.spawn_order[..self.count]
        } else {
            &[]
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Top,
    Service,
    Dependencies,
    Capabilities,
    Memory,
    Capability,
    Socket,
    Unit,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErr {
    ManifestFull,
    MissingNameOrBinary,
    TooManyDeps,
    Cycle,
    UnknownCap,
    UnknownSocket,
    UnknownTarget,
    UnknownService,
    UnknownAlias,
    UnknownInterface,
    MalformedInterface,
    InvalidWants,
    InvalidInterfaceRole,
}

fn trim(s: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = s.len();
    while start < end && (s[start] == b' ' || s[start] == b'\t' || s[start] == b'\r') {
        start += 1;
    }
    while end > start && (s[end - 1] == b' ' || s[end - 1] == b'\t' || s[end - 1] == b'\r') {
        end -= 1;
    }
    &s[start..end]
}

fn split_kv(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let eq = line.iter().position(|c| *c == b'=')?;
    Some((trim(&line[..eq]), trim(&line[eq + 1..])))
}

fn strip_services_prefix(name: &[u8]) -> &[u8] {
    if let Some(rest) = strip_prefix(name, b"/services/") {
        rest
    } else if let Some(rest) = strip_prefix(name, b"services/") {
        rest
    } else {
        name
    }
}

fn strip_prefix<'a>(bytes: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if bytes.len() < prefix.len() {
        return None;
    }
    if &bytes[..prefix.len()] == prefix {
        Some(&bytes[prefix.len()..])
    } else {
        None
    }
}

fn apply_service_kv(def: &mut ServiceDef, key: &[u8], value: &[u8]) {
    match key {
        b"Name" => def.name = NameStr::from_bytes(value),
        b"Binary" => def.binary = BinaryStr::from_bytes(value),
        b"Type" => {
            def.service_type = match value {
                b"broker" => ServiceType::Broker,
                b"server" => ServiceType::Server,
                b"oneshot" => ServiceType::Oneshot,
                b"notify" => ServiceType::Notify,
                _ => ServiceType::Simple,
            }
        }
        b"Restart" | b"RestartPolicy" => {
            def.restart = match value {
                b"on-failure" => RestartPolicy::OnFailure,
                b"always" => RestartPolicy::Always,
                b"no" => RestartPolicy::Never,
                _ => RestartPolicy::Never,
            }
        }
        b"Privileged" => {
            def.bootstrap_privileged = value == b"true";
        }
        _ => {}
    }
}

fn apply_dep_kv(def: &mut ServiceDef, key: &[u8], value: &[u8]) {
    // Architecture-specific gating: `Requires.<arch>=` lines apply
    // only when <arch> matches the build target. Strip the suffix
    // and compare; if mismatch, drop the line silently. Lines without
    // a suffix always apply.
    let key = match split_arch_suffix(key) {
        Some((base, arch)) => {
            if !arch_matches(arch) {
                return;
            }
            base
        }
        None => key,
    };
    match key {
        b"After" | b"Before" => {
            let before = key == b"Before";
            for tgt in value.split(|c| *c == b' ') {
                let tgt = trim(tgt);
                if tgt.is_empty() {
                    continue;
                }
                let n = def.deps_len as usize;
                if n >= MAX_DEPENDENCIES_PER_SERVICE {
                    return;
                }
                def.deps[n] = DependencyEntry {
                    target: NameStr::from_bytes(tgt),
                    before,
                };
                def.deps_len = (n + 1) as u8;
            }
        }
        b"Requires" => {
            for tok in value.split(|c| *c == b' ') {
                let tok = trim(tok);
                if tok.is_empty() {
                    continue;
                }
                let n = def.unit_requires_len as usize;
                if n >= MAX_UNIT_REQUIRES_PER_SERVICE {
                    return;
                }
                def.unit_requires[n] = parse_unit_ref(tok);
                def.unit_requires_len = (n + 1) as u8;
            }
        }
        b"Wants" => {
            for tok in value.split(|c| *c == b' ') {
                let tok = trim(tok);
                if tok.is_empty() {
                    continue;
                }
                let n = def.unit_wants_len as usize;
                if n >= MAX_UNIT_REQUIRES_PER_SERVICE {
                    return;
                }
                let ur = parse_unit_ref(tok);
                if matches!(ur, UnitRef::Cap(_) | UnitRef::LocalAlias { .. }) {
                    def.wants_invalid = true;
                    continue;
                }
                def.unit_wants[n] = ur;
                def.unit_wants_len = (n + 1) as u8;
            }
        }
        b"RequiresInterface" => {
            for tok in value.split(|c| *c == b' ') {
                let tok = trim(tok);
                if tok.is_empty() {
                    continue;
                }
                let optional = !tok.is_empty() && tok[tok.len() - 1] == b'?';
                let body = if optional { &tok[..tok.len() - 1] } else { tok };
                let n = def.requires_len as usize;
                if n >= MAX_REQUIRES_PER_SERVICE {
                    return;
                }
                def.requires[n] = RequiresEntry {
                    iface: IfaceKey::from_bytes(body),
                    optional,
                };
                def.requires_len = (n + 1) as u8;
            }
        }
        _ => {}
    }
}

fn apply_capabilities_kv(def: &mut ServiceDef, key: &[u8], value: &[u8]) {
    match key {
        b"ProvidesInterface" => {
            for tok in value.split(|c| *c == b' ') {
                let tok = trim(tok);
                if tok.is_empty() {
                    continue;
                }
                let n = def.provides_len as usize;
                if n >= MAX_PROVIDES_PER_SERVICE {
                    return;
                }
                def.provides[n] = ProvidesEntry {
                    iface: IfaceKey::from_bytes(tok),
                    role_id: 0,
                };
                def.provides_len = (n + 1) as u8;
            }
        }
        b"InterfaceRole" => {
            // Format: `<iface>:ROLE_*` or `<iface>:0xNN`. Update the
            // matching `provides` entry's role_id.
            let Some(colon) = value.iter().position(|c| *c == b':') else {
                def.interface_role_invalid = true;
                return;
            };
            let iface = trim(&value[..colon]);
            let role_str = trim(&value[colon + 1..]);
            if iface.is_empty() {
                def.interface_role_invalid = true;
                return;
            }
            let Some(role_id) = parse_role(role_str) else {
                def.interface_role_invalid = true;
                return;
            };
            for i in 0..def.provides_len as usize {
                if def.provides[i].iface.as_bytes() == iface {
                    def.provides[i].role_id = role_id;
                    return;
                }
            }
            // ProvidesInterface line missing for this iface — push a
            // placeholder so install_caps can still consult role_id.
            let n = def.provides_len as usize;
            if n >= MAX_PROVIDES_PER_SERVICE {
                return;
            }
            def.provides[n] = ProvidesEntry {
                iface: IfaceKey::from_bytes(iface),
                role_id,
            };
            def.provides_len = (n + 1) as u8;
        }
        b"InterfaceFlags" => {
            // Format: `<iface>:flag1,flag2,...`.
            let Some(colon) = value.iter().position(|c| *c == b':') else {
                return;
            };
            let iface = trim(&value[..colon]);
            let flags = trim(&value[colon + 1..]);
            let n = def.interface_flags_len as usize;
            if n >= MAX_INTERFACE_FLAGS_PER_SERVICE {
                return;
            }
            let mut entry = InterfaceFlagsEntry::empty();
            entry.iface = IfaceKey::from_bytes(iface);
            for tok in flags.split(|c| *c == b',') {
                let tok = trim(tok);
                if tok.is_empty() {
                    continue;
                }
                let t = entry.tokens_len as usize;
                if t >= MAX_FLAG_TOKENS_PER_INTERFACE {
                    break;
                }
                entry.tokens[t] = NameStr::from_bytes(tok);
                entry.tokens_len = (t + 1) as u8;
            }
            def.interface_flags[n] = entry;
            def.interface_flags_len = (n + 1) as u8;
        }
        b"Exports" => {
            for tok in value.split(|c| *c == b' ') {
                let tok = trim(tok);
                if tok.is_empty() {
                    continue;
                }
                let n = def.exports_len as usize;
                if n >= MAX_EXPORTS_PER_SERVICE {
                    return;
                }
                def.exports[n] = NameStr::from_bytes(tok);
                def.exports_len = (n + 1) as u8;
            }
        }
        _ => {}
    }
}

fn apply_memory_kv(def: &mut ServiceDef, key: &[u8], value: &[u8]) {
    match key {
        b"StackReserveKiB" => {
            def.stack_reserve_kib = normalize_stack_kib_u32(
                parse_u64(value),
                MIN_STACK_RESERVE_KIB,
                MAX_STACK_RESERVE_KIB,
            );
        }
        b"StackPrefaultKiB" => {
            def.stack_prefault_kib = normalize_stack_kib_u16(
                parse_u64(value),
                MIN_STACK_PREFAULT_KIB,
                MAX_STACK_PREFAULT_KIB,
            );
        }
        b"StackGuardKiB" => {
            def.stack_guard_kib =
                normalize_stack_kib_u16(parse_u64(value), MIN_STACK_GUARD_KIB, MAX_STACK_GUARD_KIB);
        }
        _ => {}
    }
}

fn normalize_stack_kib_u32(value: u64, min_kib: u32, max_kib: u32) -> u32 {
    if value == 0 {
        return 0;
    }
    let mut v = value.min(max_kib as u64).max(min_kib as u64) as u32;
    v -= v % STACK_PAGE_KIB;
    if v == 0 { min_kib } else { v }
}

fn normalize_stack_kib_u16(value: u64, min_kib: u16, max_kib: u16) -> u16 {
    if value == 0 {
        return 0;
    }
    let page_kib = STACK_PAGE_KIB as u16;
    let mut v = value.min(max_kib as u64).max(min_kib as u64) as u16;
    v -= v % page_kib;
    if v == 0 { min_kib } else { v }
}

fn apply_cap_kv(def: &mut CapDef, key: &[u8], value: &[u8]) {
    match key {
        b"SourceSlot" => def.source_slot = parse_u64(value),
        _ => {}
    }
}

fn apply_unit_kv_for_cap(def: &mut CapDef, key: &[u8], value: &[u8]) {
    if key == b"Name" {
        def.name = NameStr::from_bytes(value);
    }
}

fn apply_socket_kv(def: &mut SocketDef, key: &[u8], value: &[u8]) {
    match key {
        b"Provider" => def.provider = NameStr::from_bytes(value),
        b"Alias" => def.alias = NameStr::from_bytes(value),
        _ => {}
    }
}

fn apply_unit_kv_for_socket(def: &mut SocketDef, key: &[u8], value: &[u8]) {
    if key == b"Name" {
        def.name = NameStr::from_bytes(value);
    }
}

fn apply_target_service_kv(def: &mut TargetDef, key: &[u8], value: &[u8]) {
    match key {
        b"Name" => def.name = NameStr::from_bytes(value),
        b"Activation" => {
            def.activation = match value {
                b"event" => TargetActivation::Event,
                _ => TargetActivation::Passive,
            };
        }
        _ => {}
    }
}

fn apply_target_dep_kv(def: &mut TargetDef, key: &[u8], value: &[u8]) {
    let before = match key {
        b"After" => false,
        b"Before" => true,
        _ => return,
    };
    for tgt in value.split(|c| *c == b' ') {
        let tgt = trim(tgt);
        if tgt.is_empty() {
            continue;
        }
        let n = def.deps_len as usize;
        if n >= MAX_DEPENDENCIES_PER_SERVICE {
            return;
        }
        def.deps[n] = DependencyEntry {
            target: NameStr::from_bytes(tgt),
            before,
        };
        def.deps_len = (n + 1) as u8;
    }
}

fn parse_role(value: &[u8]) -> Option<u32> {
    let parsed = match value {
        b"ROLE_MMSRV_CLIENT" => trona_runtime::spawn::role_consts::ROLE_MMSRV_CLIENT,
        b"ROLE_MMSRV_AUTHORITY_RAW" => trona_runtime::spawn::role_consts::ROLE_MMSRV_AUTHORITY_RAW,
        b"ROLE_VFS_CLIENT" => trona_runtime::spawn::role_consts::ROLE_VFS_CLIENT,
        b"ROLE_LDSRV_CLIENT" => trona_runtime::spawn::role_consts::ROLE_LDSRV_CLIENT,
        _ => {
            if let Some(stripped) = strip_prefix(value, b"0x") {
                if stripped.is_empty() {
                    return None;
                }
                let mut out: u32 = 0;
                for &b in stripped {
                    let d = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => b - b'a' + 10,
                        b'A'..=b'F' => b - b'A' + 10,
                        _ => return None,
                    };
                    out = out.checked_mul(16)?.checked_add(d as u32)?;
                }
                out
            } else {
                if value.is_empty() {
                    return None;
                }
                let mut out: u32 = 0;
                for &b in value {
                    if !b.is_ascii_digit() {
                        return None;
                    }
                    out = out.checked_mul(10)?.checked_add((b - b'0') as u32)?;
                }
                out
            }
        }
    };
    if parsed == 0 { None } else { Some(parsed) }
}

fn parse_u64(value: &[u8]) -> u64 {
    if let Some(stripped) = strip_prefix(value, b"0x") {
        let mut out: u64 = 0;
        for &b in stripped {
            let d = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                b'A'..=b'F' => b - b'A' + 10,
                _ => return out,
            };
            out = out.wrapping_shl(4) | d as u64;
        }
        return out;
    }
    let mut out: u64 = 0;
    for &b in value {
        if !b.is_ascii_digit() {
            break;
        }
        out = out.wrapping_mul(10).wrapping_add((b - b'0') as u64);
    }
    out
}

/// Classify a single `Requires=` token into its `UnitRef` form.
fn parse_unit_ref(tok: &[u8]) -> UnitRef {
    if let Some(colon) = tok.iter().position(|c| *c == b':') {
        let provider = trim(&tok[..colon]);
        let alias = trim(&tok[colon + 1..]);
        if !provider.is_empty() && !alias.is_empty() {
            return UnitRef::LocalAlias {
                provider: NameStr::from_bytes(provider),
                alias: NameStr::from_bytes(alias),
            };
        }
    }
    if has_suffix(tok, b".cap") {
        return UnitRef::Cap(NameStr::from_bytes(tok));
    }
    if has_suffix(tok, b".socket") {
        return UnitRef::Socket(NameStr::from_bytes(tok));
    }
    if has_suffix(tok, b".target") {
        return UnitRef::Target(NameStr::from_bytes(tok));
    }
    if has_suffix(tok, b".service") {
        return UnitRef::Service(NameStr::from_bytes(tok));
    }
    UnitRef::Service(NameStr::from_bytes(tok))
}

fn has_suffix(s: &[u8], suffix: &[u8]) -> bool {
    s.len() >= suffix.len() && &s[s.len() - suffix.len()..] == suffix
}

fn split_arch_suffix(key: &[u8]) -> Option<(&[u8], &[u8])> {
    let dot = key.iter().position(|c| *c == b'.')?;
    Some((&key[..dot], &key[dot + 1..]))
}

fn arch_matches(arch: &[u8]) -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        return arch == b"x86_64";
    }
    #[cfg(target_arch = "aarch64")]
    {
        return arch == b"aarch64";
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = arch;
        return false;
    }
}
