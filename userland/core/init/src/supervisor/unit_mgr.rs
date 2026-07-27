// SPDX-License-Identifier: GPL-2.0-only
//
//! systemd-style dependency / readiness graph driver.
//!
//! `UnitGraph` is built once from `ServiceManifest` after `validate`
//! and `topo_sort` succeed. Each node corresponds to one service or
//! one target. Edges encode every kind of dependency the manifest
//! supports:
//!
//! * `[Dependencies] After=` and `Before=` → ordering edges (After
//!   pulls in target node, Before flips into the consumer's After).
//! * `[Dependencies] Requires=foo.service` → service-name edge.
//! * `[Dependencies] Requires=foo.socket` → producer-service edge
//!   (the socket's `Provider=` field).
//! * `[Dependencies] Requires=foo.target` → target node edge.
//! * `[Dependencies] Requires=foo.cap` → cap edge (always satisfied;
//!   init's `policy_cap_table` already holds the slot at boot time).
//! * `[Dependencies] Requires=provider:alias` → producer-service edge
//!   (LocalAlias resolves through the provider's `Exports=`).
//! * `[Dependencies] RequiresInterface=provider:iface` → producer-
//!   service edge.
//!
//! Each service node carries one readiness flag, `registered` — set
//! when namesrv reports a successful `NAMESRV_REGISTER` for the
//! service's own name. `[Capabilities] ProvidesInterface=` is
//! provider-local metadata, not a namesrv prefix. This mirrors
//! systemd's "name on the bus" model: a service is ready once it has
//! published its master service-EP. `Type=notify` does not introduce a
//! *separate* readiness signal — the publication itself is the signal.
//!
//! A service node is ready when (a) every node it depends on is
//! ready and (b) `registered[node_idx]` is true. A target node is
//! ready once every node it depends on is ready. `dispatch_ready`
//! returns the list of services that have not yet been spawned but
//! whose dependencies are all ready — the supervisor walks that
//! list and invokes `lifecycle::handle_spawn` for each.
//!
//! No locking — the supervisor calls `unit_mgr` from its owner thread.

use crate::supervisor::manifest::{
    MAX_SERVICES, MAX_TARGETS, ServiceDef, ServiceManifest, ServiceType, TargetDef, UnitRef,
};

pub const MAX_NODES: usize = MAX_SERVICES + MAX_TARGETS;
pub const MAX_NODE_DEPS: usize = 24;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NodeKind {
    /// Index into `ServiceManifest::services`.
    Service,
    /// Index into `ServiceManifest::targets`.
    Target,
}

#[derive(Clone, Copy)]
pub struct UnitNode {
    pub kind: NodeKind,
    /// Index inside the corresponding manifest array
    /// (`services[]` or `targets[]`).
    pub manifest_idx: u8,
    /// Other node indices this one depends on (graph-internal).
    pub deps: [u8; MAX_NODE_DEPS],
    pub deps_len: u8,
}

impl UnitNode {
    pub const fn empty() -> Self {
        Self {
            kind: NodeKind::Service,
            manifest_idx: 0,
            deps: [0; MAX_NODE_DEPS],
            deps_len: 0,
        }
    }
}

pub struct UnitGraph {
    pub nodes: [UnitNode; MAX_NODES],
    pub nodes_count: usize,
    /// Single readiness flag, set by whichever hook matches this
    /// service's `ServiceType`:
    /// - Broker/Server → `on_namesrv_register` (`NAMESRV_REGISTER` seen)
    /// - Notify        → `on_init_notify_ready` (`INIT_NOTIFY_READY` IPC)
    /// - Oneshot       → `on_oneshot_exit` (lifecycle exit handler, status=0)
    /// - Simple        → set automatically when dispatched
    /// Stage A..F core readiness goes through `mark_core_ready`.
    pub registered: [bool; MAX_NODES],
    /// Whether the supervisor has invoked `lifecycle::handle_spawn`
    /// for this node yet.
    pub dispatched: [bool; MAX_NODES],
    /// Map from `services[idx]` to graph node idx (or `u8::MAX` if
    /// the service does not appear in the graph).
    service_to_node: [u8; MAX_SERVICES],
    /// Map from `targets[idx]` to graph node idx.
    target_to_node: [u8; MAX_TARGETS],
}

impl UnitGraph {
    pub const fn new() -> Self {
        Self {
            nodes: [UnitNode::empty(); MAX_NODES],
            nodes_count: 0,
            registered: [false; MAX_NODES],
            dispatched: [false; MAX_NODES],
            service_to_node: [u8::MAX; MAX_SERVICES],
            target_to_node: [u8::MAX; MAX_TARGETS],
        }
    }

    /// Build the graph from a parsed + validated manifest. Caller is
    /// responsible for having run `Manifest::validate` first.
    pub fn build(&mut self, m: &ServiceManifest) -> Result<(), GraphErr> {
        self.nodes_count = 0;
        self.service_to_node = [u8::MAX; MAX_SERVICES];
        self.target_to_node = [u8::MAX; MAX_TARGETS];

        // First pass — allocate one node per service and per target.
        for i in 0..m.count {
            let n = self.nodes_count;
            if n >= MAX_NODES {
                return Err(GraphErr::TooManyNodes);
            }
            self.nodes[n] = UnitNode {
                kind: NodeKind::Service,
                manifest_idx: i as u8,
                deps: [0; MAX_NODE_DEPS],
                deps_len: 0,
            };
            self.service_to_node[i] = n as u8;
            self.nodes_count += 1;
        }
        for i in 0..m.targets_count {
            let n = self.nodes_count;
            if n >= MAX_NODES {
                return Err(GraphErr::TooManyNodes);
            }
            self.nodes[n] = UnitNode {
                kind: NodeKind::Target,
                manifest_idx: i as u8,
                deps: [0; MAX_NODE_DEPS],
                deps_len: 0,
            };
            self.target_to_node[i] = n as u8;
            self.nodes_count += 1;
        }

        // Second pass — translate every manifest dependency edge into
        // a graph edge between two `nodes[]` entries.
        for i in 0..m.count {
            let svc = &m.services[i];
            let consumer = self.service_to_node[i] as usize;
            self.add_service_deps(m, svc, consumer)?;
        }
        for i in 0..m.targets_count {
            let tgt = &m.targets[i];
            let consumer = self.target_to_node[i] as usize;
            self.add_target_deps(m, tgt, consumer)?;
        }

        Ok(())
    }

    fn add_service_deps(
        &mut self,
        m: &ServiceManifest,
        svc: &ServiceDef,
        consumer: usize,
    ) -> Result<(), GraphErr> {
        // After= / Before= ordering edges. Before=X on this service
        // becomes After=this on service X — the consumer flips.
        for d in 0..svc.deps_len as usize {
            let dep = svc.deps[d];
            let target_idx = match m.find_index_by_name(dep.target.as_bytes()) {
                Some(i) => i,
                None => continue,
            };
            let target_node = self.service_to_node[target_idx] as usize;
            if dep.before {
                self.add_edge(target_node, consumer)?;
            } else {
                self.add_edge(consumer, target_node)?;
            }
        }
        // Requires= unit reference edges.
        for u in 0..svc.unit_requires_len as usize {
            match svc.unit_requires[u] {
                UnitRef::None => {}
                UnitRef::Cap(_) => {
                    // .cap units are always satisfied — init holds
                    // the SourceSlot before any service spawns.
                }
                UnitRef::Socket(name) => {
                    let sock = match m.find_socket_by_name(name.as_bytes()) {
                        Some(s) => s,
                        None => return Err(GraphErr::DanglingRef),
                    };
                    let provider_idx = match m.find_index_by_name(sock.provider.as_bytes()) {
                        Some(i) => i,
                        None => return Err(GraphErr::DanglingRef),
                    };
                    let provider_node = self.service_to_node[provider_idx] as usize;
                    self.add_edge(consumer, provider_node)?;
                }
                UnitRef::Target(name) => {
                    let tgt_idx = match m.targets[..m.targets_count]
                        .iter()
                        .position(|t| t.name.as_bytes() == name.as_bytes())
                    {
                        Some(i) => i,
                        None => return Err(GraphErr::DanglingRef),
                    };
                    let tgt_node = self.target_to_node[tgt_idx] as usize;
                    self.add_edge(consumer, tgt_node)?;
                }
                UnitRef::Service(name) => {
                    let svc_idx = match m.find_index_by_name(name.as_bytes()) {
                        Some(i) => i,
                        None => return Err(GraphErr::DanglingRef),
                    };
                    let svc_node = self.service_to_node[svc_idx] as usize;
                    self.add_edge(consumer, svc_node)?;
                }
                UnitRef::LocalAlias { provider, .. } => {
                    let provider_idx = match m.find_index_by_name(provider.as_bytes()) {
                        Some(i) => i,
                        None => return Err(GraphErr::DanglingRef),
                    };
                    let provider_node = self.service_to_node[provider_idx] as usize;
                    self.add_edge(consumer, provider_node)?;
                }
            }
        }
        // RequiresInterface=provider:iface edges resolve to the
        // provider service node.
        for r in 0..svc.requires_len as usize {
            let key = svc.requires[r].iface.as_bytes();
            let Some(colon) = key.iter().position(|c| *c == b':') else {
                continue;
            };
            let provider = &key[..colon];
            let provider_idx = match m.find_index_by_name(provider) {
                Some(i) => i,
                None if svc.requires[r].optional => continue,
                None => return Err(GraphErr::DanglingRef),
            };
            let provider_node = self.service_to_node[provider_idx] as usize;
            self.add_edge(consumer, provider_node)?;
        }
        Ok(())
    }

    fn add_target_deps(
        &mut self,
        m: &ServiceManifest,
        tgt: &TargetDef,
        consumer: usize,
    ) -> Result<(), GraphErr> {
        for d in 0..tgt.deps_len as usize {
            let dep = tgt.deps[d];
            // Targets only carry ordering (`After=`/`Before=`).
            // Resolve names against either services or other targets.
            let target_node = if let Some(svc_idx) = m.find_index_by_name(dep.target.as_bytes()) {
                self.service_to_node[svc_idx] as usize
            } else if let Some(tgt_idx) = m.targets[..m.targets_count]
                .iter()
                .position(|t| t.name.as_bytes() == dep.target.as_bytes())
            {
                self.target_to_node[tgt_idx] as usize
            } else {
                continue;
            };
            if dep.before {
                self.add_edge(target_node, consumer)?;
            } else {
                self.add_edge(consumer, target_node)?;
            }
        }
        Ok(())
    }

    fn add_edge(&mut self, consumer: usize, producer: usize) -> Result<(), GraphErr> {
        if consumer == producer {
            return Ok(());
        }
        let node = &mut self.nodes[consumer];
        // Idempotent — a service that lists the same producer through
        // both `After=` and `Requires=` should only get one edge.
        for i in 0..node.deps_len as usize {
            if node.deps[i] as usize == producer {
                return Ok(());
            }
        }
        let n = node.deps_len as usize;
        if n >= MAX_NODE_DEPS {
            return Err(GraphErr::TooManyDeps);
        }
        node.deps[n] = producer as u8;
        node.deps_len = (n + 1) as u8;
        Ok(())
    }

    /// True when every dependency of `node_idx` has settled (and, for
    /// service nodes, the node itself has been registered with
    /// namesrv). Bounded recursion: depth limit equals graph node
    /// count, so a cycle that slipped past `Manifest::detect_cycle_hard`
    /// returns `false` instead of overflowing the stack.
    fn is_node_ready_bounded(&self, m: &ServiceManifest, node_idx: usize, depth: usize) -> bool {
        if depth >= MAX_NODES {
            return false;
        }
        let node = &self.nodes[node_idx];
        for i in 0..node.deps_len as usize {
            let dep_idx = node.deps[i] as usize;
            if !self.is_node_ready_bounded(m, dep_idx, depth + 1) {
                return false;
            }
        }
        match node.kind {
            NodeKind::Service => self.registered[node_idx],
            NodeKind::Target => {
                let _ = m;
                true
            }
        }
    }

    /// True when every dependency of `node_idx` has settled. This is
    /// the gate for `dispatch_ready` — the consumer service itself
    /// has not started yet, so its own readiness flags do not apply.
    fn deps_satisfied(&self, m: &ServiceManifest, node_idx: usize) -> bool {
        let node = &self.nodes[node_idx];
        for i in 0..node.deps_len as usize {
            let dep_idx = node.deps[i] as usize;
            if !self.is_node_ready_bounded(m, dep_idx, 1) {
                return false;
            }
        }
        true
    }

    /// Walk every service node whose dependencies are satisfied and
    /// which has not yet been dispatched. Returns the manifest indices
    /// of those services (newest first; the supervisor spawns them in
    /// order). Sets `dispatched[node]` to true for each returned
    /// service so the next call only yields freshly-unblocked ones.
    pub fn dispatch_ready(&mut self, m: &ServiceManifest, out: &mut [u8; MAX_SERVICES]) -> usize {
        let mut len = 0usize;
        for node_idx in 0..self.nodes_count {
            if self.dispatched[node_idx] {
                continue;
            }
            if self.nodes[node_idx].kind != NodeKind::Service {
                continue;
            }
            if !self.deps_satisfied(m, node_idx) {
                continue;
            }
            // Skip the four boot-stage cores — Stage A..F already
            // brought them up before unit_mgr starts dispatching.
            let svc = &m.services[self.nodes[node_idx].manifest_idx as usize];
            let name = svc.name.as_bytes();
            if name == b"init" || name == b"namesrv" || name == b"rsrcsrv" || name == b"mmsrv" {
                self.dispatched[node_idx] = true;
                self.registered[node_idx] = true;
                continue;
            }
            if len >= out.len() {
                break;
            }
            out[len] = self.nodes[node_idx].manifest_idx;
            len += 1;
            self.dispatched[node_idx] = true;
        }
        len
    }

    /// `Type=broker` readiness hook — child published its master
    /// service-EP via `NAMESRV_REGISTER`. Namesrv registration is keyed
    /// by service name; `[Capabilities] ProvidesInterface=` remains a
    /// provider-local interface declaration for dependency validation.
    pub fn on_namesrv_register(&mut self, m: &ServiceManifest, prefix: &[u8]) {
        for i in 0..m.count {
            let svc = &m.services[i];
            if svc.name.as_bytes() == prefix {
                let node = self.service_to_node[i];
                if node != u8::MAX {
                    self.registered[node as usize] = true;
                }
                return;
            }
        }
    }

    /// `Type=notify` readiness hook — leaf service invoked
    /// `INIT_NOTIFY_READY` on its init control endpoint. Looks up the
    /// service by manifest index (carried in `regs[0]` of the IPC).
    pub fn on_init_notify_ready(&mut self, m: &ServiceManifest, manifest_idx: usize) {
        self.mark_manifest_idx_ready(m, manifest_idx);
    }

    pub fn on_immediate_ready(&mut self, m: &ServiceManifest, manifest_idx: usize) {
        self.mark_manifest_idx_ready(m, manifest_idx);
    }

    fn mark_manifest_idx_ready(&mut self, m: &ServiceManifest, manifest_idx: usize) {
        if manifest_idx >= m.count {
            return;
        }
        let node = self.service_to_node[manifest_idx];
        if node != u8::MAX {
            self.registered[node as usize] = true;
        }
    }

    /// `Type=oneshot` readiness hook — supervisor lifecycle code calls
    /// this when a oneshot child exits with status 0. Failure exits
    /// must NOT call this (the unit stays not-ready, dependents block).
    pub fn on_oneshot_exit(&mut self, m: &ServiceManifest, name: &[u8]) -> bool {
        if let Some(i) = m.find_index_by_name(name) {
            if m.services[i].service_type != ServiceType::Oneshot {
                return false;
            }
            let node = self.service_to_node[i];
            if node != u8::MAX {
                let node_idx = node as usize;
                let was_ready = self.registered[node_idx];
                self.registered[node_idx] = true;
                return !was_ready;
            }
        }
        false
    }

    /// Stage F bookkeeping — the supervisor calls this after the
    /// boot-stage cores (namesrv/rsrcsrv/mmsrv) reach their ready
    /// handshake, so subsequent `dispatch_ready` calls don't refuse
    /// to advance because of un-set readiness flags on those nodes.
    pub fn mark_core_ready(&mut self, m: &ServiceManifest, name: &[u8]) {
        if let Some(i) = m.find_index_by_name(name) {
            let node = self.service_to_node[i];
            if node != u8::MAX {
                self.registered[node as usize] = true;
                self.dispatched[node as usize] = true;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphErr {
    TooManyNodes,
    TooManyDeps,
    DanglingRef,
}
