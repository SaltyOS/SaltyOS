//! Service Manager - dependency graph, state machine, boot orchestration
//! SPDX-License-Identifier: GPL-2.0-only

use crate::ini::{ServiceDef, RestartPolicy};
use besalt::serial;
use besalt::serial::LineBuf;

pub const MAX_SERVICES: usize = 16;
const MAX_RESTARTS: u16 = 5;

fn puts(s: &[u8]) {
    serial::serial_puts(s);
}


fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy, PartialEq)]
pub enum ServiceState {
    Stopped,
    Starting,
    Running,
    Failed,
    #[allow(dead_code)]
    Stopping,
}

#[derive(Clone, Copy)]
pub struct ServiceInstance {
    pub def: ServiceDef,
    pub state: ServiceState,
    pub cap_base: u64,
    pub pre_ep: u64,
    pub pid: u32,
    pub restart_count: u16,
    pub exit_code: i32,
    pub active: bool,
}

impl ServiceInstance {
    pub const fn zeroed() -> Self {
        ServiceInstance {
            def: ServiceDef::zeroed(),
            state: ServiceState::Stopped,
            cap_base: 0,
            pre_ep: 0,
            pid: 0,
            restart_count: 0,
            exit_code: 0,
            active: false,
        }
    }
}

pub struct ServiceManager {
    pub services: [ServiceInstance; MAX_SERVICES],
    pub count: usize,
    // Dependency adjacency matrix: adj[i] has bit j set => service i depends on j (i.e., i After j)
    adj: [u16; MAX_SERVICES],
    pub boot_order: [u8; MAX_SERVICES],
    pub boot_order_len: usize,
}

impl ServiceManager {
    pub const fn new() -> Self {
        ServiceManager {
            services: {
                const ZERO: ServiceInstance = ServiceInstance::zeroed();
                [ZERO; MAX_SERVICES]
            },
            count: 0,
            adj: [0; MAX_SERVICES],
            boot_order: [0; MAX_SERVICES],
            boot_order_len: 0,
        }
    }

    /// Register a parsed service definition. Returns index or -1 on error.
    pub fn add_service(&mut self, def: &ServiceDef) -> i32 {
        if self.count >= MAX_SERVICES {
            puts(b"[INIT] svc_mgr: too many services\n");
            return -1;
        }
        let idx = self.count;
        self.services[idx].def = *def;
        self.services[idx].state = ServiceState::Stopped;
        self.services[idx].active = true;
        self.count += 1;
        idx as i32
    }

    /// Find service index by name. Returns -1 if not found.
    #[allow(dead_code)]
    pub fn find_service(&self, name: &[u8]) -> i32 {
        for i in 0..self.count {
            if self.services[i].active && bytes_eq(self.services[i].def.name_bytes(), name) {
                return i as i32;
            }
        }
        -1
    }

    /// Build the dependency adjacency matrix from After/Before fields.
    pub fn build_deps(&mut self) {
        // Clear
        for i in 0..MAX_SERVICES {
            self.adj[i] = 0;
        }

        for i in 0..self.count {
            // Process After dependencies: service i should start after these
            for a in 0..self.services[i].def.after_count as usize {
                let dep_name = self.services[i].def.after_name(a);
                let dep_idx = self.find_dep_name(dep_name);
                if dep_idx >= 0 {
                    // i depends on dep_idx
                    self.adj[i] |= 1u16 << dep_idx;
                }
            }

            // Process Before dependencies: these services depend on i
            for b in 0..self.services[i].def.before_count as usize {
                let dep_name = self.services[i].def.before_name(b);
                let dep_idx = self.find_dep_name(dep_name);
                if dep_idx >= 0 {
                    // dep_idx depends on i
                    self.adj[dep_idx as usize] |= 1u16 << i;
                }
            }
        }
    }

    fn find_dep_name(&self, name: &[u8]) -> i32 {
        if name.is_empty() {
            return -1;
        }
        for j in 0..self.count {
            if bytes_eq(self.services[j].def.name_bytes(), name) {
                return j as i32;
            }
        }
        -1
    }

    /// Topological sort using Kahn's algorithm.
    /// Returns true if successful (no cycles). Result in boot_order/boot_order_len.
    pub fn topological_sort(&mut self) -> bool {
        let n = self.count;
        self.boot_order_len = 0;

        // Compute in-degree for each node
        let mut in_degree = [0u8; MAX_SERVICES];
        // Work copy of adjacency
        let mut adj_work = [0u16; MAX_SERVICES];
        for i in 0..n {
            adj_work[i] = self.adj[i];
        }
        for i in 0..n {
            for j in 0..n {
                if adj_work[i] & (1u16 << j) != 0 {
                    in_degree[i] += 1;
                }
            }
        }

        // Queue (BFS) — use a simple array
        let mut queue = [0u8; MAX_SERVICES];
        let mut q_head: usize = 0;
        let mut q_tail: usize = 0;

        // Enqueue all nodes with in_degree 0
        for i in 0..n {
            if in_degree[i] == 0 {
                queue[q_tail] = i as u8;
                q_tail += 1;
            }
        }

        while q_head < q_tail {
            let node = queue[q_head] as usize;
            q_head += 1;
            self.boot_order[self.boot_order_len] = node as u8;
            self.boot_order_len += 1;

            // For all nodes that depend on `node`, decrement in_degree
            for i in 0..n {
                if adj_work[i] & (1u16 << node) != 0 {
                    adj_work[i] &= !(1u16 << node);
                    in_degree[i] -= 1;
                    if in_degree[i] == 0 {
                        queue[q_tail] = i as u8;
                        q_tail += 1;
                    }
                }
            }
        }

        if self.boot_order_len != n {
            // Cycle detected — mark unprocessed services as Failed
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] svc_mgr: cycle detected! Only "); lb.hex(self.boot_order_len as u64); lb.str(b" of "); lb.hex(n as u64); lb.str(b" services sorted\n"); lb.flush(); }

            for i in 0..n {
                let mut in_order = false;
                for j in 0..self.boot_order_len {
                    if self.boot_order[j] as usize == i {
                        in_order = true;
                        break;
                    }
                }
                if !in_order {
                    self.services[i].state = ServiceState::Failed;
                    { let mut lb = LineBuf::new(); lb.str(b"[INIT] svc="); lb.bytes(self.services[i].def.name_bytes()); lb.str(b" state=Failed (cycle)\n"); lb.flush(); }
                }
            }
            return false;
        }

        true
    }

    /// Get the list of services in reverse boot order (for shutdown).
    #[allow(dead_code)]
    pub fn shutdown_order(&self) -> [u8; MAX_SERVICES] {
        let mut rev = [0u8; MAX_SERVICES];
        for i in 0..self.boot_order_len {
            rev[i] = self.boot_order[self.boot_order_len - 1 - i];
        }
        rev
    }

    /// Set service state and log the transition.
    pub fn set_state(&mut self, idx: usize, state: ServiceState) {
        if idx >= self.count {
            return;
        }
        self.services[idx].state = state;
        {
            let mut lb = LineBuf::new();
            lb.str(b"[INIT] svc=");
            lb.bytes(self.services[idx].def.name_bytes());
            lb.str(b" state=");
            match state {
                ServiceState::Stopped => lb.str(b"Stopped"),
                ServiceState::Starting => lb.str(b"Starting"),
                ServiceState::Running => lb.str(b"Running"),
                ServiceState::Failed => lb.str(b"Failed"),
                ServiceState::Stopping => lb.str(b"Stopping"),
            }
            lb.str(b"\n");
            lb.flush();
        }
    }

    /// Check if all dependencies for service at `idx` are Running.
    pub fn deps_satisfied(&self, idx: usize) -> bool {
        if idx >= self.count {
            return false;
        }
        let deps = self.adj[idx];
        for j in 0..self.count {
            if deps & (1u16 << j) != 0 {
                if self.services[j].state != ServiceState::Running {
                    return false;
                }
            }
        }
        true
    }

    /// Check if a service should be restarted based on its policy and exit code.
    pub fn should_restart(&self, idx: usize) -> bool {
        if idx >= self.count {
            return false;
        }
        let svc = &self.services[idx];
        if svc.restart_count >= MAX_RESTARTS {
            return false;
        }
        match svc.def.restart {
            RestartPolicy::No => false,
            RestartPolicy::Always => true,
            RestartPolicy::OnFailure => svc.exit_code != 0,
        }
    }

    /// Record a service exit. Updates state and restart count.
    pub fn record_exit(&mut self, idx: usize, exit_code: i32) {
        if idx >= self.count {
            return;
        }
        self.services[idx].exit_code = exit_code;
        { let mut lb = LineBuf::new(); lb.str(b"[INIT] svc="); lb.bytes(self.services[idx].def.name_bytes()); lb.str(b" exited code="); lb.hex(exit_code as u64); lb.str(b"\n"); lb.flush(); }

        if self.should_restart(idx) {
            self.services[idx].restart_count += 1;
            self.services[idx].state = ServiceState::Stopped;
            { let mut lb = LineBuf::new(); lb.str(b"[INIT] svc="); lb.bytes(self.services[idx].def.name_bytes()); lb.str(b" will restart (attempt "); lb.hex(self.services[idx].restart_count as u64); lb.str(b")\n"); lb.flush(); }
        } else {
            self.services[idx].state = ServiceState::Failed;
        }
    }

    /// Log the boot order
    pub fn log_boot_order(&self) {
        let mut lb = LineBuf::new();
        lb.str(b"[INIT] Boot order: ");
        for i in 0..self.boot_order_len {
            if i > 0 {
                lb.str(b" -> ");
            }
            let idx = self.boot_order[i] as usize;
            lb.bytes(self.services[idx].def.name_bytes());
        }
        lb.str(b"\n");
        lb.flush();
    }
}
