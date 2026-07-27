// SPDX-License-Identifier: GPL-2.0-only
//! MIB tree — hierarchical sysctl namespace.
//!
//! The tree supports arbitrary depth: `SysctlNode` (interior, VT_DIR) and
//! `SysctlLeaf` (terminal, VT_REG). A unified `entries` array holds both,
//! plus `DynamicDir` entries whose children are generated at runtime.
//!
//! The static root contains FreeBSD-standard top-level namespaces:
//! kern, hw, net, vm, vfs, security.

// =========================================================================
// Leaf type / flag constants
// =========================================================================

pub(crate) const CTLTYPE_NODE: u8 = 0;
pub(crate) const CTLTYPE_INT: u8 = 1;
pub(crate) const CTLTYPE_STRING: u8 = 2;
pub(crate) const CTLTYPE_STRUCT: u8 = 3;
/// CTLTYPE_OPAQUE is an alias for CTLTYPE_STRUCT. Used for raw struct byte
/// dumps (KinfoProc, timeval, clockinfo, etc.) where the caller interprets
/// the bytes directly rather than expecting a text representation.
pub(crate) const CTLTYPE_OPAQUE: u8 = CTLTYPE_STRUCT;
pub(crate) const CTLTYPE_U64: u8 = 4;

pub(crate) const CTLFLAG_RD: u8 = 0x01;
pub(crate) const CTLFLAG_WR: u8 = 0x02;
pub(crate) const CTLFLAG_RW: u8 = CTLFLAG_RD | CTLFLAG_WR;

// =========================================================================
// Read / write callback signatures
// =========================================================================

/// Per-call context handed to init-backed sysctl read / lookup providers
/// so they can park the owner reactor on init instead of blocking it on a
/// synchronous `mp_call` (which would deadlock against init reading back
/// into vfs). Built from the VOP's data context at the read call site.
pub(crate) struct SysctlCtx<'a> {
    pub(crate) state: &'a mut crate::owner::VfsState,
    pub(crate) caller_badge: u64,
    /// Read window forwarded into the parked snapshot so its finalize
    /// emits the requested slice.
    pub(crate) offset: u64,
    pub(crate) len: u64,
}

/// Result of a sysctl read / lookup provider call.
pub(crate) enum SysctlOutcome {
    /// Content was written synchronously into the caller's buffer
    /// (`n` bytes) — static / cached values that need no init data.
    Ready(usize),
    /// The read parked on init; the VOP returns `Parked(handle)` and the
    /// reply is emitted from the snapshot at finalize.
    Parked(crate::owner::pending::PendingOpHandle),
    /// (lookup) No such child, or an unparseable child name.
    Missing,
}

/// Read callback: produce the current value. Sync providers write into
/// `buf` and return `Ready(n)`; init-backed providers park via `ctx` and
/// return `Parked`.
pub(crate) type SysctlRead =
    unsafe fn(ctx: &mut SysctlCtx, buf: *mut u8, buf_len: usize) -> SysctlOutcome;

/// Write callback: accept `len` bytes from `src`, return 0 on success.
pub(crate) type SysctlWrite = unsafe fn(src: *const u8, len: usize) -> i32;

// =========================================================================
// DynamicDir — runtime-generated directory
// =========================================================================

/// A directory whose children are generated at runtime.
///
/// `lookup` resolves a named child's content; it parks on init for the
/// `kern.proc.*` dirs (see [`SysctlOutcome`]). Enumeration (readdir) is
/// not a callback: `enumerates_pids` tells the VFS readdir VOP whether to
/// park on init and list the live pid set, so listing — like lookup —
/// never blocks the reactor on init.
///
/// `lookup` is `unsafe` because it is always called from an unsafe context
/// by the VFS layer.
#[repr(C)]
pub(crate) struct DynamicDir {
    pub(crate) name: [u8; NODE_NAME_MAX],
    pub(crate) name_len: u8,
    /// True if this dir's children are the live pid set (`kern.proc.pid` /
    /// `.args` / `.pathname`): readdir parks on init and enumerates them.
    /// False for the filter dirs (`pgrp` / `tty` / `uid` / `ruid` /
    /// `session`), which are not enumerated (FreeBSD `list`-empty
    /// convention) and are reached only by `lookup(<value>)`.
    pub(crate) enumerates_pids: bool,
    _pad: [u8; 6],
    pub(crate) lookup: unsafe fn(
        ctx: &mut SysctlCtx,
        name: *const u8,
        name_len: usize,
        buf: *mut u8,
        buf_cap: usize,
    ) -> SysctlOutcome,
}

impl DynamicDir {
    /// Construct a `DynamicDir` with the given name and callbacks.
    ///
    /// # Safety
    ///
    /// The returned value must be stored in a `static` that outlives the MIB
    /// tree. `lookup` is called from an unsafe context.
    pub(crate) const fn new(
        name: &[u8],
        enumerates_pids: bool,
        lookup: unsafe fn(&mut SysctlCtx, *const u8, usize, *mut u8, usize) -> SysctlOutcome,
    ) -> Self {
        let mut n = [0u8; NODE_NAME_MAX];
        let len = if name.len() < NODE_NAME_MAX {
            name.len()
        } else {
            NODE_NAME_MAX
        };
        let mut i = 0;
        while i < len {
            n[i] = name[i];
            i += 1;
        }
        DynamicDir {
            name: n,
            name_len: len as u8,
            enumerates_pids,
            _pad: [0; 6],
            lookup,
        }
    }
}

// =========================================================================
// SysctlLeaf — terminal MIB entry
// =========================================================================

/// Maximum leaf name length (bytes).
pub(super) const LEAF_NAME_MAX: usize = 32;

#[repr(C)]
pub(crate) struct SysctlLeaf {
    pub(crate) name: [u8; LEAF_NAME_MAX],
    pub(crate) name_len: u8,
    pub(crate) ctl_type: u8,
    pub(crate) flags: u8,
    _pad: u8,
    pub(crate) read_fn: Option<SysctlRead>,
    pub(crate) write_fn: Option<SysctlWrite>,
}

impl SysctlLeaf {
    pub(crate) const fn zeroed() -> Self {
        SysctlLeaf {
            name: [0; LEAF_NAME_MAX],
            name_len: 0,
            ctl_type: 0,
            flags: 0,
            _pad: 0,
            read_fn: None,
            write_fn: None,
        }
    }
}

// =========================================================================
// SysctlEntry — unified node entry
// =========================================================================

/// Maximum entries per node (replaces separate child_node and leaf arrays).
pub(super) const MAX_ENTRIES: usize = 24;

/// A single entry within a `SysctlNode`.
pub(crate) enum SysctlEntry {
    /// Unused slot — the node's entries array is zero-initialized.
    Empty,
    /// A terminal MIB leaf (regular file).
    Leaf(SysctlLeaf),
    /// A child interior node (sub-directory). Pointer must be non-null.
    Node(*const SysctlNode),
    /// A runtime-generated sub-directory. Pointer must be non-null.
    Dynamic(*const DynamicDir),
}

impl SysctlEntry {
    pub(crate) const fn empty() -> Self {
        SysctlEntry::Empty
    }
}

// =========================================================================
// SysctlNode — interior MIB entry (directory)
// =========================================================================

/// Maximum node name length (bytes).
pub(super) const NODE_NAME_MAX: usize = 16;

pub(crate) struct SysctlNode {
    pub(crate) name: [u8; NODE_NAME_MAX],
    pub(crate) name_len: u8,
    _pad: [u8; 7],
    pub(crate) entries: [SysctlEntry; MAX_ENTRIES],
    pub(crate) entry_count: usize,
}

// SysctlNode contains raw pointers — safe to share across the single-threaded
// VFS bootstrap and read-only thereafter.
unsafe impl Sync for SysctlNode {}

impl SysctlNode {
    pub(crate) const fn zeroed() -> Self {
        SysctlNode {
            name: [0; NODE_NAME_MAX],
            name_len: 0,
            _pad: [0; 7],
            entries: [const { SysctlEntry::empty() }; MAX_ENTRIES],
            entry_count: 0,
        }
    }

    /// Find a child interior node by name.
    pub(crate) fn find_child_node(&self, name: &[u8]) -> Option<&SysctlNode> {
        for i in 0..self.entry_count {
            if let SysctlEntry::Node(ptr) = &self.entries[i] {
                // SAFETY: pointers are set from static arrays during init.
                let child = unsafe { &**ptr };
                if child.name_len as usize == name.len() && &child.name[..name.len()] == name {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Find a child interior node by name (mutable).
    pub(crate) fn find_child_node_mut(&mut self, name: &[u8]) -> Option<&mut SysctlNode> {
        for i in 0..self.entry_count {
            if let SysctlEntry::Node(ptr) = &self.entries[i] {
                let child_ptr = *ptr as *mut SysctlNode;
                // SAFETY: pointers are set from static mut arrays during init.
                let child = unsafe { &mut *child_ptr };
                if child.name_len as usize == name.len() && &child.name[..name.len()] == name {
                    return Some(child);
                }
            }
        }
        None
    }

    /// Find a leaf by name.
    pub(crate) fn find_leaf(&self, name: &[u8]) -> Option<&SysctlLeaf> {
        for i in 0..self.entry_count {
            if let SysctlEntry::Leaf(leaf) = &self.entries[i] {
                if leaf.name_len as usize == name.len() && &leaf.name[..name.len()] == name {
                    return Some(leaf);
                }
            }
        }
        None
    }

    /// Find a DynamicDir child by name.
    pub(crate) fn find_dynamic(&self, name: &[u8]) -> Option<&DynamicDir> {
        for i in 0..self.entry_count {
            if let SysctlEntry::Dynamic(ptr) = &self.entries[i] {
                // SAFETY: pointers are set from static arrays during init.
                let dyn_dir = unsafe { &**ptr };
                if dyn_dir.name_len as usize == name.len() && &dyn_dir.name[..name.len()] == name {
                    return Some(dyn_dir);
                }
            }
        }
        None
    }

    /// Count entries of each kind. Returns `(node_count, leaf_count, dynamic_count)`.
    pub(crate) fn entry_counts(&self) -> (usize, usize, usize) {
        let mut nodes = 0usize;
        let mut leaves = 0usize;
        let mut dynamics = 0usize;
        for i in 0..self.entry_count {
            match &self.entries[i] {
                SysctlEntry::Node(_) => nodes += 1,
                SysctlEntry::Leaf(_) => leaves += 1,
                SysctlEntry::Dynamic(_) => dynamics += 1,
                SysctlEntry::Empty => {}
            }
        }
        (nodes, leaves, dynamics)
    }

    /// Return the i-th child node entry (order among Node variants only).
    ///
    /// # Safety
    ///
    /// Pointer within the returned reference is valid for the lifetime of the
    /// static MIB tree.
    pub(crate) fn child_node_at(&self, idx: usize) -> Option<&SysctlNode> {
        let mut n = 0usize;
        for i in 0..self.entry_count {
            if let SysctlEntry::Node(ptr) = &self.entries[i] {
                if n == idx {
                    // SAFETY: pointers are set from static arrays during init.
                    return Some(unsafe { &**ptr });
                }
                n += 1;
            }
        }
        None
    }

    /// Return the i-th leaf entry (order among Leaf variants only).
    pub(crate) fn leaf_at(&self, idx: usize) -> Option<&SysctlLeaf> {
        let mut n = 0usize;
        for i in 0..self.entry_count {
            if let SysctlEntry::Leaf(leaf) = &self.entries[i] {
                if n == idx {
                    return Some(leaf);
                }
                n += 1;
            }
        }
        None
    }

    /// Return the i-th DynamicDir entry (order among Dynamic variants only).
    pub(crate) fn dynamic_at(&self, idx: usize) -> Option<&DynamicDir> {
        let mut n = 0usize;
        for i in 0..self.entry_count {
            if let SysctlEntry::Dynamic(ptr) = &self.entries[i] {
                if n == idx {
                    // SAFETY: pointers are set from static arrays during init.
                    return Some(unsafe { &**ptr });
                }
                n += 1;
            }
        }
        None
    }

    /// Register a leaf under this node. Returns false if full or duplicate.
    pub(crate) fn add_leaf(
        &mut self,
        name: &[u8],
        ctl_type: u8,
        flags: u8,
        read_fn: Option<SysctlRead>,
        write_fn: Option<SysctlWrite>,
    ) -> bool {
        if name.len() > LEAF_NAME_MAX || self.entry_count >= MAX_ENTRIES {
            return false;
        }
        if self.find_leaf(name).is_some() {
            return false;
        }
        let mut leaf = SysctlLeaf::zeroed();
        leaf.name[..name.len()].copy_from_slice(name);
        leaf.name_len = name.len() as u8;
        leaf.ctl_type = ctl_type;
        leaf.flags = flags;
        leaf.read_fn = read_fn;
        leaf.write_fn = write_fn;
        let idx = self.entry_count;
        self.entries[idx] = SysctlEntry::Leaf(leaf);
        self.entry_count = idx + 1;
        true
    }

    /// Register a child node pointer under this node.
    ///
    /// # Safety
    ///
    /// `child` must point to a static `SysctlNode` that outlives the MIB tree.
    pub(crate) unsafe fn add_node(&mut self, child: *const SysctlNode) -> bool {
        if self.entry_count >= MAX_ENTRIES {
            return false;
        }
        let idx = self.entry_count;
        self.entries[idx] = SysctlEntry::Node(child);
        self.entry_count = idx + 1;
        true
    }

    /// Register a DynamicDir pointer under this node.
    ///
    /// # Safety
    ///
    /// `dyn_dir` must point to a static `DynamicDir` that outlives the MIB tree.
    pub(crate) unsafe fn add_dynamic(&mut self, dyn_dir: *const DynamicDir) -> bool {
        if self.entry_count >= MAX_ENTRIES {
            return false;
        }
        let idx = self.entry_count;
        self.entries[idx] = SysctlEntry::Dynamic(dyn_dir);
        self.entry_count = idx + 1;
        true
    }
}

// =========================================================================
// Static MIB tree
// =========================================================================

/// Top-level MIB namespaces.
const TOP_LEVEL_COUNT: usize = 6;

static mut TOP_LEVEL_NODES: [SysctlNode; TOP_LEVEL_COUNT] =
    [const { SysctlNode::zeroed() }; TOP_LEVEL_COUNT];

/// Root of the MIB tree. Top-level nodes are registered as children during
/// `init_tree()`.
pub(crate) static mut MIB_ROOT: SysctlNode = SysctlNode::zeroed();

/// Set a node's name from a byte slice.
unsafe fn set_node_name(node: &mut SysctlNode, name: &[u8]) {
    let len = if name.len() < NODE_NAME_MAX {
        name.len()
    } else {
        NODE_NAME_MAX
    };
    node.name[..len].copy_from_slice(&name[..len]);
    node.name_len = len as u8;
}

/// Initialize the static MIB tree structure.
///
/// # Safety
///
/// Must be called once during VFS bootstrap (single-threaded).
pub(crate) unsafe fn init_tree() {
    unsafe {
        let names: [&[u8]; TOP_LEVEL_COUNT] = [b"kern", b"hw", b"net", b"vm", b"vfs", b"security"];
        for i in 0..TOP_LEVEL_COUNT {
            set_node_name(&mut *(&raw mut TOP_LEVEL_NODES[i]), names[i]);
        }

        set_node_name(&mut *(&raw mut MIB_ROOT), b"");
        // Register each top-level node as a child of root.
        for i in 0..TOP_LEVEL_COUNT {
            let ptr = &raw const TOP_LEVEL_NODES[i] as *const SysctlNode;
            (*(&raw mut MIB_ROOT)).add_node(ptr);
        }
    }
}

/// Look up a node by dotted MIB path (e.g. `b"kern"` or `b"vm.stats.vm"`).
///
/// Splits on `.` and traverses one level per component.
///
/// # Safety
///
/// Must be called after `init_tree()`.
pub(crate) unsafe fn lookup_node_mut(path: &[u8]) -> Option<&'static mut SysctlNode> {
    unsafe {
        let root = &mut *(&raw mut MIB_ROOT);
        if path.is_empty() {
            return Some(root);
        }

        // Walk the dot-separated components.
        let mut current: &mut SysctlNode = root;
        let mut remaining = path;
        loop {
            let (component, rest) = match remaining.iter().position(|&b| b == b'.') {
                Some(dot) => (&remaining[..dot], &remaining[dot + 1..]),
                None => (remaining, &[][..]),
            };
            if component.is_empty() {
                return None;
            }
            let child_ptr = match current.find_child_node_mut(component) {
                Some(c) => c as *mut SysctlNode,
                None => return None,
            };
            current = &mut *child_ptr;
            if rest.is_empty() {
                return Some(current);
            }
            remaining = rest;
        }
    }
}

/// Look up a node (immutable) by dotted MIB path from the root.
///
/// # Safety
///
/// Must be called after `init_tree()`.
pub(crate) unsafe fn lookup_node(path: &[u8]) -> Option<&'static SysctlNode> {
    unsafe {
        let root = &*(&raw const MIB_ROOT);
        if path.is_empty() {
            return Some(root);
        }

        let mut current: &SysctlNode = root;
        let mut remaining = path;
        loop {
            let (component, rest) = match remaining.iter().position(|&b| b == b'.') {
                Some(dot) => (&remaining[..dot], &remaining[dot + 1..]),
                None => (remaining, &[][..]),
            };
            if component.is_empty() {
                return None;
            }
            match current.find_child_node(component) {
                Some(child) => {
                    current = child;
                    if rest.is_empty() {
                        return Some(current);
                    }
                    remaining = rest;
                }
                None => return None,
            }
        }
    }
}
