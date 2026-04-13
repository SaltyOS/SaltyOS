// SPDX-License-Identifier: GPL-2.0-only
//! MIB tree — hierarchical sysctl namespace.
//!
//! The tree is a two-level structure: `SysctlNode` (interior, VT_DIR) and
//! `SysctlLeaf` (terminal, VT_REG). Nodes own a fixed-capacity children
//! array; leaves carry read/write callbacks invoked by the VopVector layer.
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
pub(crate) const CTLTYPE_U64: u8 = 4;

pub(crate) const CTLFLAG_RD: u8 = 0x01;
pub(crate) const CTLFLAG_WR: u8 = 0x02;
pub(crate) const CTLFLAG_RW: u8 = CTLFLAG_RD | CTLFLAG_WR;

// =========================================================================
// Read / write callback signatures
// =========================================================================

/// Read callback: write the current value into `buf`, return bytes written.
pub(crate) type SysctlRead = unsafe fn(buf: *mut u8, buf_len: usize) -> usize;

/// Write callback: accept `len` bytes from `src`, return 0 on success.
pub(crate) type SysctlWrite = unsafe fn(src: *const u8, len: usize) -> i32;

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
// SysctlNode — interior MIB entry (directory)
// =========================================================================

/// Maximum node name length (bytes).
pub(super) const NODE_NAME_MAX: usize = 16;

/// Maximum child nodes per node.
pub(super) const MAX_CHILD_NODES: usize = 8;

/// Maximum leaves per node.
pub(super) const MAX_CHILD_LEAVES: usize = 16;

#[repr(C)]
pub(crate) struct SysctlNode {
    pub(crate) name: [u8; NODE_NAME_MAX],
    pub(crate) name_len: u8,
    _pad: [u8; 7],
    pub(crate) child_nodes: *mut SysctlNode,
    pub(crate) child_node_count: usize,
    pub(crate) leaves: [SysctlLeaf; MAX_CHILD_LEAVES],
    pub(crate) leaf_count: usize,
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
            child_nodes: core::ptr::null_mut(),
            child_node_count: 0,
            leaves: [const { SysctlLeaf::zeroed() }; MAX_CHILD_LEAVES],
            leaf_count: 0,
        }
    }

    /// Find a child node by name.
    pub(crate) fn find_child_node(&self, name: &[u8]) -> Option<&SysctlNode> {
        for i in 0..self.child_node_count {
            // SAFETY: child_nodes is valid for child_node_count entries,
            // set during init_tree() from a static array.
            let child = unsafe { &*self.child_nodes.add(i) };
            if child.name_len as usize == name.len()
                && &child.name[..name.len()] == name
            {
                return Some(child);
            }
        }
        None
    }

    /// Find a child node by name (mutable).
    pub(crate) fn find_child_node_mut(&mut self, name: &[u8]) -> Option<&mut SysctlNode> {
        for i in 0..self.child_node_count {
            let child = unsafe { &mut *self.child_nodes.add(i) };
            if child.name_len as usize == name.len()
                && &child.name[..name.len()] == name
            {
                return Some(child);
            }
        }
        None
    }

    /// Find a leaf by name.
    pub(crate) fn find_leaf(&self, name: &[u8]) -> Option<&SysctlLeaf> {
        for i in 0..self.leaf_count {
            let leaf = &self.leaves[i];
            if leaf.name_len as usize == name.len()
                && &leaf.name[..name.len()] == name
            {
                return Some(leaf);
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
        if name.len() > LEAF_NAME_MAX || self.leaf_count >= MAX_CHILD_LEAVES {
            return false;
        }
        // Duplicate check.
        if self.find_leaf(name).is_some() {
            return false;
        }
        let idx = self.leaf_count;
        let leaf = &mut self.leaves[idx];
        leaf.name[..name.len()].copy_from_slice(name);
        leaf.name_len = name.len() as u8;
        leaf.ctl_type = ctl_type;
        leaf.flags = flags;
        leaf.read_fn = read_fn;
        leaf.write_fn = write_fn;
        self.leaf_count = idx + 1;
        true
    }
}

// =========================================================================
// Static MIB tree
// =========================================================================

/// Top-level MIB namespaces.
const TOP_LEVEL_COUNT: usize = 6;

static mut TOP_LEVEL_NODES: [SysctlNode; TOP_LEVEL_COUNT] = [const { SysctlNode::zeroed() }; TOP_LEVEL_COUNT];

/// Root of the MIB tree. `child_nodes` points to `TOP_LEVEL_NODES` after
/// `init_tree()` runs.
pub(crate) static mut MIB_ROOT: SysctlNode = SysctlNode::zeroed();

/// Set a node's name from a byte slice.
unsafe fn set_node_name(node: &mut SysctlNode, name: &[u8]) {
    let len = if name.len() < NODE_NAME_MAX { name.len() } else { NODE_NAME_MAX };
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
        let names: [&[u8]; TOP_LEVEL_COUNT] = [
            b"kern", b"hw", b"net", b"vm", b"vfs", b"security",
        ];
        for i in 0..TOP_LEVEL_COUNT {
            set_node_name(&mut *(&raw mut TOP_LEVEL_NODES[i]), names[i]);
        }

        set_node_name(&mut *(&raw mut MIB_ROOT), b"");
        (*&raw mut MIB_ROOT).child_nodes = &raw mut TOP_LEVEL_NODES as *mut SysctlNode;
        (*&raw mut MIB_ROOT).child_node_count = TOP_LEVEL_COUNT;
    }
}

/// Look up a node by dotted MIB path (e.g. "kern" or "hw").
/// Only supports single-level lookup from root for now; providers register
/// leaves directly on the returned node.
///
/// # Safety
///
/// Must be called after `init_tree()`.
pub(crate) unsafe fn lookup_node_mut(name: &[u8]) -> Option<&'static mut SysctlNode> {
    unsafe {
        let root = &mut *(&raw mut MIB_ROOT);
        if name.is_empty() {
            return Some(root);
        }
        root.find_child_node_mut(name)
    }
}

/// Look up a node (immutable) from the root by name.
///
/// # Safety
///
/// Must be called after `init_tree()`.
pub(crate) unsafe fn lookup_node(name: &[u8]) -> Option<&'static SysctlNode> {
    unsafe {
        let root = &*(&raw const MIB_ROOT);
        if name.is_empty() {
            return Some(root);
        }
        root.find_child_node(name)
    }
}
