//! 4-level radix tree for MemoryObject page storage.
//!
//! Same structure as hardware page tables: each node is a page (4096 bytes)
//! containing 512 × 8-byte entries. Nodes are allocated via `NodeAllocator`.
//!
//! Capacity: 512^4 = 68 billion entries (256 TB at 4KB pages).
//! Depth adapts to the maximum index used:
//!   ≤ 512:        1 level
//!   ≤ 262144:     2 levels
//!   ≤ 134217728:  3 levels
//!   > 134217728:  4 levels
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::node_alloc::NodeAllocator;
use super::PAGE_SIZE;

const ENTRIES_PER_NODE: usize = PAGE_SIZE / 8; // 512
const BITS_PER_LEVEL: u32 = 9;
const MAX_LEVELS: u32 = 4;

/// Maximum page index representable in a MAX_LEVELS-deep tree.
const MAX_INDEX: usize = 1usize << (MAX_LEVELS as usize * BITS_PER_LEVEL as usize);

/// Root of a radix tree.
#[repr(C)]
pub struct RadixTree {
    root: *mut u64,
    depth: u32, // current number of levels (0 = empty, 1-4)
}

impl RadixTree {
    pub const fn empty() -> Self {
        Self {
            root: core::ptr::null_mut(),
            depth: 0,
        }
    }

    /// Compute the minimum depth needed to index `max_idx`.
    fn depth_for_index(max_idx: usize) -> u32 {
        if max_idx == 0 {
            return 1;
        }
        let mut d = 1u32;
        while max_idx >= (1usize << (d * BITS_PER_LEVEL)) {
            d += 1;
            if d >= MAX_LEVELS {
                break;
            }
        }
        d
    }

    /// Extract the 9-bit index for a given level from a page index.
    /// Level 1 uses bits [8:0], level 2 uses [17:9], etc.
    #[inline]
    fn level_index(page_idx: usize, level: u32) -> usize {
        (page_idx >> ((level - 1) * BITS_PER_LEVEL)) & (ENTRIES_PER_NODE - 1)
    }

    /// Grow the tree depth by inserting new root nodes above the current root.
    ///
    /// # Safety
    /// Caller must ensure `alloc` is valid and the tree is not concurrently modified.
    unsafe fn grow_depth<A: NodeAllocator>(
        &mut self,
        target_depth: u32,
        alloc: &mut A,
    ) -> bool {
        while self.depth < target_depth {
            let new_root = alloc.alloc_node() as *mut u64;
            if new_root.is_null() {
                return false;
            }
            if !self.root.is_null() {
                // SAFETY: new_root is freshly allocated (zeroed). Entry 0
                // points to the old root, which becomes a child node.
                unsafe {
                    *new_root = self.root as u64;
                }
            }
            self.root = new_root;
            self.depth += 1;
        }
        true
    }

    /// Insert a value at `page_idx`. Allocates intermediate nodes as needed.
    ///
    /// Returns `true` on success, `false` if node allocation failed.
    ///
    /// # Safety
    /// `alloc` must be valid. Tree must not be concurrently modified.
    pub unsafe fn insert<A: NodeAllocator>(
        &mut self,
        page_idx: usize,
        value: u64,
        alloc: &mut A,
    ) -> bool {
        if page_idx >= MAX_INDEX {
            return false;
        }
        let needed = Self::depth_for_index(page_idx);

        // Grow tree if needed
        if needed > self.depth {
            // SAFETY: alloc is valid, no concurrent modification.
            if !unsafe { self.grow_depth(needed, alloc) } {
                return false;
            }
        }

        // Ensure root exists
        if self.root.is_null() {
            let node = alloc.alloc_node() as *mut u64;
            if node.is_null() {
                return false;
            }
            self.root = node;
            self.depth = needed;
        }

        // Walk down, creating intermediate nodes
        let mut node = self.root;
        for level in (2..=self.depth).rev() {
            let idx = Self::level_index(page_idx, level);
            // SAFETY: node is a valid page-aligned array of 512 u64 entries.
            let entry = unsafe { *node.add(idx) };
            if entry == 0 {
                let child = alloc.alloc_node() as *mut u64;
                if child.is_null() {
                    return false;
                }
                // SAFETY: node[idx] is within bounds.
                unsafe {
                    *node.add(idx) = child as u64;
                }
                node = child;
            } else {
                node = entry as *mut u64;
            }
        }

        // Write the leaf entry
        let leaf_idx = Self::level_index(page_idx, 1);
        // SAFETY: node is a valid leaf node, leaf_idx < 512.
        unsafe {
            *node.add(leaf_idx) = value;
        }
        true
    }

    /// Look up the value at `page_idx`. Returns 0 if not present.
    pub fn get(&self, page_idx: usize) -> u64 {
        if self.root.is_null() || self.depth == 0 {
            return 0;
        }

        // Check if index exceeds tree capacity
        if page_idx >= (1usize << (self.depth * BITS_PER_LEVEL)) {
            return 0;
        }

        let mut node = self.root;
        for level in (2..=self.depth).rev() {
            let idx = Self::level_index(page_idx, level);
            // SAFETY: node is a valid page-aligned array.
            let entry = unsafe { *node.add(idx) };
            if entry == 0 {
                return 0;
            }
            node = entry as *mut u64;
        }

        let leaf_idx = Self::level_index(page_idx, 1);
        // SAFETY: node is a valid leaf node.
        unsafe { *node.add(leaf_idx) }
    }

    /// Remove the value at `page_idx` (set to 0). Does not free intermediate
    /// nodes even if they become empty (lazy cleanup).
    pub fn remove(&mut self, page_idx: usize) {
        if self.root.is_null() || self.depth == 0 {
            return;
        }
        if page_idx >= (1usize << (self.depth * BITS_PER_LEVEL)) {
            return;
        }

        let mut node = self.root;
        for level in (2..=self.depth).rev() {
            let idx = Self::level_index(page_idx, level);
            // SAFETY: node is valid.
            let entry = unsafe { *node.add(idx) };
            if entry == 0 {
                return;
            }
            node = entry as *mut u64;
        }

        let leaf_idx = Self::level_index(page_idx, 1);
        // SAFETY: node is valid leaf.
        unsafe {
            *node.add(leaf_idx) = 0;
        }
    }

    /// Iterate all non-zero entries. Calls `f(page_idx, value)` for each.
    ///
    /// # Safety
    /// Tree must not be concurrently modified during iteration.
    ///
    /// Calling contexts that satisfy this contract:
    /// - `MemoryObject::destroy()` — refcount==0 guarantees no concurrent
    ///   accessor can commit or resolve pages in this tree.
    /// - `resolve_page_depth()` — called under `VSpace.lock`, which
    ///   serializes page table walks and page commits for that VSpace.
    pub unsafe fn for_each<F: FnMut(usize, u64)>(&self, mut f: F) {
        if self.root.is_null() || self.depth == 0 {
            return;
        }
        // SAFETY: tree is not concurrently modified (caller guarantee).
        unsafe {
            Self::for_each_node(self.root, self.depth, 0, &mut f);
        }
    }

    unsafe fn for_each_node<F: FnMut(usize, u64)>(
        node: *mut u64,
        level: u32,
        base_idx: usize,
        f: &mut F,
    ) {
        if node.is_null() {
            return;
        }
        for i in 0..ENTRIES_PER_NODE {
            // SAFETY: node is a valid page-aligned array.
            let entry = unsafe { *node.add(i) };
            if entry == 0 {
                continue;
            }
            let child_base = base_idx | (i << ((level as usize - 1) * BITS_PER_LEVEL as usize));
            if level == 1 {
                f(child_base, entry);
            } else {
                // SAFETY: entry is a pointer to a child node.
                unsafe {
                    Self::for_each_node(entry as *mut u64, level - 1, child_base, f);
                }
            }
        }
    }

    /// Free all nodes in the tree (not the values — caller handles those).
    ///
    /// # Safety
    /// `alloc` must be the same allocator used to create the nodes.
    pub unsafe fn destroy<A: NodeAllocator>(&mut self, alloc: &mut A) {
        if !self.root.is_null() && self.depth > 0 {
            // SAFETY: alloc matches, tree is being destroyed.
            unsafe {
                Self::destroy_node(self.root, self.depth, alloc);
            }
            self.root = core::ptr::null_mut();
            self.depth = 0;
        }
    }

    unsafe fn destroy_node<A: NodeAllocator>(node: *mut u64, level: u32, alloc: &mut A) {
        if node.is_null() {
            return;
        }
        if level > 1 {
            for i in 0..ENTRIES_PER_NODE {
                // SAFETY: node is valid.
                let entry = unsafe { *node.add(i) };
                if entry != 0 {
                    // SAFETY: entry is a child node pointer.
                    unsafe {
                        Self::destroy_node(entry as *mut u64, level - 1, alloc);
                    }
                }
            }
        }
        // SAFETY: node was allocated by alloc.
        unsafe {
            alloc.free_node(node as *mut u8);
        }
    }
}
