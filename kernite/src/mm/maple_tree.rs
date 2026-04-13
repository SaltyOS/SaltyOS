//! Maple tree — generic range-based B-tree.
//!
//! `MapleTree<V: Copy>` stores key-value pairs where keys are `u64`
//! (VA start addresses) and values are caller-defined `V`. Leaf slot
//! count is computed at compile time from `size_of::<V>()`.
//!
//! Nodes are page-sized (4096 bytes), allocated via `NodeAllocator`.
//! The tree is agnostic to what `V` represents — VSpace uses
//! `MapleTree<VmArea>`, but any `Copy` type works.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::node_alloc::NodeAllocator;
use core::marker::PhantomData;

// ---------------------------------------------------------------------------
// Node layout computations
// ---------------------------------------------------------------------------

const PAGE: usize = 4096;
const HEADER: usize = 16; // NodeTag(1) + pad(1) + count(2) + pad(4) + parent(8)

/// Compute leaf slot count for a given value size.
const fn leaf_slots(val_size: usize) -> usize {
    if val_size == 0 { return 0; }
    (PAGE - HEADER) / (8 + val_size) // pivot(8) + V
}

/// Internal node: pivots + child pointers, V-independent.
const INTERNAL_PIVOTS: usize = (PAGE - HEADER - 8) / 16; // (pivot(8) + child(8)) * N + child(8)

const INTERNAL_MIN: usize = INTERNAL_PIVOTS / 3;

// ---------------------------------------------------------------------------
// Node types
// ---------------------------------------------------------------------------

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeTag {
    Leaf = 0,
    Internal = 1,
}

#[repr(C)]
struct NodeHeader {
    tag: NodeTag,
    _pad: u8,
    count: u16,
    _pad2: u32,
    parent: *mut u8,
}

// Leaf layout: [NodeHeader][pivots: u64 × N][values: V × N]
// Internal layout: [NodeHeader][pivots: u64 × INTERNAL_PIVOTS][children: *mut u8 × (INTERNAL_PIVOTS+1)]

const INT_PIVOTS_OFF: usize = HEADER;
const INT_CHILDREN_OFF: usize = INT_PIVOTS_OFF + INTERNAL_PIVOTS * 8;

#[inline]
fn leaf_pivots_off() -> usize { HEADER }

#[inline]
fn leaf_values_off(slots: usize) -> usize { HEADER + slots * 8 }

// ---------------------------------------------------------------------------
// Raw accessors
// ---------------------------------------------------------------------------

#[inline]
unsafe fn hdr(node: *mut u8) -> &'static NodeHeader {
    unsafe { &*(node as *const NodeHeader) }
}
#[inline]
unsafe fn hdr_mut(node: *mut u8) -> &'static mut NodeHeader {
    unsafe { &mut *(node as *mut NodeHeader) }
}

#[inline]
unsafe fn leaf_pivot(node: *mut u8, i: usize) -> u64 {
    unsafe { *(node.add(leaf_pivots_off()) as *const u64).add(i) }
}
#[inline]
unsafe fn leaf_pivot_set(node: *mut u8, i: usize, v: u64) {
    unsafe { *(node.add(leaf_pivots_off()) as *mut u64).add(i) = v; }
}

#[inline]
unsafe fn leaf_val<V: Copy>(node: *mut u8, i: usize, slots: usize) -> V {
    unsafe { *(node.add(leaf_values_off(slots)) as *const V).add(i) }
}
#[inline]
unsafe fn leaf_val_set<V: Copy>(node: *mut u8, i: usize, slots: usize, v: V) {
    unsafe { *(node.add(leaf_values_off(slots)) as *mut V).add(i) = v; }
}
#[inline]
unsafe fn leaf_val_ref<V: Copy>(node: *mut u8, i: usize, slots: usize) -> &'static V {
    unsafe { &*(node.add(leaf_values_off(slots)) as *const V).add(i) }
}

#[inline]
unsafe fn int_pivot(node: *mut u8, i: usize) -> u64 {
    unsafe { *(node.add(INT_PIVOTS_OFF) as *const u64).add(i) }
}
#[inline]
unsafe fn int_pivot_set(node: *mut u8, i: usize, v: u64) {
    unsafe { *(node.add(INT_PIVOTS_OFF) as *mut u64).add(i) = v; }
}
#[inline]
unsafe fn int_child(node: *mut u8, i: usize) -> *mut u8 {
    unsafe { *(node.add(INT_CHILDREN_OFF) as *const *mut u8).add(i) }
}
#[inline]
unsafe fn int_child_set(node: *mut u8, i: usize, c: *mut u8) {
    unsafe { *(node.add(INT_CHILDREN_OFF) as *mut *mut u8).add(i) = c; }
}

#[inline]
unsafe fn set_parent(node: *mut u8, p: *mut u8) {
    unsafe { hdr_mut(node).parent = p; }
}

// ---------------------------------------------------------------------------
// Node allocation helpers
// ---------------------------------------------------------------------------

unsafe fn alloc_leaf<A: NodeAllocator>(alloc: &mut A) -> *mut u8 {
    let n = alloc.alloc_node();
    if !n.is_null() {
        unsafe { hdr_mut(n).tag = NodeTag::Leaf; }
    }
    n
}

unsafe fn alloc_internal<A: NodeAllocator>(alloc: &mut A) -> *mut u8 {
    let n = alloc.alloc_node();
    if !n.is_null() {
        unsafe { hdr_mut(n).tag = NodeTag::Internal; }
    }
    n
}

// ---------------------------------------------------------------------------
// Leaf operations
// ---------------------------------------------------------------------------

unsafe fn leaf_insert_at<V: Copy>(node: *mut u8, pos: usize, pivot: u64, val: V, slots: usize) {
    unsafe {
        let count = hdr(node).count as usize;
        for i in (pos..count).rev() {
            leaf_pivot_set(node, i + 1, leaf_pivot(node, i));
            leaf_val_set(node, i + 1, slots, leaf_val::<V>(node, i, slots));
        }
        leaf_pivot_set(node, pos, pivot);
        leaf_val_set(node, pos, slots, val);
        hdr_mut(node).count += 1;
    }
}

unsafe fn leaf_remove_at<V: Copy>(node: *mut u8, pos: usize, slots: usize) {
    unsafe {
        let count = hdr(node).count as usize;
        for i in pos..count - 1 {
            leaf_pivot_set(node, i, leaf_pivot(node, i + 1));
            leaf_val_set(node, i, slots, leaf_val::<V>(node, i + 1, slots));
        }
        leaf_pivot_set(node, count - 1, 0);
        core::ptr::write_bytes(
            (node.add(leaf_values_off(slots)) as *mut V).add(count - 1),
            0, 1,
        );
        hdr_mut(node).count -= 1;
    }
}

unsafe fn leaf_split<V: Copy, A: NodeAllocator>(
    left: *mut u8, slots: usize, alloc: &mut A,
) -> Option<(*mut u8, u64)> {
    let right = unsafe { alloc_leaf(alloc) };
    if right.is_null() { return None; }
    unsafe {
        let count = hdr(left).count as usize;
        let mid = count / 2;
        let rc = count - mid;
        for i in 0..rc {
            leaf_pivot_set(right, i, leaf_pivot(left, mid + i));
            leaf_val_set(right, i, slots, leaf_val::<V>(left, mid + i, slots));
        }
        hdr_mut(right).count = rc as u16;
        for i in mid..count {
            leaf_pivot_set(left, i, 0);
            core::ptr::write_bytes(
                (left.add(leaf_values_off(slots)) as *mut V).add(i), 0, 1,
            );
        }
        hdr_mut(left).count = mid as u16;
        Some((right, leaf_pivot(right, 0)))
    }
}

// ---------------------------------------------------------------------------
// Internal operations
// ---------------------------------------------------------------------------

unsafe fn int_insert_at(node: *mut u8, pos: usize, pivot: u64, right_child: *mut u8) {
    unsafe {
        let count = hdr(node).count as usize;
        for i in (pos..count).rev() {
            int_pivot_set(node, i + 1, int_pivot(node, i));
        }
        for i in (pos + 1..=count).rev() {
            int_child_set(node, i + 1, int_child(node, i));
        }
        int_pivot_set(node, pos, pivot);
        int_child_set(node, pos + 1, right_child);
        hdr_mut(node).count += 1;
    }
}

unsafe fn int_split<A: NodeAllocator>(
    left: *mut u8, alloc: &mut A,
) -> Option<(*mut u8, u64)> {
    let right = unsafe { alloc_internal(alloc) };
    if right.is_null() { return None; }
    unsafe {
        let count = hdr(left).count as usize;
        let mid = count / 2;
        let promoted = int_pivot(left, mid);
        let rc = count - mid - 1;
        for i in 0..rc {
            int_pivot_set(right, i, int_pivot(left, mid + 1 + i));
        }
        for i in 0..=rc {
            let c = int_child(left, mid + 1 + i);
            int_child_set(right, i, c);
            if !c.is_null() { set_parent(c, right); }
        }
        hdr_mut(right).count = rc as u16;
        for i in mid..count { int_pivot_set(left, i, 0); }
        for i in mid + 1..=count { int_child_set(left, i, core::ptr::null_mut()); }
        hdr_mut(left).count = mid as u16;
        Some((right, promoted))
    }
}

// ---------------------------------------------------------------------------
// MapleTree<V>
// ---------------------------------------------------------------------------

pub struct MapleTree<V: Copy> {
    root: *mut u8,
    entry_count: usize,
    _phantom: PhantomData<V>,
}

impl<V: Copy + 'static> MapleTree<V> {
    const SLOTS: usize = leaf_slots(core::mem::size_of::<V>());
    const LEAF_MIN: usize = Self::SLOTS / 3;

    pub const fn empty() -> Self {
        Self { root: core::ptr::null_mut(), entry_count: 0, _phantom: PhantomData }
    }

    pub fn count(&self) -> usize { self.entry_count }
    pub fn is_empty(&self) -> bool { self.root.is_null() }

    // --- Lookup ---

    pub fn lookup(&self, addr: u64) -> Option<(u64, &V)> {
        if self.root.is_null() { return None; }
        unsafe { self.lookup_inner(self.root, addr) }
    }

    unsafe fn lookup_inner(&self, mut node: *mut u8, addr: u64) -> Option<(u64, &V)> {
        loop {
            if node.is_null() { return None; }
            unsafe {
                match hdr(node).tag {
                    NodeTag::Internal => {
                        let c = hdr(node).count as usize;
                        let mut ci = c;
                        for i in 0..c {
                            if addr < int_pivot(node, i) { ci = i; break; }
                        }
                        node = int_child(node, ci);
                    }
                    NodeTag::Leaf => {
                        let c = hdr(node).count as usize;
                        for i in 0..c {
                            let start = leaf_pivot(node, i);
                            if addr >= start {
                                let v = leaf_val_ref::<V>(node, i, Self::SLOTS);
                                // Caller determines range via V's page_count field
                                if i + 1 < c {
                                    if addr < leaf_pivot(node, i + 1) {
                                        return Some((start, v));
                                    }
                                } else {
                                    return Some((start, v));
                                }
                            }
                        }
                        return None;
                    }
                }
            }
        }
    }

    // --- Find leaf ---

    unsafe fn find_leaf(&self, key: u64) -> *mut u8 {
        let mut node = self.root;
        loop {
            if node.is_null() { return core::ptr::null_mut(); }
            unsafe {
                match hdr(node).tag {
                    NodeTag::Leaf => return node,
                    NodeTag::Internal => {
                        let c = hdr(node).count as usize;
                        let mut ci = c;
                        for i in 0..c {
                            if key < int_pivot(node, i) { ci = i; break; }
                        }
                        node = int_child(node, ci);
                    }
                }
            }
        }
    }

    // --- Insert ---

    pub unsafe fn insert<A: NodeAllocator>(
        &mut self, start: u64, value: V, alloc: &mut A,
    ) -> bool {
        if self.root.is_null() {
            let leaf = unsafe { alloc_leaf(alloc) };
            if leaf.is_null() { return false; }
            unsafe { leaf_insert_at(leaf, 0, start, value, Self::SLOTS); }
            self.root = leaf;
            self.entry_count = 1;
            return true;
        }

        let leaf = unsafe { self.find_leaf(start) };
        if leaf.is_null() { return false; }

        unsafe {
            let count = hdr(leaf).count as usize;
            let mut pos = count;
            for i in 0..count {
                if start < leaf_pivot(leaf, i) { pos = i; break; }
            }

            if count < Self::SLOTS {
                leaf_insert_at(leaf, pos, start, value, Self::SLOTS);
                self.entry_count += 1;
                return true;
            }

            // Split
            let (right, split_pivot) = match leaf_split::<V, A>(leaf, Self::SLOTS, alloc) {
                Some(r) => r,
                None => return false,
            };

            if start < split_pivot {
                let lc = hdr(leaf).count as usize;
                let mut lp = lc;
                for i in 0..lc { if start < leaf_pivot(leaf, i) { lp = i; break; } }
                leaf_insert_at(leaf, lp, start, value, Self::SLOTS);
            } else {
                let rc = hdr(right).count as usize;
                let mut rp = rc;
                for i in 0..rc { if start < leaf_pivot(right, i) { rp = i; break; } }
                leaf_insert_at(right, rp, start, value, Self::SLOTS);
            }

            self.entry_count += 1;
            self.propagate_split(leaf, split_pivot, right, alloc)
        }
    }

    pub unsafe fn replace(&mut self, start: u64, value: V) -> bool {
        if self.root.is_null() {
            return false;
        }
        let leaf = unsafe { self.find_leaf(start) };
        if leaf.is_null() {
            return false;
        }

        unsafe {
            let count = hdr(leaf).count as usize;
            for i in 0..count {
                if leaf_pivot(leaf, i) == start {
                    leaf_val_set(leaf, i, Self::SLOTS, value);
                    return true;
                }
            }
        }

        false
    }

    unsafe fn propagate_split<A: NodeAllocator>(
        &mut self, left: *mut u8, pivot: u64, right: *mut u8, alloc: &mut A,
    ) -> bool {
        unsafe {
            let parent = hdr(left).parent;

            if parent.is_null() {
                let new_root = alloc_internal(alloc);
                if new_root.is_null() { return false; }
                int_pivot_set(new_root, 0, pivot);
                int_child_set(new_root, 0, left);
                int_child_set(new_root, 1, right);
                hdr_mut(new_root).count = 1;
                set_parent(left, new_root);
                set_parent(right, new_root);
                self.root = new_root;
                return true;
            }

            let pc = hdr(parent).count as usize;
            let mut pos = 0;
            for i in 0..=pc { if int_child(parent, i) == left { pos = i; break; } }

            if pc < INTERNAL_PIVOTS {
                int_insert_at(parent, pos, pivot, right);
                set_parent(right, parent);
                return true;
            }

            let (rp, promoted) = match int_split(parent, alloc) {
                Some(r) => r,
                None => return false,
            };

            if pivot < promoted {
                let c2 = hdr(parent).count as usize;
                let mut ip = 0;
                for i in 0..=c2 { if int_child(parent, i) == left { ip = i; break; } }
                int_insert_at(parent, ip, pivot, right);
                set_parent(right, parent);
            } else {
                let c2 = hdr(rp).count as usize;
                let mut ip = c2;
                for i in 0..c2 { if pivot < int_pivot(rp, i) { ip = i; break; } }
                int_insert_at(rp, ip, pivot, right);
                set_parent(right, rp);
            }

            self.propagate_split(parent, promoted, rp, alloc)
        }
    }

    // --- Remove ---

    pub unsafe fn remove<A: NodeAllocator>(
        &mut self, start: u64, alloc: &mut A,
    ) -> bool {
        if self.root.is_null() { return false; }
        let leaf = unsafe { self.find_leaf(start) };
        if leaf.is_null() { return false; }

        unsafe {
            let count = hdr(leaf).count as usize;
            let mut found = false;
            for i in 0..count {
                if leaf_pivot(leaf, i) == start {
                    leaf_remove_at::<V>(leaf, i, Self::SLOTS);
                    self.entry_count -= 1;
                    found = true;
                    break;
                }
            }
            if !found { return false; }
            self.rebalance_leaf(leaf, alloc);
            true
        }
    }

    /// Attempt to rebalance an underfull leaf after removal.
    ///
    /// Tries four strategies: steal from right sibling, steal from left,
    /// merge with right, merge with left. If none succeeds (e.g., leaf
    /// is the only child of its parent), the leaf remains underfull.
    /// This is structurally valid but may degrade lookup from O(log n)
    /// toward O(n) for the affected range — rare in VMA workloads.
    unsafe fn rebalance_leaf<A: NodeAllocator>(&mut self, leaf: *mut u8, alloc: &mut A) {
        unsafe {
            let count = hdr(leaf).count as usize;
            let parent = hdr(leaf).parent;
            if parent.is_null() { return; }
            if count >= Self::LEAF_MIN { return; }

            let pc = hdr(parent).count as usize;
            let mut ci = 0;
            for i in 0..=pc { if int_child(parent, i) == leaf { ci = i; break; } }

            // Steal from right
            if ci < pc {
                let rs = int_child(parent, ci + 1);
                if !rs.is_null() && hdr(rs).tag == NodeTag::Leaf && hdr(rs).count as usize > Self::LEAF_MIN {
                    let sp = leaf_pivot(rs, 0);
                    let sv: V = leaf_val(rs, 0, Self::SLOTS);
                    leaf_remove_at::<V>(rs, 0, Self::SLOTS);
                    let lc = hdr(leaf).count as usize;
                    leaf_insert_at(leaf, lc, sp, sv, Self::SLOTS);
                    int_pivot_set(parent, ci, leaf_pivot(rs, 0));
                    return;
                }
            }

            // Steal from left
            if ci > 0 {
                let ls = int_child(parent, ci - 1);
                if !ls.is_null() && hdr(ls).tag == NodeTag::Leaf && hdr(ls).count as usize > Self::LEAF_MIN {
                    let lsc = hdr(ls).count as usize;
                    let sp = leaf_pivot(ls, lsc - 1);
                    let sv: V = leaf_val(ls, lsc - 1, Self::SLOTS);
                    leaf_remove_at::<V>(ls, lsc - 1, Self::SLOTS);
                    leaf_insert_at(leaf, 0, sp, sv, Self::SLOTS);
                    int_pivot_set(parent, ci - 1, leaf_pivot(leaf, 0));
                    return;
                }
            }

            // Merge with right
            if ci < pc {
                let rs = int_child(parent, ci + 1);
                if !rs.is_null() && hdr(rs).tag == NodeTag::Leaf {
                    let rc = hdr(rs).count as usize;
                    let lc = hdr(leaf).count as usize;
                    for i in 0..rc {
                        leaf_insert_at(leaf, lc + i, leaf_pivot(rs, i),
                            leaf_val::<V>(rs, i, Self::SLOTS), Self::SLOTS);
                    }
                    alloc.free_node(rs);
                    self.remove_from_internal(parent, ci, alloc);
                    return;
                }
            }

            // Merge into left
            if ci > 0 {
                let ls = int_child(parent, ci - 1);
                if !ls.is_null() && hdr(ls).tag == NodeTag::Leaf {
                    let lsc = hdr(ls).count as usize;
                    let mc = hdr(leaf).count as usize;
                    for i in 0..mc {
                        leaf_insert_at(ls, lsc + i, leaf_pivot(leaf, i),
                            leaf_val::<V>(leaf, i, Self::SLOTS), Self::SLOTS);
                    }
                    alloc.free_node(leaf);
                    self.remove_from_internal(parent, ci - 1, alloc);
                }
            }
        }
    }

    unsafe fn remove_from_internal<A: NodeAllocator>(
        &mut self, node: *mut u8, pivot_idx: usize, alloc: &mut A,
    ) {
        unsafe {
            let count = hdr(node).count as usize;
            for i in pivot_idx..count - 1 { int_pivot_set(node, i, int_pivot(node, i + 1)); }
            int_pivot_set(node, count - 1, 0);
            for i in pivot_idx + 1..count { int_child_set(node, i, int_child(node, i + 1)); }
            int_child_set(node, count, core::ptr::null_mut());
            hdr_mut(node).count -= 1;
            let nc = hdr(node).count as usize;
            let parent = hdr(node).parent;

            if parent.is_null() {
                if nc == 0 {
                    let only = int_child(node, 0);
                    if !only.is_null() { set_parent(only, core::ptr::null_mut()); self.root = only; }
                    else { self.root = core::ptr::null_mut(); }
                    alloc.free_node(node);
                }
                return;
            }
            if nc >= INTERNAL_MIN { return; }
            self.rebalance_internal(node, alloc);
        }
    }

    unsafe fn rebalance_internal<A: NodeAllocator>(&mut self, node: *mut u8, alloc: &mut A) {
        unsafe {
            let parent = hdr(node).parent;
            if parent.is_null() { return; }
            let pc = hdr(parent).count as usize;
            let mut ci = 0;
            for i in 0..=pc { if int_child(parent, i) == node { ci = i; break; } }

            // Steal from right sibling
            if ci < pc {
                let rs = int_child(parent, ci + 1);
                if !rs.is_null() && hdr(rs).tag == NodeTag::Internal && hdr(rs).count as usize > INTERNAL_MIN {
                    let mc = hdr(node).count as usize;
                    int_pivot_set(node, mc, int_pivot(parent, ci));
                    let fc = int_child(rs, 0);
                    int_child_set(node, mc + 1, fc);
                    if !fc.is_null() { set_parent(fc, node); }
                    hdr_mut(node).count += 1;
                    int_pivot_set(parent, ci, int_pivot(rs, 0));
                    let rc = hdr(rs).count as usize;
                    for i in 0..rc - 1 { int_pivot_set(rs, i, int_pivot(rs, i + 1)); }
                    int_pivot_set(rs, rc - 1, 0);
                    for i in 0..rc { int_child_set(rs, i, int_child(rs, i + 1)); }
                    int_child_set(rs, rc, core::ptr::null_mut());
                    hdr_mut(rs).count -= 1;
                    return;
                }
            }

            // Steal from left sibling
            if ci > 0 {
                let ls = int_child(parent, ci - 1);
                if !ls.is_null() && hdr(ls).tag == NodeTag::Internal && hdr(ls).count as usize > INTERNAL_MIN {
                    let mc = hdr(node).count as usize;
                    for i in (0..mc).rev() { int_pivot_set(node, i + 1, int_pivot(node, i)); }
                    for i in (0..=mc).rev() { int_child_set(node, i + 1, int_child(node, i)); }
                    int_pivot_set(node, 0, int_pivot(parent, ci - 1));
                    let lc = hdr(ls).count as usize;
                    let lch = int_child(ls, lc);
                    int_child_set(node, 0, lch);
                    if !lch.is_null() { set_parent(lch, node); }
                    hdr_mut(node).count += 1;
                    int_pivot_set(parent, ci - 1, int_pivot(ls, lc - 1));
                    int_pivot_set(ls, lc - 1, 0);
                    int_child_set(ls, lc, core::ptr::null_mut());
                    hdr_mut(ls).count -= 1;
                    return;
                }
            }

            // Merge with right
            if ci < pc {
                let rs = int_child(parent, ci + 1);
                if !rs.is_null() && hdr(rs).tag == NodeTag::Internal {
                    let mc = hdr(node).count as usize;
                    let rc = hdr(rs).count as usize;
                    int_pivot_set(node, mc, int_pivot(parent, ci));
                    for i in 0..rc { int_pivot_set(node, mc + 1 + i, int_pivot(rs, i)); }
                    for i in 0..=rc {
                        let c = int_child(rs, i);
                        int_child_set(node, mc + 1 + i, c);
                        if !c.is_null() { set_parent(c, node); }
                    }
                    hdr_mut(node).count = (mc + 1 + rc) as u16;
                    alloc.free_node(rs);
                    self.remove_from_internal(parent, ci, alloc);
                    return;
                }
            }

            // Merge into left
            if ci > 0 {
                let ls = int_child(parent, ci - 1);
                if !ls.is_null() && hdr(ls).tag == NodeTag::Internal {
                    let lc = hdr(ls).count as usize;
                    let mc = hdr(node).count as usize;
                    int_pivot_set(ls, lc, int_pivot(parent, ci - 1));
                    for i in 0..mc { int_pivot_set(ls, lc + 1 + i, int_pivot(node, i)); }
                    for i in 0..=mc {
                        let c = int_child(node, i);
                        int_child_set(ls, lc + 1 + i, c);
                        if !c.is_null() { set_parent(c, ls); }
                    }
                    hdr_mut(ls).count = (lc + 1 + mc) as u16;
                    alloc.free_node(node);
                    self.remove_from_internal(parent, ci - 1, alloc);
                }
            }
        }
    }

    // --- Iteration ---

    pub fn for_each<F: FnMut(u64, &V)>(&self, f: &mut F) {
        if self.root.is_null() { return; }
        unsafe { self.iter_inner(self.root, f); }
    }

    unsafe fn iter_inner<F: FnMut(u64, &V)>(&self, node: *mut u8, f: &mut F) {
        if node.is_null() { return; }
        unsafe {
            match hdr(node).tag {
                NodeTag::Leaf => {
                    let c = hdr(node).count as usize;
                    for i in 0..c { f(leaf_pivot(node, i), leaf_val_ref::<V>(node, i, Self::SLOTS)); }
                }
                NodeTag::Internal => {
                    let c = hdr(node).count as usize;
                    for i in 0..=c { self.iter_inner(int_child(node, i), f); }
                }
            }
        }
    }

    // --- Destroy ---

    pub unsafe fn destroy<A: NodeAllocator>(&mut self, alloc: &mut A) {
        if !self.root.is_null() {
            unsafe { self.destroy_inner(self.root, alloc); }
            self.root = core::ptr::null_mut();
            self.entry_count = 0;
        }
    }

    unsafe fn destroy_inner<A: NodeAllocator>(&self, node: *mut u8, alloc: &mut A) {
        if node.is_null() { return; }
        unsafe {
            if hdr(node).tag == NodeTag::Internal {
                let c = hdr(node).count as usize;
                for i in 0..=c { self.destroy_inner(int_child(node, i), alloc); }
            }
            alloc.free_node(node);
        }
    }
}
