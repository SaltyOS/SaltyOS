//! Child cspace layout — spawner-internal.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! init's view of where well-known capabilities live in a child's CSpace.
//! Built per-spawn from a `ChildSlotAlloc` cursor inside `spawn_server`.
//!
//! The slot positions chosen here are then communicated to the child via
//! `AT_TRONA_*` auxv tags so that lib code (libtrona, libposix, ...) can
//! reach the caps via the substrate `caps::*` getters without ever
//! hard-coding a slot number.
//!
//! `ChildSlotAlloc::new(0, ...)` deliberately starts at zero so that the
//! first three allocations land on slots 0/1/2, which are the kernel ABI
//! positions for `CAP_SELF_TCB`, `CAP_SELF_VSPACE`, and `CAP_SELF_CSPACE`.
//! Everything past that is spawner-private and may move freely.

/// Init-side per-service offsets used to lay out child kernel objects in
/// init's own CSpace (`cap_base + COFF_X`). These are spawner-private and
/// have nothing to do with where the child sees the caps in *its* CSpace.
pub const COFF_TCB: u64 = 0;
pub const COFF_VSPACE: u64 = 1;
pub const COFF_CNODE: u64 = 2;
pub const COFF_SC: u64 = 3;
pub const COFF_STACK_FR: u64 = 4;
pub const COFF_EP: u64 = 5;
pub const COFF_IPC_FR: u64 = 6;
pub const COFF_READY_NTFN: u64 = 8;
pub const COFF_FRAME_START: u64 = 16;

/// First child CNode slot reserved for RTLD-driven runtime frame allocation.
/// Cursor-allocated well-known caps are kept strictly below this value so
/// that RTLD's frame slot pool never collides with them.
pub const CHILD_RTLD_FRAME_SLOT_START: u64 = 64;

/// Sequential allocator that hands out child CNode slots one at a time.
/// Used by `spawn_server` to choose where each well-known capability lives
/// in the child's CSpace.
pub struct ChildSlotAlloc {
    next: u64,
    limit: u64,
}

impl ChildSlotAlloc {
    /// Create a new allocator that hands out slots in `[start, limit)`.
    pub fn new(start: u64, limit: u64) -> Self {
        Self { next: start, limit }
    }

    /// Allocate the next free slot, or return `None` if the cursor would
    /// cross `limit`.
    pub fn alloc(&mut self) -> Option<u64> {
        if self.next >= self.limit {
            return None;
        }
        let s = self.next;
        self.next += 1;
        Some(s)
    }

    /// Peek at the next slot the cursor will return without consuming it.
    pub fn next_free(&self) -> u64 {
        self.next
    }
}

/// Layout of well-known capabilities in a child's CSpace, as chosen by
/// the spawner for one specific spawn.
///
/// A field that is `0` means the corresponding capability was not minted
/// for this child — `spawn_server` may legitimately omit some caps (for
/// example, services spawned before procmgr have no procmgr control EP, and
/// services that do not use the rsrcsrv have no rsrcsrv EP).
#[derive(Clone, Copy)]
pub struct ChildCapLayout {
    pub self_tcb: u64,
    pub self_vspace: u64,
    pub self_cspace: u64,
    pub service_ep: u64,
    pub sc: u64,
    pub ready_ntfn: u64,
    pub initrd_untyped: u64,
    pub procmgr_ep: u64,
    pub rsrcsrv_ep: u64,
    pub frame_slot_start: u64,
}

impl ChildCapLayout {
    /// Build a layout by drawing slot positions from `alloc`.
    ///
    /// The first three allocations are pinned to 0/1/2 (kernel ABI for
    /// `CAP_SELF_TCB`/`VSPACE`/`CSPACE`). Everything else is whatever the
    /// cursor returns next.
    ///
    /// Returns `None` if the cursor runs out of slots, which would mean
    /// the child CNode is too small for the well-known cap set.
    pub fn from_alloc(alloc: &mut ChildSlotAlloc) -> Option<Self> {
        Some(Self {
            self_tcb: alloc.alloc()?,
            self_vspace: alloc.alloc()?,
            self_cspace: alloc.alloc()?,
            service_ep: alloc.alloc()?,
            sc: alloc.alloc()?,
            ready_ntfn: alloc.alloc()?,
            initrd_untyped: alloc.alloc()?,
            procmgr_ep: alloc.alloc()?,
            rsrcsrv_ep: alloc.alloc()?,
            frame_slot_start: CHILD_RTLD_FRAME_SLOT_START,
        })
    }
}

// init does not expose a `populate_cap_table` helper on `ChildCapLayout`:
// several of its cap_table entries are gated by context-dependent
// predicates in `spawn.rs` (`has_procmgr_ep`, `has_mm_ep`,
// `has_rsrcsrv_ep`, `has_initrd_untyped`, `child_cspace_ntfn_slot`) that
// also decide which legacy `AT_TRONA_*` tags are emitted. Rather than
// replicate those gates here, `spawn.rs` pushes role entries directly
// so the invariant "every legacy tag has a matching cap_table entry"
// lives in one place.
