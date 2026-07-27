// SPDX-License-Identifier: GPL-2.0-only
//
//! Page cache — file-backed page residency tracker.
//!
//! mmsrv owns the address-space machinery (VSpace mappings, COW,
//! MAP_SHARED region tables); vfs owns the *content* of file-
//! backed pages. The page cache stores the bytes a `mmap(fd, ..)`
//! call should see for any given file offset, plus the dirty /
//! writeback state mmsrv interrogates through the pager callback
//! when it needs to evict or flush a page.
//!
//! Each [`PageCacheEntry`] records:
//!
//!   * the source vnode + page offset (cache key);
//!   * the [`PageState`] discriminator — Clean / Dirty / Writeback;
//!   * an LRU position and pin / refcount counters.
//!
//! The page cache is metadata-only: the actual page bytes live in
//! kernel-owned MO pages backed via the pager-cap path. Eviction
//! drops the cache entry; the kernel's MO ownership owns the
//! phys backing.
//!
//! Two indices track residency: a (vnode, offset) hash for
//! lookup-on-fault, and an intrusive doubly-linked LRU list rooted
//! in [`VfsState`] for eviction. Both indices live alongside the
//! [`Arena<PageCacheEntry>`] so the eviction path runs without a
//! second allocator.

use crate::arena::handle::Handle;
use crate::core::vnode::VnodeHandle;

/// Cache key — (`vnode`, `page_offset`) uniquely identifies a
/// resident page within vfs's view of the system.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PageKey {
    pub vnode: VnodeHandle,
    pub page_offset: u64,
}

/// Page lifecycle state.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageState {
    /// Slot unused.
    Empty = 0,
    /// Page contents match disk; eviction can drop the frame
    /// without writeback.
    Clean = 1,
    /// MAP_SHARED writer touched the page; eviction must
    /// `BACKEND_WRITE` before releasing the frame.
    Dirty = 2,
    /// `BACKEND_WRITE` is in flight against the dirty page;
    /// eviction must wait for the completion before reclaim.
    Writeback = 3,
}

/// One residency record. Placement-stable inside the arena;
/// raw pointers handed to mmsrv via the pager callback survive
/// arena segment grows.
#[repr(C)]
pub(crate) struct PageCacheEntry {
    pub key: PageKey,
    pub state: PageState,
    pub last_access_ns: u64,
    pub refcount: u32,
    pub pin_count: u32,
    /// Doubly-linked LRU pointers — slot indices into the same
    /// arena. `u32::MAX` for head / tail termination.
    pub lru_prev: u32,
    pub lru_next: u32,
}

impl PageCacheEntry {
    pub(crate) const EMPTY: Self = Self {
        key: PageKey {
            vnode: Handle::INVALID,
            page_offset: 0,
        },
        state: PageState::Empty,
        last_access_ns: 0,
        refcount: 0,
        pin_count: 0,
        lru_prev: u32::MAX,
        lru_next: u32::MAX,
    };
}

pub(crate) type PageCacheHandle = Handle<PageCacheEntry>;

/// Linear lookup — the arena is bounded by physical memory so the
/// scan stays fast in practice. A real hash index can be added
/// later without changing the call sites.
pub(crate) fn lookup(state: &crate::owner::VfsState, key: PageKey) -> Option<PageCacheHandle> {
    let mut found = None;
    state.page_cache.for_each_active(|h, e| {
        if e.state != PageState::Empty && e.key == key {
            found = Some(h);
            false
        } else {
            true
        }
    });
    found
}

/// Allocate a fresh `PageCacheEntry` for `key`. The cache is
/// metadata-only — page contents live in the kernel-owned MO
/// backing the file.
pub(crate) fn install(state: &mut crate::owner::VfsState, key: PageKey) -> Option<PageCacheHandle> {
    let h = state.page_cache.alloc()?;
    if let Some(e) = state.page_cache.get_mut(h) {
        *e = PageCacheEntry::EMPTY;
        e.key = key;
        e.state = PageState::Clean;
        e.refcount = 1;
        e.pin_count = 1;
    }
    crate::owner::page_cache_lru::insert_at_head(state, h);
    Some(h)
}

/// Record that the pager-cap path has supplied `key` into the
/// kernel-owned MO. The entry starts pinned while the supply path is
/// filling the frame, then immediately unpins after the kernel has
/// accepted it; vfs keeps only metadata after that point.
pub(crate) fn record_supplied_clean(
    state: &mut crate::owner::VfsState,
    key: PageKey,
    now_ns: u64,
) -> Option<PageCacheHandle> {
    let handle = match lookup(state, key) {
        Some(h) => h,
        None => install(state, key)?,
    };
    touch(state, handle, now_ns);
    unpin(state, handle);
    Some(handle)
}

/// Force the owner-side mirror back to Dirty. The kernel remains
/// the dirty-bit authority; this is used after failed writeback so
/// the reactor prioritizes a retry instead of waiting for another
/// full resident-page scan.
pub(crate) fn mark_dirty(state: &mut crate::owner::VfsState, handle: PageCacheHandle) {
    if let Some(e) = state.page_cache.get_mut(handle) {
        if matches!(e.state, PageState::Clean | PageState::Writeback) {
            e.state = PageState::Dirty;
        }
    }
}

/// Mark `handle` writeback-pending. Called once
/// `pager_rpc::issue_writeback` fires and the matching backend
/// completion has not yet landed.
pub(crate) fn mark_writeback(state: &mut crate::owner::VfsState, handle: PageCacheHandle) {
    if let Some(e) = state.page_cache.get_mut(handle) {
        if matches!(e.state, PageState::Dirty | PageState::Clean) {
            e.state = PageState::Writeback;
        }
    }
}

/// Mirror the kernel's "no dirty work pending" verdict for this
/// resident page. The kernel remains authoritative; this only keeps
/// the owner-side scheduler from treating a stale Dirty mirror as
/// mandatory writeback.
pub(crate) fn mark_clean(state: &mut crate::owner::VfsState, handle: PageCacheHandle) {
    if let Some(e) = state.page_cache.get_mut(handle) {
        if e.state != PageState::Empty {
            e.state = PageState::Clean;
        }
    }
}

/// Resolve a writeback to either Clean (success) or back to
/// Dirty (caller will retry on the next sweep).
pub(crate) fn complete_writeback(
    state: &mut crate::owner::VfsState,
    handle: PageCacheHandle,
    ok: bool,
) {
    let was_writeback = state
        .page_cache
        .get(handle)
        .map(|e| e.state == PageState::Writeback)
        .unwrap_or(false);
    if !was_writeback {
        return;
    }
    if ok {
        mark_clean(state, handle);
    } else {
        mark_dirty(state, handle);
    }
}

/// Drop `handle`'s pin and queue it for LRU eviction once
/// `refcount` reaches zero.
pub(crate) fn unpin(state: &mut crate::owner::VfsState, handle: PageCacheHandle) {
    if let Some(e) = state.page_cache.get_mut(handle) {
        e.pin_count = e.pin_count.saturating_sub(1);
        if e.pin_count == 0 {
            e.refcount = e.refcount.saturating_sub(1);
        }
    }
}

/// Bump `last_access_ns` and move `handle` to the head of the
/// LRU list. Called on every cache hit so eviction prefers
/// pages that nobody has touched recently.
pub(crate) fn touch(state: &mut crate::owner::VfsState, handle: PageCacheHandle, now_ns: u64) {
    if let Some(e) = state.page_cache.get_mut(handle) {
        e.last_access_ns = now_ns;
    }
    crate::owner::page_cache_lru::move_to_head(state, handle);
}

/// Try to reclaim the LRU tail page. Returns `true` if a page was
/// freed (or a stale mirror dropped). Non-droppable tails — pinned /
/// in-use, or a "Clean" mirror the kernel reports dirty — are rotated
/// to the head so a dirty-pinned tail cannot starve eviction, and the
/// call returns `false`. Used by the reactor's idle-tick reclaim hook.
///
/// The owner-side `PageState` is advisory: the kernel is the dirty-bit
/// authority. Before dropping a Clean mirror for a pager-backed page
/// this asks the kernel to evict the frame ([`invoke_pager_evict_page`]).
/// If the kernel finds it dirty the page is written back and rotated
/// rather than dropped, so no MAP_SHARED write is lost.
///
/// # Safety
/// Invokes the pager capability; must run on the owner thread with the
/// page cache and MO bindings consistent.
pub(crate) unsafe fn evict_one_clean(state: &mut crate::owner::VfsState) -> bool {
    let tail = state.page_cache_lru_tail;
    if tail == u32::MAX {
        return false;
    }
    let Some(handle) = state.page_cache.handle_from_slot(tail) else {
        if state.page_cache_lru_head == tail {
            state.page_cache_lru_head = u32::MAX;
        }
        state.page_cache_lru_tail = u32::MAX;
        return false;
    };

    let Some((key, page_state, refcount)) = state
        .page_cache
        .get(handle)
        .map(|e| (e.key, e.state, e.refcount))
    else {
        return false;
    };

    // Not a clean-eviction candidate (dirty / writeback in flight / pinned /
    // referenced): rotate off the tail so it cannot starve eviction. Any
    // dirty page drains through the reactor's writeback-budget sweep.
    if page_state != PageState::Clean || refcount != 0 {
        crate::owner::page_cache_lru::move_to_head(state, handle);
        return false;
    }

    // Clean mirror. Resolve the MO binding so we can consult the kernel
    // (the dirty authority) before dropping the entry.
    let pager_cap = state.pager_cap.as_raw();
    let Some(binding) = crate::owner::pager_rpc::lookup_binding_by_vnode(state, key.vnode) else {
        // No pager binding: not a kernel-backed file page (anonymous or
        // detached). The mirror is the only record — drop it.
        crate::owner::page_cache_lru::unlink(state, handle);
        let _ = state.page_cache.release(handle);
        return true;
    };
    if pager_cap == 0 || binding.mo_id == 0 || key.page_offset < binding.file_offset {
        // No usable pager path / offset before the bound region: the mirror
        // is orphaned — drop it.
        crate::owner::page_cache_lru::unlink(state, handle);
        let _ = state.page_cache.release(handle);
        return true;
    }
    let relative = key.page_offset - binding.file_offset;
    if relative % (uapi::KERNITE_PAGE_BYTES as u64) != 0 {
        // Misaligned mirror key (should not occur): leave it resident.
        crate::owner::page_cache_lru::move_to_head(state, handle);
        return false;
    }
    let page_idx = relative / (uapi::KERNITE_PAGE_BYTES as u64);

    match unsafe {
        crate::owner::pager_rpc::invoke_pager_evict_page(pager_cap, binding.mo_id, page_idx)
    } {
        crate::owner::pager_rpc::PagerEvict::Evicted
        | crate::owner::pager_rpc::PagerEvict::NotResident => {
            // Kernel freed the frame (or it was already gone). Drop the now-
            // stale mirror; a later fault re-supplies and re-tracks the page.
            crate::owner::page_cache_lru::unlink(state, handle);
            let _ = state.page_cache.release(handle);
            true
        }
        crate::owner::pager_rpc::PagerEvict::Dirty => {
            // Kernel reports this "Clean" mirror is actually dirty. Flush it
            // now so the write is not lost, then rotate off the tail; a later
            // sweep reclaims it once the writeback lands.
            let _ = unsafe { crate::owner::pager_rpc::writeback_handle(state, handle) };
            crate::owner::page_cache_lru::move_to_head(state, handle);
            false
        }
    }
}
