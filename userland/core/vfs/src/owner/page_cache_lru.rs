// SPDX-License-Identifier: GPL-2.0-only
//
//! Page-cache LRU intrusive doubly-linked list.
//!
//! [`PageCacheEntry`] carries `lru_prev` / `lru_next` slot
//! indices; the head and tail anchors live on [`VfsState`] as
//! `page_cache_lru_head` / `page_cache_lru_tail`. `u32::MAX`
//! marks list termination.
//!
//! Operations:
//! * [`move_to_head`] — promote on every cache hit so eviction
//!   prefers cold pages.
//! * [`unlink`] — remove from the list, typically just before
//!   release.
//! * [`insert_at_head`] — add a freshly installed entry.

use crate::owner::VfsState;
use crate::owner::page_cache::PageCacheHandle;

#[inline]
fn slot_of(h: PageCacheHandle) -> u32 {
    h.slot()
}

#[inline]
fn handle_from_slot(state: &VfsState, slot: u32) -> Option<PageCacheHandle> {
    if slot == u32::MAX {
        return None;
    }
    state.page_cache.handle_from_slot(slot)
}

/// Splice `handle` to the head of the LRU list. Idempotent — a
/// node already at the head is left untouched.
pub(crate) fn insert_at_head(state: &mut VfsState, handle: PageCacheHandle) {
    let slot = slot_of(handle);
    let old_head = state.page_cache_lru_head;
    if old_head == slot {
        return;
    }
    if let Some(e) = state.page_cache.get_mut(handle) {
        e.lru_prev = u32::MAX;
        e.lru_next = old_head;
    }
    if let Some(prev_head) = handle_from_slot(state, old_head) {
        if let Some(e) = state.page_cache.get_mut(prev_head) {
            e.lru_prev = slot;
        }
    }
    state.page_cache_lru_head = slot;
    if state.page_cache_lru_tail == u32::MAX {
        state.page_cache_lru_tail = slot;
    }
}

/// Detach `handle` from the LRU list. Safe to call on a node
/// that is not currently linked (a detached node has both
/// neighbours set to `u32::MAX`); the head / tail anchors are
/// updated only when this entry is the boundary.
pub(crate) fn unlink(state: &mut VfsState, handle: PageCacheHandle) {
    let slot = slot_of(handle);
    let (prev, next) = match state.page_cache.get(handle) {
        Some(e) => (e.lru_prev, e.lru_next),
        None => return,
    };
    if let Some(p) = handle_from_slot(state, prev) {
        if let Some(e) = state.page_cache.get_mut(p) {
            e.lru_next = next;
        }
    } else if state.page_cache_lru_head == slot {
        state.page_cache_lru_head = next;
    }
    if let Some(n) = handle_from_slot(state, next) {
        if let Some(e) = state.page_cache.get_mut(n) {
            e.lru_prev = prev;
        }
    } else if state.page_cache_lru_tail == slot {
        state.page_cache_lru_tail = prev;
    }
    if let Some(e) = state.page_cache.get_mut(handle) {
        e.lru_prev = u32::MAX;
        e.lru_next = u32::MAX;
    }
}

/// Move `handle` to the head of the LRU list — used by `touch`
/// on every cache hit.
pub(crate) fn move_to_head(state: &mut VfsState, handle: PageCacheHandle) {
    if state.page_cache_lru_head == slot_of(handle) {
        return;
    }
    unlink(state, handle);
    insert_at_head(state, handle);
}
