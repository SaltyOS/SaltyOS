// SPDX-License-Identifier: GPL-2.0-only
//! `BadgeMap` — O(1) badge-to-client lookup via open-addressing hash table.
//!
//! Replaces the O(n) scan in the old `get_client()`. Stores `(badge, slot,
//! epoch)` triples so the consumer can reconstruct a `Handle<ClientState>`
//! without BadgeMap knowing about ClientState.

const EMPTY_BADGE: u64 = 0;
const TOMBSTONE_BADGE: u64 = u64::MAX;

/// Open-addressing hash table entry.
#[repr(C)]
#[derive(Clone, Copy)]
struct Entry {
    badge: u64,
    slot: u32,
    epoch: u32,
}

impl Entry {
    const EMPTY: Self = Entry {
        badge: EMPTY_BADGE,
        slot: 0,
        epoch: 0,
    };
}

/// Fixed-capacity open-addressing hash map: `badge -> (slot, epoch)`.
///
/// Capacity is always a power of two. Load factor should stay below 75%.
/// Growth is not supported — choose a capacity large enough at init time.
pub(crate) struct BadgeMap {
    entries: *mut Entry,
    cap: u32,
    mask: u32,
    count: u32,
}

impl BadgeMap {
    /// Create a new BadgeMap with the given capacity (rounded up to power of 2).
    /// Returns `None` if allocation fails.
    pub(crate) fn new(min_cap: u32) -> Option<Self> {
        let cap = min_cap.next_power_of_two().max(16);
        let bytes = (cap as usize) * core::mem::size_of::<Entry>();
        let alloc_bytes = (bytes + 4095) & !4095;
        let ptr = unsafe { crate::server::mem::map_anon(alloc_bytes as u64) };
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return None;
        }
        // map_anon returns zeroed memory. badge=0 means EMPTY_BADGE.
        Some(BadgeMap {
            entries: ptr as *mut Entry,
            cap,
            mask: cap - 1,
            count: 0,
        })
    }

    /// Look up a badge. Returns `(slot, epoch)` if found.
    pub(crate) fn lookup(&self, badge: u64) -> Option<(u32, u32)> {
        if badge == EMPTY_BADGE || badge == TOMBSTONE_BADGE {
            return None;
        }
        let mut idx = self.hash(badge);
        for _ in 0..self.cap {
            let e = unsafe { &*self.entries.add(idx as usize) };
            if e.badge == badge {
                return Some((e.slot, e.epoch));
            }
            if e.badge == EMPTY_BADGE {
                return None;
            }
            idx = (idx + 1) & self.mask;
        }
        None
    }

    /// Insert or update a mapping. Returns `false` if the table is full.
    pub(crate) fn insert(&mut self, badge: u64, slot: u32, epoch: u32) -> bool {
        if badge == EMPTY_BADGE || badge == TOMBSTONE_BADGE {
            return false;
        }
        let mut idx = self.hash(badge);
        for _ in 0..self.cap {
            let e = unsafe { &mut *self.entries.add(idx as usize) };
            if e.badge == badge {
                // Update existing entry.
                e.slot = slot;
                e.epoch = epoch;
                return true;
            }
            if e.badge == EMPTY_BADGE || e.badge == TOMBSTONE_BADGE {
                e.badge = badge;
                e.slot = slot;
                e.epoch = epoch;
                self.count += 1;
                return true;
            }
            idx = (idx + 1) & self.mask;
        }
        false
    }

    /// Remove a badge mapping. Returns `true` if it was found and removed.
    pub(crate) fn remove(&mut self, badge: u64) -> bool {
        if badge == EMPTY_BADGE || badge == TOMBSTONE_BADGE {
            return false;
        }
        let mut idx = self.hash(badge);
        for _ in 0..self.cap {
            let e = unsafe { &mut *self.entries.add(idx as usize) };
            if e.badge == badge {
                e.badge = TOMBSTONE_BADGE;
                e.slot = 0;
                e.epoch = 0;
                self.count -= 1;
                return true;
            }
            if e.badge == EMPTY_BADGE {
                return false;
            }
            idx = (idx + 1) & self.mask;
        }
        false
    }

    /// Number of entries in the map.
    #[inline]
    pub(crate) fn len(&self) -> u32 {
        self.count
    }

    /// Fibonacci hashing: multiply by the golden-ratio constant and take
    /// the upper bits. Produces excellent distribution for sequential and
    /// semi-random badge values.
    #[inline]
    fn hash(&self, badge: u64) -> u32 {
        let h = badge.wrapping_mul(0x9E3779B97F4A7C15);
        ((h >> 32) as u32) & self.mask
    }
}
