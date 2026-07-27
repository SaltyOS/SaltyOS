// SPDX-License-Identifier: GPL-2.0-only
//! `BadgeMap` — O(1) badge-to-client lookup via open-addressing hash table.
//!
//! Replaces the O(n) scan in the old `get_client()`. Stores `(badge, slot,
//! epoch)` triples so the consumer can reconstruct a `Handle<ClientState>`
//! without BadgeMap knowing about ClientState.

const EMPTY_BADGE: u64 = 0;
const TOMBSTONE_BADGE: u64 = u64::MAX;

#[derive(Clone, Copy)]
pub(crate) struct NoSpace;

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
/// Capacity is always a power of two. The table grows on demand when the
/// live-entry load factor crosses 75%.
pub(crate) struct BadgeMap {
    entries: *mut Entry,
    cap: u32,
    mask: u32,
    count: u32,
}

impl BadgeMap {
    #[inline]
    fn alloc_bytes_for(cap: u32) -> u64 {
        let bytes = (cap as usize) * core::mem::size_of::<Entry>();
        ((bytes + 4095) & !4095) as u64
    }

    fn alloc_entries(cap: u32) -> Option<*mut Entry> {
        let ptr = unsafe { crate::server::mem::map_anon(Self::alloc_bytes_for(cap)) };
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            None
        } else {
            Some(ptr as *mut Entry)
        }
    }

    fn insert_no_grow(&mut self, badge: u64, slot: u32, epoch: u32) -> Result<(), NoSpace> {
        let mut idx = self.hash(badge);
        for _ in 0..self.cap {
            let e = unsafe { &mut *self.entries.add(idx as usize) };
            if e.badge == badge {
                e.slot = slot;
                e.epoch = epoch;
                return Ok(());
            }
            if e.badge == EMPTY_BADGE || e.badge == TOMBSTONE_BADGE {
                e.badge = badge;
                e.slot = slot;
                e.epoch = epoch;
                self.count += 1;
                return Ok(());
            }
            idx = (idx + 1) & self.mask;
        }
        Err(NoSpace)
    }

    fn grow(&mut self) -> Result<(), NoSpace> {
        let new_cap = self.cap.checked_mul(2).ok_or(NoSpace)?;
        let new_entries = Self::alloc_entries(new_cap).ok_or(NoSpace)?;

        let old_entries = self.entries;
        let old_cap = self.cap;

        self.entries = new_entries;
        self.cap = new_cap;
        self.mask = new_cap - 1;
        self.count = 0;

        for i in 0..old_cap {
            let e = unsafe { &*old_entries.add(i as usize) };
            if e.badge != EMPTY_BADGE && e.badge != TOMBSTONE_BADGE {
                self.insert_no_grow(e.badge, e.slot, e.epoch)?;
            }
        }

        unsafe {
            crate::server::mem::unmap(old_entries as *mut u8, Self::alloc_bytes_for(old_cap));
        }

        Ok(())
    }

    /// Create a new BadgeMap with the given capacity (rounded up to power of 2).
    /// Returns `None` if allocation fails.
    pub(crate) fn new(min_cap: u32) -> Option<Self> {
        let cap = min_cap.next_power_of_two().max(16);
        let ptr = Self::alloc_entries(cap)?;
        Some(BadgeMap {
            entries: ptr,
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

    /// Insert or update a mapping. Returns `Err(NoSpace)` if the table cannot
    /// accept the mapping.
    pub(crate) fn insert(&mut self, badge: u64, slot: u32, epoch: u32) -> Result<(), NoSpace> {
        if badge == EMPTY_BADGE || badge == TOMBSTONE_BADGE {
            return Err(NoSpace);
        }

        if self.lookup(badge).is_none()
            && self.count.saturating_add(1).saturating_mul(4) >= self.cap.saturating_mul(3)
        {
            self.grow()?;
        }

        self.insert_no_grow(badge, slot, epoch)
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

    /// Total bucket capacity.
    #[inline]
    pub(crate) fn capacity(&self) -> u32 {
        self.cap
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
