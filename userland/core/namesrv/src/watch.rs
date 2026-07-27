// SPDX-License-Identifier: GPL-2.0-only
//
//! `WatchSlab` — fixed-capacity pool of pre-retyped Watch caps that
//! namesrv arms against registered cap objects' `STATE_PEER_CLOSED`
//! bit. When a publisher process exits its registered cap closes; the
//! Watch fires; namesrv evicts the matching `NameEntry`.
//!
//! Watch caps come from init at boot (init retypes `KERNITE_OBJ_WATCH`
//! out of namesrv's untyped and delivers the slot range via
//! `ROLE_NAMESRV_WATCH_BASE`). Slab size is 16 — sized to the active
//! publisher count plus headroom; saturation refuses new REGISTERs
//! with `INSUFFICIENT_RESOURCES`.

pub const WATCH_SLAB_SIZE: usize = 16;

pub struct WatchSlab {
    base_slot: u64,
    used_bitmap: u32,
}

impl WatchSlab {
    pub const fn new() -> Self {
        Self {
            base_slot: 0,
            used_bitmap: 0,
        }
    }

    pub fn bind(&mut self, base_slot: u64) {
        self.base_slot = base_slot;
        self.used_bitmap = 0;
    }

    pub fn alloc(&mut self) -> Option<(u8, u64)> {
        for i in 0..WATCH_SLAB_SIZE {
            let bit = 1u32 << i;
            if self.used_bitmap & bit == 0 {
                self.used_bitmap |= bit;
                return Some((i as u8, self.base_slot + i as u64));
            }
        }
        None
    }

    pub fn free(&mut self, idx: u8) {
        let i = idx as usize;
        if i >= WATCH_SLAB_SIZE {
            return;
        }
        self.used_bitmap &= !(1u32 << i);
    }

    pub fn slot(&self, idx: u8) -> Option<u64> {
        let i = idx as usize;
        if i >= WATCH_SLAB_SIZE {
            return None;
        }
        if self.used_bitmap & (1u32 << i) == 0 {
            return None;
        }
        Some(self.base_slot + i as u64)
    }
}
