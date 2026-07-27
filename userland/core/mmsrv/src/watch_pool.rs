// SPDX-License-Identifier: GPL-2.0-only
//
//! Watch slab — a fixed pool of pre-retyped `Watch` objects mmsrv
//! arms onto its service / fault EQs. Each `MM_REGISTER_CLIENT` and
//! `MM_REGISTER_FAULT_PIPE` consumes one entry; `MM_DEREGISTER_CLIENT`
//! returns it. Watches fire one-shot, so the dispatcher re-arms the
//! same cap after every drain via [`arm`].

use uapi::{KERNITE_INV_UNTYPED_RETYPE, KERNITE_OBJ_WATCH, KERNITE_STATE_READABLE};

use trona_server::frame_alloc::FrameAllocator;

/// Maximum number of Watch caps mmsrv keeps. One per active per-client
/// request MP plus one per active fault MP — sized for `MAX_CLIENTS +
/// MAX_FAULT_ENTRIES` worst case (128 + 256 = 384).
pub const WATCH_POOL_LEN: usize = 384;

pub struct WatchPool {
    /// Absolute CSpace slot of the i-th Watch cap, or 0 when retype
    /// failed for that index.
    slots: [u64; WATCH_POOL_LEN],
    /// Per-slot `active` flag; non-zero when the slot is rented out
    /// to a client/fault entry.
    active: [u8; WATCH_POOL_LEN],
    populated: usize,
}

impl WatchPool {
    pub const fn new() -> Self {
        Self {
            slots: [0; WATCH_POOL_LEN],
            active: [0; WATCH_POOL_LEN],
            populated: 0,
        }
    }

    /// Retype `count` Watch objects out of `frames` (mmsrv's own
    /// untyped pool) and place each cap at `base_slot + i`. The
    /// caller has already reserved `[base_slot .. base_slot + count)`
    /// in mmsrv's CSpace via `slot_alloc`.
    pub fn populate(&mut self, frames: &mut FrameAllocator, base_slot: u64, count: usize) -> bool {
        let n = count.min(WATCH_POOL_LEN);
        let mut produced = 0;
        for i in 0..n {
            let dest = base_slot + i as u64;
            // Walk the frame allocator's untyped chunks looking for
            // one with at least `KERNITE_WATCH_BYTES` (104B) free.
            // `alloc_watch` is a thin wrapper that runs
            // `UNTYPED_RETYPE(OBJ_WATCH)` against the first chunk
            // that succeeds.
            if !alloc_watch_into(frames, dest) {
                self.slots[i] = 0;
                continue;
            }
            self.slots[i] = dest;
            produced += 1;
        }
        self.populated = produced;
        produced > 0
    }

    /// Hand out an unused Watch cap. Returns the absolute slot or 0
    /// when the pool is empty.
    pub fn alloc(&mut self) -> u64 {
        for i in 0..self.populated {
            if self.active[i] == 0 && self.slots[i] != 0 {
                self.active[i] = 1;
                return self.slots[i];
            }
        }
        0
    }

    /// Return a Watch cap to the pool. Caller has already disarmed it
    /// (or knows the watched object is gone, which auto-detaches).
    pub fn free(&mut self, watch_cap: u64) {
        if watch_cap == 0 {
            return;
        }
        for i in 0..self.populated {
            if self.slots[i] == watch_cap {
                self.active[i] = 0;
                return;
            }
        }
    }
}

/// Arm a Watch over `watched_cap`'s `STATE_READABLE` bit on `eq_cap`
/// with the given cookie. Returns 0 on success, kernel error
/// otherwise.
pub fn arm(watch_cap: u64, watched_cap: u64, eq_cap: u64, cookie: u64) -> i32 {
    if watch_cap == 0 {
        return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
    }
    trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(watched_cap),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        KERNITE_STATE_READABLE as u64,
        cookie,
    )
}

fn alloc_watch_into(frames: &mut FrameAllocator, dest_slot: u64) -> bool {
    let chunk_count = frames.chunk_count();
    for idx in 0..chunk_count {
        let Some(chunk_cap) = frames.chunk_cap(idx) else {
            continue;
        };
        let r = trona_kernel::syscall::invoke(
            chunk_cap,
            KERNITE_INV_UNTYPED_RETYPE as u64,
            KERNITE_OBJ_WATCH as u64,
            0,
            dest_slot,
            0,
        );
        if r.error == 0 {
            frames.note_typed_child(idx);
            return true;
        }
    }
    false
}
