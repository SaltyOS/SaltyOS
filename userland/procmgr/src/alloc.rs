//! Centralized capability slot and object allocator for procmgr.
//!
//! Provides bitmap-based slot allocation, multi-untyped retype with
//! round-robin scan, and transactional reservations with rollback.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use salty::types::Cap;
use salty::serial::LineBuf;

// ---- Pool layout ----
/// Slots 0..255 are reserved for well-known caps (server EP, untypeds, etc.)
const SLOT_POOL_BASE: Cap = 256;
/// Total usable pool slots: 4096 - 256 = 3840
const SLOT_POOL_SIZE: usize = 3840;
/// Bitmap words: ceil(3840 / 64) = 60
const BITMAP_WORDS: usize = 60;

/// Maximum untyped sources we track
const MAX_UT_SOURCES: usize = 12;
/// Maximum objects per reservation
const MAX_RESERVE_OBJECTS: usize = 128;

// ---- Data structures ----

struct SlotBitmap {
    bits: [u64; BITMAP_WORDS],
    hint: usize,
}

impl SlotBitmap {
    const fn new() -> Self {
        SlotBitmap {
            bits: [0u64; BITMAP_WORDS],
            hint: 0,
        }
    }

    /// Allocate `count` contiguous free slots. Returns pool-relative base index.
    fn alloc_contiguous(&mut self, count: usize) -> Option<usize> {
        if count == 0 || count > SLOT_POOL_SIZE {
            return None;
        }
        if count == 1 {
            return self.alloc_single();
        }

        // Linear scan for `count` contiguous free bits
        let mut run_start = 0;
        let mut run_len = 0;

        for i in 0..SLOT_POOL_SIZE {
            let word = i / 64;
            let bit = i % 64;
            if (self.bits[word] & (1u64 << bit)) == 0 {
                if run_len == 0 {
                    run_start = i;
                }
                run_len += 1;
                if run_len == count {
                    // Mark all bits
                    for j in run_start..run_start + count {
                        let w = j / 64;
                        let b = j % 64;
                        self.bits[w] |= 1u64 << b;
                    }
                    return Some(run_start);
                }
            } else {
                run_len = 0;
            }
        }
        None
    }

    fn alloc_single(&mut self) -> Option<usize> {
        // Start from hint
        for i in self.hint..SLOT_POOL_SIZE {
            let word = i / 64;
            let bit = i % 64;
            if (self.bits[word] & (1u64 << bit)) == 0 {
                self.bits[word] |= 1u64 << bit;
                self.hint = i + 1;
                return Some(i);
            }
        }
        // Wrap around
        for i in 0..self.hint {
            let word = i / 64;
            let bit = i % 64;
            if (self.bits[word] & (1u64 << bit)) == 0 {
                self.bits[word] |= 1u64 << bit;
                self.hint = i + 1;
                return Some(i);
            }
        }
        None
    }

    /// Free `count` contiguous slots starting at pool-relative `base`.
    fn free_contiguous(&mut self, base: usize, count: usize) {
        for i in base..base + count {
            if i < SLOT_POOL_SIZE {
                let word = i / 64;
                let bit = i % 64;
                self.bits[word] &= !(1u64 << bit);
            }
        }
        if base < self.hint {
            self.hint = base;
        }
    }
}

struct UntypedSource {
    cap: Cap,
    active: bool,
}

impl UntypedSource {
    const fn empty() -> Self {
        UntypedSource {
            cap: 0,
            active: false,
        }
    }
}

struct ReservedObject {
    /// Absolute CSpace slot
    slot: Cap,
    /// Whether retype succeeded (needs revoke on rollback)
    committed: bool,
}

impl ReservedObject {
    const fn empty() -> Self {
        ReservedObject {
            slot: 0,
            committed: false,
        }
    }
}

struct Reservation {
    active: bool,
    /// Pool-relative base index
    pool_base: usize,
    /// Number of slots reserved
    slot_count: usize,
    /// Objects realized within this reservation
    objects: [ReservedObject; MAX_RESERVE_OBJECTS],
    object_count: usize,
    /// Next slot offset within reservation for sequential allocation
    next_offset: usize,
}

impl Reservation {
    const fn empty() -> Self {
        Reservation {
            active: false,
            pool_base: 0,
            slot_count: 0,
            objects: {
                const E: ReservedObject = ReservedObject::empty();
                [E; MAX_RESERVE_OBJECTS]
            },
            object_count: 0,
            next_offset: 0,
        }
    }
}

// ===========================================================================
// Allocator
// ===========================================================================

pub struct Allocator {
    bitmap: SlotBitmap,
    ut_sources: [UntypedSource; MAX_UT_SOURCES],
    ut_count: usize,
    ut_hint: usize,
    reservation: Reservation,
    cap_self_cspace: Cap,
}

impl Allocator {
    pub const fn new() -> Self {
        Allocator {
            bitmap: SlotBitmap::new(),
            ut_sources: {
                const E: UntypedSource = UntypedSource::empty();
                [E; MAX_UT_SOURCES]
            },
            ut_count: 0,
            ut_hint: 0,
            reservation: Reservation::empty(),
            cap_self_cspace: 0,
        }
    }

    /// Initialize the allocator. Call once at procmgr startup.
    ///
    /// - `cap_self_cspace`: procmgr's own CSpace cap (for revoke/delete)
    /// - `primary_ut`: main untyped cap (CAP_UNTYPED, slot 7)
    /// - `mirror_start`: first mirrored untyped slot (CAP_UNTYPED_START)
    /// - `mirror_count`: number of mirrored untyped caps
    pub fn init(
        &mut self,
        cap_self_cspace: Cap,
        primary_ut: Cap,
        _primary_ut_bits: u8,
        mirror_start: Cap,
        mirror_count: usize,
    ) {
        self.cap_self_cspace = cap_self_cspace;

        // Register primary untyped
        self.ut_sources[0] = UntypedSource {
            cap: primary_ut,
            active: true,
        };
        self.ut_count = 1;

        // Register mirror untyped sources
        for i in 0..mirror_count {
            if self.ut_count >= MAX_UT_SOURCES {
                break;
            }
            let cap = mirror_start + i as u64;
            self.ut_sources[self.ut_count] = UntypedSource {
                cap,
                active: true,
            };
            self.ut_count += 1;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] Allocator: ");
            lb.hex(self.ut_count as u64);
            lb.str(b" untyped sources\n");
            lb.flush();
        }
    }

    // -----------------------------------------------------------------------
    // Slot allocation (absolute CSpace slots)
    // -----------------------------------------------------------------------

    /// Allocate `count` contiguous CSpace slots.
    /// Returns (absolute_base, count) or None.
    pub fn alloc_slots(&mut self, count: usize) -> Option<(Cap, usize)> {
        let pool_idx = self.bitmap.alloc_contiguous(count)?;
        Some((SLOT_POOL_BASE + pool_idx as Cap, count))
    }

    /// Free `count` contiguous CSpace slots starting at `base`.
    pub fn free_slots(&mut self, base: Cap, count: usize) {
        if base < SLOT_POOL_BASE {
            return;
        }
        let pool_idx = (base - SLOT_POOL_BASE) as usize;
        self.bitmap.free_contiguous(pool_idx, count);
    }

    /// Allocate a single CSpace slot.
    pub fn alloc_single_slot(&mut self) -> Option<Cap> {
        let pool_idx = self.bitmap.alloc_single()?;
        Some(SLOT_POOL_BASE + pool_idx as Cap)
    }

    /// Free a single CSpace slot.
    pub fn free_single_slot(&mut self, slot: Cap) {
        if slot < SLOT_POOL_BASE {
            return;
        }
        let pool_idx = (slot - SLOT_POOL_BASE) as usize;
        self.bitmap.free_contiguous(pool_idx, 1);
    }

    // -----------------------------------------------------------------------
    // Multi-untyped retype
    // -----------------------------------------------------------------------

    /// Retype an object from any available untyped source.
    /// Scans from `ut_hint` with wrap-around.
    pub fn retype_any(&mut self, obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
        if self.ut_count == 0 {
            return salty::SALTY_OUT_OF_MEMORY as i32;
        }

        let start = if self.ut_hint < self.ut_count {
            self.ut_hint
        } else {
            0
        };

        let mut best_err = salty::SALTY_OUT_OF_MEMORY as i32;

        // First pass: from hint to end
        for i in start..self.ut_count {
            if !self.ut_sources[i].active {
                continue;
            }
            let err = salty::invoke::untyped_retype(
                self.ut_sources[i].cap,
                obj_type,
                size_bits,
                dest_slot,
            );
            if err == 0 {
                self.ut_hint = i;
                return 0;
            }
            if err != salty::SALTY_INVALID_CAPABILITY as i32
                && err != salty::SALTY_INVALID_OPERATION as i32
                && err != salty::SALTY_NOT_FOUND as i32
            {
                best_err = err;
            }
        }

        // Second pass: wrap around
        for i in 0..start {
            if !self.ut_sources[i].active {
                continue;
            }
            let err = salty::invoke::untyped_retype(
                self.ut_sources[i].cap,
                obj_type,
                size_bits,
                dest_slot,
            );
            if err == 0 {
                self.ut_hint = i;
                return 0;
            }
            if err != salty::SALTY_INVALID_CAPABILITY as i32
                && err != salty::SALTY_INVALID_OPERATION as i32
                && err != salty::SALTY_NOT_FOUND as i32
            {
                best_err = err;
            }
        }

        best_err
    }

    // -----------------------------------------------------------------------
    // Transactional reservation
    // -----------------------------------------------------------------------

    /// Reserve `total_slots` contiguous capability slots for a spawn operation.
    /// Only one reservation can be active at a time (single-threaded procmgr).
    pub fn reserve(&mut self, total_slots: usize) -> bool {
        if self.reservation.active {
            return false;
        }
        let pool_idx = match self.bitmap.alloc_contiguous(total_slots) {
            Some(idx) => idx,
            None => return false,
        };
        self.reservation = Reservation {
            active: true,
            pool_base: pool_idx,
            slot_count: total_slots,
            objects: {
                const E: ReservedObject = ReservedObject::empty();
                [E; MAX_RESERVE_OBJECTS]
            },
            object_count: 0,
            next_offset: 0,
        };
        true
    }

    /// Get the absolute CSpace slot for the Nth object in the reservation.
    pub fn reservation_slot(&self, offset: usize) -> Cap {
        SLOT_POOL_BASE + (self.reservation.pool_base + offset) as Cap
    }

    /// Realize (retype) a kernel object into the next available reservation slot.
    /// Records the object for potential rollback.
    pub fn realize_object(&mut self, obj_type: u64, size_bits: u64) -> Result<Cap, i32> {
        if !self.reservation.active {
            return Err(salty::SALTY_INVALID_OPERATION as i32);
        }
        if self.reservation.next_offset >= self.reservation.slot_count {
            return Err(salty::SALTY_OUT_OF_MEMORY as i32);
        }
        if self.reservation.object_count >= MAX_RESERVE_OBJECTS {
            return Err(salty::SALTY_OUT_OF_MEMORY as i32);
        }

        let slot = self.reservation_slot(self.reservation.next_offset);
        self.reservation.next_offset += 1;

        let err = self.retype_any(obj_type, size_bits, slot);
        if err != 0 {
            return Err(err);
        }

        let obj_idx = self.reservation.object_count;
        self.reservation.objects[obj_idx] = ReservedObject {
            slot,
            committed: true,
        };
        self.reservation.object_count += 1;

        Ok(slot)
    }

    /// Realize a kernel object into a specific offset within the reservation.
    pub fn realize_object_at(
        &mut self,
        obj_type: u64,
        size_bits: u64,
        offset: usize,
    ) -> Result<Cap, i32> {
        if !self.reservation.active {
            return Err(salty::SALTY_INVALID_OPERATION as i32);
        }
        if offset >= self.reservation.slot_count {
            return Err(salty::SALTY_OUT_OF_MEMORY as i32);
        }
        if self.reservation.object_count >= MAX_RESERVE_OBJECTS {
            return Err(salty::SALTY_OUT_OF_MEMORY as i32);
        }

        let slot = self.reservation_slot(offset);
        let err = self.retype_any(obj_type, size_bits, slot);
        if err != 0 {
            return Err(err);
        }

        // Update next_offset if needed
        if offset >= self.reservation.next_offset {
            self.reservation.next_offset = offset + 1;
        }

        let obj_idx = self.reservation.object_count;
        self.reservation.objects[obj_idx] = ReservedObject {
            slot,
            committed: true,
        };
        self.reservation.object_count += 1;

        Ok(slot)
    }

    /// Commit the reservation: mark it inactive, slots stay allocated.
    /// Returns (base, count) for recording in process table.
    pub fn commit(&mut self) -> (Cap, u16) {
        let base = SLOT_POOL_BASE + self.reservation.pool_base as Cap;
        let count = self.reservation.slot_count as u16;
        self.reservation.active = false;
        (base, count)
    }

    /// Rollback: revoke+delete all realized objects in reverse order,
    /// then free the reserved slots.
    pub fn rollback(&mut self) {
        if !self.reservation.active {
            return;
        }

        // Revoke+delete in reverse order
        let mut i = self.reservation.object_count;
        while i > 0 {
            i -= 1;
            let obj = &self.reservation.objects[i];
            if obj.committed {
                let err = salty::invoke::cnode_revoke(self.cap_self_cspace, obj.slot);
                if err != 0 {
                    salty::invoke::cnode_delete(self.cap_self_cspace, obj.slot);
                }
            }
        }

        // Free bitmap slots
        self.bitmap.free_contiguous(
            self.reservation.pool_base,
            self.reservation.slot_count,
        );

        self.reservation = Reservation::empty();
    }

}
