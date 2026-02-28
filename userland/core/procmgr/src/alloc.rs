//! Centralized capability slot and object allocator for procmgr.
//!
//! Provides bitmap-based slot allocation, multi-untyped retype with
//! round-robin scan, and transactional reservations with rollback.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use besalt::serial::LineBuf;
use besalt::types::Cap;

// ---- Pool layout ----
/// Slots 0..255 are reserved for well-known caps (server EP, untypeds, etc.)
const SLOT_POOL_BASE: Cap = 256;
/// Total usable pool slots: 4096 - 256 = 3840
const SLOT_POOL_SIZE: usize = 3840;
/// Bitmap words: ceil(3840 / 64) = 60
const BITMAP_WORDS: usize = 60;

/// Maximum untyped sources we track
const MAX_UT_SOURCES: usize = 12;
/// Maximum objects tracked explicitly per reservation.
/// Rollback also sweeps the full reserved slot range, so tracking is best-effort.
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

    /// Mark a pool-relative slot as occupied by non-allocator state.
    fn mark_used(&mut self, index: usize) {
        if index >= SLOT_POOL_SIZE {
            return;
        }
        let word = index / 64;
        let bit = index % 64;
        self.bits[word] |= 1u64 << bit;
        if index == self.hint {
            while self.hint < SLOT_POOL_SIZE {
                let w = self.hint / 64;
                let b = self.hint % 64;
                if (self.bits[w] & (1u64 << b)) == 0 {
                    break;
                }
                self.hint += 1;
            }
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
            self.ut_sources[self.ut_count] = UntypedSource { cap, active: true };
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

    /// Mark a pre-existing CSpace slot as used so allocator reservations
    /// never overlap inherited/static capabilities.
    pub fn mark_slot_used(&mut self, slot: Cap) {
        if slot < SLOT_POOL_BASE {
            return;
        }
        let pool_idx = (slot - SLOT_POOL_BASE) as usize;
        self.bitmap.mark_used(pool_idx);
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
            return besalt::BESALT_OUT_OF_MEMORY as i32;
        }

        let start = if self.ut_hint < self.ut_count {
            self.ut_hint
        } else {
            0
        };

        let mut best_err = besalt::BESALT_OUT_OF_MEMORY as i32;

        // First pass: from hint to end
        for i in start..self.ut_count {
            if !self.ut_sources[i].active {
                continue;
            }
            let err = besalt::invoke::untyped_retype(
                self.ut_sources[i].cap,
                obj_type,
                size_bits,
                dest_slot,
            );
            if err == 0 {
                self.ut_hint = i;
                return 0;
            }
            best_err = err;
        }

        // Second pass: wrap around
        for i in 0..start {
            if !self.ut_sources[i].active {
                continue;
            }
            let err = besalt::invoke::untyped_retype(
                self.ut_sources[i].cap,
                obj_type,
                size_bits,
                dest_slot,
            );
            if err == 0 {
                self.ut_hint = i;
                return 0;
            }
            best_err = err;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] retype_any: all ");
            lb.hex(self.ut_count as u64);
            lb.str(b" sources failed, best_err=");
            lb.hex(best_err as u64);
            lb.str(b" dest=");
            lb.hex(dest_slot);
            lb.str(b" type=");
            lb.hex(obj_type);
            lb.str(b" bits=");
            lb.hex(size_bits);
            lb.str(b"\n");
            lb.flush();
        }
        best_err
    }

    /// Retype a core kernel object (TCB/VSpace/CNode/SchedContext).
    ///
    /// Prefers the primary untyped (index 0, CAP_UNTYPED slot) before falling
    /// back to mirrors. This reduces fragmentation and keeps core objects in a
    /// predictable region of the untyped pool.
    pub fn retype_core_object(&mut self, obj_type: u64, size_bits: u64, dest_slot: Cap) -> i32 {
        if self.ut_count == 0 {
            return besalt::BESALT_OUT_OF_MEMORY as i32;
        }

        // Try primary untyped first (index 0)
        if self.ut_sources[0].active {
            let err = besalt::invoke::untyped_retype(
                self.ut_sources[0].cap,
                obj_type,
                size_bits,
                dest_slot,
            );
            if err == 0 {
                self.ut_hint = 0;
                return 0;
            }
        }

        // Fallback: scan mirrors (indices 1..ut_count)
        let mut best_err = besalt::BESALT_OUT_OF_MEMORY as i32;
        for i in 1..self.ut_count {
            if !self.ut_sources[i].active {
                continue;
            }
            let err = besalt::invoke::untyped_retype(
                self.ut_sources[i].cap,
                obj_type,
                size_bits,
                dest_slot,
            );
            if err == 0 {
                self.ut_hint = i;
                return 0;
            }
            best_err = err;
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] retype_core_object: all ");
            lb.hex(self.ut_count as u64);
            lb.str(b" sources failed, best_err=");
            lb.hex(best_err as u64);
            lb.str(b" dest=");
            lb.hex(dest_slot);
            lb.str(b" type=");
            lb.hex(obj_type);
            lb.str(b" bits=");
            lb.hex(size_bits);
            lb.str(b"\n");
            lb.flush();
        }
        best_err
    }

    /// Realize a core kernel object (TCB/VSpace/CNode/SchedContext) into the
    /// next available reservation slot, preferring the primary untyped source.
    pub fn realize_core_object(&mut self, obj_type: u64, size_bits: u64) -> Result<Cap, i32> {
        if !self.reservation.active {
            return Err(besalt::BESALT_INVALID_OPERATION as i32);
        }
        if self.reservation.next_offset >= self.reservation.slot_count {
            return Err(besalt::BESALT_OUT_OF_MEMORY as i32);
        }

        let slot = self.reservation_slot(self.reservation.next_offset);
        self.reservation.next_offset += 1;

        let err = self.retype_core_object(obj_type, size_bits, slot);
        if err != 0 {
            return Err(err);
        }

        if self.reservation.object_count < MAX_RESERVE_OBJECTS {
            let obj_idx = self.reservation.object_count;
            self.reservation.objects[obj_idx] = ReservedObject {
                slot,
                committed: true,
            };
            self.reservation.object_count += 1;
        }

        Ok(slot)
    }

    /// Realize a core kernel object into a specific offset within the reservation,
    /// preferring the primary untyped source.
    pub fn realize_core_object_at(
        &mut self,
        obj_type: u64,
        size_bits: u64,
        offset: usize,
    ) -> Result<Cap, i32> {
        if !self.reservation.active {
            return Err(besalt::BESALT_INVALID_OPERATION as i32);
        }
        if offset >= self.reservation.slot_count {
            return Err(besalt::BESALT_OUT_OF_MEMORY as i32);
        }

        let slot = self.reservation_slot(offset);
        let err = self.retype_core_object(obj_type, size_bits, slot);
        if err != 0 {
            return Err(err);
        }

        if offset >= self.reservation.next_offset {
            self.reservation.next_offset = offset + 1;
        }

        if self.reservation.object_count < MAX_RESERVE_OBJECTS {
            let obj_idx = self.reservation.object_count;
            self.reservation.objects[obj_idx] = ReservedObject {
                slot,
                committed: true,
            };
            self.reservation.object_count += 1;
        }

        Ok(slot)
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
            return Err(besalt::BESALT_INVALID_OPERATION as i32);
        }
        if self.reservation.next_offset >= self.reservation.slot_count {
            return Err(besalt::BESALT_OUT_OF_MEMORY as i32);
        }

        let slot = self.reservation_slot(self.reservation.next_offset);
        self.reservation.next_offset += 1;

        let err = self.retype_any(obj_type, size_bits, slot);
        if err != 0 {
            return Err(err);
        }

        if self.reservation.object_count < MAX_RESERVE_OBJECTS {
            let obj_idx = self.reservation.object_count;
            self.reservation.objects[obj_idx] = ReservedObject {
                slot,
                committed: true,
            };
            self.reservation.object_count += 1;
        }

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
            return Err(besalt::BESALT_INVALID_OPERATION as i32);
        }
        if offset >= self.reservation.slot_count {
            return Err(besalt::BESALT_OUT_OF_MEMORY as i32);
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

        if self.reservation.object_count < MAX_RESERVE_OBJECTS {
            let obj_idx = self.reservation.object_count;
            self.reservation.objects[obj_idx] = ReservedObject {
                slot,
                committed: true,
            };
            self.reservation.object_count += 1;
        }

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

        // Revoke+delete full reserved range to handle reservations that
        // realized more objects than explicit tracking capacity.
        for off in 0..self.reservation.slot_count {
            let slot = SLOT_POOL_BASE + (self.reservation.pool_base + off) as Cap;
            let err = besalt::invoke::cnode_revoke(self.cap_self_cspace, slot);
            if err != 0 {
                besalt::invoke::cnode_delete(self.cap_self_cspace, slot);
            }
        }

        // Free bitmap slots
        self.bitmap
            .free_contiguous(self.reservation.pool_base, self.reservation.slot_count);

        self.reservation = Reservation::empty();
    }
}
