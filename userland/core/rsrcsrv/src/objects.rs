// SPDX-License-Identifier: GPL-2.0-only
//
//! Vending-class size table and `ObjectRecord` storage.
//!
//! NUM_OBJ_CLASSES = 12 covers the resource classes rsrcsrv may vend.
//! FRAME / MEMORY_OBJECT / system caps / device authority (IRQ_HANDLER /
//! IO_PORT, which are DeviceControl-minted) / NULL / UNTYPED are rejected up
//! front. The IRQ_HANDLER / IO_PORT class ids stay reserved (cost table) to
//! keep the quota wire stable, but `class_of` no longer maps to them.

use uapi::{
    KERNITE_CNODE_HEADER_BYTES, KERNITE_CNODE_SLOT_BYTES, KERNITE_DATA_PIPE_BYTES,
    KERNITE_DATA_PIPE_CORE_BYTES, KERNITE_EVENT_QUEUE_BYTES, KERNITE_IO_PORT_BYTES,
    KERNITE_IRQ_HANDLER_BYTES, KERNITE_MESSAGE_PIPE_BYTES, KERNITE_MESSAGE_PIPE_CORE_BYTES,
    KERNITE_OBJ_CNODE, KERNITE_OBJ_DATA_PIPE, KERNITE_OBJ_DATA_PIPE_CORE, KERNITE_OBJ_EVENT_QUEUE,
    KERNITE_OBJ_MESSAGE_PIPE, KERNITE_OBJ_MESSAGE_PIPE_CORE, KERNITE_OBJ_PAGER,
    KERNITE_OBJ_SCHED_CONTEXT, KERNITE_OBJ_TCB, KERNITE_OBJ_TIMER, KERNITE_OBJ_VSPACE,
    KERNITE_PAGER_BYTES, KERNITE_SCHED_CONTEXT_BYTES, KERNITE_TCB_BYTES, KERNITE_TIMER_BYTES,
    KERNITE_VSPACE_BYTES, KERNITE_WATCH_BYTES,
};

pub const NUM_OBJ_CLASSES: usize = 12;
pub const MAX_OBJECTS: usize = 1024;

pub const CLASS_TCB: usize = 0;
pub const CLASS_CNODE: usize = 1;
pub const CLASS_VSPACE: usize = 2;
pub const CLASS_SCHED_CONTEXT: usize = 3;
pub const CLASS_EVENT_QUEUE: usize = 4;
pub const CLASS_WATCH: usize = 5;
pub const CLASS_MP_PAIR: usize = 6;
pub const CLASS_DP_PAIR: usize = 7;
pub const CLASS_TIMER: usize = 8;
pub const CLASS_IRQ_HANDLER: usize = 9;
pub const CLASS_IO_PORT: usize = 10;
pub const CLASS_PAGER: usize = 11;

/// Map a `KERNITE_OBJ_*` to its vending class. Returns `None` for types
/// rsrcsrv refuses: FRAME / MO / system caps / NULL / UNTYPED, and the
/// device-authority types IRQ_HANDLER / IO_PORT (DeviceControl-minted only).
pub fn class_of(obj_type: u64) -> Option<usize> {
    match obj_type {
        x if x == KERNITE_OBJ_TCB => Some(CLASS_TCB),
        x if x == KERNITE_OBJ_CNODE => Some(CLASS_CNODE),
        x if x == KERNITE_OBJ_VSPACE => Some(CLASS_VSPACE),
        x if x == KERNITE_OBJ_SCHED_CONTEXT => Some(CLASS_SCHED_CONTEXT),
        x if x == KERNITE_OBJ_EVENT_QUEUE => Some(CLASS_EVENT_QUEUE),
        x if x == uapi::KERNITE_OBJ_WATCH => Some(CLASS_WATCH),
        x if x == KERNITE_OBJ_MESSAGE_PIPE_CORE || x == KERNITE_OBJ_MESSAGE_PIPE => {
            Some(CLASS_MP_PAIR)
        }
        x if x == KERNITE_OBJ_DATA_PIPE_CORE || x == KERNITE_OBJ_DATA_PIPE => Some(CLASS_DP_PAIR),
        x if x == KERNITE_OBJ_TIMER => Some(CLASS_TIMER),
        // IrqHandler / IoPort are device authority: minted only via the
        // DeviceControl capability (create_irq_handler / create_ioport), never
        // vended by generic retype. Refused here so rsrcsrv never attempts a
        // retype the kernel now rejects at the UntypedMemory::retype primitive.
        // Their CLASS ids stay reserved (cost table) to keep the quota wire stable.
        x if x == KERNITE_OBJ_PAGER => Some(CLASS_PAGER),
        _ => None,
    }
}

/// Byte cost charged against a quota for one retype of `class` at
/// `size_bits`. Variable-size classes (CNode) use `size_bits` to compute
/// the actual byte count; fixed-size classes ignore it.
pub fn class_cost_bytes(class: usize, size_bits: u64) -> u64 {
    match class {
        CLASS_TCB => KERNITE_TCB_BYTES,
        CLASS_CNODE => {
            let slots = 1u64 << size_bits;
            KERNITE_CNODE_HEADER_BYTES + slots * KERNITE_CNODE_SLOT_BYTES
        }
        CLASS_VSPACE => KERNITE_VSPACE_BYTES,
        CLASS_SCHED_CONTEXT => KERNITE_SCHED_CONTEXT_BYTES,
        CLASS_EVENT_QUEUE => KERNITE_EVENT_QUEUE_BYTES,
        CLASS_WATCH => KERNITE_WATCH_BYTES,
        CLASS_MP_PAIR => KERNITE_MESSAGE_PIPE_CORE_BYTES + 2 * KERNITE_MESSAGE_PIPE_BYTES,
        CLASS_DP_PAIR => KERNITE_DATA_PIPE_CORE_BYTES + 2 * KERNITE_DATA_PIPE_BYTES,
        CLASS_TIMER => KERNITE_TIMER_BYTES,
        CLASS_IRQ_HANDLER => KERNITE_IRQ_HANDLER_BYTES,
        CLASS_IO_PORT => KERNITE_IO_PORT_BYTES,
        CLASS_PAGER => KERNITE_PAGER_BYTES,
        _ => 0,
    }
}

/// Approximate `size_bits` argument to `KERNITE_INV_UNTYPED_RETYPE`
/// for a given class. CNode passes its caller-supplied `size_bits`
/// directly; others ignore it (the kernel's retype size is fixed by
/// the type ID alone). For pair allocations the call site does two
/// separate retypes — the side-handle retype uses
/// `KERNITE_OBJ_MESSAGE_PIPE` / `_DATA_PIPE` with size_bits = 0.
pub fn class_size_bits_default(class: usize, requested: u64) -> u64 {
    match class {
        CLASS_CNODE => requested,
        _ => 0,
    }
}

#[derive(Clone, Copy)]
pub struct ObjectRecord {
    pub epoch: u32,
    pub obj_type: u16,
    pub size_bits: u8,
    pub class: u8,
    pub pair_group: u32,
    /// Caller's `client_id` (badge low 32 bits, parsed via
    /// `authz::BadgeFields`). Replaces the previous opaque 64-bit
    /// `owner_badge` so the record's owner key matches OwnerTable
    /// keys and is consistent with namesrv's publisher table.
    pub owner_id: u32,
    pub back_ref_slot: u64,
    pub parent_chunk_idx: u16,
    pub bytes: u32,
    pub active: u8,
}

impl ObjectRecord {
    pub const fn empty() -> Self {
        Self {
            epoch: 0,
            obj_type: 0,
            size_bits: 0,
            class: 0,
            pair_group: u32::MAX,
            owner_id: 0,
            back_ref_slot: 0,
            parent_chunk_idx: 0,
            bytes: 0,
            active: 0,
        }
    }
}

pub struct ObjectTable {
    records: [ObjectRecord; MAX_OBJECTS],
    used: u32,
}

impl ObjectTable {
    pub const fn new() -> Self {
        Self {
            records: [ObjectRecord::empty(); MAX_OBJECTS],
            used: 0,
        }
    }

    pub fn alloc(&mut self) -> Option<usize> {
        for (idx, r) in self.records.iter().enumerate() {
            if r.active == 0 {
                return Some(idx);
            }
        }
        None
    }

    pub fn record(&self, idx: usize) -> Option<&ObjectRecord> {
        self.records.get(idx).filter(|r| r.active != 0)
    }

    pub fn install(
        &mut self,
        idx: usize,
        obj_type: u64,
        size_bits: u8,
        class: usize,
        pair_group: u32,
        owner_id: u32,
        back_ref_slot: u64,
        parent_chunk_idx: usize,
        bytes: u32,
    ) -> u64 {
        let r = &mut self.records[idx];
        r.epoch = r.epoch.wrapping_add(1);
        r.obj_type = obj_type as u16;
        r.size_bits = size_bits;
        r.class = class as u8;
        r.pair_group = pair_group;
        r.owner_id = owner_id;
        r.back_ref_slot = back_ref_slot;
        r.parent_chunk_idx = parent_chunk_idx as u16;
        r.bytes = bytes;
        r.active = 1;
        self.used += 1;
        pack_record_id(r.epoch, idx as u32)
    }

    pub fn vacate(&mut self, idx: usize) -> Option<ObjectRecord> {
        let r = self.records.get_mut(idx)?;
        if r.active == 0 {
            return None;
        }
        let snapshot = *r;
        r.active = 0;
        r.back_ref_slot = 0;
        r.bytes = 0;
        r.owner_id = 0;
        r.pair_group = u32::MAX;
        self.used = self.used.saturating_sub(1);
        Some(snapshot)
    }

    pub fn used(&self) -> u32 {
        self.used
    }
}

pub fn pack_record_id(epoch: u32, idx: u32) -> u64 {
    ((epoch as u64) << 32) | idx as u64
}

pub fn unpack_record_id(record_id: u64) -> (u32, u32) {
    ((record_id >> 32) as u32, (record_id & 0xFFFF_FFFF) as u32)
}
