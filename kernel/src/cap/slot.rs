//! Global Capability Slot Array
//!
//! Fixed-address capability slots with separate metadata for CDT links.
//! Zero heap allocation - all slots are pre-allocated static array.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::Capability;

/// Maximum number of capability slots system-wide
/// 128K slots — sufficient for multi-level CNode trees with dynamic expansion
pub const MAX_SLOTS: usize = 131072;

/// Invalid slot marker (used as null pointer equivalent)
pub const INVALID_SLOT: CapSlot = 0xFFFF_FFFF;

/// Maximum capability derivation depth (prevents infinite loops)
pub const MAX_DERIVATION_DEPTH: u8 = 64;

/// Slot index type (32-bit allows up to 4B slots if needed)
pub type CapSlot = u32;

/// Slot state
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotState {
    Free = 0,
    Occupied = 1,
}

/// Slot metadata (separate from capability payload)
///
/// This struct contains all the CDT and untyped tracking information
/// that is NOT part of the 32-byte capability structure.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapSlotMeta {
    /// CDT: parent slot
    pub cdt_parent: CapSlot,

    /// CDT: first child slot (derivation tree children)
    pub cdt_first_child: CapSlot,

    /// CDT: next sibling
    pub cdt_next: CapSlot,

    /// CDT: previous sibling
    pub cdt_prev: CapSlot,

    /// Untyped: first child in untyped's child list (separate from CDT)
    pub ut_first_child: CapSlot,

    /// Untyped: next child in untyped's child list
    pub ut_next: CapSlot,

    /// Untyped: this object's parent untyped slot
    pub ut_parent: CapSlot,

    /// Slot state
    pub state: SlotState,
}

impl CapSlotMeta {
    /// Create metadata for a free slot
    pub const fn free() -> Self {
        Self {
            cdt_parent: INVALID_SLOT,
            cdt_first_child: INVALID_SLOT,
            cdt_next: INVALID_SLOT,
            cdt_prev: INVALID_SLOT,
            ut_first_child: INVALID_SLOT,
            ut_next: INVALID_SLOT,
            ut_parent: INVALID_SLOT,
            state: SlotState::Free,
        }
    }

    /// Create metadata for an occupied slot
    pub const fn occupied() -> Self {
        Self {
            cdt_parent: INVALID_SLOT,
            cdt_first_child: INVALID_SLOT,
            cdt_next: INVALID_SLOT,
            cdt_prev: INVALID_SLOT,
            ut_first_child: INVALID_SLOT,
            ut_next: INVALID_SLOT,
            ut_parent: INVALID_SLOT,
            state: SlotState::Occupied,
        }
    }
}

/// Slot storage (capability + metadata)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapSlotStorage {
    /// Capability payload (exactly 32 bytes)
    pub cap: Capability,

    /// Slot metadata (CDT links, untyped links, state)
    pub meta: CapSlotMeta,
}

/// Global slot array (static, no heap)
///
/// All capabilities in the system are stored here at fixed addresses.
/// CNodes contain references (slot indices) to these global slots.
///
/// # Safety
/// Direct access to this static is unsafe. Use the accessor functions
/// (get_cap, get_cap_mut, etc.) when possible. Raw pointer access is only
/// for carefully audited internal use (e.g., untyped child tracking).
pub static mut SLOTS: [CapSlotStorage; MAX_SLOTS] = [CapSlotStorage {
    cap: Capability::null(),
    meta: CapSlotMeta::free(),
}; MAX_SLOTS];

/// Slot bitmap for allocation tracking
/// Each bit represents one slot (1 = allocated, 0 = free)
static mut SLOT_BITMAP: [u64; MAX_SLOTS / 64] = [0; MAX_SLOTS / 64];

/// Next slot to check for allocation (simple optimization)
static mut NEXT_SLOT: CapSlot = 0;

/// Allocate a capability slot
///
/// Returns the slot index if allocation succeeds.
/// Returns None if all slots are exhausted.
pub fn alloc_slot() -> Option<CapSlot> {
    unsafe {
        // Start from NEXT_SLOT and wrap around if needed
        let start = NEXT_SLOT as usize;

        // Search from start to end
        for i in start..MAX_SLOTS {
            let idx = i / 64;
            let bit = i % 64;
            if (SLOT_BITMAP[idx] & (1 << bit)) == 0 {
                // Found free slot
                SLOT_BITMAP[idx] |= 1 << bit;
                SLOTS[i].meta = CapSlotMeta::occupied();
                NEXT_SLOT = (i + 1) as CapSlot;
                return Some(i as CapSlot);
            }
        }

        // Wrap around and search from 0 to start
        for i in 0..start {
            let idx = i / 64;
            let bit = i % 64;
            if (SLOT_BITMAP[idx] & (1 << bit)) == 0 {
                // Found free slot
                SLOT_BITMAP[idx] |= 1 << bit;
                SLOTS[i].meta = CapSlotMeta::occupied();
                NEXT_SLOT = (i + 1) as CapSlot;
                return Some(i as CapSlot);
            }
        }

        // All slots exhausted
        None
    }
}

/// Free a capability slot
///
/// # Safety
/// The slot must be empty (capability nullified) before freeing.
pub fn free_slot(slot: CapSlot) {
    let idx = slot as usize;
    if idx >= MAX_SLOTS {
        return;
    }

    unsafe {
        let bitmap_idx = idx / 64;
        let bit = idx % 64;
        SLOT_BITMAP[bitmap_idx] &= !(1 << bit);
        SLOTS[idx].meta = CapSlotMeta::free();

        // Update NEXT_SLOT if we freed a lower slot
        if (slot as usize) < NEXT_SLOT as usize {
            NEXT_SLOT = slot;
        }
    }
}

/// Get immutable reference to capability in slot
pub fn get_cap(slot: CapSlot) -> &'static Capability {
    unsafe { &SLOTS[slot as usize].cap }
}

/// Get mutable reference to capability in slot
pub fn get_cap_mut(slot: CapSlot) -> &'static mut Capability {
    unsafe { &mut SLOTS[slot as usize].cap }
}

/// Get immutable reference to slot metadata
pub fn get_meta(slot: CapSlot) -> &'static CapSlotMeta {
    unsafe { &SLOTS[slot as usize].meta }
}

/// Get mutable reference to slot metadata
pub fn get_meta_mut(slot: CapSlot) -> &'static mut CapSlotMeta {
    unsafe { &mut SLOTS[slot as usize].meta }
}

/// Nullify a capability (set to null capability)
///
/// This does NOT free the slot - it only nullifies the capability data.
/// Use free_slot() after nullifying to release the slot.
pub fn nullify_capability(slot: CapSlot) {
    let cap = get_cap_mut(slot);
    *cap = Capability::null();
}

/// Write capability to slot
///
/// # Safety
/// Caller must ensure slot is allocated and this write is synchronized.
pub fn write_capability(slot: CapSlot, cap: Capability) {
    let slot_cap = get_cap_mut(slot);
    *slot_cap = cap;
}

/// Check if slot contains a null capability
pub fn is_slot_null(slot: CapSlot) -> bool {
    get_cap(slot).is_null()
}

/// Get total number of allocated slots
pub fn allocated_count() -> usize {
    unsafe {
        let mut count = 0;
        for i in 0..(MAX_SLOTS / 64) {
            count += SLOT_BITMAP[i].count_ones() as usize;
        }
        count
    }
}

/// Get total number of free slots
pub fn free_count() -> usize {
    MAX_SLOTS - allocated_count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_allocation() {
        let slot1 = alloc_slot().unwrap();
        let slot2 = alloc_slot().unwrap();

        assert_ne!(slot1, slot2);
        // alloc_slot marks the slot as Occupied but does not populate the
        // capability payload, so is_slot_null() is still true.  Verify
        // occupation via metadata instead.
        assert_eq!(get_meta(slot1).state, SlotState::Occupied);
        assert_eq!(get_meta(slot2).state, SlotState::Occupied);

        free_slot(slot1);
        free_slot(slot2);
    }

    #[test]
    fn test_slot_metadata() {
        let slot = alloc_slot().unwrap();
        let meta = get_meta(slot);

        assert_eq!(meta.cdt_parent, INVALID_SLOT);
        assert_eq!(meta.state, SlotState::Occupied);

        free_slot(slot);
    }
}
