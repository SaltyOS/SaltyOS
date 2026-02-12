//! Global Capability Slot Array
//!
//! Dynamically-allocated capability slots with separate metadata for CDT links.
//! Slot count is determined at boot based on available physical memory.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::Capability;

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

/// Dynamic slot array state
struct SlotArrayState {
    /// Pointer to dynamically-allocated SLOTS array
    slots_ptr: *mut CapSlotStorage,
    /// Pointer to dynamically-allocated bitmap
    bitmap_ptr: *mut u64,
    /// Number of slots in the array
    num_slots: usize,
}

// SAFETY: Pointers are only accessed under CAP_LOCK
unsafe impl Sync for SlotArrayState {}

/// Global dynamic slot state (initialized by init_slots)
static mut SLOT_STATE: SlotArrayState = SlotArrayState {
    slots_ptr: core::ptr::null_mut(),
    bitmap_ptr: core::ptr::null_mut(),
    num_slots: 0,
};

/// Next slot to check for allocation (simple optimization)
static mut NEXT_SLOT: CapSlot = 0;

/// Initialize dynamic slot array.
///
/// Allocates contiguous physical frames for the SLOTS array and bitmap,
/// then initializes all slots as free.
///
/// # Safety
/// Must be called exactly once during boot, after paging::init().
/// The direct physical map must be available.
pub unsafe fn init_slots(num_slots: usize) {
    use crate::mm::{self, PAGE_SIZE};

    let slot_size = core::mem::size_of::<CapSlotStorage>();
    let slots_bytes = num_slots * slot_size;
    let slots_pages = (slots_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    let bitmap_words = (num_slots + 63) / 64;
    let bitmap_bytes = bitmap_words * 8;
    let bitmap_pages = (bitmap_bytes + PAGE_SIZE - 1) / PAGE_SIZE;

    // Allocate physical frames for SLOTS array
    let slots_phys = mm::alloc_contiguous_frames(slots_pages)
        .expect("[CAP] SLOTS allocation failed");
    let slots_virt = mm::phys_to_virt(slots_phys) as *mut CapSlotStorage;

    // Allocate physical frames for bitmap
    let bitmap_phys = mm::alloc_contiguous_frames(bitmap_pages)
        .expect("[CAP] SLOT_BITMAP allocation failed");
    let bitmap_virt = mm::phys_to_virt(bitmap_phys) as *mut u64;

    // Zero bitmap
    // SAFETY: bitmap_virt points to freshly allocated memory via direct map
    unsafe {
        core::ptr::write_bytes(bitmap_virt, 0, bitmap_words);
    }

    // Initialize all slots as free
    // SAFETY: slots_virt points to freshly allocated memory via direct map
    unsafe {
        for i in 0..num_slots {
            let slot = slots_virt.add(i);
            (*slot).cap = Capability::null();
            (*slot).meta = CapSlotMeta::free();
        }
    }

    // SAFETY: Single-threaded init
    unsafe {
        let state = &mut *(&raw mut SLOT_STATE);
        state.slots_ptr = slots_virt;
        state.bitmap_ptr = bitmap_virt;
        state.num_slots = num_slots;
        (*(&raw mut NEXT_SLOT)) = 0;
    }
}

/// Get pointer to the base of the SLOTS array.
///
/// Used by untyped.rs for raw pointer arithmetic on slot storage.
#[inline]
pub fn slots_ptr() -> *mut CapSlotStorage {
    // SAFETY: SLOT_STATE is initialized before any cap operations
    unsafe { (*(&raw const SLOT_STATE)).slots_ptr }
}

/// Get the dynamic slot count.
#[inline]
pub fn max_slots() -> usize {
    // SAFETY: SLOT_STATE is initialized before any cap operations
    unsafe { (*(&raw const SLOT_STATE)).num_slots }
}

/// Allocate a capability slot
///
/// Returns the slot index if allocation succeeds.
/// Returns None if all slots are exhausted.
pub fn alloc_slot() -> Option<CapSlot> {
    unsafe {
        let state = &*(&raw const SLOT_STATE);
        let num_slots = state.num_slots;
        if num_slots == 0 {
            return None;
        }

        // Start from NEXT_SLOT and wrap around if needed
        let start = (*(&raw const NEXT_SLOT)) as usize;

        // Search from start to end
        for i in start..num_slots {
            let idx = i / 64;
            let bit = i % 64;
            let bitmap = state.bitmap_ptr;
            if ((*bitmap.add(idx)) & (1u64 << bit)) == 0 {
                // Found free slot
                (*bitmap.add(idx)) |= 1u64 << bit;
                (*state.slots_ptr.add(i)).meta = CapSlotMeta::occupied();
                (*(&raw mut NEXT_SLOT)) = (i + 1) as CapSlot;
                return Some(i as CapSlot);
            }
        }

        // Wrap around and search from 0 to start
        for i in 0..start {
            let idx = i / 64;
            let bit = i % 64;
            let bitmap = state.bitmap_ptr;
            if ((*bitmap.add(idx)) & (1u64 << bit)) == 0 {
                // Found free slot
                (*bitmap.add(idx)) |= 1u64 << bit;
                (*state.slots_ptr.add(i)).meta = CapSlotMeta::occupied();
                (*(&raw mut NEXT_SLOT)) = (i + 1) as CapSlot;
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
    // SAFETY: SLOT_STATE is initialized before any cap operations
    let num_slots = unsafe { (*(&raw const SLOT_STATE)).num_slots };
    if idx >= num_slots {
        return;
    }

    unsafe {
        let state = &*(&raw const SLOT_STATE);
        let bitmap_idx = idx / 64;
        let bit = idx % 64;
        (*state.bitmap_ptr.add(bitmap_idx)) &= !(1u64 << bit);
        (*state.slots_ptr.add(idx)).meta = CapSlotMeta::free();

        // Update NEXT_SLOT if we freed a lower slot
        if (slot as usize) < (*(&raw const NEXT_SLOT)) as usize {
            (*(&raw mut NEXT_SLOT)) = slot;
        }
    }
}

/// Get immutable reference to capability in slot
pub fn get_cap(slot: CapSlot) -> &'static Capability {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { &(*slots_ptr().add(slot as usize)).cap }
}

/// Get mutable reference to capability in slot
pub fn get_cap_mut(slot: CapSlot) -> &'static mut Capability {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { &mut (*slots_ptr().add(slot as usize)).cap }
}

/// Get immutable reference to slot metadata
pub fn get_meta(slot: CapSlot) -> &'static CapSlotMeta {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { &(*slots_ptr().add(slot as usize)).meta }
}

/// Get mutable reference to slot metadata
pub fn get_meta_mut(slot: CapSlot) -> &'static mut CapSlotMeta {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { &mut (*slots_ptr().add(slot as usize)).meta }
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
        let state = &*(&raw const SLOT_STATE);
        let bitmap_words = (state.num_slots + 63) / 64;
        let mut count = 0;
        for i in 0..bitmap_words {
            count += (*state.bitmap_ptr.add(i)).count_ones() as usize;
        }
        count
    }
}

/// Get total number of free slots
pub fn free_count() -> usize {
    max_slots() - allocated_count()
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
