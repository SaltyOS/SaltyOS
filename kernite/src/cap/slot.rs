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

    /// Slot state
    pub state: SlotState,

    /// In-transit pin count. Held by in-flight IPC cap carriers between
    /// capturing a cap (`take_ref` into a carrier) and delivering or
    /// dropping it. While non-zero the slot's global identity is frozen:
    /// `free_slot` and `CDT::delete_capability` refuse to recycle it or
    /// advance its `generation`, so a concurrent CSpace teardown cannot
    /// pull the cap out from under a deferred install. Counts logical
    /// in-transit caps, not carrier struct copies (carrier arrays are
    /// `Copy` and snapshot through the pipe ring).
    pub transit_pins: u32,

    /// Slot reuse counter, incremented every time `free_slot` retires
    /// the slot. Pairs the slot index `S` into a logical identity
    /// `(S, generation)` so transient holders (IPC install identity,
    /// CDT lookup hand-off) can detect that the slot they captured
    /// has been freed and re-allocated to an unrelated capability.
    /// Without this, slot index alone would let `rollback` /
    /// `auto-delete` paths operate on a different cap that happens
    /// to have inherited the same slot index.
    pub generation: u64,
}

impl CapSlotMeta {
    /// Create metadata for a free slot
    pub const fn free() -> Self {
        Self {
            cdt_parent: INVALID_SLOT,
            cdt_first_child: INVALID_SLOT,
            cdt_next: INVALID_SLOT,
            cdt_prev: INVALID_SLOT,
            state: SlotState::Free,
            transit_pins: 0,
            generation: 0,
        }
    }

    /// Create metadata for an occupied slot, carrying forward an
    /// existing reuse counter. `alloc_slot` reads the current
    /// `generation` of the slot it is reviving and threads it through
    /// here so the increment performed by `free_slot` survives the
    /// alloc round-trip — without this, an old `(slot, gen)` capture
    /// would re-match a freshly allocated slot and bypass identity
    /// checks in `rollback` / `auto-delete` paths.
    pub const fn occupied(generation: u64) -> Self {
        Self {
            cdt_parent: INVALID_SLOT,
            cdt_first_child: INVALID_SLOT,
            cdt_next: INVALID_SLOT,
            cdt_prev: INVALID_SLOT,
            state: SlotState::Occupied,
            transit_pins: 0,
            generation,
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
    let slot_owner = mm::frame::FrameOwner::KernelPrivate {
        subkind: mm::frame::KernelMetaKind::General,
    };
    let slots_phys = mm::pmm_alloc_contiguous_owned(slots_pages, &slot_owner)
        .expect("[CAP] SLOTS allocation failed");
    let slots_virt = mm::phys_to_virt(slots_phys) as *mut CapSlotStorage;

    // Allocate physical frames for bitmap
    let bitmap_phys = mm::pmm_alloc_contiguous_owned(bitmap_pages, &slot_owner)
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

#[inline]
fn slot_storage_ptr(slot: CapSlot) -> *mut CapSlotStorage {
    // SAFETY: slot index validity is a global capability-system invariant enforced
    // by callers that hold CAP_LOCK or otherwise control slot allocation.
    unsafe { slots_ptr().add(slot as usize) }
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
                // Found free slot. Preserve the existing generation
                // counter — `free_slot` bumped it before clearing the
                // rest of the metadata; alloc must not roll that back.
                (*bitmap.add(idx)) |= 1u64 << bit;
                let prev_gen = (*state.slots_ptr.add(i)).meta.generation;
                (*state.slots_ptr.add(i)).meta = CapSlotMeta::occupied(prev_gen);
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
                // Found free slot — same generation-preservation rule
                // as the forward scan above.
                (*bitmap.add(idx)) |= 1u64 << bit;
                let prev_gen = (*state.slots_ptr.add(i)).meta.generation;
                (*state.slots_ptr.add(i)).meta = CapSlotMeta::occupied(prev_gen);
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

    // A transit-pinned slot is owned by an in-flight IPC carrier — its
    // global identity must not be recycled and its generation must not
    // advance until the carrier delivers or drops the cap. Refuse the
    // free; the carrier's unpin path frees it once transit ends.
    // SAFETY: idx bounds-checked above; SLOT_STATE initialized.
    if unsafe { (*slot_storage_ptr(slot)).meta.transit_pins } != 0 {
        return;
    }

    unsafe {
        let state = &*(&raw const SLOT_STATE);
        let bitmap_idx = idx / 64;
        let bit = idx % 64;
        (*state.bitmap_ptr.add(bitmap_idx)) &= !(1u64 << bit);
        // Bump generation BEFORE clearing the rest of the metadata so
        // any concurrent reader that captured a stale (slot, gen)
        // pair sees the new generation and can reject its take_ref
        // attempt. The CDT links / state are then reset to the
        // standard free shape.
        let prev_gen = (*state.slots_ptr.add(idx)).meta.generation;
        let mut fresh = CapSlotMeta::free();
        fresh.generation = prev_gen.wrapping_add(1);
        (*state.slots_ptr.add(idx)).meta = fresh;

        // Update NEXT_SLOT if we freed a lower slot
        if (slot as usize) < (*(&raw const NEXT_SLOT)) as usize {
            (*(&raw mut NEXT_SLOT)) = slot;
        }
    }
}

/// Read the current generation counter for a slot. Pairs with the
/// slot index to form a logical capability-instance identity that
/// stable across `take_ref` / install transitions but breaks across
/// `free_slot` boundaries.
#[inline]
pub fn get_generation(slot: CapSlot) -> u64 {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { (*slot_storage_ptr(slot)).meta.generation }
}

/// Increment the in-transit pin count on `slot`. An in-flight IPC
/// carrier holds one pin between capturing the cap (`take_ref` into a
/// carrier) and delivering or dropping it; while pinned, `free_slot`
/// and `CDT::delete_capability` refuse to recycle the slot or advance
/// its generation.
///
/// # Safety
/// Caller must hold `CAP_LOCK`. `slot` must be a valid occupied slot.
#[inline]
pub fn pin_transit(slot: CapSlot) {
    update_meta(slot, |m| m.transit_pins = m.transit_pins.saturating_add(1));
}

/// Decrement the in-transit pin count on `slot`, paired with a prior
/// `pin_transit`. Called when the cap leaves transit — installed into
/// the receiver, rolled back to the sender, or dropped.
///
/// # Safety
/// Caller must hold `CAP_LOCK` and must have previously pinned `slot`.
#[inline]
pub fn unpin_transit(slot: CapSlot) {
    update_meta(slot, |m| m.transit_pins = m.transit_pins.saturating_sub(1));
}

/// True if `slot` currently carries any in-transit pin.
#[inline]
pub fn is_transit_pinned(slot: CapSlot) -> bool {
    get_meta(slot).transit_pins != 0
}

/// Read the capability payload stored in a slot.
pub fn get_cap(slot: CapSlot) -> Capability {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { (*slot_storage_ptr(slot)).cap }
}

/// Read slot metadata.
pub fn get_meta(slot: CapSlot) -> CapSlotMeta {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { (*slot_storage_ptr(slot)).meta }
}

/// Mutate the capability payload stored in a slot within a narrow scope.
pub fn update_cap<R>(slot: CapSlot, f: impl FnOnce(&mut Capability) -> R) -> R {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { f(&mut (*slot_storage_ptr(slot)).cap) }
}

/// Mutate slot metadata within a narrow scope.
pub fn update_meta<R>(slot: CapSlot, f: impl FnOnce(&mut CapSlotMeta) -> R) -> R {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe { f(&mut (*slot_storage_ptr(slot)).meta) }
}

/// Nullify a capability (set to null capability)
///
/// This does NOT free the slot - it only nullifies the capability data.
/// Use free_slot() after nullifying to release the slot.
pub fn nullify_capability(slot: CapSlot) {
    write_capability(slot, Capability::null());
}

/// Write capability to slot
///
/// # Safety
/// Caller must ensure slot is allocated and this write is synchronized.
pub fn write_capability(slot: CapSlot, cap: Capability) {
    // SAFETY: slot index is validated by caller (cap system invariant)
    unsafe {
        (*slot_storage_ptr(slot)).cap = cap;
    }
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
