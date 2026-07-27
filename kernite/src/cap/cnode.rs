//! CNode - Capability Node
//!
//! CNodes store capability references (slot indices), not capability values.
//! This allows multiple CNodes to reference the same capability (sharing).
//!
//! CNodes support seL4-style multi-level address resolution via guard fields.
//! A guard_bits=0 preserves flat (single-level) behavior.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use super::{
    CDT, CapRights, Capability, INVALID_SLOT, KernelObject, ObjectType, alloc_slot, free_slot,
    get_cap, get_generation, write_capability,
};

/// Default CNode size_bits when caller passes 0 (ABI backward compat)
pub const CNODE_DEFAULT_SIZE_BITS: u8 = 10; // 1024 slots
/// Minimum allowed CNode size_bits
pub const CNODE_MIN_SIZE_BITS: u8 = 4; // 16 slots
/// Maximum allowed CNode size_bits
pub const CNODE_MAX_SIZE_BITS: u8 = 16; // 65536 slots

/// Legacy aliases (kept for any external references)
pub const CNODE_SIZE_BITS: usize = CNODE_DEFAULT_SIZE_BITS as usize;
pub const CNODE_SIZE: usize = 1 << CNODE_SIZE_BITS;

// Mixed-mode root-CSpace addressing ABI:
// - low slot values address the flat root CNode directly
// - slots in the deterministic expansion window encode a leaf slot as
//   (root_slot << 10) | subslot, matching libtrona's slot allocator
const ROOT_CSPACE_EXPAND_BASE: u64 = 1008;
const ROOT_CSPACE_EXPAND_COUNT: u64 = 64;
const ROOT_CSPACE_EXPAND_SLOT_BITS: u8 = 10;

/// Capability reference - points to global slot
///
/// CNodes store CapRef values, which are indices into the global slot array.
/// This allows:
/// - Multiple CNodes to reference the same capability
/// - Moving capabilities between CNodes without copying
/// - Efficient capability transfer
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CapRef {
    pub slot: u32,
    /// Generation of `slot` captured when this reference was created.
    /// Validated at every dereference: a reference whose generation has
    /// fallen behind the slot's current `meta.generation` (low 32 bits)
    /// points at a slot that was freed and re-allocated to an unrelated
    /// capability — the reference is stale and resolves to null. This
    /// extends the carrier `epoch` ABA defence to durable CNode-stored
    /// references.
    pub generation: u32,
}

impl CapRef {
    /// Reference `slot`, capturing the slot's current generation. Use
    /// for a freshly established cap (copy / mint / retype / bootstrap)
    /// whose current identity the caller owns.
    pub fn new(slot: u32) -> Self {
        Self {
            slot,
            generation: get_generation(slot) as u32,
        }
    }

    /// Reference `slot` with an explicitly supplied generation. Use when
    /// reconstructing a reference whose identity was snapshotted earlier
    /// (IPC carrier reconstruction passes the captured `epoch`):
    /// capturing the *current* generation there would wrongly validate a
    /// slot that has since been freed and reused.
    pub const fn from_slot_generation(slot: u32, generation: u32) -> Self {
        Self { slot, generation }
    }

    pub const fn null() -> Self {
        Self {
            slot: INVALID_SLOT,
            generation: 0,
        }
    }

    pub fn is_null(&self) -> bool {
        self.slot == INVALID_SLOT
    }

    /// True if this reference's captured generation still matches the
    /// slot's current generation. A stale reference (slot freed and
    /// reused since capture) returns false. Null references are never
    /// live.
    pub fn is_live(&self) -> bool {
        !self.is_null() && (get_generation(self.slot) as u32) == self.generation
    }

    /// Get the capability this reference points to, or a null capability
    /// if the reference is stale. Every dereference is generation-checked
    /// here.
    pub fn get(&self) -> Capability {
        if self.is_live() {
            get_cap(self.slot)
        } else {
            Capability::null()
        }
    }

    /// Resolve to `(slot, capability)` only when the reference is live.
    /// Raw-slot operations (CDT mutate, refcount, badge rewrite) route
    /// through this so a stale reference never operates on a reused slot.
    pub fn get_live(&self) -> Option<(u32, Capability)> {
        if self.is_live() {
            Some((self.slot, get_cap(self.slot)))
        } else {
            None
        }
    }
}

#[cfg(any(klog_trace, klog_mod_cap))]
fn trace_cap_error_name(g: &crate::kernel::printk::SerialGuard, err: CapError) {
    g.puts(match err {
        CapError::InvalidSlot => "InvalidSlot",
        CapError::SlotOccupied => "SlotOccupied",
        CapError::SlotEmpty => "SlotEmpty",
        CapError::InsufficientRights => "InsufficientRights",
        CapError::DepthExceeded => "DepthExceeded",
        CapError::InvalidOperation => "InvalidOperation",
        CapError::InvalidBadge => "InvalidBadge",
        CapError::InsufficientMemory => "InsufficientMemory",
        CapError::OutOfSlots => "OutOfSlots",
        CapError::OutOfClasses => "OutOfClasses",
        CapError::NotAChild => "NotAChild",
        CapError::HasChildren => "HasChildren",
        CapError::HasDerivedCaps => "HasDerivedCaps",
        CapError::ObjectInUse => "ObjectInUse",
        CapError::InvalidState => "InvalidState",
        CapError::InvalidArgument => "InvalidArgument",
        CapError::GuardMismatch => "GuardMismatch",
    });
}

/// Capability Node - stores capability references
///
/// CNodes are kernel objects that hold a header followed by guard fields
/// and a contiguous array of CapRef entries in memory. The number of
/// slots is determined by `header.size_bits` (capacity = 1 << size_bits).
///
/// Guard fields enable seL4-style multi-level CNode trees. A guard_bits=0
/// with guard=0 preserves flat (single-level) CNode behavior.
///
/// Memory layout:
///   +0:  KernelObject header (16 bytes, header.size_bits = log2(num_slots))
///   +12: guard_bits (1 byte)
///   +13: _pad (3 bytes)
///   +16: guard (8 bytes)
///   +24: CapRef[0] .. CapRef[2^size_bits - 1]
#[repr(C)]
pub struct CNode {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Number of guard bits (0 = no guard, flat mode)
    pub guard_bits: u8,
    /// Padding for alignment
    _pad: [u8; 3],
    /// Guard value — prefix bits that must match during address resolution
    pub guard: u64,
    // Slots [CapRef; 1 << header.size_bits] follow contiguously in memory.
    // Accessed via pointer arithmetic (slot_ptr / slot_ptr_mut).
}

/// Validate size_bits for CNode, returning effective bits or error.
///
/// - 0 → default (CNODE_DEFAULT_SIZE_BITS = 10, i.e. 1024 slots)
/// - 1..3 → InvalidArgument (too small)
/// - 4..16 → use as-is
/// - 17+ → InvalidArgument (too large)
pub fn effective_cnode_bits(size_bits: u8) -> Result<u8, CapError> {
    if size_bits == 0 {
        Ok(CNODE_DEFAULT_SIZE_BITS)
    } else if size_bits < CNODE_MIN_SIZE_BITS {
        Err(CapError::InvalidArgument)
    } else if size_bits > CNODE_MAX_SIZE_BITS {
        Err(CapError::InvalidArgument)
    } else {
        Ok(size_bits)
    }
}

impl CNode {
    /// Number of slots this CNode holds (1 << header.size_bits)
    pub fn num_slots(&self) -> usize {
        1usize << (self.header.size_bits as usize)
    }

    /// Get pointer to slot at `index` (no bounds check)
    ///
    /// # Safety
    /// Caller must ensure `index < num_slots()`.
    pub(crate) unsafe fn slot_ptr(&self, index: usize) -> *const CapRef {
        unsafe {
            let base = (self as *const CNode).add(1) as *const CapRef;
            base.add(index)
        }
    }

    /// Get mutable pointer to slot at `index` (no bounds check)
    unsafe fn slot_ptr_mut(&mut self, index: usize) -> *mut CapRef {
        unsafe {
            let base = (self as *mut CNode).add(1) as *mut CapRef;
            base.add(index)
        }
    }

    /// Initialize a CNode in-place at the given memory address.
    ///
    /// Writes the header, guard fields, and zero-fills all slot entries
    /// with CapRef::null(). The caller must ensure `ptr` points to at least
    /// `size_of::<CNode>() + (1 << size_bits) * size_of::<CapRef>()` bytes.
    pub unsafe fn init_at(ptr: *mut u8, size_bits: u8) {
        unsafe {
            let cnode = ptr as *mut CNode;
            // Write header
            core::ptr::write(
                &raw mut (*cnode).header,
                KernelObject::new(ObjectType::CNode, size_bits),
            );
            // Initialize guard fields (flat mode: no guard)
            core::ptr::write(&raw mut (*cnode).guard_bits, 0);
            core::ptr::write(&raw mut (*cnode)._pad, [0u8; 3]);
            core::ptr::write(&raw mut (*cnode).guard, 0);
            // Zero-fill all slots with CapRef::null() (INVALID_SLOT = 0xFFFFFFFF)
            let num_slots = 1usize << (size_bits as usize);
            let slots_base = cnode.add(1) as *mut CapRef;
            for i in 0..num_slots {
                core::ptr::write(slots_base.add(i), CapRef::null());
            }
        }
    }

    /// Check if slot is empty (holds null reference)
    pub fn is_slot_empty(&self, index: usize) -> bool {
        if index >= self.num_slots() {
            return false;
        }
        unsafe { (*self.slot_ptr(index)).is_null() }
    }

    /// Insert a capability reference into a slot
    pub fn insert_ref(&mut self, index: usize, cap_ref: CapRef) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }
        if !self.is_slot_empty(index) {
            return Err(CapError::SlotOccupied);
        }
        unsafe {
            core::ptr::write(self.slot_ptr_mut(index), cap_ref);
        }
        Ok(())
    }

    /// Take the `CapRef` out of a slot, leaving the slot empty.
    /// Returns `None` if the index is out of range or the slot was
    /// already empty. Used by IPC cap-carrier transfer to move a
    /// `CapRef` out of the sender's CNode without touching the
    /// underlying global slot's CDT linkage or object refcount.
    pub fn take_ref(&mut self, index: usize) -> Option<CapRef> {
        if index >= self.num_slots() {
            return None;
        }
        unsafe {
            let p = self.slot_ptr_mut(index);
            let cur = *p;
            if cur.is_null() {
                return None;
            }
            core::ptr::write(p, CapRef::null());
            Some(cur)
        }
    }

    /// Get capability reference at index
    pub fn get_ref(&self, index: usize) -> Option<CapRef> {
        if index < self.num_slots() && !self.is_slot_empty(index) {
            Some(unsafe { *self.slot_ptr(index) })
        } else {
            None
        }
    }

    /// Get capability at index
    pub fn get(&self, index: usize) -> Option<Capability> {
        self.get_ref(index).map(|r| r.get())
    }

    /// Copy capability from source to destination
    ///
    /// Creates a new capability with potentially reduced rights.
    /// The new capability becomes a child of the source in the CDT.
    pub fn copy_slot(
        &mut self,
        dest: usize,
        src_cnode: &CNode,
        src: usize,
        new_rights: CapRights,
    ) -> Result<(), CapError> {
        // Validate indices
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_copy slot failed reason=invalid_index dest=");
                g.hex(dest as u64);
                g.puts(" dest_slots=");
                g.hex(self.num_slots() as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts(" src_slots=");
                g.hex(src_cnode.num_slots() as u64);
                g.puts("\n");
            });
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_copy slot failed reason=dest_occupied dest=");
                g.hex(dest as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts("\n");
            });
            return Err(CapError::SlotOccupied);
        }

        // Get source capability. A stale reference (slot freed + reused
        // since this CNode entry was written) resolves to none here.
        let src_ref = match src_cnode.get_ref(src) {
            Some(r) => r,
            None => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_copy slot failed reason=src_empty dest=");
                    g.hex(dest as u64);
                    g.puts(" src=");
                    g.hex(src as u64);
                    g.puts("\n");
                });
                return Err(CapError::SlotEmpty);
            }
        };
        let (src_slot, src_cap) = match src_ref.get_live() {
            Some(v) => v,
            None => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_copy slot failed reason=src_stale dest=");
                    g.hex(dest as u64);
                    g.puts(" src=");
                    g.hex(src as u64);
                    g.puts(" cap_slot=");
                    g.hex(src_ref.slot as u64);
                    g.puts(" captured_gen=");
                    g.hex(src_ref.generation as u64);
                    g.puts(" current_gen=");
                    g.hex(get_generation(src_ref.slot));
                    g.puts("\n");
                });
                return Err(CapError::SlotEmpty);
            }
        };

        // Check source has Grant right
        if !src_cap.has_right(CapRights::GRANT) {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_copy slot failed reason=src_no_grant dest=");
                g.hex(dest as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts(" cap_slot=");
                g.hex(src_slot as u64);
                g.puts(" obj_type=");
                g.hex(src_cap.obj_type as u64);
                g.puts("\n");
            });
            return Err(CapError::InsufficientRights);
        }

        // Allocate new slot for destination
        let dest_slot = match alloc_slot() {
            Some(slot) => slot,
            None => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_copy slot failed reason=out_of_slots dest=");
                    g.hex(dest as u64);
                    g.puts(" src=");
                    g.hex(src as u64);
                    g.puts(" cap_slot=");
                    g.hex(src_slot as u64);
                    g.puts("\n");
                });
                return Err(CapError::OutOfSlots);
            }
        };

        // Perform copy (this updates CDT and refcount)
        if let Err(e) = src_cap.copy(src_slot, new_rights, dest_slot) {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_copy slot failed reason=copy_impl dest=");
                g.hex(dest as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts(" src_cap_slot=");
                g.hex(src_slot as u64);
                g.puts(" new_cap_slot=");
                g.hex(dest_slot as u64);
                g.puts(" err=");
                trace_cap_error_name(&g, e);
                g.puts("\n");
            });
            free_slot(dest_slot);
            return Err(e);
        }

        // Insert reference into destination CNode
        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), CapRef::new(dest_slot));
        }

        Ok(())
    }

    /// Derive an executable capability to the source MemoryObject into `dest`.
    /// Mirrors `copy_slot` but confers a fixed `R|E|GRANT|TRANSFER` right set
    /// (see `Capability::confer_exec`) and requires the source to be a readable
    /// MemoryObject. The exec-authority gate is enforced by the caller, so —
    /// unlike `copy_slot` — no source GRANT right is required.
    pub fn confer_exec_slot(
        &mut self,
        dest: usize,
        src_cnode: &CNode,
        src: usize,
    ) -> Result<(), CapError> {
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }
        if !self.is_slot_empty(dest) {
            return Err(CapError::SlotOccupied);
        }

        // Resolve the source cap; a stale reference resolves to none.
        let src_ref = src_cnode.get_ref(src).ok_or(CapError::SlotEmpty)?;
        let (src_slot, src_cap) = src_ref.get_live().ok_or(CapError::SlotEmpty)?;

        // EXECUTE may only be conferred on a readable MemoryObject.
        if src_cap.obj_type != crate::cap::ObjectType::MemoryObject {
            return Err(CapError::InvalidOperation);
        }
        if !src_cap.has_right(CapRights::READ) {
            return Err(CapError::InsufficientRights);
        }

        let dest_slot = alloc_slot().ok_or(CapError::OutOfSlots)?;

        // Perform the conferral (updates CDT and refcount).
        if let Err(e) = src_cap.confer_exec(src_slot, dest_slot) {
            free_slot(dest_slot);
            return Err(e);
        }

        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), CapRef::new(dest_slot));
        }

        Ok(())
    }

    /// Mint badged capability
    ///
    /// Creates a badged copy of a badge-carrying capability
    /// (`MessagePipe` / `DataPipe` / `EventQueue` / `Watch` / `Timer`
    /// / `IrqHandler`). Badged capabilities cannot have Grant right.
    pub fn mint_slot(
        &mut self,
        dest: usize,
        src_cnode: &CNode,
        src: usize,
        badge: u64,
        new_rights: CapRights,
    ) -> Result<(), CapError> {
        // Validate indices
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            return Err(CapError::SlotOccupied);
        }

        // Get source capability. A stale reference resolves to none.
        let src_ref = src_cnode.get_ref(src).ok_or(CapError::SlotEmpty)?;
        let (src_slot, src_cap) = src_ref.get_live().ok_or(CapError::SlotEmpty)?;

        // Allocate new slot for destination
        let dest_slot = alloc_slot().ok_or(CapError::OutOfSlots)?;

        // Perform mint (this updates CDT and refcount)
        if let Err(e) = src_cap.mint(src_slot, badge, new_rights, dest_slot) {
            free_slot(dest_slot);
            return Err(e);
        }

        // Insert reference into destination CNode
        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), CapRef::new(dest_slot));
        }

        Ok(())
    }

    /// Move capability from source to destination
    ///
    /// Transfers the capability reference without creating a new capability.
    /// The source slot becomes empty.
    pub fn move_slot(
        &mut self,
        dest: usize,
        src_cnode: &mut CNode,
        src: usize,
    ) -> Result<(), CapError> {
        // Validate indices
        if dest >= self.num_slots() || src >= src_cnode.num_slots() {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_move slot failed reason=invalid_index dest=");
                g.hex(dest as u64);
                g.puts(" dest_slots=");
                g.hex(self.num_slots() as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts(" src_slots=");
                g.hex(src_cnode.num_slots() as u64);
                g.puts("\n");
            });
            return Err(CapError::InvalidSlot);
        }

        // Check destination is empty
        if !self.is_slot_empty(dest) {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_move slot failed reason=dest_occupied dest=");
                g.hex(dest as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts("\n");
            });
            return Err(CapError::SlotOccupied);
        }

        // Get source reference
        let src_ref = match src_cnode.get_ref(src) {
            Some(r) => r,
            None => {
                crate::kernel::printk::ktrace!(cap, |g| {
                    g.puts("[CAP] cnode_move slot failed reason=src_empty dest=");
                    g.hex(dest as u64);
                    g.puts(" src=");
                    g.hex(src as u64);
                    g.puts("\n");
                });
                return Err(CapError::SlotEmpty);
            }
        };
        if !src_ref.is_live() {
            crate::kernel::printk::ktrace!(cap, |g| {
                g.puts("[CAP] cnode_move slot warning reason=src_stale dest=");
                g.hex(dest as u64);
                g.puts(" src=");
                g.hex(src as u64);
                g.puts(" cap_slot=");
                g.hex(src_ref.slot as u64);
                g.puts(" captured_gen=");
                g.hex(src_ref.generation as u64);
                g.puts(" current_gen=");
                g.hex(get_generation(src_ref.slot));
                g.puts("\n");
            });
        }

        // Transfer reference (no global slot changes)
        unsafe {
            core::ptr::write(self.slot_ptr_mut(dest), src_ref);
            core::ptr::write(src_cnode.slot_ptr_mut(src), CapRef::null());
        }

        Ok(())
    }

    /// Mutate capability: move from source to destination and set a new
    /// badge on the moved cap. Source slot becomes empty.
    pub fn mutate_slot(
        &mut self,
        dest: usize,
        src_cnode: &mut CNode,
        src: usize,
        new_badge: u64,
    ) -> Result<(), CapError> {
        self.move_slot(dest, src_cnode, src)?;

        let cap_ref = self.get_ref(dest).ok_or(CapError::SlotEmpty)?;
        let (slot, mut cap) = cap_ref.get_live().ok_or(CapError::SlotEmpty)?;
        cap.badge = new_badge;
        write_capability(slot, cap);
        Ok(())
    }

    /// Revoke capability and all descendants
    ///
    /// Deletes the capability at the given index and recursively
    /// revokes all its descendants in the CDT.
    pub fn revoke(&mut self, index: usize) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;

        // Only revoke a live reference — a stale entry (slot freed +
        // reused since this CNode slot was written) must not revoke the
        // unrelated cap now occupying the slot. The CNode slot is
        // cleared either way.
        if let Some((slot, _)) = cap_ref.get_live() {
            // Revoke handles full lifecycle including slot cleanup
            CDT::revoke(slot);
        }

        // Clear CNode slot
        unsafe {
            core::ptr::write(self.slot_ptr_mut(index), CapRef::null());
        }

        Ok(())
    }

    /// Delete single capability
    ///
    /// Deletes the capability at the given index. Any capabilities derived
    /// from this cap are preserved by re-parenting them to this cap's CDT
    /// parent (so an ancestor's revoke still reaches them); use
    /// [`revoke`](Self::revoke) when the whole derived subtree must be torn
    /// down.
    pub fn delete(&mut self, index: usize) -> Result<(), CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;

        // Only touch the global slot for a live reference. A stale
        // entry resolves to nothing — clearing the CNode slot is the
        // whole job.
        if let Some((slot, _)) = cap_ref.get_live() {
            // Delegate to the unified per-cap cleanup path.
            // `CDT::delete_capability` preserves derived caps by re-parenting
            // them to this cap's CDT parent, unlinks this cap from CDT,
            // decrements the object refcount (the reaper performs every
            // object-level transition when the last reference goes), then
            // nullifies and frees the slot.
            super::cdt::CDT::delete_capability(slot);
        }

        // Clear CNode slot
        unsafe {
            core::ptr::write(self.slot_ptr_mut(index), CapRef::null());
        }

        Ok(())
    }

    /// Get information about a capability
    pub fn cap_info(&self, index: usize) -> Result<CapInfo, CapError> {
        if index >= self.num_slots() {
            return Err(CapError::InvalidSlot);
        }

        let cap_ref = self.get_ref(index).ok_or(CapError::SlotEmpty)?;
        let (slot, cap) = cap_ref.get_live().ok_or(CapError::SlotEmpty)?;

        Ok(CapInfo {
            obj_type: cap.obj_type,
            rights: cap.rights,
            badge: cap.badge,
            depth: cap.depth,
            has_children: CDT::has_children(slot),
            child_count: CDT::child_count(slot),
        })
    }
}

/// Information about a capability
#[derive(Debug, Clone, Copy)]
pub struct CapInfo {
    pub obj_type: super::ObjectType,
    pub rights: CapRights,
    pub badge: u64,
    pub depth: u8,
    pub has_children: bool,
    pub child_count: usize,
}

/// Capability errors
#[derive(Debug, Clone, Copy)]
pub enum CapError {
    InvalidSlot,
    SlotOccupied,
    SlotEmpty,
    InsufficientRights,
    DepthExceeded,
    InvalidOperation,
    InvalidBadge,
    InsufficientMemory,
    OutOfSlots,
    OutOfClasses,
    NotAChild,
    HasChildren,
    HasDerivedCaps,
    ObjectInUse,
    InvalidState,
    InvalidArgument,
    GuardMismatch,
}

/// Maximum depth for multi-level CNode resolution (prevents infinite loops)
pub const MAX_RESOLVE_DEPTH: usize = 8;

/// Resolve a capability address for write operations, returning (CNode*, leaf_index).
///
/// Same seL4-style guard+radix algorithm as `resolve_address`, but returns a mutable
/// CNode pointer and the terminal slot index instead of the capability itself.
/// This is needed for operations that modify CNode slots (retype, copy, delete, etc.)
/// where the caller needs to operate on the leaf CNode directly.
///
/// # Arguments
/// * `root` - Root CNode to start resolution from
/// * `cap_addr` - Full capability address to resolve
/// * `addr_bits` - Total number of significant bits in cap_addr
///
/// # Returns
/// * `Ok((*mut CNode, usize))` - Pointer to the leaf CNode and the slot index within it
/// * `Err(CapError)` - Resolution failed
pub fn resolve_address_for_slot(
    root: &CNode,
    cap_addr: u64,
    addr_bits: u8,
) -> Result<(*mut CNode, usize), CapError> {
    resolve_for_slot_inner(root, cap_addr, addr_bits as usize, 0)
}

fn resolve_for_slot_inner(
    cnode: &CNode,
    cap_addr: u64,
    bits_remaining: usize,
    depth: usize,
) -> Result<(*mut CNode, usize), CapError> {
    if depth > MAX_RESOLVE_DEPTH {
        return Err(CapError::DepthExceeded);
    }

    let guard_bits = cnode.guard_bits as usize;
    let radix = cnode.header.size_bits as usize;

    if bits_remaining < guard_bits + radix {
        return Err(CapError::InvalidSlot);
    }

    // Verify guard prefix
    if guard_bits > 0 {
        let shift = bits_remaining - guard_bits;
        let mask = (1u64 << guard_bits) - 1;
        let guard_val = (cap_addr >> shift) & mask;
        if guard_val != cnode.guard {
            return Err(CapError::GuardMismatch);
        }
    }
    let bits_after_guard = bits_remaining - guard_bits;

    // Index into slot array
    let shift = bits_after_guard - radix;
    let mask = (1u64 << radix) - 1;
    let index = ((cap_addr >> shift) & mask) as usize;
    let bits_left = bits_after_guard - radix;

    if bits_left == 0 {
        // Terminal — return the CNode pointer and index for write operations
        return Ok((cnode as *const CNode as *mut CNode, index));
    }

    // Bits remaining — follow CNode pointer
    let cap_ref = cnode.get_ref(index).ok_or(CapError::SlotEmpty)?;
    let cap = cap_ref.get();

    if cap.obj_type == super::ObjectType::CNode && !cap.object.is_null() {
        let next_cnode = unsafe { &*(cap.object as *const CNode) };
        return resolve_for_slot_inner(next_cnode, cap_addr, bits_left, depth + 1);
    }

    // Bits remaining but not a CNode — cannot continue resolution
    Err(CapError::InvalidSlot)
}

/// Resolve a capability address through a multi-level CNode tree.
///
/// Walks through CNode guards and slot arrays, following CNode capabilities
/// at intermediate levels until all address bits are consumed.
///
/// # Arguments
/// * `root` - Root CNode to start resolution from
/// * `cap_addr` - Full capability address to resolve
/// * `addr_bits` - Total number of significant bits in cap_addr
///
/// # Returns
/// * `Ok(Capability)` - The resolved capability
/// * `Err(CapError)` - Resolution failed (guard mismatch, invalid slot, depth exceeded, etc.)
pub fn resolve_address(root: &CNode, cap_addr: u64, addr_bits: u8) -> Result<Capability, CapError> {
    resolve_address_inner(root, cap_addr, addr_bits as usize, 0)
}

fn mixed_root_cspace_addr_bits(root: &CNode, cap_addr: u64) -> Option<u8> {
    let root_slot = cap_addr >> ROOT_CSPACE_EXPAND_SLOT_BITS;
    if !(ROOT_CSPACE_EXPAND_BASE..ROOT_CSPACE_EXPAND_BASE + ROOT_CSPACE_EXPAND_COUNT)
        .contains(&root_slot)
    {
        return None;
    }
    root.header
        .size_bits
        .checked_add(ROOT_CSPACE_EXPAND_SLOT_BITS)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootCspaceAddrKind {
    Flat { index: usize },
    Expanded { addr_bits: u8 },
}

pub fn classify_root_cspace_addr(root: &CNode, cap_addr: u64) -> RootCspaceAddrKind {
    if let Some(addr_bits) = mixed_root_cspace_addr_bits(root, cap_addr) {
        RootCspaceAddrKind::Expanded { addr_bits }
    } else {
        RootCspaceAddrKind::Flat {
            index: cap_addr as usize,
        }
    }
}

/// Resolve a capability address in a root CSpace that uses mixed flat/expanded
/// slot semantics.
pub fn resolve_root_cspace_address(root: &CNode, cap_addr: u64) -> Result<Capability, CapError> {
    match classify_root_cspace_addr(root, cap_addr) {
        RootCspaceAddrKind::Expanded { addr_bits } => resolve_address(root, cap_addr, addr_bits),
        RootCspaceAddrKind::Flat { index } => root.get(index).ok_or(CapError::InvalidSlot),
    }
}

/// Resolve a capability address and return the CapRef (slot reference).
///
/// Same as `resolve_address` but returns the CapRef instead of the Capability,
/// needed by operations that modify CNode slots (retype, delete, etc.).
pub fn resolve_address_slot(
    root: &CNode,
    cap_addr: u64,
    addr_bits: u8,
) -> Result<CapRef, CapError> {
    resolve_slot_inner(root, cap_addr, addr_bits as usize, 0)
}

/// Resolve a capability slot in a root CSpace that uses mixed flat/expanded
/// slot semantics.
pub fn resolve_root_cspace_slot(root: &CNode, cap_addr: u64) -> Result<CapRef, CapError> {
    match classify_root_cspace_addr(root, cap_addr) {
        RootCspaceAddrKind::Expanded { addr_bits } => {
            resolve_address_slot(root, cap_addr, addr_bits)
        }
        RootCspaceAddrKind::Flat { index } => root.get_ref(index).ok_or(CapError::InvalidSlot),
    }
}

/// Resolve a read source in a root CSpace that uses mixed flat/expanded slot
/// semantics, returning the leaf CNode and slot index.
///
/// Unlike [`resolve_root_cspace_for_slot`], this requires the terminal slot to
/// be populated so callers can distinguish an empty read source from a valid
/// empty write target.
pub fn resolve_root_cspace_read_slot(
    root: &CNode,
    cap_addr: u64,
) -> Result<(*mut CNode, usize), CapError> {
    match classify_root_cspace_addr(root, cap_addr) {
        RootCspaceAddrKind::Expanded { addr_bits } => {
            let (leaf, index) = resolve_address_for_slot(root, cap_addr, addr_bits)?;
            let leaf_ref = unsafe { &*leaf };
            if leaf_ref.get_ref(index).is_some() {
                Ok((leaf, index))
            } else {
                Err(CapError::SlotEmpty)
            }
        }
        RootCspaceAddrKind::Flat { index } => {
            if root.get_ref(index).is_some() {
                Ok((root as *const CNode as *mut CNode, index))
            } else {
                Err(CapError::SlotEmpty)
            }
        }
    }
}

/// Resolve a write target in a root CSpace that uses mixed flat/expanded slot
/// semantics, returning the leaf CNode and slot index.
pub fn resolve_root_cspace_for_slot(
    root: &CNode,
    cap_addr: u64,
) -> Result<(*mut CNode, usize), CapError> {
    match classify_root_cspace_addr(root, cap_addr) {
        RootCspaceAddrKind::Expanded { addr_bits } => {
            resolve_address_for_slot(root, cap_addr, addr_bits)
        }
        RootCspaceAddrKind::Flat { index } => {
            if index < root.num_slots() {
                Ok((root as *const CNode as *mut CNode, index))
            } else {
                Err(CapError::InvalidSlot)
            }
        }
    }
}

fn resolve_address_inner(
    cnode: &CNode,
    cap_addr: u64,
    bits_remaining: usize,
    depth: usize,
) -> Result<Capability, CapError> {
    if depth > MAX_RESOLVE_DEPTH {
        return Err(CapError::DepthExceeded);
    }

    let guard_bits = cnode.guard_bits as usize;
    let radix = cnode.header.size_bits as usize;

    if bits_remaining < guard_bits + radix {
        return Err(CapError::InvalidSlot);
    }

    // Verify guard prefix
    if guard_bits > 0 {
        let shift = bits_remaining - guard_bits;
        let mask = (1u64 << guard_bits) - 1;
        let guard_val = (cap_addr >> shift) & mask;
        if guard_val != cnode.guard {
            return Err(CapError::GuardMismatch);
        }
    }
    let bits_after_guard = bits_remaining - guard_bits;

    // Index into slot array
    let shift = bits_after_guard - radix;
    let mask = (1u64 << radix) - 1;
    let index = ((cap_addr >> shift) & mask) as usize;
    let bits_left = bits_after_guard - radix;

    let cap_ref = cnode.get_ref(index).ok_or(CapError::SlotEmpty)?;
    let cap = cap_ref.get();

    if bits_left == 0 {
        // Terminal — all bits consumed
        return Ok(cap);
    }

    // Bits remaining but slot holds a CNode — recurse
    if cap.obj_type == super::ObjectType::CNode && !cap.object.is_null() {
        let next_cnode = unsafe { &*(cap.object as *const CNode) };
        return resolve_address_inner(next_cnode, cap_addr, bits_left, depth + 1);
    }

    // Bits remaining but not a CNode — cannot continue resolution
    Err(CapError::InvalidSlot)
}

fn resolve_slot_inner(
    cnode: &CNode,
    cap_addr: u64,
    bits_remaining: usize,
    depth: usize,
) -> Result<CapRef, CapError> {
    if depth > MAX_RESOLVE_DEPTH {
        return Err(CapError::DepthExceeded);
    }

    let guard_bits = cnode.guard_bits as usize;
    let radix = cnode.header.size_bits as usize;

    if bits_remaining < guard_bits + radix {
        return Err(CapError::InvalidSlot);
    }

    // Verify guard prefix
    if guard_bits > 0 {
        let shift = bits_remaining - guard_bits;
        let mask = (1u64 << guard_bits) - 1;
        let guard_val = (cap_addr >> shift) & mask;
        if guard_val != cnode.guard {
            return Err(CapError::GuardMismatch);
        }
    }
    let bits_after_guard = bits_remaining - guard_bits;

    // Index into slot array
    let shift = bits_after_guard - radix;
    let mask = (1u64 << radix) - 1;
    let index = ((cap_addr >> shift) & mask) as usize;
    let bits_left = bits_after_guard - radix;

    if bits_left == 0 {
        // Terminal — return the CapRef at this slot
        return cnode.get_ref(index).ok_or(CapError::SlotEmpty);
    }

    // Bits remaining — follow CNode pointer
    let cap_ref = cnode.get_ref(index).ok_or(CapError::SlotEmpty)?;
    let cap = cap_ref.get();

    if cap.obj_type == super::ObjectType::CNode && !cap.object.is_null() {
        let next_cnode = unsafe { &*(cap.object as *const CNode) };
        return resolve_slot_inner(next_cnode, cap_addr, bits_left, depth + 1);
    }

    Err(CapError::InvalidSlot)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Size of a test CNode buffer (header + 16 slots, size_bits=4)
    const TEST_SIZE_BITS: u8 = CNODE_MIN_SIZE_BITS; // 16 slots
    const TEST_BUF_SIZE: usize =
        core::mem::size_of::<CNode>() + ((1 << TEST_SIZE_BITS) * core::mem::size_of::<CapRef>());

    fn make_test_cnode(buf: &mut [u8; TEST_BUF_SIZE]) -> &mut CNode {
        unsafe {
            CNode::init_at(buf.as_mut_ptr(), TEST_SIZE_BITS);
            &mut *(buf.as_mut_ptr() as *mut CNode)
        }
    }

    #[test]
    fn test_cnode_new() {
        let mut buf = [0u8; TEST_BUF_SIZE];
        let cnode = make_test_cnode(&mut buf);
        assert_eq!(cnode.num_slots(), 1 << TEST_SIZE_BITS);
        assert!(cnode.is_slot_empty(0));
        assert!(cnode.get(0).is_none());
    }

    #[test]
    fn test_insert_ref() {
        let mut buf = [0u8; TEST_BUF_SIZE];
        let cnode = make_test_cnode(&mut buf);
        let cap_ref = CapRef::from_slot_generation(100, 0);

        assert!(cnode.insert_ref(0, cap_ref).is_ok());
        assert!(!cnode.is_slot_empty(0));
        assert_eq!(cnode.get_ref(0).unwrap().slot, 100);
    }

    #[test]
    fn test_insert_occupied() {
        let mut buf = [0u8; TEST_BUF_SIZE];
        let cnode = make_test_cnode(&mut buf);
        let cap_ref = CapRef::from_slot_generation(100, 0);

        assert!(cnode.insert_ref(0, cap_ref).is_ok());
        assert!(cnode.insert_ref(0, cap_ref).is_err());
    }

    #[test]
    fn test_move_slot() {
        let mut buf1 = [0u8; TEST_BUF_SIZE];
        let mut buf2 = [0u8; TEST_BUF_SIZE];
        unsafe {
            CNode::init_at(buf1.as_mut_ptr(), TEST_SIZE_BITS);
            CNode::init_at(buf2.as_mut_ptr(), TEST_SIZE_BITS);
        }
        let cnode1 = unsafe { &mut *(buf1.as_mut_ptr() as *mut CNode) };
        let cnode2 = unsafe { &mut *(buf2.as_mut_ptr() as *mut CNode) };
        let cap_ref = CapRef::from_slot_generation(100, 0);

        // Insert into first CNode
        cnode1.insert_ref(0, cap_ref).unwrap();

        // Move to second CNode
        cnode2.move_slot(5, cnode1, 0).unwrap();

        assert!(cnode1.is_slot_empty(0));
        assert!(!cnode2.is_slot_empty(5));
    }

    #[test]
    fn test_effective_cnode_bits() {
        // 0 → default
        assert_eq!(effective_cnode_bits(0).unwrap(), CNODE_DEFAULT_SIZE_BITS);
        // 1..3 → error
        assert!(effective_cnode_bits(1).is_err());
        assert!(effective_cnode_bits(3).is_err());
        // 4..16 → as-is
        assert_eq!(effective_cnode_bits(4).unwrap(), 4);
        assert_eq!(effective_cnode_bits(10).unwrap(), 10);
        assert_eq!(effective_cnode_bits(16).unwrap(), 16);
        // 17+ → error
        assert!(effective_cnode_bits(17).is_err());
        assert!(effective_cnode_bits(255).is_err());
    }
}
