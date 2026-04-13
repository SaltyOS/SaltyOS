//! Capability System
//!
//! Fat capabilities (32 bytes) with rights management and seL4-style CDT.
//!
//! SPDX-License-Identifier: GPL-2.0-only

mod cdt;
pub(crate) mod cnode;
pub mod ioport;
pub mod memory_object;
mod object;
mod refcount;
mod slot;
mod untyped;

pub use cdt::CDT;
pub use cnode::{CNode, CapError, CapRef};
pub use object::{KernelObject, ObjectType};
pub use refcount::{increment_refcount, release_object};
pub(crate) use refcount::destroy_object_deferred;
pub use slot::{
    alloc_slot, free_slot, get_cap, get_cap_mut, get_meta, get_meta_mut, nullify_capability,
    CapSlot, INVALID_SLOT,
};
pub use ioport::IoPortRange;
pub(crate) use untyped::UntypedTracker;
pub use untyped::{FrameObject, UntypedMemory};

/// Capability rights bitmap
///
/// Represents the access rights associated with a capability.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CapRights(u32);

impl CapRights {
    /// Create CapRights from raw bits
    ///
    /// # Safety
    /// Callers should ensure only valid rights bits are set.
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Read permission
    pub const READ: CapRights = CapRights(1 << 0);
    /// Write permission
    pub const WRITE: CapRights = CapRights(1 << 1);
    /// Execute permission (for code mappings)
    pub const EXECUTE: CapRights = CapRights(1 << 2);
    /// Grant right (can copy to others)
    pub const GRANT: CapRights = CapRights(1 << 3);
    /// Revoke right (can revoke derived caps)
    pub const REVOKE: CapRights = CapRights(1 << 4);

    // IPC rights
    /// Send to endpoint
    pub const SEND: CapRights = CapRights(1 << 5);
    /// Receive from endpoint
    pub const RECV: CapRights = CapRights(1 << 6);
    /// Send + receive atomically
    pub const CALL: CapRights = CapRights(1 << 7);
    /// Reply capability
    pub const REPLY: CapRights = CapRights(1 << 8);

    // Thread management
    /// Configure thread
    pub const CONFIGURE: CapRights = CapRights(1 << 9);
    /// Suspend thread
    pub const SUSPEND: CapRights = CapRights(1 << 10);
    /// Resume thread
    pub const RESUME: CapRights = CapRights(1 << 11);

    // Memory management
    /// Map pages
    pub const MAP: CapRights = CapRights(1 << 12);
    /// Unmap pages
    pub const UNMAP: CapRights = CapRights(1 << 13);
    /// Retype untyped
    pub const RETYPE: CapRights = CapRights(1 << 14);

    /// All rights
    pub const ALL: CapRights = CapRights(0xFFFFFFFF);

    /// Create an empty CapRights (no rights)
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Check if this CapRights contains the specified right
    #[inline]
    pub fn contains(&self, other: CapRights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Bitwise OR of two CapRights
    #[inline]
    pub fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl core::ops::BitOr for CapRights {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for CapRights {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Fat capability (exactly 32 bytes)
///
/// Memory layout:
/// Offset  Field          Size
/// ------  -----          ----
/// 0x00    object         8
/// 0x08    badge          8
/// 0x10    rights         4
/// 0x14    obj_type       1
/// 0x15    depth          1
/// 0x16    _reserved      2
/// 0x18    _pad           8
/// ------                ---
/// Total                  32
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Capability {
    /// Pointer to kernel object (8 bytes)
    pub object: *mut KernelObject,

    /// Badge value for IPC identification (8 bytes)
    pub badge: u64,

    /// Access rights (4 bytes)
    pub rights: CapRights,

    /// Object type (1 byte)
    pub obj_type: ObjectType,

    /// Derivation depth (1 byte) - prevents infinite loops
    pub depth: u8,

    /// Reserved for future use (2 bytes)
    pub _reserved: u16,

    /// Padding to 32 bytes (8 bytes)
    pub _pad: u64,
}

// Compile-time assertion: Capability must be exactly 32 bytes
const _: () = assert!(core::mem::size_of::<Capability>() == 32);

impl Capability {
    /// Create a null capability
    pub const fn null() -> Self {
        Self {
            object: core::ptr::null_mut(),
            badge: 0,
            rights: CapRights::empty(),
            obj_type: ObjectType::Null,
            depth: 0,
            _reserved: 0,
            _pad: 0,
        }
    }

    /// Check if capability is null
    pub fn is_null(&self) -> bool {
        self.object.is_null()
    }

    /// Check if capability has a specific right
    pub fn has_right(&self, right: CapRights) -> bool {
        self.rights.contains(right)
    }

    /// Copy capability with reduced rights
    ///
    /// Creates a new capability in dest_slot that references the same object
    /// but with potentially reduced rights. The new capability becomes a
    /// child of the source in the CDT.
    ///
    /// # Errors
    /// - InsufficientRights: Source cap must have Grant right
    /// - RightsNotSubset: New rights must be subset of source rights
    /// - DepthExceeded: Maximum derivation depth reached
    pub fn copy(
        &self,
        source_slot: CapSlot,
        new_rights: CapRights,
        dest_slot: CapSlot,
    ) -> Result<(), CapError> {
        // Check source has Grant right
        if !self.has_right(CapRights::GRANT) {
            return Err(CapError::InsufficientRights);
        }

        // New rights must be subset of current rights
        if !self.rights.contains(new_rights) {
            return Err(CapError::RightsNotSubset);
        }

        // Check derivation depth
        if self.depth >= slot::MAX_DERIVATION_DEPTH {
            return Err(CapError::DepthExceeded);
        }

        // Copy to destination slot
        let dest_cap = get_cap_mut(dest_slot);
        *dest_cap = *self;
        dest_cap.rights = new_rights;
        dest_cap.depth = self.depth + 1;

        // Insert into CDT as child of source
        CDT::insert_child(source_slot, dest_slot);

        // Increment object refcount
        unsafe {
            if !self.object.is_null() {
                increment_refcount(self.object);
            }
        }

        Ok(())
    }

    /// Mint badged capability
    ///
    /// Creates a new capability with a badge value. Only endpoints can be minted.
    /// Minted capabilities cannot have Grant right (cannot be further delegated).
    ///
    /// # Errors
    /// - InvalidOperation: Object type is not Endpoint
    /// - InsufficientRights: Source must have Grant right
    /// - InvalidBadge: Attempting to grant with badge (badged caps can't grant)
    pub fn mint(
        &self,
        source_slot: CapSlot,
        badge: u64,
        new_rights: CapRights,
        dest_slot: CapSlot,
    ) -> Result<(), CapError> {
        // Only endpoints and notifications can be badged
        if self.obj_type != ObjectType::Endpoint && self.obj_type != ObjectType::Notification {
            return Err(CapError::InvalidOperation);
        }

        // Source must have Grant right
        if !self.has_right(CapRights::GRANT) {
            return Err(CapError::InsufficientRights);
        }

        // Badged capabilities cannot have Grant right
        if new_rights.contains(CapRights::GRANT) {
            return Err(CapError::InvalidBadge);
        }

        // Check derivation depth
        if self.depth >= slot::MAX_DERIVATION_DEPTH {
            return Err(CapError::DepthExceeded);
        }

        // Create minted capability
        let dest_cap = get_cap_mut(dest_slot);
        *dest_cap = *self;
        dest_cap.rights = new_rights;
        dest_cap.badge = badge;
        dest_cap.depth = self.depth + 1;

        // Insert into CDT
        CDT::insert_child(source_slot, dest_slot);

        // Increment object refcount
        unsafe {
            if !self.object.is_null() {
                increment_refcount(self.object);
            }
        }

        Ok(())
    }
}

/// Initialize capability system
///
/// Dynamically allocates slot and metadata arrays proportional to available
/// physical memory. Must be called after `paging::init()` (direct map available).
pub fn init() {
    let free = crate::mm::pmm_free_count();
    // Slot demand is dominated by fixed boot costs (~240 shared-lib cache +
    // copies, ~50/service × 6 services, ~30/fork) rather than RAM size.
    // Floor of 768 covers the standard 6-service boot + test forks.
    // Above ~3K frames the linear term dominates.
    const MIN_CAP_SLOTS: usize = 768;
    let num_slots = (free / 4).clamp(MIN_CAP_SLOTS, 131_072);

    crate::kinfo!(|_g| {
        _g.puts("[CAP] Dynamic slot count: ");
        _g.dec(num_slots as u64);
        _g.puts(" (");
        _g.dec(free as u64);
        _g.puts(" free frames)\n");
    });

    // SAFETY: Called once during single-threaded boot, direct map available
    unsafe {
        slot::init_slots(num_slots);
        untyped::init_metadata(num_slots);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_size() {
        assert_eq!(core::mem::size_of::<Capability>(), 32);
    }

    #[test]
    fn test_null_capability() {
        let cap = Capability::null();
        assert!(cap.is_null());
        assert_eq!(cap.obj_type, ObjectType::Null);
    }

    #[test]
    fn test_rights_check() {
        let mut cap = Capability::null();
        cap.rights = CapRights::READ | CapRights::WRITE;

        assert!(cap.has_right(CapRights::READ));
        assert!(cap.has_right(CapRights::WRITE));
        assert!(!cap.has_right(CapRights::GRANT));
    }

    #[test]
    fn test_mint_badge() {
        use core::sync::atomic::Ordering;

        // Create a fake Endpoint object on the stack
        let obj = KernelObject::new(ObjectType::Endpoint, 0);
        let obj_ptr = &obj as *const KernelObject as *mut KernelObject;

        // Set up source capability in a slot
        let src_slot = alloc_slot().unwrap();
        let dest_slot = alloc_slot().unwrap();

        let src_cap = get_cap_mut(src_slot);
        src_cap.object = obj_ptr;
        src_cap.obj_type = ObjectType::Endpoint;
        src_cap.rights = CapRights::SEND | CapRights::RECV | CapRights::GRANT;
        src_cap.badge = 0;
        src_cap.depth = 0;

        CDT::insert_root(src_slot);

        // Mint with badge=42, rights=SEND only (no GRANT, required for badged caps)
        let badge: u64 = 42;
        let new_rights = CapRights::SEND;
        let result = get_cap(src_slot).mint(src_slot, badge, new_rights, dest_slot);
        assert!(result.is_ok());

        // Verify minted capability
        let minted = get_cap(dest_slot);
        assert_eq!(minted.badge, 42);
        assert_eq!(minted.obj_type, ObjectType::Endpoint);
        assert!(minted.has_right(CapRights::SEND));
        assert!(!minted.has_right(CapRights::RECV));
        assert!(!minted.has_right(CapRights::GRANT));
        assert_eq!(minted.depth, 1);
        assert_eq!(minted.object, obj_ptr);

        // Verify refcount was incremented (1 original + 1 mint = 2)
        assert_eq!(obj.ref_count.load(Ordering::Acquire), 2);

        // Verify CDT relationship
        assert_eq!(CDT::parent(dest_slot), src_slot);
        assert!(CDT::has_children(src_slot));

        // Clean up: remove CDT links and free slots
        CDT::remove(dest_slot);
        CDT::remove(src_slot);
        nullify_capability(src_slot);
        nullify_capability(dest_slot);
        free_slot(src_slot);
        free_slot(dest_slot);
    }

    #[test]
    fn test_mint_rejects_non_endpoint() {
        // Mint should fail for non-Endpoint types
        let src_slot = alloc_slot().unwrap();
        let dest_slot = alloc_slot().unwrap();

        let src_cap = get_cap_mut(src_slot);
        src_cap.obj_type = ObjectType::Frame; // Not an endpoint
        src_cap.rights = CapRights::GRANT;

        CDT::insert_root(src_slot);

        let result = get_cap(src_slot).mint(src_slot, 1, CapRights::READ, dest_slot);
        assert!(matches!(result, Err(CapError::InvalidOperation)));

        CDT::remove(src_slot);
        nullify_capability(src_slot);
        free_slot(src_slot);
        free_slot(dest_slot);
    }

    #[test]
    fn test_mint_rejects_grant_in_badge() {
        // Badged caps must not have Grant right
        let obj = KernelObject::new(ObjectType::Endpoint, 0);
        let obj_ptr = &obj as *const KernelObject as *mut KernelObject;

        let src_slot = alloc_slot().unwrap();
        let dest_slot = alloc_slot().unwrap();

        let src_cap = get_cap_mut(src_slot);
        src_cap.object = obj_ptr;
        src_cap.obj_type = ObjectType::Endpoint;
        src_cap.rights = CapRights::SEND | CapRights::GRANT;

        CDT::insert_root(src_slot);

        let result = get_cap(src_slot).mint(
            src_slot,
            99,
            CapRights::SEND | CapRights::GRANT, // Grant not allowed in minted cap
            dest_slot,
        );
        assert!(matches!(result, Err(CapError::InvalidBadge)));

        CDT::remove(src_slot);
        nullify_capability(src_slot);
        free_slot(src_slot);
        free_slot(dest_slot);
    }

    #[test]
    fn test_copy_reduced_rights() {
        let obj = KernelObject::new(ObjectType::Endpoint, 0);
        let obj_ptr = &obj as *const KernelObject as *mut KernelObject;

        let src_slot = alloc_slot().unwrap();
        let dest_slot = alloc_slot().unwrap();

        let src_cap = get_cap_mut(src_slot);
        src_cap.object = obj_ptr;
        src_cap.obj_type = ObjectType::Endpoint;
        src_cap.rights = CapRights::SEND | CapRights::RECV | CapRights::GRANT;
        src_cap.depth = 0;

        CDT::insert_root(src_slot);

        // Copy with reduced rights (SEND only)
        let result = get_cap(src_slot).copy(src_slot, CapRights::SEND, dest_slot);
        assert!(result.is_ok());

        let copied = get_cap(dest_slot);
        assert!(copied.has_right(CapRights::SEND));
        assert!(!copied.has_right(CapRights::RECV));
        assert!(!copied.has_right(CapRights::GRANT));
        assert_eq!(copied.depth, 1);
        assert_eq!(CDT::parent(dest_slot), src_slot);

        CDT::remove(dest_slot);
        CDT::remove(src_slot);
        nullify_capability(src_slot);
        nullify_capability(dest_slot);
        free_slot(src_slot);
        free_slot(dest_slot);
    }

    #[test]
    fn test_copy_rejects_without_grant() {
        let src_slot = alloc_slot().unwrap();
        let dest_slot = alloc_slot().unwrap();

        let src_cap = get_cap_mut(src_slot);
        src_cap.obj_type = ObjectType::Endpoint;
        src_cap.rights = CapRights::SEND | CapRights::RECV; // No GRANT

        CDT::insert_root(src_slot);

        let result = get_cap(src_slot).copy(src_slot, CapRights::SEND, dest_slot);
        assert!(matches!(result, Err(CapError::InsufficientRights)));

        CDT::remove(src_slot);
        nullify_capability(src_slot);
        free_slot(src_slot);
        free_slot(dest_slot);
    }
}
