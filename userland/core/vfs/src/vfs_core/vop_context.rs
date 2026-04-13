// SPDX-License-Identifier: GPL-2.0-only
//! VOP operation context types.
//!
//! `VopContext` and `VopDataContext` replace the raw `*mut Vnode` parameter
//! in the old VopVector signatures. They carry resolved handles, transient
//! raw pointers, and arena-access callbacks so backends never need to touch
//! global state or arena internals directly.

use super::mount::{Mount, MountHandle};
use super::vnode::{Vnode, VnodeHandle};

// =========================================================================
// Arena-access callbacks
// =========================================================================

/// Allocate a new vnode from the global arena.
///
/// Called by backends during lookup (cache miss), create, mkdir, symlink.
/// The owner loop sets up a trampoline before each VOP call that captures
/// the arena pointer via an unsafe static (safe because single-threaded).
///
/// Returns `(VnodeHandle, *mut Vnode)` or `None` if the arena is exhausted.
pub(crate) type VnodeAllocFn = unsafe fn() -> Option<(VnodeHandle, *mut Vnode)>;

/// Resolve an arbitrary VnodeHandle to a read-only raw pointer.
///
/// Called by backends that need to inspect a foreign vnode (e.g. `link`
/// reads the target vnode's inode/nlink, `rename` may need the source
/// vnode's type). Valid for Active and Retired slots.
///
/// Returns `None` if the handle is stale or the slot is Free/Reclaimable.
pub(crate) type VnodeResolveFn = unsafe fn(VnodeHandle) -> Option<*const Vnode>;

/// Resolve a MountHandle to a read-only raw pointer.
///
/// Called by backends that need to inspect a foreign mount (e.g. cross-mount
/// rename validation). Valid for Active slots only.
pub(crate) type MountResolveFn = unsafe fn(MountHandle) -> Option<*const Mount>;

// =========================================================================
// VopContext — owner-thread metadata operations
// =========================================================================

/// Context passed to `VopMetaOps` functions.
///
/// Constructed by the owner loop before each MetaOps call. The resolved
/// raw pointers are valid for the duration of the call (the arena is
/// non-moving and the slot is Active).
///
/// Provides full access to the target vnode, its owning mount, and
/// arena-level operations (alloc, resolve) via callbacks.
#[repr(C)]
pub(crate) struct VopContext {
    // -- Target identity --------------------------------------------------
    /// Handle to the vnode being operated on.
    pub(crate) handle: VnodeHandle,
    /// Resolved mutable pointer to the vnode.
    pub(crate) vnode: *mut Vnode,

    // -- Owning mount -----------------------------------------------------
    /// Handle to the owning mount.
    pub(crate) mount_handle: MountHandle,
    /// Resolved read-only pointer to the owning mount.
    pub(crate) mount: *const Mount,

    // -- Backend shortcut pointers ----------------------------------------
    /// Backend-specific vnode data (`(*vnode).data`).
    pub(crate) data: *mut u8,
    /// Backend-specific mount data (`(*mount).data`).
    pub(crate) mount_data: *mut u8,

    // -- Arena callbacks --------------------------------------------------
    /// Allocate a new vnode from the global arena.
    pub(crate) alloc: VnodeAllocFn,
    /// Resolve a VnodeHandle to a read-only vnode pointer.
    pub(crate) resolve_vnode: VnodeResolveFn,
    /// Resolve a MountHandle to a read-only mount pointer.
    pub(crate) resolve_mount: MountResolveFn,
}

// =========================================================================
// VopDataContext — async-capable data operations
// =========================================================================

/// Immutable snapshot context passed to `VopDataOps` functions.
///
/// May be dispatched to worker threads for blocking operations. Contains
/// no arena references — only stable raw pointers (guaranteed by
/// non-moving segments + flight counting) and scalar copies.
#[repr(C)]
pub(crate) struct VopDataContext {
    /// Handle to the vnode (for completion routing, not resolution).
    pub(crate) vnode_handle: VnodeHandle,
    /// Handle to the mount (for completion routing).
    pub(crate) mount_handle: MountHandle,
    /// Backend-specific vnode data pointer. Stable because the arena
    /// segment is non-moving and the slot is guarded by flight counting.
    pub(crate) data: *mut u8,
    /// Backend-specific mount data pointer.
    pub(crate) mount_data: *mut u8,
    /// Vnode type (cached from `vnode.vtype`).
    pub(crate) vtype: u8,
    _pad: [u8; 7],
    /// Backend-defined vnode ID (cached from `vnode.id`).
    pub(crate) id: u64,
}

unsafe impl Send for VopDataContext {}

impl VopDataContext {
    #[inline]
    pub(crate) const fn new(
        vnode_handle: VnodeHandle,
        mount_handle: MountHandle,
        data: *mut u8,
        mount_data: *mut u8,
        vtype: u8,
        id: u64,
    ) -> Self {
        Self {
            vnode_handle,
            mount_handle,
            data,
            mount_data,
            vtype,
            _pad: [0; 7],
            id,
        }
    }
}

#[inline]
pub(crate) unsafe fn data_ctx_from_meta(ctx: &VopContext) -> VopDataContext {
    let vnode = unsafe { &*ctx.vnode };
    VopDataContext::new(
        ctx.handle,
        ctx.mount_handle,
        ctx.data,
        ctx.mount_data,
        vnode.vtype,
        vnode.id,
    )
}
