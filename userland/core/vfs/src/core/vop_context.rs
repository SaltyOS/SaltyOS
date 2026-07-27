// SPDX-License-Identifier: GPL-2.0-only
//
//! VOP operation context types.
//!
//! * [`OwnerVopCtx`] carries `&'a mut VfsState` plus pre-resolved
//!   raw pointers for the target vnode, its owning mount, and
//!   backend data. Backends dispatched through `VopMetaOps`
//!   receive `&mut OwnerVopCtx<'_>`.
//! * [`OwnerMountCtx`] is the mount-level sibling: same owner-
//!   state lend plus a pre-resolved `*mut Mount`. Passed to
//!   `VfsOps::{mount, unmount, root, vget, statfs, sync}`.
//! * [`VopDataCtx`] is the data-plane snapshot used by
//!   `VopDataOps`.

use crate::owner::VfsState;

use super::identity::{FsInstanceId, VnodeKey};
use super::mount::{Mount, MountHandle};
use super::vnode::{Vnode, VnodeHandle};

// ---------------------------------------------------------------------------
// OwnerVopCtx — per-vnode owner-thread metadata operations
// ---------------------------------------------------------------------------

/// Context passed to `VopMetaOps` functions.
///
/// The raw pointers are valid for the duration of the call (the
/// arena is non-moving and the slot is Active). `state` is
/// uniquely borrowed for the lifetime of the ctx so helper
/// methods can mutate owner state without re-borrowing through
/// raw pointers.
#[repr(C)]
pub(crate) struct OwnerVopCtx<'a> {
    /// Owner state uniquely borrowed for this VOP.
    pub(crate) state: &'a mut VfsState,
    /// Handle of the vnode being operated on.
    pub(crate) handle: VnodeHandle,
    /// Resolved mutable pointer to the vnode.
    pub(crate) vnode: *mut Vnode,
    /// Handle of the owning mount.
    pub(crate) mount_handle: MountHandle,
    /// Resolved read-only pointer to the owning mount.
    pub(crate) mount: *const Mount,
    /// Backend-specific vnode data (`(*vnode).data`).
    pub(crate) data: *mut u8,
    /// Backend-specific mount data (`(*mount).data`).
    pub(crate) mount_data: *mut u8,
    /// IPC badge of the client whose request is being served, when the
    /// dispatcher supplies it (0 otherwise). init-async vops use it to
    /// tag the parked `PendingOp` so the client-teardown badge sweep
    /// reaps the in-flight query.
    pub(crate) caller_badge: u64,
}

impl<'a> OwnerVopCtx<'a> {
    /// Build an `OwnerVopCtx` for `vnode_h`. Returns `None` if the
    /// vnode handle is stale.
    ///
    /// Mount resolution is best-effort: when `vnode.mount` is the
    /// `INVALID` sentinel (used by mount-less synthetic vnodes —
    /// anonymous pipes, socket pairs, devfs char nodes that have
    /// no per-mount state) the ctx carries `mount = null` and
    /// `mount_data = null`. Vops that need the mount must
    /// guard the deref themselves; mount-less ops dereference
    /// `vnode.data` directly. The mount-bearing path is the
    /// common case for backed filesystems.
    pub(crate) unsafe fn from_state(state: &'a mut VfsState, vnode_h: VnodeHandle) -> Option<Self> {
        unsafe {
            let vnode_ptr = state.vnodes.raw_ptr(vnode_h)?;
            let mount_h = (*vnode_ptr).mount;
            let (mount_ptr, mount_data) = if mount_h.is_valid() {
                match state.mounts.raw_ptr(mount_h) {
                    Some(mp) => (mp as *const Mount, (*mp).data),
                    None => (::core::ptr::null(), ::core::ptr::null_mut()),
                }
            } else {
                (::core::ptr::null(), ::core::ptr::null_mut())
            };
            let data = (*vnode_ptr).data;
            Some(Self {
                state,
                handle: vnode_h,
                vnode: vnode_ptr,
                mount_handle: mount_h,
                mount: mount_ptr,
                data,
                mount_data,
                caller_badge: 0,
            })
        }
    }

    /// Stamp the serving client's IPC badge so init-async vops can tag
    /// their parked `PendingOp` for client-teardown reaping. Chainable.
    #[inline]
    pub(crate) fn with_caller_badge(mut self, badge: u64) -> Self {
        self.caller_badge = badge;
        self
    }

    /// Allocate a fresh vnode slot from the arena.
    #[inline]
    pub(crate) unsafe fn alloc_vnode(&mut self) -> Option<(VnodeHandle, *mut Vnode)> {
        unsafe {
            let h = self.state.vnodes.alloc()?;
            let ptr = self.state.vnodes.raw_ptr(h)?;
            *ptr = Vnode::EMPTY;
            Some((h, ptr))
        }
    }

    /// Resolve any `VnodeHandle` to a read-only raw pointer, or
    /// `None` when the handle is stale.
    #[inline]
    pub(crate) unsafe fn resolve_vnode(&self, vnode_h: VnodeHandle) -> Option<*const Vnode> {
        unsafe {
            self.state
                .vnodes
                .raw_ptr(vnode_h)
                .map(|p| p as *const Vnode)
        }
    }

    /// Resolve any `MountHandle` to a read-only raw pointer.
    #[inline]
    pub(crate) unsafe fn resolve_mount(&self, mount_h: MountHandle) -> Option<*const Mount> {
        unsafe {
            self.state
                .mounts
                .raw_ptr(mount_h)
                .map(|p| p as *const Mount)
        }
    }

    /// Install a `(VnodeKey, VnodeHandle)` entry in the owner's
    /// resolve cache. No-op on invalid identity / handle.
    #[inline]
    pub(crate) fn install_resolve_cache(&mut self, key: VnodeKey, handle: VnodeHandle) {
        self.state.install_resolve_cache(key, handle);
    }

    /// Resolve a slot number to a `MountHandle` via the mount
    /// arena.
    #[inline]
    pub(crate) fn mount_handle_from_slot(&self, slot: u32) -> Option<MountHandle> {
        self.state.mounts.handle_from_slot(slot)
    }

    /// Return the `FsInstanceId` of the mount whose `covered_key`
    /// matches `key`, so cache-hit `vget` paths can restore
    /// `VN_COVERED` on a vnode reallocated into a slot previously
    /// holding a mountpoint.
    pub(crate) fn covering_fs_id_for_key(&self, key: VnodeKey) -> Option<FsInstanceId> {
        if !key.is_valid() {
            return None;
        }
        let mut found = None;
        self.state.mounts.for_each_active(|_mh, mp| {
            if mp.covered_key == key {
                found = Some(mp.fs_instance_id);
                return false;
            }
            true
        });
        found
    }

    /// Return the target vnode as a read-only reference.
    ///
    /// # Safety
    /// Valid for the lifetime of the ctx — the arena slot stays
    /// Active for the duration of the meta-op call.
    #[inline]
    pub(crate) unsafe fn vnode(&self) -> &Vnode {
        unsafe { &*self.vnode }
    }

    /// Return the target vnode as a mutable reference.
    ///
    /// # Safety
    /// Arena pointer is unique to this ctx for the call duration
    /// (single-threaded owner loop).
    #[inline]
    pub(crate) unsafe fn vnode_mut(&mut self) -> &mut Vnode {
        unsafe { &mut *self.vnode }
    }

    /// Return the owning mount as a read-only reference.
    #[inline]
    pub(crate) unsafe fn mount(&self) -> &Mount {
        unsafe { &*self.mount }
    }

    /// Cached vtype byte — equivalent to `(*self.vnode).vtype()`.
    #[inline]
    pub(crate) unsafe fn vtype(&self) -> u8 {
        unsafe { (*self.vnode).vtype() }
    }

    /// Cached `fs_instance_id` — equivalent to
    /// `(*self.mount).fs_instance_id`.
    #[inline]
    pub(crate) unsafe fn fs_instance_id(&self) -> FsInstanceId {
        unsafe { (*self.mount).fs_instance_id }
    }

    /// Cached backend node id — equivalent to
    /// `(*self.vnode).id()`.
    #[inline]
    pub(crate) unsafe fn node_id(&self) -> u64 {
        unsafe { (*self.vnode).id() }
    }

    /// Cached backend incarnation — equivalent to
    /// `(*self.vnode).backend_seq`.
    #[inline]
    pub(crate) unsafe fn backend_seq(&self) -> u32 {
        unsafe { (*self.vnode).backend_seq }
    }

    /// Re-borrow the ctx with a shorter lifetime. Used by nested
    /// meta-op dispatch (dotdot walk crossing a mount boundary,
    /// rename's final-component lookup) so the caller does not
    /// have to rebuild a second `OwnerVopCtx` from scratch.
    #[inline]
    #[allow(dead_code)]
    pub(crate) unsafe fn reborrow<'b>(&'b mut self) -> OwnerVopCtx<'b>
    where
        'a: 'b,
    {
        OwnerVopCtx {
            state: &mut *self.state,
            handle: self.handle,
            vnode: self.vnode,
            mount_handle: self.mount_handle,
            mount: self.mount,
            data: self.data,
            mount_data: self.mount_data,
            caller_badge: self.caller_badge,
        }
    }

    /// Build a `VopDataCtx` snapshot from this meta ctx. DataOps
    /// run on the owner thread; backend-backed operations park by
    /// issuing a backend-session RPC and resume through `PendingOp`
    /// completion rather than through a local vfs worker.
    #[inline]
    pub(crate) unsafe fn data_ctx(&self) -> VopDataCtx {
        unsafe {
            let vnode = &*self.vnode;
            // Mount-less synthetic vnodes (anonymous pipes, socket
            // pairs, etc.) read `INVALID` for `fs_instance_id` —
            // their data ops do not consult it.
            let fs_id = if self.mount.is_null() {
                FsInstanceId::INVALID
            } else {
                (*self.mount).fs_instance_id
            };
            let ops = (*self.vnode).ops;
            VopDataCtx::new(
                self.handle,
                self.mount_handle,
                self.data,
                self.mount_data,
                vnode.vtype(),
                vnode.id(),
                fs_id,
            )
            .with_ops(ops)
            .with_state(self.state as *const VfsState as *mut VfsState)
            .with_caller_badge(self.caller_badge)
        }
    }
}

// ---------------------------------------------------------------------------
// OwnerMountCtx — owner-thread mount-level operations
// ---------------------------------------------------------------------------

/// Context passed to `VfsOps` functions. Carries `&'a mut VfsState`
/// plus a pre-resolved `*mut Mount` for the mount under
/// construction / inspection.
pub(crate) struct OwnerMountCtx<'a> {
    pub(crate) state: &'a mut VfsState,
    pub(crate) mount_handle: MountHandle,
    pub(crate) mount: *mut Mount,
}

impl<'a> OwnerMountCtx<'a> {
    /// Build an `OwnerMountCtx` for `mount_h`. `None` when the mount
    /// slot is retired between allocation and dispatch.
    pub(crate) unsafe fn from_state(state: &'a mut VfsState, mount_h: MountHandle) -> Option<Self> {
        unsafe {
            let mount_ptr = state.mounts.raw_ptr(mount_h)?;
            Some(Self {
                state,
                mount_handle: mount_h,
                mount: mount_ptr,
            })
        }
    }

    /// Allocate a fresh vnode slot from the arena.
    #[inline]
    pub(crate) unsafe fn alloc_vnode(&mut self) -> Option<(VnodeHandle, *mut Vnode)> {
        unsafe {
            let h = self.state.vnodes.alloc()?;
            let ptr = self.state.vnodes.raw_ptr(h)?;
            *ptr = Vnode::EMPTY;
            Some((h, ptr))
        }
    }

    /// Install a `(VnodeKey, VnodeHandle)` entry in the owner's
    /// resolve cache.
    #[inline]
    pub(crate) fn install_resolve_cache(&mut self, key: VnodeKey, handle: VnodeHandle) {
        self.state.install_resolve_cache(key, handle);
    }

    /// Resolve a slot number to a `MountHandle`.
    #[inline]
    pub(crate) fn mount_handle_from_slot(&self, slot: u32) -> Option<MountHandle> {
        self.state.mounts.handle_from_slot(slot)
    }

    /// Read-only reference to the mount under construction /
    /// inspection.
    #[inline]
    pub(crate) unsafe fn mount(&self) -> &Mount {
        unsafe { &*self.mount }
    }

    /// Mutable reference to the mount under construction /
    /// inspection.
    #[inline]
    pub(crate) unsafe fn mount_mut(&mut self) -> &mut Mount {
        unsafe { &mut *self.mount }
    }
}

// ---------------------------------------------------------------------------
// VopDataCtx — data-plane snapshot for VopDataOps
// ---------------------------------------------------------------------------

/// Immutable snapshot context passed to `VopDataOps` functions.
///
/// Owner-local by construction: contains stable raw pointers and
/// scalar copies for one data VOP dispatch. Backend-backed data
/// ops use this context to issue async backend-session RPCs, then
/// return `Parked` so the owner reactor can resume via completion.
#[repr(C)]
pub(crate) struct VopDataCtx {
    pub(crate) vnode_handle: VnodeHandle,
    pub(crate) mount_handle: MountHandle,
    pub(crate) data: *mut u8,
    pub(crate) mount_data: *mut u8,
    pub(crate) vtype: u8,
    _pad: [u8; 7],
    pub(crate) id: u64,
    pub(crate) fs_instance_id: FsInstanceId,
    /// Present only on readdir / streaming pread paths where the
    /// backend needs the current open-object's per-file cursor
    /// state. Owner sets `Some(...)` before dispatch; every other
    /// DataOps call sees `None`.
    pub(crate) open_object: Option<crate::server::types::OpenObjectHandle>,
    /// Backend's `VopVector *` snapshotted at ctx construction.
    /// Data ops use this when they need to re-enter sibling VOPs
    /// without resolving the vnode arena again.
    pub(crate) ops: *const super::vop::VopVector,
    /// Raw pointer to `VfsState` — non-null when DataOps is
    /// dispatched from the owner thread (which holds
    /// `&mut VfsState` for the call). Access via
    /// [`Self::state_mut`].
    state: *mut VfsState,
    /// IPC badge of the client whose request is being served, used by
    /// tty-control ioctls to resolve the caller's POSIX session via init.
    pub(crate) caller_badge: u64,
}

impl VopDataCtx {
    #[inline]
    pub(crate) const fn new(
        vnode_handle: VnodeHandle,
        mount_handle: MountHandle,
        data: *mut u8,
        mount_data: *mut u8,
        vtype: u8,
        id: u64,
        fs_instance_id: FsInstanceId,
    ) -> Self {
        Self {
            vnode_handle,
            mount_handle,
            data,
            mount_data,
            vtype,
            _pad: [0; 7],
            id,
            fs_instance_id,
            open_object: None,
            ops: ::core::ptr::null(),
            state: ::core::ptr::null_mut(),
            caller_badge: 0,
        }
    }

    /// Attach the backend's VopVector pointer for data ops that
    /// need sibling VOP callbacks.
    #[inline]
    pub(crate) fn with_ops(mut self, ops: *const super::vop::VopVector) -> Self {
        self.ops = ops;
        self
    }

    /// Attach an open-object handle for cursor-bearing data ops
    /// (readdir / streaming read).
    #[inline]
    pub(crate) fn with_open_object(mut self, h: crate::server::types::OpenObjectHandle) -> Self {
        self.open_object = Some(h);
        self
    }

    /// Owner-side escape hatch: returns a `&mut VfsState` when
    /// the ctx was constructed on the owner thread.
    ///
    /// # Safety
    ///
    /// The owner loop holds a unique `&mut VfsState` for the
    /// duration of a DataOps dispatch, so the returned reference
    /// does not alias.
    #[inline]
    pub(crate) unsafe fn state_mut<'a>(&self) -> Option<&'a mut VfsState> {
        if self.state.is_null() {
            None
        } else {
            unsafe { Some(&mut *self.state) }
        }
    }

    /// Owner-side constructor: embeds the current `&mut VfsState`
    /// as a raw pointer so DataOps can reach owner state without
    /// the retired module-level trampoline.
    #[inline]
    pub(crate) fn with_state(mut self, state: *mut VfsState) -> Self {
        self.state = state;
        self
    }

    /// Stamp the serving client's IPC badge so tty-control ioctls can
    /// resolve the caller's POSIX session.
    #[inline]
    pub(crate) fn with_caller_badge(mut self, badge: u64) -> Self {
        self.caller_badge = badge;
        self
    }
}
