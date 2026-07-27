// SPDX-License-Identifier: GPL-2.0-only
//! VOP operation context types.
//!
//! - [`OwnerVopCtx`] carries `&'a mut VfsState` plus pre-resolved raw
//!   pointers for the target vnode, its owning mount, and backend data.
//!   Backends dispatched through `VopMetaOps` receive `&mut OwnerVopCtx<'_>`.
//! - [`OwnerMountCtx`] is the mount-level sibling: same owner-state lend
//!   plus a pre-resolved `*mut Mount`. Passed to `VfsOps::{mount, unmount,
//!   root, vget, statfs, sync}`.
//! - [`WorkerIoCtx`] is the data-plane snapshot used by `VopDataOps`;
//!   `Send`-safe scalar copies only. Returned by [`OwnerVopCtx::data_ctx`].

use super::identity::{FsInstanceId, VnodeKey};
use super::mount::{Mount, MountHandle};
use super::vnode::{Vnode, VnodeHandle};
use crate::owner::VfsState;

// =========================================================================
// OwnerVopCtx — per-vnode owner-thread metadata operations
// =========================================================================

/// Context passed to `VopMetaOps` functions.
///
/// The raw pointers are valid for the duration of the call (the arena is
/// non-moving and the slot is Active). `state` is uniquely borrowed for the
/// lifetime of the ctx so helper methods can mutate owner state without
/// re-borrowing through raw pointers.
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
}

impl<'a> OwnerVopCtx<'a> {
    /// Build an `OwnerVopCtx` for `vh`. Returns `None` if the vnode handle
    /// is stale, the owning mount cannot be resolved, or the mount slot is
    /// retired.
    pub(crate) unsafe fn from_state(state: &'a mut VfsState, vh: VnodeHandle) -> Option<Self> {
        let vnode_ptr = state.vnodes.raw_ptr(vh)?;
        let mh = unsafe { (&*vnode_ptr).mount.resolve_ro(state)? };
        let mount_ptr = state.mounts.raw_ptr(mh)?;
        let (data, mount_data) = unsafe { ((&*vnode_ptr).data, (&*mount_ptr).data) };
        Some(Self {
            state,
            handle: vh,
            vnode: vnode_ptr,
            mount_handle: mh,
            mount: mount_ptr as *const Mount,
            data,
            mount_data,
        })
    }

    /// Allocate a fresh vnode slot from the arena.
    #[inline]
    pub(crate) unsafe fn alloc_vnode(&mut self) -> Option<(VnodeHandle, *mut Vnode)> {
        let h = self.state.vnodes.alloc()?;
        let ptr = self.state.vnodes.raw_ptr(h)?;
        Some((h, ptr))
    }

    /// Resolve any `VnodeHandle` to a read-only raw pointer, or `None` when
    /// the handle is stale.
    #[inline]
    pub(crate) unsafe fn resolve_vnode(&self, vh: VnodeHandle) -> Option<*const Vnode> {
        self.state.vnodes.raw_ptr(vh).map(|p| p as *const Vnode)
    }

    /// Resolve any `MountHandle` to a read-only raw pointer.
    #[inline]
    pub(crate) unsafe fn resolve_mount(&self, mh: MountHandle) -> Option<*const Mount> {
        self.state.mounts.raw_ptr(mh).map(|p| p as *const Mount)
    }

    /// Install a `(VnodeKey, VnodeHandle)` entry in the owner's resolve
    /// cache. No-op on invalid identity / handle.
    #[inline]
    pub(crate) fn install_resolve_cache(&mut self, key: VnodeKey, handle: VnodeHandle) {
        if !key.is_valid() || !handle.is_valid() {
            return;
        }
        self.state.install_resolve_cache(key, handle);
    }

    /// Resolve a slot number to a `MountHandle` via the mount arena.
    #[inline]
    pub(crate) fn mount_handle_from_slot(&self, slot: u32) -> Option<MountHandle> {
        self.state.mounts.handle_from_slot(slot)
    }

    /// Return the `FsInstanceId` of the mount whose `covered` key matches
    /// `key`, so cache-hit `vget` paths can restore `VN_COVERED` +
    /// `covered_by` after arena slot recycling.
    pub(crate) fn covering_fs_id_for_key(&self, key: VnodeKey) -> Option<FsInstanceId> {
        if !key.is_valid() {
            return None;
        }
        let mut found = None;
        self.state.mounts.for_each_active(|_mh, mp| {
            if mp.covered.id() == key {
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
    /// Valid for the lifetime of the ctx — the arena slot stays Active
    /// for the duration of the meta-op call.
    #[inline]
    pub(crate) unsafe fn vnode(&self) -> &Vnode {
        unsafe { &*self.vnode }
    }

    /// Return the target vnode as a mutable reference.
    ///
    /// # Safety
    /// Arena pointer is unique to this ctx for the call duration; no
    /// other code holds a live borrow of the same slot while the meta-op
    /// is running (single-threaded owner loop).
    #[inline]
    pub(crate) unsafe fn vnode_mut(&mut self) -> &mut Vnode {
        unsafe { &mut *self.vnode }
    }

    /// Return the owning mount as a read-only reference.
    ///
    /// # Safety
    /// Valid for the lifetime of the ctx — the mount arena slot is
    /// pinned while the meta-op runs.
    #[inline]
    pub(crate) unsafe fn mount(&self) -> &Mount {
        unsafe { &*self.mount }
    }

    /// Cached scalar vtype byte — equivalent to `(*self.vnode).vtype`.
    #[inline]
    pub(crate) unsafe fn vtype(&self) -> u8 {
        unsafe { (*self.vnode).vtype }
    }

    /// Cached scalar `fs_instance_id` — equivalent to
    /// `(*self.mount).fs_instance_id`.
    #[inline]
    pub(crate) unsafe fn fs_instance_id(&self) -> FsInstanceId {
        unsafe { (*self.mount).fs_instance_id }
    }

    /// Cached scalar backend node id — equivalent to `(*self.vnode).id`.
    #[inline]
    pub(crate) unsafe fn node_id(&self) -> u64 {
        unsafe { (*self.vnode).id }
    }

    /// Cached scalar backend incarnation — equivalent to
    /// `(*self.vnode).backend_seq`.
    #[inline]
    pub(crate) unsafe fn backend_seq(&self) -> u32 {
        unsafe { (*self.vnode).backend_seq }
    }

    /// Re-borrow the ctx with a shorter lifetime. Used by nested
    /// meta-op dispatch (dotdot walk crossing a mount boundary,
    /// rename's final-component lookup) so the caller does not have to
    /// rebuild a second `OwnerVopCtx` from scratch with a fresh
    /// `&mut state` borrow.
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
        }
    }

    /// Build a `WorkerIoCtx` snapshot from this meta ctx. The returned
    /// ctx carries a raw-pointer handle to `VfsState` so DataOps
    /// dispatched synchronously on the owner thread can reach owner
    /// state. When the ctx is moved across a thread boundary the
    /// `state` field must be nulled by the dispatcher.
    #[inline]
    pub(crate) unsafe fn data_ctx(&self) -> WorkerIoCtx {
        let vnode = unsafe { &*self.vnode };
        let fs_id = unsafe { (*self.mount).fs_instance_id };
        let ops = unsafe { (*self.vnode).ops };
        WorkerIoCtx::new(
            self.handle,
            self.mount_handle,
            self.data,
            self.mount_data,
            vnode.vtype,
            vnode.id,
            fs_id,
        )
        .with_ops(ops)
        .with_state(self.state as *const VfsState as *mut VfsState)
    }
}

// =========================================================================
// OwnerMountCtx — owner-thread mount-level operations
// =========================================================================

/// Context passed to `VfsOps` functions. Carries `&'a mut VfsState` plus a
/// pre-resolved `*mut Mount` for the mount under construction / inspection.
pub(crate) struct OwnerMountCtx<'a> {
    pub(crate) state: &'a mut VfsState,
    pub(crate) mount_handle: MountHandle,
    pub(crate) mount: *mut Mount,
}

impl<'a> OwnerMountCtx<'a> {
    /// Build an `OwnerMountCtx` for `mh`. `None` when the mount slot is
    /// retired between allocation and dispatch.
    pub(crate) unsafe fn from_state(state: &'a mut VfsState, mh: MountHandle) -> Option<Self> {
        let mount_ptr = state.mounts.raw_ptr(mh)?;
        Some(Self {
            state,
            mount_handle: mh,
            mount: mount_ptr,
        })
    }

    /// Allocate a fresh vnode slot from the arena.
    #[inline]
    pub(crate) unsafe fn alloc_vnode(&mut self) -> Option<(VnodeHandle, *mut Vnode)> {
        let h = self.state.vnodes.alloc()?;
        let ptr = self.state.vnodes.raw_ptr(h)?;
        Some((h, ptr))
    }

    /// Install a `(VnodeKey, VnodeHandle)` entry in the owner's resolve
    /// cache.
    #[inline]
    pub(crate) fn install_resolve_cache(&mut self, key: VnodeKey, handle: VnodeHandle) {
        if !key.is_valid() || !handle.is_valid() {
            return;
        }
        self.state.install_resolve_cache(key, handle);
    }

    /// Resolve a slot number to a `MountHandle`.
    #[inline]
    pub(crate) fn mount_handle_from_slot(&self, slot: u32) -> Option<MountHandle> {
        self.state.mounts.handle_from_slot(slot)
    }

    /// Read-only reference to the mount under construction / inspection.
    #[inline]
    pub(crate) unsafe fn mount(&self) -> &Mount {
        unsafe { &*self.mount }
    }

    /// Mutable reference to the mount under construction / inspection.
    #[inline]
    pub(crate) unsafe fn mount_mut(&mut self) -> &mut Mount {
        unsafe { &mut *self.mount }
    }
}

// =========================================================================
// WorkerIoCtx — data-plane snapshot for VopDataOps
// =========================================================================

/// Immutable snapshot context passed to `VopDataOps` functions.
///
/// `Send`-safe by construction — contains no arena references, only stable
/// raw pointers (guaranteed by non-moving arena segments + flight counting)
/// and scalar copies. A future worker pool will dispatch `WorkItem`s whose
/// payload carries this ctx; today the owner loop constructs it per-call
/// and invokes DataOps inline.
#[repr(C)]
pub(crate) struct WorkerIoCtx {
    pub(crate) vnode_handle: VnodeHandle,
    pub(crate) mount_handle: MountHandle,
    pub(crate) data: *mut u8,
    pub(crate) mount_data: *mut u8,
    pub(crate) vtype: u8,
    _pad: [u8; 7],
    pub(crate) id: u64,
    pub(crate) fs_instance_id: FsInstanceId,
    /// Present only on readdir / streaming pread paths where the backend
    /// needs the current open-object's per-file cursor state. Owner sets
    /// `Some(...)` before dispatch; every other DataOps call sees `None`.
    pub(crate) open_object: Option<crate::server::open_object::OpenObjectHandle>,
    /// Backend's `VopVector *` snapshotted at ctx construction. Worker
    /// threads cannot reach the arena to look this up, so it must travel
    /// with the ctx. Valid for the work-item's lifetime (flight-count
    /// pins the vnode slot until completion).
    pub(crate) ops: *const super::vop::VopVector,
    /// Raw pointer to `VfsState` — non-null when DataOps is dispatched
    /// from the owner thread (which holds `&mut VfsState` for the call).
    /// MUST be null when a `WorkerIoCtx` is handed across a thread
    /// boundary (future worker pool); this is the `Send` invariant.
    /// Access via [`state_mut`].
    state: *mut VfsState,
}

// SAFETY: `Send` is sound when `state` is null. Any code path that moves
// a `WorkerIoCtx` across threads must null out `state` first. Constructors
// below default to null; only the owner-local `data_ctx` builders set it.
unsafe impl Send for WorkerIoCtx {}

impl WorkerIoCtx {
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
            ops: core::ptr::null(),
            state: core::ptr::null_mut(),
        }
    }

    /// Attach the backend's VopVector pointer so the worker can
    /// dispatch DataOps without consulting the arena.
    #[inline]
    pub(crate) fn with_ops(mut self, ops: *const super::vop::VopVector) -> Self {
        self.ops = ops;
        self
    }

    #[inline]
    pub(crate) fn with_open_object(
        mut self,
        h: crate::server::open_object::OpenObjectHandle,
    ) -> Self {
        self.open_object = Some(h);
        self
    }

    /// Owner-side escape hatch: returns a `&mut VfsState` when the ctx
    /// was constructed on the owner thread. Returns `None` for worker-
    /// dispatched ctxs where state is unreachable by construction.
    ///
    /// # Safety
    ///
    /// Caller must not call this from a worker thread. The owner loop
    /// holds a unique `&mut VfsState` for the duration of a DataOps
    /// dispatch, so the returned reference does not alias; however, the
    /// raw pointer is only valid for the lifetime of that dispatch.
    #[inline]
    pub(crate) unsafe fn state_mut<'a>(&self) -> Option<&'a mut VfsState> {
        if self.state.is_null() {
            None
        } else {
            unsafe { Some(&mut *self.state) }
        }
    }

    /// Owner-side constructor: embeds the current `&mut VfsState` as a
    /// raw pointer so DataOps can reach owner state without the
    /// retired module-level trampoline.
    #[inline]
    pub(crate) fn with_state(mut self, state: *mut VfsState) -> Self {
        self.state = state;
        self
    }

    /// Strip the owner-state raw pointer before handing this ctx to a
    /// worker thread. Consuming rather than mutating makes the boundary
    /// explicit — worker dispatchers `let ctx = ctx.into_worker_ctx();`
    /// and the resulting ctx is `Send`-safe because `state.is_null()`.
    /// DataOps backends that need to reach state will see `None` from
    /// `state_mut()` and must fall back to worker-safe paths (pre-
    /// reserved handles carried via other ctx fields) or return an
    /// error indicating the call must run on the owner thread.
    #[inline]
    pub(crate) fn into_worker_ctx(mut self) -> Self {
        self.state = core::ptr::null_mut();
        self
    }
}
