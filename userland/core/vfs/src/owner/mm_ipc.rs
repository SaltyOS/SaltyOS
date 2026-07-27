// SPDX-License-Identifier: GPL-2.0-only
//
//! mmsrv ↔ vfs MM RPC wrappers — pager-cap edition.
//!
//! Owner-thread helpers for the `MM_*` calls vfs issues to mmsrv.
//! The legacy `MM_PAGER_ACQUIRE_SESSION / _COMMIT / _ABORT` lease
//! wire is gone — file-backed MOs are now produced by a single
//! `MM_FILE_MMAP` round-trip that returns `(mo_cap, mo_id)` and
//! attaches mmsrv's MO to vfs's `OBJ_PAGER` so the kernel routes
//! page-absent faults through `KERNITE_EVENT_TYPE_PAGER_REQUEST`
//! events directly into `state.owner_eq`.
//!
//! [`ensure_backing_mo_for_vnode`] is the canonical entry point:
//! idempotent per-vnode (returns the existing binding on repeat
//! calls), install-on-miss, returns the mo_cap slot + kernel-issued
//! `mo_id` plus the covered `(file_offset, length)` range.

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc::mp_call_ctx;
use trona_protocol::common::TRONA_OK;
use trona_protocol::mm::{MM_FILE_MMAP, MM_MO_CREATE};

use crate::core::error::VfsError;
use crate::core::vnode::VnodeHandle;
use crate::core::vop_context::OwnerVopCtx;
use crate::owner::pager_rpc::install_mo_binding;
use crate::owner::{MoBinding, VfsState};
use trona_runtime::core::slot_alloc::OwnedCap;

/// `(mo_cap, mo_id, file_offset, length, size)` returned by
/// [`ensure_backing_mo_for_vnode`]. `mo_cap` is the cnode slot in
/// vfs's cspace where the MO cap copy is stored; callers that need
/// to forward it to a client copy the slot via `caps[0]` on their
/// reply.
#[derive(Clone, Copy, Debug)]
pub(crate) struct BackingMoInfo {
    pub mo_cap: u64,
    pub mo_id: u64,
    pub file_offset: u64,
    pub length: u64,
    pub size: u64,
}

/// Create a fresh anonymous MemoryObject through mmsrv's self-tier
/// `MM_MO_CREATE` label and receive the returned MO cap into a stable
/// VFS CSpace slot.
pub(crate) unsafe fn mmsrv_mo_create(
    state: &VfsState,
    length: u64,
    flags: u64,
) -> Result<u64, VfsError> {
    if length == 0 {
        return Err(VfsError::Inval);
    }
    let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();
    if mmsrv_ep == 0 {
        return Err(VfsError::Io);
    }

    let mo_cap_slot = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"vfs mo_create");
    if mo_cap_slot == 0 {
        return Err(VfsError::NoMem);
    }

    let mut req = TronaMsg::default();
    req.label = MM_MO_CREATE;
    req.regs[0] = length;
    req.regs[1] = flags;
    req.length = 2;

    let mut reply = TronaMsg::default();
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            mo_cap_slot,
            0,
        );
    }
    let err = unsafe {
        mp_call_ctx(
            crate::ipc_ctx(),
            mmsrv_ep,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            state.recv_scratch_slot,
            0,
        );
    }
    if err != 0 || reply.label != TRONA_OK {
        // SAFETY: mo_cap_slot holds the MO cap moved in above, solely owned here;
        // freed once on this error path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(mo_cap_slot) };
        return Err(VfsError::Io);
    }
    Ok(mo_cap_slot)
}

/// # Safety
/// `mo_cap` is an MO cap slot the caller solely owns; torn down and freed once.
pub(crate) unsafe fn release_mo_cap_silent(mo_cap: u64) {
    // SAFETY: exclusive ownership of `mo_cap` per this fn's `# Safety`.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(mo_cap) };
}

/// Resolve `(vnode → mo_cap)` against the binding table, installing
/// a fresh binding via `MM_FILE_MMAP` on miss.
///
/// On miss: issues `MM_FILE_MMAP(vnode_slot, vnode_epoch,
/// file_handle, file_offset, length, prot, flags)` to mmsrv;
/// receives `(mo_idx, mo_id; caps=[mo_cap])`; moves the inbound
/// mo_cap out of `state.recv_scratch_slot` into a freshly-allocated
/// stable cspace slot; installs the `MoBinding` so
/// `EVENT_TYPE_PAGER_REQUEST` events keyed on `mo_id` can resolve
/// back to the originating vnode; returns the populated
/// `BackingMoInfo`.
///
/// On hit: returns the existing binding's `mo_cap_slot` / `mo_id`
/// / file range — no RPC fired.
pub(crate) unsafe fn ensure_backing_mo_for_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
) -> Result<BackingMoInfo, VfsError> {
    let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();
    if mmsrv_ep == 0 || !state.mmsrv_pager_registered {
        return Err(VfsError::Io);
    }

    // Reuse an existing binding if vfs has already materialised an
    // MO for this vnode. Linear scan — bounded by the live mmap
    // working set, which stays small.
    let n = state.pager_bindings.len();
    for i in 0..n {
        if let Some(b) = state.pager_bindings.get(i) {
            if b.active && b.vnode == vnode {
                return Ok(BackingMoInfo {
                    mo_cap: b.mo_cap.as_raw(),
                    mo_id: b.mo_id,
                    file_offset: b.file_offset,
                    length: b.length,
                    size: b.length,
                });
            }
        }
    }

    // Sanity-check the vnode is live before sinking IPC.
    let _vnode_entry = state.vnodes.get(vnode).ok_or(VfsError::BadF)?;

    // Pull the cached file size from the backend's `data_size`
    // accessor (vop_table::meta.data_size). Owner-thread
    // synchronous; backends that have no notion of a file size
    // (sysctlfs / procfs / devfs / pipes) return 0 and we refuse
    // the mmap with `Inval`.
    let cached_size = unsafe {
        let mut ctx_owner = match OwnerVopCtx::from_state(state, vnode) {
            Some(c) => c,
            None => return Err(VfsError::BadF),
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            return Err(VfsError::Inval);
        }
        ((*ops).meta.data_size)(&mut ctx_owner)
    };
    if cached_size == 0 {
        return Err(VfsError::Inval);
    }
    let page_mask = (uapi::KERNITE_PAGE_BYTES as u64) - 1;
    let length = (cached_size + page_mask) & !page_mask;
    let file_offset: u64 = 0;
    // `file_handle` is vfs-internal: mmsrv stamps it on the
    // file_backed_registry record but never re-emits it on the
    // wire — using the vnode's arena slot keeps it stable across
    // pager-event lookups even though mmsrv treats it as opaque.
    let file_handle: u64 = vnode.slot() as u64;

    // Allocate the stable cap slot before the RPC and arm it as the
    // receive destination. This avoids borrowing the frontend scratch
    // slot reserved for inbound client call payload caps.
    let mo_cap_slot = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"vfs file-backed mo");
    if mo_cap_slot == 0 {
        return Err(VfsError::NoMem);
    }

    let mut req = TronaMsg::default();
    req.label = MM_FILE_MMAP;
    req.regs[0] = vnode.slot() as u64;
    req.regs[1] = vnode.epoch() as u64;
    req.regs[2] = file_handle;
    req.regs[3] = file_offset;
    req.regs[4] = length;
    req.regs[5] = 0; // prot — informational; the client supplies
    // real prot when it issues `MM_MMAP_MO`.
    req.regs[6] = 0; // flags — same.
    req.length = 7;

    let mut reply = TronaMsg::default();
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            mo_cap_slot,
            0,
        );
    }
    let err = unsafe {
        mp_call_ctx(
            crate::ipc_ctx(),
            mmsrv_ep,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            state.recv_scratch_slot,
            0,
        );
    }
    if err != 0 || reply.label != TRONA_OK {
        // SAFETY: mo_cap_slot holds the MO cap moved in above, solely owned here;
        // freed once on this error path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(mo_cap_slot) };
        return Err(VfsError::Io);
    }
    let mo_id = reply.regs[1];

    let binding = MoBinding {
        mo_id,
        // Adopt the freshly-allocated slot; MoBinding takes sole ownership.
        // SAFETY: mo_cap_slot holds the MO cap moved in above and is solely
        // owned by this MoBinding.
        mo_cap: unsafe { OwnedCap::adopt_received(mo_cap_slot) },
        vnode,
        file_offset,
        length,
        active: true,
    };
    let _ = unsafe { install_mo_binding(state, binding)? };

    Ok(BackingMoInfo {
        mo_cap: mo_cap_slot,
        mo_id,
        file_offset,
        length,
        size: length,
    })
}
