// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-client bulk-transfer SHM region.
//!
//! When a client wants to read or write more bytes than fit in the
//! `regs[]` inline area, it asks vfs to register a SHM region via
//! `VFS_REGISTER_BULK_SHM`. vfs creates the SHM MO through mmsrv,
//! maps one view into vfs, and returns a cap copy to the client. The
//! client maps its own view through its self-tier mmsrv endpoint.
//! No server maps a foreign VSpace by badge.
//!
//! Lifetime: a region is allocated on `VFS_REGISTER_BULK_SHM` and
//! released on `VFS_RELEASE_BULK_SHM`, on `ClientState` teardown
//! (PEER_CLOSED), or on vfs shutdown. Release unmaps vfs's local
//! view, drops vfs's retained cap, then asks mmsrv to destroy the
//! SHM object. mmsrv rejects destroy while any self-tier mapping is
//! still live.
//!
//! Boundary invariant: vfs is the *only* writer of `client_va`'s
//! contents that the client trusts — cross-client SHM sharing is
//! refused at registration. Each client gets its own region; the
//! backend never sees the client SHM directly. This keeps the
//! security boundary at vfs.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;
use trona_protocol::mm::{MM_MUNMAP, MM_SHM_CREATE, MM_SHM_DESTROY, MM_SHM_MAP};
use trona_protocol::posix_abi::mm::{PROT_READ, PROT_WRITE};
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::arena::Handle;
use crate::core::error::VfsError;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

/// Opaque arena handle for a client bulk SHM region.
pub(crate) type ClientShmHandle = Handle<ClientShmRegion>;

/// Per-client bulk-transfer SHM region. `vfs_va` is vfs's local
/// mapping. The client holds a cap copy returned by
/// `VFS_REGISTER_BULK_SHM` and maps its own view through mmsrv.
pub(crate) struct ClientShmRegion {
    /// `mmsrv` SHM registry slot returned by `MM_SHM_CREATE`.
    pub(crate) shm_idx: u64,
    /// VFS-retained cap to the SHM MO. `None` on an empty slot.
    /// A copy is returned to the client on registration; this
    /// original is dropped during release after vfs's own mapping
    /// is unmapped.
    pub(crate) shm_cap: Option<OwnedCap>,
    /// VA of the region inside vfs's own VSpace. `read` / `write`
    /// dispatch reads or writes bytes through this pointer when
    /// the wire selects SHM mode.
    pub(crate) vfs_va: u64,
    /// Region size in bytes (page-rounded by mmsrv).
    pub(crate) bytes: u64,
    /// Owning client. Set at registration and consulted on every
    /// bulk read / write to refuse cross-client misuse.
    pub(crate) owner_client: crate::server::types::ClientHandle,
}

impl ClientShmRegion {
    /// Free-slot sentinel. `Default` falls through to this so the
    /// arena's `alloc` initialiser writes a deterministic empty
    /// state.
    pub(crate) const EMPTY: Self = Self {
        shm_idx: 0,
        shm_cap: None,
        vfs_va: 0,
        bytes: 0,
        owner_client: crate::server::types::ClientHandle::INVALID,
    };

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes == 0
    }
}

impl Default for ClientShmRegion {
    #[inline]
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Maximum bulk SHM region size per client. 1 MiB is enough to
/// carry a typical `read(fd, buf, 1 MiB)` in a single round-trip;
/// larger requests still work but get split across multiple bulk
/// calls by the personality projection. The cap exists to refuse
/// pathological registrations (e.g. malicious 16 GiB request)
/// rather than to bound legitimate workloads.
pub(crate) const BULK_SHM_MAX_BYTES: u64 = 1 << 20;

/// Page size used to round bulk SHM allocations. Mirrors mmsrv's
/// `MM_SHM_CREATE` granularity.
pub(crate) const BULK_SHM_PAGE_BYTES: u64 = 4096;

/// Initial arena segment capacity. Bulk SHM is one region per
/// active client, so a small starting segment is the right
/// default.
pub(crate) const CLIENT_SHM_INITIAL_CAP: u32 = 16;

/// Lookup whether `region` covers the byte range `[off, off + len)`.
/// Returns `Some(vfs_va_byte_pointer)` on a successful bounds
/// check, `None` when the range escapes the region.
#[inline]
pub(crate) fn slice_in_region(region: &ClientShmRegion, off: u64, len: u64) -> Option<*mut u8> {
    let end = off.checked_add(len)?;
    if end > region.bytes {
        return None;
    }
    let base = region.vfs_va as *mut u8;
    Some(unsafe { base.add(off as usize) })
}

/// Bounds-check + cast helper for the read direction (immutable
/// byte view).
#[inline]
pub(crate) fn const_slice_in_region(
    region: &ClientShmRegion,
    off: u64,
    len: u64,
) -> Option<*const u8> {
    slice_in_region(region, off, len).map(|p| p as *const u8)
}

pub(crate) unsafe fn mmsrv_shm_create(
    state: &VfsState,
    shm_name: u64,
    bytes: u64,
) -> Result<(u64, u64), VfsError> {
    unsafe {
        let cap_slot = trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"vfs bulk shm cap");
        if cap_slot == 0 {
            return Err(VfsError::NoMem);
        }
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = MM_SHM_CREATE;
        req.regs[0] = shm_name;
        req.regs[1] = 0;
        req.regs[2] = bytes;
        req.length = 3;
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            cap_slot,
            0,
        );
        let err = trona_kernel::ipc::mp_call_ctx(
            trona_posix::tls::current_ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            uapi::KERNITE_CAP_SELF_CSPACE as u64,
            state.recv_scratch_slot,
            0,
        );
        if err != 0 || reply.label != TRONA_OK {
            trona_runtime::core::slot_alloc::delete_and_free(cap_slot);
            Err(VfsError::NoMem)
        } else {
            Ok((reply.regs[0], cap_slot))
        }
    }
}

/// Map an SHM region into vfs's own VSpace. `cap` is the SHM MO
/// capability handed to mmsrv; it is consumed by the send (the kernel
/// moves it out of vfs's CSpace into mmsrv). Callers that keep the
/// region's MO alive (for later release / further transfers) must pass a
/// `dup_for_transfer`; the `TransferCap` drop reclaims the staged slot.
pub(crate) unsafe fn mmsrv_shm_map(
    shm_idx: u64,
    cap: trona_runtime::core::slot_alloc::TransferCap,
    bytes: u64,
) -> Result<u64, VfsError> {
    let result = unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = MM_SHM_MAP;
        req.regs[0] = 0; // hint: auto-place
        req.regs[1] = shm_idx;
        req.regs[2] = 0; // offset
        req.regs[3] = bytes;
        req.regs[4] = (PROT_READ | PROT_WRITE) as u64;
        req.regs[5] = 0; // flags
        req.length = 6;
        trona_kernel::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, cap.slot());
        let err = trona_kernel::ipc::mp_call_ctx(
            trona_posix::tls::current_ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            Err(VfsError::NoMem)
        } else {
            Ok(reply.regs[0])
        }
    };
    // `cap` drops here, after the send: reclaims the staged slot (empty
    // on success, rolled-back-then-deleted on send failure).
    result
}

pub(crate) unsafe fn mmsrv_munmap(vaddr: u64, bytes: u64) -> Result<(), VfsError> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = MM_MUNMAP;
        req.regs[0] = vaddr;
        req.regs[1] = bytes;
        req.length = 2;
        let err = trona_kernel::ipc::mp_call_ctx(
            trona_posix::tls::current_ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            Err(VfsError::Io)
        } else {
            Ok(())
        }
    }
}

pub(crate) unsafe fn mmsrv_shm_destroy(shm_idx: u64) -> Result<(), VfsError> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = MM_SHM_DESTROY;
        req.regs[0] = shm_idx;
        req.length = 1;
        let err = trona_kernel::ipc::mp_call_ctx(
            trona_posix::tls::current_ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep().addr(),
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        );
        if err != 0 || reply.label != TRONA_OK {
            Err(VfsError::Io)
        } else {
            Ok(())
        }
    }
}

/// Release the bulk SHM region attached to `client` (if any).
pub(crate) unsafe fn release_for_client(state: &mut VfsState, client: ClientHandle) {
    unsafe {
        let region_h = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm)
            .unwrap_or(ClientShmHandle::INVALID);
        // Extract fields before munmap / destroy so we hold no shared borrow
        // on state while issuing IPC.
        let (vfs_va, bytes, shm_idx, shm_cap) = {
            let Some(region) = state.client_shm_regions.get_mut(region_h) else {
                return;
            };
            (
                region.vfs_va,
                region.bytes,
                region.shm_idx,
                // Disarm the cap field; Drop fires delete_and_free
                // exactly once via the explicit `drop(shm_cap)` below.
                core::mem::replace(&mut region.shm_cap, None),
            )
        };
        let _ = mmsrv_munmap(vfs_va, bytes);
        // Drop the OwnedCap after the unmap so the cap is still valid for
        // any residual kernel page-walk that mmsrv triggers during MUNMAP.
        drop(shm_cap);
        let _ = mmsrv_shm_destroy(shm_idx);
        if let Some(cli) = state.clients.get_mut(client) {
            cli.bulk_shm = ClientShmHandle::INVALID;
        }
        let _ = state.client_shm_regions.release(region_h);
    }
}
