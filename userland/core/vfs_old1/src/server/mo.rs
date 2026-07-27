// SPDX-License-Identifier: GPL-2.0-only
//! MemoryObject lifecycle helpers for vfs-owned storage.
//!
//! tmpfs (and any future fs that wants mmap-able backing) needs to own
//! a real `MemoryObject` capability so that mmsrv can transfer it to a
//! mmap-ing client. mmsrv reaches rsrcsrv directly through its own
//! `kernel_vm` module; vfs follows the same pattern but keeps the
//! plumbing here so backends do not duplicate the rsrcsrv IPC dance.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use uapi::*;

const PAGE_BYTES: u64 = 4096;
const VFS_MO_BASE: u64 = 0x0000_0000_8000_0000;
const VFS_MO_LIMIT: u64 = 0x0000_0000_F000_0000;

/// Bump cursor for vfs-private MO mappings. Single-threaded vfs owner
/// loop guarantees exclusive access; we never recycle ranges so reads /
/// writes never see stale tmpfs data.
static mut VFS_MO_NEXT: u64 = VFS_MO_BASE;

#[inline]
unsafe fn ipc_ctx() -> *mut IpcContext {
    crate::ipc_ctx()
}

/// Snapshot of the IPC receive-slot triple. The vfs main loop sets
/// the receive slot to `state.owner_recv_slot` once at startup; helpers
/// here that flip the slot to receive an rsrcsrv-delivered MO cap must
/// restore the previous values before the dispatcher hands control
/// back to the owner loop, otherwise the next inbound message lands
/// into the wrong cnode slot and the owner ends up wedged.
#[derive(Clone, Copy)]
struct RecvSlotSnapshot {
    cnode: Cap,
    index: u64,
    depth: u64,
    slot_depth: u64,
}

unsafe fn snapshot_receive_slot(ctx: *mut IpcContext) -> RecvSlotSnapshot {
    if ctx.is_null() {
        return RecvSlotSnapshot {
            cnode: 0,
            index: 0,
            depth: 0,
            slot_depth: 0,
        };
    }
    unsafe {
        let buf = (*ctx).ipc_buffer;
        if buf.is_null() {
            return RecvSlotSnapshot {
                cnode: 0,
                index: 0,
                depth: 0,
                slot_depth: 0,
            };
        }
        RecvSlotSnapshot {
            cnode: (*buf).receive_cnode,
            index: (*buf).receive_index,
            depth: (*buf).receive_depth,
            slot_depth: (*buf).reserved[IPC_BUFFER_RECV_SLOT_DEPTH_INDEX],
        }
    }
}

unsafe fn restore_receive_slot(ctx: *mut IpcContext, snap: RecvSlotSnapshot) {
    unsafe {
        ipc::set_receive_slot_path_ctx(ctx, snap.cnode, snap.index, snap.depth, snap.slot_depth);
    }
}

/// Allocate `min_pages`-page MemoryObject via rsrcsrv. Returns
/// `(mo_cap, rsrcsrv_handle, actual_pages)` on success.
pub(crate) unsafe fn alloc(min_pages: u64) -> Result<(Cap, u64, u64), u64> {
    if min_pages == 0 {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let mut size_bits: u64 = 0;
    while (1u64 << size_bits) < min_pages {
        size_bits += 1;
    }
    let actual_pages = 1u64 << size_bits;

    let dest_slot = trona_runtime::core::slot_alloc::slot_alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    unsafe {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, dest_slot);
        let saved = snapshot_receive_slot(ipc_ctx());
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx(),
            CAP_SELF_CSPACE,
            dest_slot,
            0,
        );

        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = trona_protocol::rsrcsrv::RES_ALLOC_OBJECT;
        req.length = 4;
        req.regs[0] = 0;
        req.regs[1] = OBJ_MEMORY_OBJECT;
        req.regs[2] = size_bits;
        req.regs[3] = 0;

        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::rsrcsrv_ep(),
            &raw const req,
            &raw mut reply,
        );
        restore_receive_slot(ipc_ctx(), saved);
        if err != 0 {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, dest_slot);
            let _ = trona_runtime::core::slot_alloc::slot_free(dest_slot);
            return Err(err as u64);
        }
        if reply.label != TRONA_OK {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, dest_slot);
            let _ = trona_runtime::core::slot_alloc::slot_free(dest_slot);
            return Err(reply.label);
        }

        let handle = reply.regs[0];
        let (commit_err, committed) = invoke::mo_commit(dest_slot, 0, actual_pages, 0);
        if commit_err != 0 || committed != actual_pages {
            let _ = free(dest_slot, handle);
            return Err(if commit_err != 0 {
                commit_err as u64
            } else {
                TRONA_OUT_OF_MEMORY
            });
        }
        Ok((dest_slot, handle, actual_pages))
    }
}

/// Free a previously allocated MemoryObject.
///
/// Returns `Ok(())` on success or the rsrcsrv error otherwise. Always
/// reclaims the cap slot, even when rsrcsrv reports an error.
pub(crate) unsafe fn free(mo_cap: Cap, handle: u64) -> Result<(), u64> {
    if mo_cap == 0 {
        return Ok(());
    }
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = trona_protocol::rsrcsrv::RES_FREE_HANDLE;
        req.length = 2;
        req.regs[0] = 0;
        req.regs[1] = handle;
        let err = ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::rsrcsrv_ep(),
            &raw const req,
            &raw mut reply,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, mo_cap);
        let _ = trona_runtime::core::slot_alloc::slot_free(mo_cap);
        if err != 0 {
            return Err(err as u64);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

/// Map a fully-committed MemoryObject into vfs's own VSpace and return
/// the mapped base address. Each call consumes a fresh VA range from
/// the per-process bump cursor.
pub(crate) unsafe fn map_local(
    mo_cap: Cap,
    page_count: u64,
    writable: bool,
) -> Result<*mut u8, u64> {
    if page_count == 0 {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let bytes = page_count * PAGE_BYTES;
    unsafe {
        let base = *(&raw const VFS_MO_NEXT);
        if base
            .checked_add(bytes)
            .map(|end| end > VFS_MO_LIMIT)
            .unwrap_or(true)
        {
            return Err(TRONA_OUT_OF_MEMORY);
        }
        let mut flags = VSPACE_FLAG_USER;
        if writable {
            flags |= VSPACE_FLAG_WRITABLE;
        }
        let count_and_flags = (page_count << 32) | flags;
        let (err, mapped) =
            invoke::vspace_map_mo_with_count(CAP_SELF_VSPACE, mo_cap, base, 0, count_and_flags);
        if err != 0 || mapped != page_count {
            for page in 0..mapped {
                let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, base + page * PAGE_BYTES);
            }
            return Err(if err != 0 {
                err as u64
            } else {
                TRONA_INVALID_OPERATION
            });
        }
        *(&raw mut VFS_MO_NEXT) = base + bytes;
        Ok(base as *mut u8)
    }
}

/// Reverse of [`map_local`]: unmap every page that was mapped at
/// `addr`. The VA range is intentionally not recycled — the bump cursor
/// keeps marching to keep mappings disjoint without an extra free list.
pub(crate) unsafe fn unmap_local(addr: *mut u8, page_count: u64) {
    if addr.is_null() || page_count == 0 {
        return;
    }
    unsafe {
        for page in 0..page_count {
            let _ = invoke::vspace_unmap(CAP_SELF_VSPACE, addr as u64 + page * PAGE_BYTES);
        }
    }
}

/// Resize an existing MO and commit any pages added to the tail.
/// `current_pages` lets the caller skip the commit entirely on shrink
/// or no-op resizes — only the [`current_pages`, `new_pages`) range
/// needs new physical frames.
pub(crate) unsafe fn resize(mo_cap: Cap, current_pages: u64, new_pages: u64) -> Result<(), u64> {
    if mo_cap == 0 || new_pages == 0 {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    unsafe {
        let err = invoke::mo_resize(mo_cap, new_pages);
        if err != 0 {
            return Err(err as u64);
        }
        if new_pages > current_pages {
            let extra = new_pages - current_pages;
            let (err2, committed) = invoke::mo_commit(mo_cap, current_pages, extra, 0);
            if err2 != 0 || committed != extra {
                return Err(if err2 != 0 {
                    err2 as u64
                } else {
                    TRONA_OUT_OF_MEMORY
                });
            }
        }
        Ok(())
    }
}
