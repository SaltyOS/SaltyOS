// SPDX-License-Identifier: GPL-2.0-only
//! Per-client SHM bulk I/O handlers.
//!
//! Each client process creates a 256KB SHM region and registers it with VFS
//! via VFS_BULK_SETUP. VFS maps the SHM into its own address space so that
//! bulk reads can copy data directly from the VFS-SaltyFS SHM into the
//! client's SHM, avoiding the 152-byte-per-IPC bottleneck.

use besalt::consts::*;
use besalt::ipc;
use besalt::types::*;

use crate::client;
use crate::consts::*;
use crate::mount;
use crate::types::*;

/// Handle VFS_BULK_SETUP: map client's SHM into VFS address space.
///
/// Message layout:
///   regs[0] = shm_id (unique per client, typically badge | 0x42_0000_0000)
///   regs[1] = page_count (informational)
pub(crate) unsafe fn handle_bulk_setup(
    msg: *const BesaltMsg,
    reply: *mut BesaltMsg,
    badge: u64,
) {
    unsafe {
        let shm_id = (*msg).regs[0];
        let client_pages = (*msg).regs[1];

        // Reject clients that claim fewer pages than VFS needs for bulk I/O.
        // VFS always writes up to CLIENT_BULK_SHM_PAGES pages per request;
        // a smaller mapping would allow writes past the end of the client SHM.
        if client_pages < CLIENT_BULK_SHM_PAGES {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        // Map the client-created SHM into VFS via mmsrv (auto-place)
        let mut req = BesaltMsg::zeroed();
        let mut mm_reply = BesaltMsg::zeroed();
        req.label = MM_SHM_MAP;
        req.regs[0] = shm_id;
        req.regs[1] = 0; // map into VFS (caller's own badge)
        req.regs[2] = 0; // auto-place
        req.regs[3] = 0x3; // RW
        req.length = 4;
        ipc::call_ctx(
            crate::ipc_ctx(),
            VFS_CAP_MMSRV_EP,
            &raw const req,
            &raw mut mm_reply,
        );

        if mm_reply.label != BESALT_OK {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            (*reply).length = 0;
            return;
        }

        let mapped_vaddr = mm_reply.regs[0];
        let cli = client::get_client(badge);
        if !cli.is_null() {
            (*cli).bulk_shm_vaddr = mapped_vaddr;
            (*cli).bulk_shm_id = shm_id;
        }

        (*reply).label = BESALT_OK;
        (*reply).length = 0;
    }
}

/// Handle VFS_BULK_READ: read file data into client's SHM.
///
/// Message layout:
///   regs[0] = fd
///   regs[1] = count (bytes to read)
///   regs[2] = shm_offset (offset within client SHM)
///
/// Reply:
///   label = BESALT_OK
///   regs[0] = total bytes read
pub(crate) unsafe fn handle_bulk_read(
    msg: *const BesaltMsg,
    reply: *mut BesaltMsg,
    badge: u64,
) {
    unsafe {
        let fd = (*msg).regs[0] as i32;
        let count = (*msg).regs[1];
        let shm_offset = (*msg).regs[2];

        let cli = client::get_client_noalloc(badge);
        if cli.is_null() || (*cli).bulk_shm_vaddr == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        if fd < 0 || fd >= (*cli).fds_cap as i32 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let fde = &mut *(*cli).fds.add(fd as usize);
        if fde.active == 0 {
            (*reply).label = BESALT_INVALID_ARGUMENT;
            (*reply).length = 1;
            (*reply).regs[0] = 0;
            return;
        }

        let client_shm = (*cli).bulk_shm_vaddr;
        let shm_limit = CLIENT_BULK_SHM_PAGES * 4096;
        let capped = count.min(shm_limit.saturating_sub(shm_offset));

        match fde.fd_type {
            FD_TYPE_MOUNT if *(&raw const crate::VFS_SHM_ACTIVE) => {
                bulk_read_mount(fde, client_shm, shm_offset, capped, reply);
            }
            _ => {
                (*reply).label = BESALT_INVALID_ARGUMENT;
                (*reply).length = 1;
                (*reply).regs[0] = 0;
            }
        }
    }
}

/// Read from a mount-backed fd into client SHM.
///
/// Reads from SaltyFS via the VFS-SaltyFS SHM and copies chunks into the
/// client's per-process SHM. Handles multi-chunk transfers up to 256KB.
unsafe fn bulk_read_mount(
    fde: &mut FdEntry,
    client_shm: u64,
    shm_offset: u64,
    count: u64,
    reply: *mut BesaltMsg,
) {
    unsafe {
        let mount_idx = fde.dev_type as usize;
        let remote_ino = fde.sock_id as u64;
        let saltyfs_shm_size = VFS_SALTYFS_SHM_PAGES * 4096;

        let mut total = 0u64;
        while total < count {
            let chunk = (count - total).min(saltyfs_shm_size);
            mount::mount_read_shm(
                mount_idx,
                remote_ino,
                fde.offset + total,
                chunk,
                0,
                reply,
            );
            if (*reply).label != BESALT_OK {
                break;
            }

            let bytes = (*reply).regs[0];
            if bytes == 0 {
                break;
            }

            // SAFETY: VFS_SALTYFS_SHM_VADDR and client_shm are both mapped,
            // non-overlapping memory regions. bytes <= saltyfs_shm_size and
            // total + bytes <= count <= CLIENT_BULK_SHM_PAGES * 4096.
            let src = VFS_SALTYFS_SHM_VADDR as *const u8;
            let dst = (client_shm + shm_offset + total) as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, bytes as usize);

            total += bytes;
            if bytes < chunk {
                break; // short read = EOF
            }
        }

        fde.offset += total;
        (*reply).label = BESALT_OK;
        (*reply).regs[0] = total;
        (*reply).length = 1;
    }
}

/// Clean up client's bulk SHM on exit.
///
/// Unmaps the client's SHM from VFS address space via mmsrv.
pub(crate) unsafe fn cleanup_bulk_shm(cli: *mut ClientState) {
    unsafe {
        if (*cli).bulk_shm_vaddr == 0 {
            return;
        }

        // Unmap from VFS address space
        let mut req = BesaltMsg::zeroed();
        let mut mm_reply = BesaltMsg::zeroed();
        req.label = MM_SHM_UNMAP;
        req.regs[0] = (*cli).bulk_shm_id;
        req.regs[1] = 0; // VFS's own badge
        req.regs[2] = (*cli).bulk_shm_vaddr;
        req.length = 3;
        ipc::call_ctx(
            crate::ipc_ctx(),
            VFS_CAP_MMSRV_EP,
            &raw const req,
            &raw mut mm_reply,
        );

        (*cli).bulk_shm_vaddr = 0;
        (*cli).bulk_shm_id = 0;
    }
}
