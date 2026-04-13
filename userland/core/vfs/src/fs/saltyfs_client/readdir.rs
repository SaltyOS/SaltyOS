// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS readdir — SHM-based streaming with batch caching.
//!
//! The SaltyFS server streams readdir entries into VFS SHM as fixed-size
//! 96-byte records via `handle_readdir`. This module issues the IPC call,
//! parses the SHM entries, and emits them through the `ReaddirEmit` callback.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VAttr;
use crate::vfs_core::vop::ReaddirEmit;

use super::rpc::ipc_ctx;
use super::types::SaltyfsMountData;

/// Size of one readdir entry in the SHM stream.
const READDIR_ENTRY_BYTES: usize = 96;

/// Maximum name length within a readdir entry.
const READDIR_NAME_MAX: usize = 44;

/// Perform a SHM-based readdir against the remote SaltyFS.
///
/// `cookie` is an opaque cursor (0 to start). On return, `*cookie` is updated
/// to the next cursor value (0 = EOF).
///
/// Requires SHM transport to be active.
pub(super) unsafe fn saltyfs_readdir_shm(
    md: *mut SaltyfsMountData,
    dir_ino: u64,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VfsResult<()> {
    unsafe {
        let start_cookie = *cookie;
        if !(*md).shm_active {
            return Err(VfsError::NotSupported);
        }

        let shm_vaddr = (*md).shm_vaddr;
        let shm_size = (*md).shm_size;
        if shm_size == 0 {
            return Err(VfsError::NotSupported);
        }

        let shm_offset: u64 = 0;
        let buf_bytes = shm_size;

        let mut req = TronaMsg::zeroed();
        req.label = SALTYFS_READDIR;
        req.regs[0] = dir_ino;
        req.regs[1] = *cookie;
        req.regs[2] = shm_offset;
        req.regs[3] = buf_bytes;
        req.length = 4;

        let mut reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(ipc_ctx(), (*md).fs_cap, &raw const req, &raw mut reply);

        if err != 0 {
            return Err(VfsError::Io);
        }

        if reply.label != TRONA_OK {
            return Err(VfsError::Io);
        }

        let next_cursor = reply.regs[0];
        let entries_written = reply.regs[1] as usize;
        let _bytes_written = reply.regs[2] as usize;

        if entries_written == 0 {
            *cookie = 0;
            return Ok(());
        }

        let base = (shm_vaddr + shm_offset) as *const u8;
        let attr = VAttr::zeroed();

        for i in 0..entries_written {
            let entry_ptr = base.add(i * READDIR_ENTRY_BYTES);

            let ino = core::ptr::read_unaligned(entry_ptr as *const u64);
            let mode = core::ptr::read_unaligned(entry_ptr.add(32) as *const u32);
            let dir_type = *entry_ptr.add(48);
            let mut name_len = *entry_ptr.add(49) as usize;
            if name_len > READDIR_NAME_MAX {
                name_len = READDIR_NAME_MAX;
            }
            let name_ptr = entry_ptr.add(52);

            if name_len == 0 {
                continue;
            }

            let d_type = if dir_type != 0 {
                dir_type
            } else {
                mode_to_dtype(mode)
            };

            if !emit(ino, name_ptr, name_len as u8, d_type, &attr) {
                *cookie = start_cookie + i as u64 + 1;
                return Ok(());
            }
        }

        *cookie = next_cursor;
        Ok(())
    }
}

/// Map POSIX mode bits to d_type for readdir.
#[inline]
fn mode_to_dtype(mode: u32) -> u8 {
    match mode & S_IFMT_L {
        S_IFDIR_L => 4,  // DT_DIR
        S_IFREG_L => 8,  // DT_REG
        S_IFLNK_L => 10, // DT_LNK
        S_IFCHR_L => 2,  // DT_CHR
        _ => 0,          // DT_UNKNOWN
    }
}
