// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client VfsOps implementation — filesystem-level operations.
//!
//! Handles mount (namesrv lookup, SALTYFS_MOUNT IPC, SHM setup),
//! unmount, root, vget, statfs, and sync.

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::invoke;
use trona::ipc;
use trona::protocol::*;
use trona::types::core::*;

use crate::personality::posix::consts::*;
use crate::server::consts::*;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::VStatfs;
use crate::vfs_core::mount::Mount;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vnode::{VnodeHandle, VN_ROOT, VT_DIR};

use super::pool;
use super::rpc;
use super::types::{SaltyfsMountData, SaltyfsVnodeData};

// =========================================================================
// Mount
// =========================================================================

/// Initialize a SaltyFS mount.
///
/// `source` is the IPC endpoint capability slot for the SaltyFS server.
/// If `source == 0`, the implementation performs a namesrv lookup for "saltyfs".
pub(super) unsafe fn saltyfs_mount(
    mp: *mut Mount,
    source: u64,
    _opts_ptr: *const u8,
    _opts_len: u8,
) -> VfsResult<()> {
    unsafe {
        // Allocate SaltyfsMountData
        let alloc_size = core::mem::size_of::<SaltyfsMountData>();
        let alloc_pages = (alloc_size + 4095) / 4096;
        let md_raw = crate::server::mem::map_anon((alloc_pages * 4096) as u64);
        if md_raw.is_null() || md_raw == usize::MAX as *mut u8 {
            return Err(VfsError::NoSpace);
        }
        core::ptr::write_bytes(md_raw, 0, alloc_pages * 4096);

        let md = md_raw as *mut SaltyfsMountData;
        *md = SaltyfsMountData::zeroed();
        (*mp).data = md as *mut u8;

        // Resolve the SaltyFS server endpoint
        let fs_cap = if source != 0 {
            source
        } else {
            resolve_saltyfs_endpoint()?
        };
        (*md).fs_cap = fs_cap;

        // Send SALTYFS_MOUNT
        let mut mnt_req = TronaMsg::zeroed();
        mnt_req.label = SALTYFS_MOUNT;
        mnt_req.length = 0;

        let mut mnt_reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            fs_cap,
            &raw const mnt_req,
            &raw mut mnt_reply,
        );
        if err != 0 || (mnt_reply.label != TRONA_OK && mnt_reply.label != TRONA_ALREADY_EXISTS) {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] saltyfs mount failed err=");
                _lb.hex(err as u64);
                _lb.str(b" label=");
                _lb.hex(mnt_reply.label);
                _lb.str(b"\n");
            });
            return Err(VfsError::Io);
        }

        let root_ino = mnt_reply.regs[0];
        (*md).root_ino = root_ino;

        // Enable V2 protocol (current SaltyFS server always supports it)
        (*md).v2_protocol = true;

        // Initialize vdata pool
        if pool::init_pools(md) != 0 {
            return Err(VfsError::NoSpace);
        }

        // Set up SHM bulk transport
        setup_shm(md, fs_cap);

        // Create root vnode data
        let root_vd = pool::alloc_vdata(md);
        if root_vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        (*root_vd).active = 1;
        (*root_vd).ftype = VT_DIR;
        (*root_vd).mode = S_IFDIR_L | 0o755;
        (*root_vd).remote_ino = root_ino;
        (*root_vd).nlink = 2;

        // Allocate root vnode from the central arena via trampoline.
        let (root_vh, root_vp) = mount_ctl::trampoline_alloc_vnode().ok_or(VfsError::NoSpace)?;
        let mount_handle =
            mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32).ok_or(VfsError::Io)?;
        (*root_vp).id = root_ino;
        (*root_vp).vtype = VT_DIR;
        (*root_vp).flags = VN_ROOT;
        (*root_vp).data = root_vd as *mut u8;
        (*root_vp).nlink = 2;
        (*root_vp).mount = mount_handle;
        (*root_vp).ops = &raw const super::SALTYFS_VOPS;
        (*root_vd).vnode_handle = root_vh;

        (*mp).root_vnode = root_vh;

        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] Mounted saltyfs root_ino=");
            _lb.hex(root_ino);
            _lb.str(b"\n");
        });

        Ok(())
    }
}

// =========================================================================
// Unmount
// =========================================================================

pub(super) unsafe fn saltyfs_unmount(mp: *mut Mount, _force: bool) -> VfsResult<()> {
    unsafe {
        (*mp).root_vnode = VnodeHandle::INVALID;
        (*mp).data = core::ptr::null_mut();
        Ok(())
    }
}

// =========================================================================
// Root
// =========================================================================

pub(super) unsafe fn saltyfs_root(mp: *mut Mount) -> VfsResult<VnodeHandle> {
    unsafe {
        let root = (*mp).root_vnode;
        if !root.is_valid() {
            return Err(VfsError::Io);
        }
        Ok(root)
    }
}

// =========================================================================
// Vget
// =========================================================================

pub(super) unsafe fn saltyfs_vget(mp: *mut Mount, id: u64) -> VfsResult<VnodeHandle> {
    unsafe {
        let md = (*mp).data as *mut SaltyfsMountData;

        // Check if vdata already exists for this remote inode
        let existing_vd = pool::find_vdata_by_ino(md, id);
        if !existing_vd.is_null() {
            if (*existing_vd).vnode_handle.is_valid()
                && crate::vfs_core::mount_ctl::vnode_resolve_trampoline((*existing_vd).vnode_handle)
                    .is_some()
            {
                return Ok((*existing_vd).vnode_handle);
            }
            // Allocate a new arena vnode pointing to the existing vdata
            let (vh, vp) = mount_ctl::trampoline_alloc_vnode().ok_or(VfsError::NoSpace)?;
            let mount_handle = mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32)
                .ok_or(VfsError::Io)?;
            (*vp).id = id;
            (*vp).vtype = (*existing_vd).ftype;
            (*vp).data = existing_vd as *mut u8;
            (*vp).nlink = (*existing_vd).nlink;
            (*vp).mount = mount_handle;
            (*vp).ops = &raw const super::SALTYFS_VOPS;
            (*existing_vd).vnode_handle = vh;
            return Ok(vh);
        }

        // Stat the remote inode to populate a new vnode
        match rpc::saltyfs_ipc_stat(md, id) {
            Some((size, mode, nlink, mtime, blocks, uid, gid)) => {
                let vd = pool::alloc_vdata(md);
                if vd.is_null() {
                    return Err(VfsError::NoSpace);
                }
                let ftype = match mode & S_IFMT_L {
                    S_IFDIR_L => VT_DIR,
                    S_IFLNK_L => crate::vfs_core::vnode::VT_LNK,
                    _ => crate::vfs_core::vnode::VT_REG,
                };
                (*vd).active = 1;
                (*vd).ftype = ftype;
                (*vd).mode = mode;
                (*vd).remote_ino = id;
                (*vd).size = size;
                (*vd).nlink = nlink;
                (*vd).uid = uid;
                (*vd).gid = gid;
                (*vd).mtime = mtime;
                (*vd).blocks = blocks;

                let (vh, vp) = mount_ctl::trampoline_alloc_vnode().ok_or(VfsError::NoSpace)?;
                let mount_handle = mount_ctl::trampoline_mount_handle_from_slot((*mp).id as u32)
                    .ok_or(VfsError::Io)?;
                (*vp).id = id;
                (*vp).vtype = ftype;
                (*vp).data = vd as *mut u8;
                (*vp).nlink = nlink;
                (*vp).mount = mount_handle;
                (*vp).ops = &raw const super::SALTYFS_VOPS;
                (*vd).vnode_handle = vh;
                Ok(vh)
            }
            None => Err(VfsError::NotFound),
        }
    }
}

// =========================================================================
// Statfs
// =========================================================================

pub(super) unsafe fn saltyfs_statfs(mp: *mut Mount, out: *mut VStatfs) -> VfsResult<()> {
    unsafe {
        let md = (*mp).data as *mut SaltyfsMountData;
        match rpc::saltyfs_ipc_getinfo(md) {
            Some((total_blocks, used_blocks, block_size)) => {
                (*out).bsize = block_size;
                (*out).blocks = total_blocks;
                (*out).bfree = total_blocks.saturating_sub(used_blocks);
                (*out).bavail = (*out).bfree;
                (*out).files = 0;
                (*out).ffree = 0;
                let ft = &mut (*out).fs_type;
                ft[..7].copy_from_slice(b"saltyfs");
                (*out).flags = (*mp).flags;
                (*out).name_max = 255;
                Ok(())
            }
            None => Err(VfsError::Io),
        }
    }
}

// =========================================================================
// Sync
// =========================================================================

pub(super) unsafe fn saltyfs_sync(_mp: *mut Mount) -> VfsResult<()> {
    Ok(())
}

// =========================================================================
// Helpers
// =========================================================================

/// Resolve the "saltyfs" endpoint via namesrv.
unsafe fn resolve_saltyfs_endpoint() -> VfsResult<u64> {
    unsafe {
        let slot = match trona::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => return Err(VfsError::NoSpace),
        };
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
        ipc::set_receive_slot_ctx(crate::ipc_ctx(), CAP_SELF_CSPACE, slot, 0);

        let mut ns_req = TronaMsg::zeroed();
        ns_req.label = NS_LOOKUP;
        let name = b"saltyfs";
        ns_req.regs[0] = name.len() as u64;
        ns_req.length = 1 + (name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut ns_req.regs[1] as *mut u8;
        for i in 0..name.len() {
            *ns_dst.add(i) = name[i];
        }

        let mut ns_reply = TronaMsg::zeroed();
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::namesrv_ep(),
            &raw const ns_req,
            &raw mut ns_reply,
        );

        if err != 0 || ns_reply.label != TRONA_OK {
            trona::udebug!(|_lb| {
                _lb.str(b"[VFS] saltyfs not found in namesrv\n");
            });
            return Err(VfsError::NotFound);
        }

        Ok(slot)
    }
}

/// Set up VFS-SaltyFS SHM for bulk data transport.
unsafe fn setup_shm(md: *mut SaltyfsMountData, fs_cap: u64) {
    unsafe {
        let mut shm_create = TronaMsg::zeroed();
        shm_create.label = MM_SHM_CREATE;
        shm_create.length = 2;
        shm_create.regs[0] = VFS_SALTYFS_SHM_ID;
        shm_create.regs[1] = VFS_SALTYFS_SHM_PAGES;

        let mut shm_reply = TronaMsg::zeroed();
        let serr = ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const shm_create,
            &raw mut shm_reply,
        );
        if serr != 0 || (shm_reply.label != 0 && shm_reply.label != TRONA_ALREADY_EXISTS) {
            trona::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM create failed (non-fatal)\n");
            });
            return;
        }

        let mut shm_map = TronaMsg::zeroed();
        shm_map.label = MM_SHM_MAP;
        shm_map.length = 4;
        shm_map.regs[0] = VFS_SALTYFS_SHM_ID;
        shm_map.regs[1] = 0;
        shm_map.regs[2] = VFS_SALTYFS_SHM_VADDR;
        shm_map.regs[3] = 0x3; // RW

        let mut map_reply = TronaMsg::zeroed();
        let merr = ipc::call_ctx(
            crate::ipc_ctx(),
            trona::caps::mmsrv_ep(),
            &raw const shm_map,
            &raw mut map_reply,
        );
        if merr != 0 || map_reply.label != 0 {
            trona::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM map failed (non-fatal)\n");
            });
            return;
        }

        let mut setup_msg = TronaMsg::zeroed();
        setup_msg.label = SALTYFS_SHM_SETUP;
        setup_msg.regs[0] = VFS_SALTYFS_SHM_ID;
        setup_msg.length = 1;

        let mut setup_reply = TronaMsg::zeroed();
        let serr2 = ipc::call_ctx(
            crate::ipc_ctx(),
            fs_cap,
            &raw const setup_msg,
            &raw mut setup_reply,
        );
        if serr2 == 0 && setup_reply.label == TRONA_OK {
            trona::uinfo!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM transport established\n");
            });
            (*md).shm_active = true;
            (*md).shm_vaddr = VFS_SALTYFS_SHM_VADDR;
            (*md).shm_size = VFS_SALTYFS_SHM_PAGES * 4096;

            *(&raw mut crate::VFS_SHM_ACTIVE) = true;
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[VFS] saltyfs SHM setup failed (non-fatal)\n");
            });
            let mut shm_unmap = TronaMsg::zeroed();
            shm_unmap.label = MM_SHM_UNMAP;
            shm_unmap.length = 3;
            shm_unmap.regs[0] = VFS_SALTYFS_SHM_ID;
            shm_unmap.regs[1] = 0;
            shm_unmap.regs[2] = VFS_SALTYFS_SHM_VADDR;
            let mut unmap_reply = TronaMsg::zeroed();
            let _ = ipc::call_ctx(
                crate::ipc_ctx(),
                trona::caps::mmsrv_ep(),
                &raw const shm_unmap,
                &raw mut unmap_reply,
            );
        }
    }
}
