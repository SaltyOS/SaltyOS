// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS client per-mount pool management — vnode-data allocation.
//!
//! Vnode allocation is handled by the central arena (via `VopContext.alloc`
//! or `ctx.alloc_vnode`). This module only manages the
//! per-mount `SaltyfsVnodeData` pool.

use super::types::{SALTYFS_VDATA_POOL_SIZE, SaltyfsMountData, SaltyfsVnodeData};

/// Initialize the vdata pool for a saltyfs mount.
pub(super) unsafe fn init_pools(md: *mut SaltyfsMountData) -> i32 {
    unsafe {
        let vdata = crate::vfs_alloc_array::<SaltyfsVnodeData>(SALTYFS_VDATA_POOL_SIZE);
        if vdata.is_null() {
            return -1;
        }
        (*md).vdata_ptr = vdata;
        (*md).vdata_cap = SALTYFS_VDATA_POOL_SIZE;
        0
    }
}

/// Allocate a free vnode-data slot.
pub(super) unsafe fn alloc_vdata(md: *mut SaltyfsMountData) -> *mut SaltyfsVnodeData {
    unsafe {
        for i in 0..(*md).vdata_cap {
            let vd = (*md).vdata_ptr.add(i);
            if (*vd).active == 0 {
                *vd = SaltyfsVnodeData::zeroed();
                (*vd).active = 1;
                return vd;
            }
        }
        core::ptr::null_mut()
    }
}

/// Find an existing vdata slot by remote backend node identity.
pub(super) unsafe fn find_vdata_by_node(
    md: *mut SaltyfsMountData,
    remote_ino: u64,
    remote_seq: u32,
) -> *mut SaltyfsVnodeData {
    unsafe {
        for i in 0..(*md).vdata_cap {
            let vd = (*md).vdata_ptr.add(i);
            if (*vd).active != 0 && (*vd).remote_ino == remote_ino && (*vd).remote_seq == remote_seq
            {
                return vd;
            }
        }
        core::ptr::null_mut()
    }
}
