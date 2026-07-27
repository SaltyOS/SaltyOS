// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs `VopVector` — per-vnode operations for the sysctl virtual filesystem.

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{MODE_TYPE_DIR, MODE_TYPE_REG};
use crate::core::file::{VAttr, VStatfs};
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::outcome::{Parked, Ready, VopOutcome};
use crate::core::vnode::{VN_NOCACHE, VnodeHandle, VnodeKind};
use crate::core::vop::{
    DATA_OPS_DEFAULT, META_OPS_DEFAULT, ReaddirEmit, VopDataOps, VopMetaOps, VopVector,
};
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};

use super::tree::{
    CTLFLAG_WR, CTLTYPE_NODE, CTLTYPE_STRING, DynamicDir, MIB_ROOT, SysctlCtx, SysctlLeaf,
    SysctlNode, SysctlOutcome,
};
use super::{SysctlfsKind, SysctlfsVnodeData, encode_dynleaf_id, encode_id};

const SYSCTL_BUF_SIZE: usize = 4096;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut SysctlfsVnodeData {
    ctx.data as *mut SysctlfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataCtx) -> *mut SysctlfsVnodeData {
    ctx.data as *mut SysctlfsVnodeData
}

unsafe fn ctl_type_for_vdata(vdata: *const SysctlfsVnodeData) -> u8 {
    unsafe {
        match (*vdata).kind {
            SysctlfsKind::Root | SysctlfsKind::Node | SysctlfsKind::DynDir => CTLTYPE_NODE,
            SysctlfsKind::Leaf => {
                let leaf = (*vdata).node as *const SysctlLeaf;
                if leaf.is_null() {
                    CTLTYPE_STRING
                } else {
                    (*leaf).ctl_type
                }
            }
            SysctlfsKind::DynLeaf => CTLTYPE_STRING,
        }
    }
}

unsafe fn fill_node_vnode(
    ctx: &mut OwnerVopCtx<'_>,
    kind: VnodeKind,
    pkind: SysctlfsKind,
    ptr: *const u8,
    nlink: u32,
    flags: u32,
) -> Result<(VnodeHandle, *mut crate::core::vnode::Vnode), VfsError> {
    unsafe {
        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vnode_ptr).kind = kind;
        (*vnode_ptr).flags = flags;
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(encode_id(pkind, ptr), 0),
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).mount = ctx.mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).ops = (*ctx.vnode).ops;
        (*vnode_ptr).nlink = nlink;
        Ok((vnode_h, vnode_ptr))
    }
}

unsafe fn sysctlfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dir_vdata = vdata(ctx);

        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            if !ctx.mount.is_null() {
                let root_vh = (*ctx.mount).root;
                if root_vh.is_valid() {
                    return Ok(Ready(root_vh));
                }
            }
            return Ok(Ready(ctx.handle));
        }

        let node_ptr = match (*dir_vdata).kind {
            SysctlfsKind::Root => {
                if (*dir_vdata).node.is_null() {
                    &raw const MIB_ROOT as *const SysctlNode
                } else {
                    (*dir_vdata).node
                }
            }
            SysctlfsKind::Node => (*dir_vdata).node,
            SysctlfsKind::Leaf | SysctlfsKind::DynLeaf => return Err(VfsError::NotDir),
            SysctlfsKind::DynDir => {
                let dyn_ptr = (*dir_vdata).node as *const DynamicDir;
                if dyn_ptr.is_null() {
                    return Err(VfsError::Io);
                }
                // Create the dyn leaf optimistically. Existence and content
                // are resolved by the parked `read` (the `kern.proc.*`
                // provider parks on init), so lookup must not call the
                // provider here — that would block the reactor on init.
                let name_slice = ::core::slice::from_raw_parts(name, name_len as usize);
                let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
                let fs_instance_id = (*ctx.mount).fs_instance_id;
                (*vnode_ptr).kind = VnodeKind::Regular;
                (*vnode_ptr).flags = VN_NOCACHE;
                (*vnode_ptr).key = VnodeKey {
                    fs_instance_id,
                    backend_id: BackendNodeId::new(encode_dynleaf_id(dyn_ptr, name_slice), 0),
                };
                (*vnode_ptr).backend_seq = 0;
                (*vnode_ptr).mount = ctx.mount_handle;
                (*vnode_ptr).fs_instance_id = fs_instance_id;
                (*vnode_ptr).ops = (*ctx.vnode).ops;
                (*vnode_ptr).nlink = 1;
                let vdata = super::alloc_vdata(ctx.mount_data);
                if vdata.is_null() {
                    return Err(VfsError::NoMem);
                }
                (*vdata).kind = SysctlfsKind::DynLeaf;
                (*vdata).node = dyn_ptr as *const SysctlNode;
                let copy_len = name_len.min(32);
                ::core::ptr::copy_nonoverlapping(
                    name,
                    (*vdata).dyn_name.as_mut_ptr(),
                    copy_len as usize,
                );
                (*vdata).dyn_name_len = copy_len;
                (*vnode_ptr).data = vdata as *mut u8;
                return Ok(Ready(vnode_h));
            }
        };
        if node_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let node = &*node_ptr;
        let name_slice = ::core::slice::from_raw_parts(name, name_len as usize);

        if let Some(child) = node.find_child_node(name_slice) {
            let child_ptr = child as *const SysctlNode;
            let (vnode_h, vnode_ptr) = fill_node_vnode(
                ctx,
                VnodeKind::Directory,
                SysctlfsKind::Node,
                child_ptr as *const u8,
                2,
                VN_NOCACHE,
            )?;
            let vdata = super::alloc_vdata(ctx.mount_data);
            if vdata.is_null() {
                return Err(VfsError::NoMem);
            }
            (*vdata).kind = SysctlfsKind::Node;
            (*vdata).node = child_ptr;
            (*vnode_ptr).data = vdata as *mut u8;
            return Ok(Ready(vnode_h));
        }

        if let Some(leaf) = node.find_leaf(name_slice) {
            let leaf_ptr = leaf as *const SysctlLeaf as *const SysctlNode;
            let (vnode_h, vnode_ptr) = fill_node_vnode(
                ctx,
                VnodeKind::Regular,
                SysctlfsKind::Leaf,
                leaf_ptr as *const u8,
                1,
                VN_NOCACHE,
            )?;
            let vdata = super::alloc_vdata(ctx.mount_data);
            if vdata.is_null() {
                return Err(VfsError::NoMem);
            }
            (*vdata).kind = SysctlfsKind::Leaf;
            (*vdata).node = leaf_ptr;
            (*vnode_ptr).data = vdata as *mut u8;
            return Ok(Ready(vnode_h));
        }

        if let Some(dyn_dir) = node.find_dynamic(name_slice) {
            let dyn_ptr = dyn_dir as *const DynamicDir;
            let (vnode_h, vnode_ptr) = fill_node_vnode(
                ctx,
                VnodeKind::Directory,
                SysctlfsKind::DynDir,
                dyn_ptr as *const u8,
                2,
                VN_NOCACHE,
            )?;
            let vdata = super::alloc_vdata(ctx.mount_data);
            if vdata.is_null() {
                return Err(VfsError::NoMem);
            }
            (*vdata).kind = SysctlfsKind::DynDir;
            (*vdata).node = dyn_ptr as *const SysctlNode;
            (*vnode_ptr).data = vdata as *mut u8;
            return Ok(Ready(vnode_h));
        }

        Ok(Ready(VnodeHandle::INVALID))
    }
}

unsafe fn sysctlfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata(ctx);

        (*attr).fs_instance_id = (*ctx.vnode).fs_instance_id;
        (*attr).backend_node_id = (*ctx.vnode).key.backend_id.id;
        (*attr).backend_seq = (*ctx.vnode).backend_seq;
        (*attr).uid = 0;
        (*attr).gid = 0;
        (*attr).nlink = (*ctx.vnode).nlink;
        (*attr).atime = 0;
        (*attr).mtime = 0;
        (*attr).ctime = 0;
        (*attr).blocks = 0;
        (*attr).size = 0;

        if ctl_type_for_vdata(vdata) == CTLTYPE_NODE {
            (*attr).mode = MODE_TYPE_DIR | 0o555;
            (*attr).nlink = 2;
            (*attr).kind = VnodeKind::Directory;
        } else {
            match (*vdata).kind {
                SysctlfsKind::Leaf => {
                    let leaf = (*vdata).node as *const SysctlLeaf;
                    let writable = if !leaf.is_null() {
                        (*leaf).flags & CTLFLAG_WR != 0
                    } else {
                        false
                    };
                    (*attr).mode = if writable {
                        MODE_TYPE_REG | 0o644
                    } else {
                        MODE_TYPE_REG | 0o444
                    };
                    (*attr).kind = VnodeKind::Regular;
                }
                SysctlfsKind::DynLeaf => {
                    (*attr).mode = MODE_TYPE_REG | 0o444;
                    (*attr).kind = VnodeKind::Regular;
                }
                SysctlfsKind::Root | SysctlfsKind::Node | SysctlfsKind::DynDir => {
                    return Err(VfsError::Io);
                }
            }
        }

        Ok(Ready(()))
    }
}

unsafe fn sysctlfs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn sysctlfs_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn sysctlfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn sysctlfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
    }
    Ok(Ready(()))
}

unsafe fn sysctlfs_readdir(
    ctx: &VopDataCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        if (*vdata).kind == SysctlfsKind::DynDir {
            let dyn_ptr = (*vdata).node as *const DynamicDir;
            if dyn_ptr.is_null() {
                return Err(VfsError::Io);
            }
            let dyn_dir = &*dyn_ptr;

            if pos == 0 {
                if !emit(ctx.id, b".".as_ptr(), 1, DT_DIR, &attr) {
                    *cookie = 1;
                    return Ok(Ready(()));
                }
                pos += 1;
            }
            if pos == 1 {
                let parent_id = encode_id(SysctlfsKind::Root, ::core::ptr::null());
                if !emit(parent_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                    *cookie = 2;
                    return Ok(Ready(()));
                }
                pos += 1;
            }
            // Pid-enumerated dirs (`kern.proc.pid` / `.args` / `.pathname`)
            // park on init and list the live pid set (one entry per getdents,
            // like procfs root); the filter dirs are not enumerated (FreeBSD
            // `list`-empty convention).
            if dyn_dir.enumerates_pids {
                let caller_badge = ctx.caller_badge;
                let Some(open_h) = ctx.open_object else {
                    return Err(VfsError::Io);
                };
                let Some(st) = ctx.state_mut() else {
                    return Err(VfsError::Io);
                };
                let plan = [crate::owner::init_rpc::InitStep {
                    label: trona_protocol::init::INIT_GET_PROC_INFO,
                    sub_op: trona_protocol::posix::INIT_GET_PROC_INFO_SUB_LIST_PIDS,
                    arg: 0,
                }];
                return match crate::owner::init_rpc::begin_init_read_deferred(
                    st,
                    &plan,
                    crate::owner::init_rpc::InitReadState::Readdir {
                        open_h,
                        cursor: pos,
                        base: 2,
                        reply: crate::ops::ReadDirReplyIntent::PosixGetDents,
                        pids: [0u32; 32],
                        pid_count: 0,
                        dtype: DT_REG,
                    },
                    0,
                    caller_badge,
                ) {
                    Some(handle) => Ok(Parked(handle)),
                    None => Err(VfsError::Io),
                };
            }
            *cookie = pos;
            return Ok(Ready(()));
        }

        let node_ptr = match (*vdata).kind {
            SysctlfsKind::Root => {
                if (*vdata).node.is_null() {
                    &raw const MIB_ROOT as *const SysctlNode
                } else {
                    (*vdata).node
                }
            }
            SysctlfsKind::Node => (*vdata).node,
            _ => return Err(VfsError::NotDir),
        };
        if node_ptr.is_null() {
            return Err(VfsError::Io);
        }
        let node = &*node_ptr;
        let (node_count, leaf_count, dyn_count) = node.entry_counts();

        if pos == 0 {
            if !emit(ctx.id, b".".as_ptr(), 1, DT_DIR, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        if pos == 1 {
            let parent_id = encode_id(SysctlfsKind::Root, ::core::ptr::null());
            if !emit(parent_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                *cookie = pos + 1;
                return Ok(Ready(()));
            }
            pos += 1;
        }

        let child_base = 2u64;
        for i in 0..node_count {
            let entry_pos = child_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let Some(child) = node.child_node_at(i) else {
                break;
            };
            if !emit(0, child.name.as_ptr(), child.name_len, DT_DIR, &attr) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        let leaf_base = child_base + node_count as u64;
        for i in 0..leaf_count {
            let entry_pos = leaf_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let Some(leaf) = node.leaf_at(i) else {
                break;
            };
            if !emit(0, leaf.name.as_ptr(), leaf.name_len, DT_REG, &attr) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        let dyn_base = leaf_base + leaf_count as u64;
        for i in 0..dyn_count {
            let entry_pos = dyn_base + i as u64;
            if pos > entry_pos {
                continue;
            }
            let Some(dyn_dir) = node.dynamic_at(i) else {
                break;
            };
            if !emit(0, dyn_dir.name.as_ptr(), dyn_dir.name_len, DT_DIR, &attr) {
                *cookie = entry_pos + 1;
                return Ok(Ready(()));
            }
            pos = entry_pos + 1;
        }

        *cookie = pos;
        Ok(Ready(()))
    }
}

unsafe fn sysctlfs_read(ctx: &VopDataCtx, offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);

        if (*vdata).kind == SysctlfsKind::DynLeaf {
            let dyn_ptr = (*vdata).node as *const DynamicDir;
            if dyn_ptr.is_null() {
                return Err(VfsError::Io);
            }
            let dyn_dir = &*dyn_ptr;
            let name = (*vdata).dyn_name.as_ptr();
            let name_len = (*vdata).dyn_name_len as usize;
            let caller_badge = ctx.caller_badge;
            let Some(st) = ctx.state_mut() else {
                return Err(VfsError::Io);
            };
            let mut sctx = SysctlCtx {
                state: st,
                caller_badge,
                offset,
                len,
            };
            let mut content = [0u8; SYSCTL_BUF_SIZE];
            return match (dyn_dir.lookup)(
                &mut sctx,
                name,
                name_len,
                content.as_mut_ptr(),
                SYSCTL_BUF_SIZE,
            ) {
                // init-backed dyn leaf (`kern.proc.*`): the reply is emitted
                // from the snapshot at finalize.
                SysctlOutcome::Parked(h) => Ok(Parked(h)),
                SysctlOutcome::Missing => Err(VfsError::Io),
                SysctlOutcome::Ready(content_len) => {
                    if offset as usize >= content_len {
                        return Ok(Ready(0));
                    }
                    let available = content_len - offset as usize;
                    let to_copy = (len as usize).min(available);
                    ::core::ptr::copy_nonoverlapping(
                        content.as_ptr().add(offset as usize),
                        dst,
                        to_copy,
                    );
                    Ok(Ready(to_copy as u64))
                }
            };
        }

        if (*vdata).kind != SysctlfsKind::Leaf {
            return Err(VfsError::IsDir);
        }

        let leaf = (*vdata).node as *const SysctlLeaf;
        if leaf.is_null() {
            return Err(VfsError::Io);
        }
        let read_fn = match (*leaf).read_fn {
            Some(f) => f,
            None => return Err(VfsError::NotSup),
        };

        let caller_badge = ctx.caller_badge;
        let Some(st) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        let mut sctx = SysctlCtx {
            state: st,
            caller_badge,
            offset,
            len,
        };
        let mut content = [0u8; SYSCTL_BUF_SIZE];
        match read_fn(&mut sctx, content.as_mut_ptr(), SYSCTL_BUF_SIZE) {
            SysctlOutcome::Parked(h) => Ok(Parked(h)),
            SysctlOutcome::Missing => Err(VfsError::Io),
            SysctlOutcome::Ready(content_len) => {
                if offset as usize >= content_len {
                    return Ok(Ready(0));
                }
                let available = content_len - offset as usize;
                let to_copy = if (len as usize) < available {
                    len as usize
                } else {
                    available
                };
                ::core::ptr::copy_nonoverlapping(
                    content.as_ptr().add(offset as usize),
                    dst,
                    to_copy,
                );
                Ok(Ready(to_copy as u64))
            }
        }
    }
}

unsafe fn sysctlfs_write(
    ctx: &VopDataCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        match (*vdata).kind {
            SysctlfsKind::Root | SysctlfsKind::Node | SysctlfsKind::DynDir => {
                return Err(VfsError::IsDir);
            }
            SysctlfsKind::DynLeaf => return Err(VfsError::Acces),
            SysctlfsKind::Leaf => {}
        }

        let leaf = (*vdata).node as *const SysctlLeaf;
        if leaf.is_null() {
            return Err(VfsError::Io);
        }
        if (*leaf).flags & CTLFLAG_WR == 0 {
            return Err(VfsError::Acces);
        }
        let write_fn = match (*leaf).write_fn {
            Some(f) => f,
            None => return Err(VfsError::NotSup),
        };

        let result = write_fn(src, len as usize);
        if result != 0 {
            return Err(VfsError::Inval);
        }
        Ok(Ready(len))
    }
}

unsafe fn sysctlfs_statfs(_ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        (*out).bsize = 4096;
        (*out).frsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = 0;
        (*out).ffree = 0;
        (*out).favail = 0;
        (*out).fsid = 0;
        (*out).flag = 0;
        (*out).namemax = 255;
        (*out).set_fs_name(b"sysctlfs");
        Ok(Ready(()))
    }
}

pub(super) static SYSCTLFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: sysctlfs_lookup,
        getattr: sysctlfs_getattr,
        access: sysctlfs_access,
        open: sysctlfs_open,
        close: sysctlfs_close,
        inactive: sysctlfs_inactive,
        ..META_OPS_DEFAULT
    },
    data: VopDataOps {
        readdir: sysctlfs_readdir,
        read: sysctlfs_read,
        write: sysctlfs_write,
        writeback: sysctlfs_write,
        statfs: sysctlfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
