// SPDX-License-Identifier: GPL-2.0-only
//! procfs `VopVector` — per-vnode operations for the process information filesystem.
//!
//! All content is generated dynamically from IPC queries to init server and
//! netsrv. Every non-root vnode carries `VN_NOCACHE` and is reclaimed after
//! last close.

use crate::core::cred::VfsCred;
use crate::core::error::VfsError;
use crate::core::file::{MODE_TYPE_DIR, MODE_TYPE_LNK, MODE_TYPE_REG};
use crate::core::file::{VAttr, VStatfs};
use crate::core::identity::{BackendNodeId, VnodeKey};
use crate::core::outcome::{Parked, Ready, VopOutcome};
use crate::core::vnode::{VN_NOCACHE, VnodeHandle, VnodeKind};
use crate::core::vop::{
    DATA_OPS_DEFAULT, META_OPS_DEFAULT, ReaddirEmit, VopDataOps, VopMetaOps, VopVector,
};
use crate::core::vop_context::{OwnerVopCtx, VopDataCtx};
use crate::server::consts::MAX_PATH_LEN;

use super::generators::parse_pid;
use super::net::{
    proc_gen_arp, proc_gen_hosts, proc_gen_net_dev, proc_gen_resolv_conf, proc_gen_route,
};
use super::pid::{
    proc_gen_cgroup, proc_gen_io, proc_gen_maps, proc_gen_oom_score, proc_gen_reservations,
    proc_gen_smaps, proc_gen_statm, proc_pid_exists,
};
use super::{
    ProcfsKind, ProcfsVnodeData, alloc_vdata, encode_id, encode_sys_dynleaf_id, encode_sys_id,
};
use crate::fs::sysctlfs::tree::{SysctlCtx, SysctlOutcome};

const PROC_TEXT_BUF_SIZE: usize = 2048;
const DT_DIR: u8 = 4;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut ProcfsVnodeData {
    ctx.data as *mut ProcfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataCtx) -> *mut ProcfsVnodeData {
    ctx.data as *mut ProcfsVnodeData
}

#[inline]
fn name_eq(a: *const u8, a_len: u8, b: &[u8]) -> bool {
    if a_len as usize != b.len() {
        return false;
    }
    for i in 0..b.len() {
        if unsafe { *a.add(i) } != b[i] {
            return false;
        }
    }
    true
}

unsafe fn alloc_procfs_vnode(
    ctx: &mut OwnerVopCtx<'_>,
    kind: VnodeKind,
    pkind: ProcfsKind,
    pid: u32,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vnode_ptr).kind = kind;
        (*vnode_ptr).flags = VN_NOCACHE;
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(encode_id(pkind, pid), 0),
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).mount = ctx.mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).ops = (*ctx.vnode).ops;
        (*vnode_ptr).nlink = 1;

        let vdata = alloc_vdata(ctx.mount_data);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        (*vdata).kind = pkind;
        (*vdata).pid = pid;
        (*vdata).sys_ptr = ::core::ptr::null();
        (*vdata).dyn_name = [0; 32];
        (*vdata).dyn_name_len = 0;
        (*vnode_ptr).data = vdata as *mut u8;

        Ok(Ready(vnode_h))
    }
}

unsafe fn alloc_procfs_sys_vnode(
    ctx: &mut OwnerVopCtx<'_>,
    kind: VnodeKind,
    pkind: ProcfsKind,
    sys_ptr: *const u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
        let fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vnode_ptr).kind = kind;
        (*vnode_ptr).flags = VN_NOCACHE;
        (*vnode_ptr).key = VnodeKey {
            fs_instance_id,
            backend_id: BackendNodeId::new(encode_sys_id(pkind, sys_ptr), 0),
        };
        (*vnode_ptr).backend_seq = 0;
        (*vnode_ptr).mount = ctx.mount_handle;
        (*vnode_ptr).fs_instance_id = fs_instance_id;
        (*vnode_ptr).ops = (*ctx.vnode).ops;
        (*vnode_ptr).nlink = if matches!(kind, VnodeKind::Directory) {
            2
        } else {
            1
        };

        let vdata = alloc_vdata(ctx.mount_data);
        if vdata.is_null() {
            return Err(VfsError::NoMem);
        }
        (*vdata).kind = pkind;
        (*vdata).pid = 0;
        (*vdata).sys_ptr = sys_ptr;
        (*vdata).dyn_name = [0; 32];
        (*vdata).dyn_name_len = 0;
        (*vnode_ptr).data = vdata as *mut u8;

        Ok(Ready(vnode_h))
    }
}

unsafe fn procfs_lookup(
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
            match (*dir_vdata).kind {
                ProcfsKind::PidDir
                | ProcfsKind::NetDir
                | ProcfsKind::SysDir
                | ProcfsKind::SysDynDir => {
                    let root_vh = (*ctx.mount).root;
                    if root_vh.is_valid() {
                        return Ok(Ready(root_vh));
                    }
                    return Ok(Ready(ctx.handle));
                }
                _ => {
                    return Ok(Ready(ctx.handle));
                }
            }
        }

        match (*dir_vdata).kind {
            ProcfsKind::Root => {
                if name_eq(name, name_len, b"self") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Symlink, ProcfsKind::SelfLink, 0);
                }

                if name_eq(name, name_len, b"net") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Directory, ProcfsKind::NetDir, 0);
                }

                if name_eq(name, name_len, b"sys") {
                    let root_ptr = &raw const crate::fs::sysctlfs::tree::MIB_ROOT;
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VnodeKind::Directory,
                        ProcfsKind::SysDir,
                        root_ptr as *const u8,
                    );
                }

                if name_eq(name, name_len, b"stat") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::SysStat, 0);
                }
                if name_eq(name, name_len, b"meminfo") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::SysMeminfo, 0);
                }
                if name_eq(name, name_len, b"uptime") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::SysUptime, 0);
                }
                if name_eq(name, name_len, b"cpuinfo") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::SysCpuinfo, 0);
                }
                if name_eq(name, name_len, b"loadavg") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::SysLoadavg, 0);
                }

                let pid_slice = ::core::slice::from_raw_parts(name, name_len as usize);
                let (pid, ok) = parse_pid(pid_slice);
                if !ok {
                    return Ok(Ready(VnodeHandle::INVALID));
                }

                if !proc_pid_exists(pid) {
                    return Ok(Ready(VnodeHandle::INVALID));
                }

                alloc_procfs_vnode(ctx, VnodeKind::Directory, ProcfsKind::PidDir, pid)
            }

            ProcfsKind::PidDir => {
                let pid = (*dir_vdata).pid;

                if name_eq(name, name_len, b"stat") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidStat, pid);
                }
                if name_eq(name, name_len, b"status") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidStatus, pid);
                }
                if name_eq(name, name_len, b"maps") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidMaps, pid);
                }
                if name_eq(name, name_len, b"exe") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Symlink, ProcfsKind::PidExe, pid);
                }
                if name_eq(name, name_len, b"cmdline") {
                    return alloc_procfs_vnode(
                        ctx,
                        VnodeKind::Regular,
                        ProcfsKind::PidCmdline,
                        pid,
                    );
                }
                if name_eq(name, name_len, b"comm") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidComm, pid);
                }
                if name_eq(name, name_len, b"statm") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidStatm, pid);
                }
                if name_eq(name, name_len, b"io") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidIo, pid);
                }
                if name_eq(name, name_len, b"smaps") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidSmaps, pid);
                }
                if name_eq(name, name_len, b"cgroup") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::PidCgroup, pid);
                }
                if name_eq(name, name_len, b"reservations") {
                    return alloc_procfs_vnode(
                        ctx,
                        VnodeKind::Regular,
                        ProcfsKind::PidReservations,
                        pid,
                    );
                }
                if name_eq(name, name_len, b"oom_score") {
                    return alloc_procfs_vnode(
                        ctx,
                        VnodeKind::Regular,
                        ProcfsKind::PidOomScore,
                        pid,
                    );
                }

                Ok(Ready(VnodeHandle::INVALID))
            }

            ProcfsKind::NetDir => {
                if name_eq(name, name_len, b"route") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::NetRoute, 0);
                }
                if name_eq(name, name_len, b"arp") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::NetArp, 0);
                }
                if name_eq(name, name_len, b"dev") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::NetDev, 0);
                }
                if name_eq(name, name_len, b"hosts") {
                    return alloc_procfs_vnode(ctx, VnodeKind::Regular, ProcfsKind::NetHosts, 0);
                }
                if name_eq(name, name_len, b"resolv.conf") {
                    return alloc_procfs_vnode(
                        ctx,
                        VnodeKind::Regular,
                        ProcfsKind::NetResolvConf,
                        0,
                    );
                }

                Ok(Ready(VnodeHandle::INVALID))
            }

            ProcfsKind::SysDir => {
                let node_ptr = (*dir_vdata).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlNode;
                if node_ptr.is_null() {
                    return Ok(Ready(VnodeHandle::INVALID));
                }

                let mapped_name: &[u8];
                let mut name_buf_storage = [0u8; 32];
                let name_slice = ::core::slice::from_raw_parts(name, name_len as usize);
                if name_slice == b"kernel" {
                    mapped_name = b"kern";
                } else {
                    let len = name_len as usize;
                    if len <= 32 {
                        name_buf_storage[..len].copy_from_slice(name_slice);
                        mapped_name = &name_buf_storage[..len];
                    } else {
                        return Ok(Ready(VnodeHandle::INVALID));
                    }
                }

                let node = &*node_ptr;

                if let Some(child) = node.find_child_node(mapped_name) {
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VnodeKind::Directory,
                        ProcfsKind::SysDir,
                        child as *const _ as *const u8,
                    );
                }

                if let Some(leaf) = node.find_leaf(mapped_name) {
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VnodeKind::Regular,
                        ProcfsKind::SysLeaf,
                        leaf as *const _ as *const u8,
                    );
                }

                if let Some(dyn_dir) = node.find_dynamic(mapped_name) {
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VnodeKind::Directory,
                        ProcfsKind::SysDynDir,
                        dyn_dir as *const _ as *const u8,
                    );
                }

                Ok(Ready(VnodeHandle::INVALID))
            }

            ProcfsKind::SysDynDir => {
                let dyn_ptr = (*dir_vdata).sys_ptr as *const crate::fs::sysctlfs::tree::DynamicDir;
                if dyn_ptr.is_null() {
                    return Ok(Ready(VnodeHandle::INVALID));
                }
                let name_slice = ::core::slice::from_raw_parts(name, name_len as usize);
                // Create the dyn leaf optimistically — existence + content
                // resolve in the parked `read` (the `kern.proc.*` provider
                // parks on init), so lookup must not call the provider here
                // (that would block the reactor on init).
                let (vnode_h, vnode_ptr) = ctx.alloc_vnode().ok_or(VfsError::NoMem)?;
                let fs_instance_id = (*ctx.mount).fs_instance_id;
                (*vnode_ptr).kind = VnodeKind::Regular;
                (*vnode_ptr).flags = VN_NOCACHE;
                (*vnode_ptr).key = VnodeKey {
                    fs_instance_id,
                    backend_id: BackendNodeId::new(
                        encode_sys_dynleaf_id((*dir_vdata).sys_ptr, name_slice),
                        0,
                    ),
                };
                (*vnode_ptr).backend_seq = 0;
                (*vnode_ptr).mount = ctx.mount_handle;
                (*vnode_ptr).fs_instance_id = fs_instance_id;
                (*vnode_ptr).ops = (*ctx.vnode).ops;
                (*vnode_ptr).nlink = 1;
                let vdata = alloc_vdata(ctx.mount_data);
                if vdata.is_null() {
                    return Err(VfsError::NoMem);
                }
                (*vdata).kind = ProcfsKind::SysDynLeaf;
                (*vdata).pid = 0;
                (*vdata).sys_ptr = (*dir_vdata).sys_ptr;
                let copy_len = (name_len as usize).min(32);
                ::core::ptr::copy_nonoverlapping(name, (*vdata).dyn_name.as_mut_ptr(), copy_len);
                (*vdata).dyn_name_len = copy_len as u8;
                (*vnode_ptr).data = vdata as *mut u8;
                Ok(Ready(vnode_h))
            }

            _ => Err(VfsError::NotDir),
        }
    }
}

unsafe fn procfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
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

        match (*vdata).kind {
            ProcfsKind::Root
            | ProcfsKind::PidDir
            | ProcfsKind::NetDir
            | ProcfsKind::SysDir
            | ProcfsKind::SysDynDir => {
                (*attr).mode = MODE_TYPE_DIR | 0o555;
                (*attr).nlink = 2;
                (*attr).kind = VnodeKind::Directory;
            }

            ProcfsKind::SelfLink | ProcfsKind::PidExe => {
                (*attr).mode = MODE_TYPE_LNK | 0o777;
                (*attr).kind = VnodeKind::Symlink;
            }

            ProcfsKind::PidStat
            | ProcfsKind::PidStatus
            | ProcfsKind::PidMaps
            | ProcfsKind::PidCmdline
            | ProcfsKind::PidComm
            | ProcfsKind::PidStatm
            | ProcfsKind::PidIo
            | ProcfsKind::PidSmaps
            | ProcfsKind::PidCgroup
            | ProcfsKind::PidReservations
            | ProcfsKind::PidOomScore
            | ProcfsKind::NetRoute
            | ProcfsKind::NetArp
            | ProcfsKind::NetDev
            | ProcfsKind::NetHosts
            | ProcfsKind::NetResolvConf
            | ProcfsKind::SysLeaf
            | ProcfsKind::SysDynLeaf
            | ProcfsKind::SysStat
            | ProcfsKind::SysMeminfo
            | ProcfsKind::SysUptime
            | ProcfsKind::SysCpuinfo
            | ProcfsKind::SysLoadavg => {
                (*attr).mode = MODE_TYPE_REG | 0o444;
                (*attr).kind = VnodeKind::Regular;
            }
        }

        Ok(Ready(()))
    }
}

unsafe fn procfs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn procfs_open(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn procfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn procfs_readlink(
    ctx: &mut OwnerVopCtx<'_>,
    buf: *mut u8,
    buf_len: usize,
    cred: *const VfsCred,
) -> VopOutcome<usize> {
    unsafe {
        let vdata = vdata(ctx);

        match (*vdata).kind {
            ProcfsKind::SelfLink => {
                let pid = if !cred.is_null() { (*cred).pid } else { 0 };
                let prefix = b"/proc/";
                let mut tmp = [0u8; 16];
                let mut pid_len = 0usize;
                if pid == 0 {
                    tmp[0] = b'0';
                    pid_len = 1;
                } else {
                    let mut n = pid;
                    while n > 0 {
                        tmp[pid_len] = b'0' + (n % 10) as u8;
                        pid_len += 1;
                        n /= 10;
                    }
                    let half = pid_len / 2;
                    for i in 0..half {
                        let t = tmp[i];
                        tmp[i] = tmp[pid_len - 1 - i];
                        tmp[pid_len - 1 - i] = t;
                    }
                }
                let total = prefix.len() + pid_len;
                if total > buf_len {
                    return Err(VfsError::NameTooLong);
                }
                for i in 0..prefix.len() {
                    *buf.add(i) = prefix[i];
                }
                for i in 0..pid_len {
                    *buf.add(prefix.len() + i) = tmp[i];
                }
                Ok(Ready(total))
            }

            ProcfsKind::PidExe => {
                // Async: query init's `GET_EXE_PATH` without blocking the
                // owner reactor. The readlink reply is emitted at
                // finalize from the snapshot (`buf`/`buf_len` unused on
                // this path — the inline emitter caps the wire length).
                let _ = (buf, buf_len);
                let pid = (*vdata).pid;
                let client_id = if !cred.is_null() { (*cred).pid } else { 0 };
                let plan = [crate::owner::init_rpc::InitStep {
                    label: trona_protocol::init::INIT_GET_PROC_INFO,
                    sub_op: trona_protocol::init::INIT_GET_PROC_INFO_SUB_GET_EXE_PATH,
                    arg: pid as u64,
                }];
                let read_state = crate::owner::init_rpc::InitReadState::ProcExeReadlink {
                    personality: crate::personality::Personality::Posix,
                    path: [0u8; MAX_PATH_LEN],
                    len: 0,
                };
                match crate::owner::init_rpc::begin_init_read_deferred(
                    ctx.state,
                    &plan,
                    read_state,
                    client_id,
                    ctx.caller_badge,
                ) {
                    Some(op_h) => Ok(Parked(op_h)),
                    None => Err(VfsError::Io),
                }
            }

            _ => Err(VfsError::Inval),
        }
    }
}

unsafe fn procfs_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
    }
    Ok(Ready(()))
}

unsafe fn procfs_readdir(
    ctx: &VopDataCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vdata = vdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        match (*vdata).kind {
            ProcfsKind::Root => {
                let root_id = ctx.id;

                if pos == 0 {
                    if !emit(root_id, b".".as_ptr(), 1, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                if pos == 1 {
                    if !emit(root_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                if pos == 2 {
                    if !emit(0, b"self".as_ptr(), 4, DT_LNK, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                if pos == 3 {
                    if !emit(0, b"net".as_ptr(), 3, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                if pos == 4 {
                    if !emit(0, b"sys".as_ptr(), 3, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                let sys_entries: &[&[u8]] =
                    &[b"stat", b"meminfo", b"uptime", b"cpuinfo", b"loadavg"];
                let sys_base = 5u64;
                for (i, name) in sys_entries.iter().enumerate() {
                    let entry_pos = sys_base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    if !emit(0, name.as_ptr(), name.len() as u8, DT_REG, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                // The pid entries come from init's process table. Fetch
                // them asynchronously — a blocking VFS→init query here would
                // risk the init↔VFS reactor cycle. Park on init `LIST_PIDS`
                // (inline regs); the finalize emits the single dirent at
                // this cursor (procfs readdir is one entry per `getdents`).
                // procfs is POSIX-only, so the reply framing is `PosixGetDents`.
                let base = sys_base + sys_entries.len() as u64;
                let Some(st) = ctx.state_mut() else {
                    return Err(VfsError::Io);
                };
                let Some(open_h) = ctx.open_object else {
                    return Err(VfsError::Io);
                };
                let plan = [crate::owner::init_rpc::InitStep {
                    label: trona_protocol::init::INIT_GET_PROC_INFO,
                    sub_op: trona_protocol::posix::INIT_GET_PROC_INFO_SUB_LIST_PIDS,
                    arg: 0,
                }];
                match crate::owner::init_rpc::begin_init_read_deferred(
                    st,
                    &plan,
                    crate::owner::init_rpc::InitReadState::Readdir {
                        open_h,
                        cursor: pos,
                        base,
                        reply: crate::ops::ReadDirReplyIntent::PosixGetDents,
                        pids: [0u32; 32],
                        pid_count: 0,
                        dtype: DT_DIR,
                    },
                    0,
                    ctx.caller_badge,
                ) {
                    Some(handle) => Ok(Parked(handle)),
                    None => Err(VfsError::Io),
                }
            }

            ProcfsKind::PidDir => {
                let entries: &[(&[u8], u8)] = &[
                    (b"stat", DT_REG),
                    (b"status", DT_REG),
                    (b"maps", DT_REG),
                    (b"exe", DT_LNK),
                    (b"cmdline", DT_REG),
                    (b"comm", DT_REG),
                    (b"statm", DT_REG),
                    (b"io", DT_REG),
                    (b"smaps", DT_REG),
                    (b"cgroup", DT_REG),
                    (b"reservations", DT_REG),
                    (b"oom_score", DT_REG),
                ];

                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                let base = 2u64;
                let idx_start = if pos >= base {
                    (pos - base) as usize
                } else {
                    0
                };
                for i in idx_start..entries.len() {
                    let entry_pos = base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let (name, dtype) = entries[i];
                    if !emit(0, name.as_ptr(), name.len() as u8, dtype, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(Ready(()))
            }

            ProcfsKind::NetDir => {
                let entries: &[&[u8]] = &[b"route", b"arp", b"dev", b"hosts", b"resolv.conf"];

                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                let base = 2u64;
                let idx_start = if pos >= base {
                    (pos - base) as usize
                } else {
                    0
                };
                for i in idx_start..entries.len() {
                    let entry_pos = base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let name = entries[i];
                    if !emit(0, name.as_ptr(), name.len() as u8, DT_REG, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(Ready(()))
            }

            ProcfsKind::SysDir => {
                let node_ptr = (*vdata).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlNode;
                if node_ptr.is_null() {
                    return Err(VfsError::NotDir);
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
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                let base = 2u64;

                for i in 0..node_count {
                    let entry_pos = base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let Some(child) = node.child_node_at(i) else {
                        break;
                    };
                    let child_name = &child.name[..child.name_len as usize];
                    let (emit_name, emit_len): (&[u8], u8) = if child_name == b"kern" {
                        (b"kernel", 6)
                    } else {
                        (child_name, child.name_len)
                    };
                    if !emit(0, emit_name.as_ptr(), emit_len, DT_DIR, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                let leaf_base = base + node_count as u64;
                for i in 0..leaf_count {
                    let entry_pos = leaf_base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let Some(leaf) = node.leaf_at(i) else {
                        break;
                    };
                    let leaf_name = &leaf.name[..leaf.name_len as usize];
                    if !emit(0, leaf_name.as_ptr(), leaf.name_len, DT_REG, &attr) {
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

            ProcfsKind::SysDynDir => {
                let dyn_ptr = (*vdata).sys_ptr as *const crate::fs::sysctlfs::tree::DynamicDir;
                if dyn_ptr.is_null() {
                    return Err(VfsError::NotDir);
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
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, DT_DIR, &attr) {
                        *cookie = 2;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }
                // Pid-enumerated dirs (`kern.proc.pid` / `.args` / `.pathname`)
                // park on init and list the live pid set (one entry per
                // getdents, like the procfs root); the filter dirs are not
                // enumerated (FreeBSD `list`-empty convention).
                if dyn_dir.enumerates_pids {
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
                        ctx.caller_badge,
                    ) {
                        Some(handle) => Ok(Parked(handle)),
                        None => Err(VfsError::Io),
                    };
                }
                *cookie = pos;
                Ok(Ready(()))
            }

            _ => Err(VfsError::NotDir),
        }
    }
}

/// Park a procfs content read on init data: hand the query `plan` +
/// typed `read_state` to `init_rpc`, returning `Parked` (the
/// `do_read_fd_inline` `Parked` arm attaches the client lease + records
/// the read-reply framing). One call site per init-backed `ProcfsKind`.
unsafe fn park_proc_read(
    ctx: &VopDataCtx,
    pid: u32,
    plan: &[crate::owner::init_rpc::InitStep],
    read_state: crate::owner::init_rpc::InitReadState,
) -> VopOutcome<u64> {
    unsafe {
        let Some(st) = ctx.state_mut() else {
            return Err(VfsError::Io);
        };
        match crate::owner::init_rpc::begin_init_read_deferred(
            st,
            plan,
            read_state,
            pid,
            ctx.caller_badge,
        ) {
            Some(op_h) => Ok(Parked(op_h)),
            None => Err(VfsError::Io),
        }
    }
}

unsafe fn procfs_read(ctx: &VopDataCtx, offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64> {
    unsafe {
        let vdata = vdata_d(ctx);
        let pid = (*vdata).pid;

        if (*vdata).kind == ProcfsKind::SysDynLeaf {
            let dyn_ptr = (*vdata).sys_ptr as *const crate::fs::sysctlfs::tree::DynamicDir;
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
            let mut content = [0u8; 4096];
            return match (dyn_dir.lookup)(&mut sctx, name, name_len, content.as_mut_ptr(), 4096) {
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

        if (*vdata).kind == ProcfsKind::SysLeaf {
            let leaf_ptr = (*vdata).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlLeaf;
            if leaf_ptr.is_null() {
                return Err(VfsError::Io);
            }
            let leaf = &*leaf_ptr;
            let read_fn = match leaf.read_fn {
                Some(f) => f,
                None => return Ok(Ready(0)),
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
            let mut content = [0u8; 4096];
            return match read_fn(&mut sctx, content.as_mut_ptr(), 4096) {
                SysctlOutcome::Parked(h) => Ok(Parked(h)),
                SysctlOutcome::Missing => Ok(Ready(0)),
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

        // procfs reads backed by init data park the owner reactor rather
        // than blocking on `mp_call`: issue the init query plan and
        // re-enter the formatter from the snapshot at finalize. The
        // `do_read_fd_inline` `Parked` arm routes these (`Resume::Init`)
        // via `attach_lease_if_init`, distinct from backend bulk reads.
        {
            use crate::owner::init_rpc::{InitReadState, InitStep, ProcReadKind, ProcReadResults};
            use trona_protocol::init::{
                INIT_ARGV_PAGE_BYTES, INIT_GET_PROC_INFO, INIT_GET_PROC_INFO_SUB_GET_ARGV,
                INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL, INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES,
                INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS,
            };
            match (*vdata).kind {
                ProcfsKind::PidComm => {
                    let plan = [InitStep {
                        label: INIT_GET_PROC_INFO,
                        sub_op: INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL,
                        arg: pid as u64,
                    }];
                    return park_proc_read(
                        ctx,
                        pid,
                        &plan,
                        InitReadState::ProcRead {
                            kind: ProcReadKind::Comm,
                            pid,
                            offset,
                            len,
                            intent: crate::ops::ReadReplyIntent::PosixRead,
                            results: ProcReadResults::default(),
                        },
                    );
                }
                ProcfsKind::PidStat => {
                    let plan = [
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL,
                            arg: pid as u64,
                        },
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES,
                            arg: pid as u64,
                        },
                    ];
                    return park_proc_read(
                        ctx,
                        pid,
                        &plan,
                        InitReadState::ProcRead {
                            kind: ProcReadKind::PidStat,
                            pid,
                            offset,
                            len,
                            intent: crate::ops::ReadReplyIntent::PosixRead,
                            results: ProcReadResults::default(),
                        },
                    );
                }
                ProcfsKind::PidStatus => {
                    let plan = [
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_PROC_INFO_FULL,
                            arg: pid as u64,
                        },
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_PROC_TIMES,
                            arg: pid as u64,
                        },
                    ];
                    return park_proc_read(
                        ctx,
                        pid,
                        &plan,
                        InitReadState::ProcRead {
                            kind: ProcReadKind::PidStatus,
                            pid,
                            offset,
                            len,
                            intent: crate::ops::ReadReplyIntent::PosixRead,
                            results: ProcReadResults::default(),
                        },
                    );
                }
                ProcfsKind::SysLoadavg => {
                    let plan = [InitStep {
                        label: INIT_GET_PROC_INFO,
                        sub_op: INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS,
                        arg: 0,
                    }];
                    return park_proc_read(
                        ctx,
                        pid,
                        &plan,
                        InitReadState::ProcRead {
                            kind: ProcReadKind::SysLoadavg,
                            pid,
                            offset,
                            len,
                            intent: crate::ops::ReadReplyIntent::PosixRead,
                            results: ProcReadResults::default(),
                        },
                    );
                }
                ProcfsKind::SysStat => {
                    let plan = [InitStep {
                        label: INIT_GET_PROC_INFO,
                        sub_op: INIT_GET_PROC_INFO_SUB_GET_SYSTEM_STATS,
                        arg: 0,
                    }];
                    return park_proc_read(
                        ctx,
                        pid,
                        &plan,
                        InitReadState::ProcRead {
                            kind: ProcReadKind::SysStat,
                            pid,
                            offset,
                            len,
                            intent: crate::ops::ReadReplyIntent::PosixRead,
                            results: ProcReadResults::default(),
                        },
                    );
                }
                ProcfsKind::PidCmdline => {
                    // argv (up to ARGV_MAX) exceeds one MP record, so page it:
                    // three GET_ARGV steps at byte offsets 0 / PAGE / 2*PAGE,
                    // each carrying `(pid << 32) | offset`. The decode arm
                    // reassembles the pages into the argv accumulator.
                    let page = INIT_ARGV_PAGE_BYTES as u64;
                    let base = (pid as u64) << 32;
                    let plan = [
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_ARGV,
                            arg: base,
                        },
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_ARGV,
                            arg: base | page,
                        },
                        InitStep {
                            label: INIT_GET_PROC_INFO,
                            sub_op: INIT_GET_PROC_INFO_SUB_GET_ARGV,
                            arg: base | (2 * page),
                        },
                    ];
                    return park_proc_read(
                        ctx,
                        pid,
                        &plan,
                        InitReadState::ProcRead {
                            kind: ProcReadKind::Cmdline,
                            pid,
                            offset,
                            len,
                            intent: crate::ops::ReadReplyIntent::PosixRead,
                            results: ProcReadResults::default(),
                        },
                    );
                }
                _ => {}
            }
        }

        let mut content = [0u8; PROC_TEXT_BUF_SIZE];
        let content_len = match (*vdata).kind {
            ProcfsKind::PidMaps => proc_gen_maps(pid, &mut content),
            ProcfsKind::PidStatm => proc_gen_statm(pid, &mut content),
            ProcfsKind::PidIo => proc_gen_io(pid, &mut content),
            ProcfsKind::PidSmaps => proc_gen_smaps(pid, &mut content),
            ProcfsKind::PidCgroup => proc_gen_cgroup(pid, &mut content),
            ProcfsKind::PidReservations => proc_gen_reservations(pid, &mut content),
            ProcfsKind::PidOomScore => proc_gen_oom_score(pid, &mut content),
            ProcfsKind::SysMeminfo => super::sysnode::proc_gen_meminfo(&mut content),
            ProcfsKind::SysUptime => super::sysnode::proc_gen_uptime(&mut content),
            ProcfsKind::SysCpuinfo => super::sysnode::proc_gen_cpuinfo(&mut content),
            ProcfsKind::NetRoute => proc_gen_route(&mut content),
            ProcfsKind::NetArp => proc_gen_arp(&mut content),
            ProcfsKind::NetDev => proc_gen_net_dev(&mut content),
            ProcfsKind::NetHosts => proc_gen_hosts(&mut content),
            ProcfsKind::NetResolvConf => proc_gen_resolv_conf(&mut content),
            _ => return Err(VfsError::IsDir),
        };

        if offset as usize >= content_len {
            return Ok(Ready(0));
        }

        let available = content_len - offset as usize;
        let to_copy = if (len as usize) < available {
            len as usize
        } else {
            available
        };

        for i in 0..to_copy {
            *dst.add(i) = content[offset as usize + i];
        }
        Ok(Ready(to_copy as u64))
    }
}

unsafe fn procfs_statfs(_ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()> {
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
        (*out).set_fs_name(b"procfs");
        Ok(Ready(()))
    }
}

pub(super) static PROCFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: procfs_lookup,
        getattr: procfs_getattr,
        access: procfs_access,
        open: procfs_open,
        close: procfs_close,
        readlink: procfs_readlink,
        inactive: procfs_inactive,
        ..META_OPS_DEFAULT
    },
    data: VopDataOps {
        readdir: procfs_readdir,
        read: procfs_read,
        statfs: procfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
