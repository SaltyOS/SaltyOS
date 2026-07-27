// SPDX-License-Identifier: GPL-2.0-only
//! procfs `VopVector` — per-vnode operations for the process information filesystem.
//!
//! All content is generated dynamically from IPC queries to procmgr and netsrv.
//! Every non-root vnode carries `VN_NOCACHE` and is reclaimed after last close.

use crate::personality::posix::consts::{S_IFDIR_L, S_IFLNK_L, S_IFREG_L};
use crate::server::consts::MAX_PATH_LEN;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::outcome::{Ready, VopOutcome};
use crate::vfs_core::vnode::{VN_NOCACHE, VT_DIR, VT_LNK, VT_REG, VnodeHandle};
use crate::vfs_core::vop::{
    DATA_OPS_DEFAULT, DataExecMode, META_OPS_DEFAULT, ReaddirEmit, VopDataOps, VopMetaOps,
    VopVector,
};
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};

use super::generators::{fmt_u32, parse_pid};
use super::net::{proc_gen_arp, proc_gen_net_dev, proc_gen_route};
use super::pid::{
    proc_gen_cgroup, proc_gen_cmdline, proc_gen_comm, proc_gen_io, proc_gen_maps,
    proc_gen_oom_score, proc_gen_smaps, proc_gen_stat, proc_gen_statm, proc_gen_status,
    proc_get_exe_path, proc_list_pids, proc_pid_exists,
};
use super::{
    ProcfsKind, ProcfsVnodeData, alloc_vdata, encode_id, encode_sys_dynleaf_id, encode_sys_id,
};

/// Content generation buffer size.
const PROC_TEXT_BUF_SIZE: usize = 2048;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut ProcfsVnodeData {
    ctx.data as *mut ProcfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &WorkerIoCtx) -> *mut ProcfsVnodeData {
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

/// Allocate an ephemeral procfs vnode via the arena trampoline.
///
/// Sets up the vnode fields and allocates a vdata slot from the mount pool.
/// Returns the new VnodeHandle, or an error if allocation fails.
unsafe fn alloc_procfs_vnode(
    ctx: &mut OwnerVopCtx<'_>,
    vtype: u8,
    kind: ProcfsKind,
    pid: u32,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*vp).vtype = vtype;
        (*vp).flags = VN_NOCACHE;
        (*vp).id = encode_id(kind, pid);
        (*vp)
            .mount
            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
        (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vp).ops = (*ctx.vnode).ops;
        (*vp).nlink = 1;

        let vd = alloc_vdata(ctx.mount_data);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        (*vd).kind = kind;
        (*vd).pid = pid;
        (*vd).sys_ptr = core::ptr::null();
        (*vp).data = vd as *mut u8;

        Ok(Ready(vh))
    }
}

/// Allocate an ephemeral procfs vnode with a sys_ptr (SysDir/SysLeaf/SysDynDir).
unsafe fn alloc_procfs_sys_vnode(
    ctx: &mut OwnerVopCtx<'_>,
    vtype: u8,
    kind: ProcfsKind,
    sys_ptr: *const u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
        (*vp).vtype = vtype;
        (*vp).flags = VN_NOCACHE;
        (*vp).id = encode_sys_id(kind, sys_ptr);
        (*vp)
            .mount
            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
        (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
        (*vp).ops = (*ctx.vnode).ops;
        (*vp).nlink = if vtype == VT_DIR { 2 } else { 1 };

        let vd = alloc_vdata(ctx.mount_data);
        if vd.is_null() {
            return Err(VfsError::NoSpace);
        }
        (*vd).kind = kind;
        (*vd).pid = 0;
        (*vd).sys_ptr = sys_ptr;
        (*vp).data = vd as *mut u8;

        Ok(Ready(vh))
    }
}

// =========================================================================
// MetaOps — Lookup
// =========================================================================

/// Look up a child by name in a procfs directory vnode.
///
/// - Root directory: "self" (SelfLink), "net" (NetDir), "sys" (SysDir), numeric PID (PidDir).
/// - PidDir: "stat", "status", "maps", "exe", "cmdline", "comm".
/// - NetDir: "route", "arp", "dev".
/// - SysDir: delegates to sysctlfs MIB tree (child nodes + leaves + dynamic dirs).
/// - SysDynDir: delegates to DynamicDir lookup function.
unsafe fn procfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // ".." — parent. Root's parent is itself (mount layer handles cross-mount).
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            match (*dvd).kind {
                ProcfsKind::PidDir
                | ProcfsKind::NetDir
                | ProcfsKind::SysDir
                | ProcfsKind::SysDynDir => {
                    let root_vh = (*ctx.mount).root_vnode;
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

        match (*dvd).kind {
            ProcfsKind::Root => {
                // "self" → SelfLink
                if name_eq(name, name_len, b"self") {
                    return alloc_procfs_vnode(ctx, VT_LNK, ProcfsKind::SelfLink, 0);
                }

                // "net" → NetDir
                if name_eq(name, name_len, b"net") {
                    let vh = alloc_procfs_vnode(ctx, VT_DIR, ProcfsKind::NetDir, 0)?;
                    return Ok(vh);
                }

                // "sys" → SysDir (Linux compat, delegates to sysctlfs MIB root)
                if name_eq(name, name_len, b"sys") {
                    let root_ptr = &raw const crate::fs::sysctlfs::tree::MIB_ROOT;
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VT_DIR,
                        ProcfsKind::SysDir,
                        root_ptr as *const u8,
                    );
                }

                // System-wide Linux-format files.
                if name_eq(name, name_len, b"stat") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::SysStat, 0);
                }
                if name_eq(name, name_len, b"meminfo") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::SysMeminfo, 0);
                }
                if name_eq(name, name_len, b"uptime") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::SysUptime, 0);
                }
                if name_eq(name, name_len, b"cpuinfo") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::SysCpuinfo, 0);
                }
                if name_eq(name, name_len, b"loadavg") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::SysLoadavg, 0);
                }

                // Numeric PID → PidDir (validate via procmgr IPC).
                let pid_slice = core::slice::from_raw_parts(name, name_len as usize);
                let (pid, ok) = parse_pid(pid_slice);
                if !ok {
                    return Ok(Ready(VnodeHandle::INVALID));
                }

                if !proc_pid_exists(pid) {
                    return Ok(Ready(VnodeHandle::INVALID));
                }

                alloc_procfs_vnode(ctx, VT_DIR, ProcfsKind::PidDir, pid)
            }

            ProcfsKind::PidDir => {
                let pid = (*dvd).pid;

                if name_eq(name, name_len, b"stat") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidStat, pid);
                }
                if name_eq(name, name_len, b"status") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidStatus, pid);
                }
                if name_eq(name, name_len, b"maps") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidMaps, pid);
                }
                if name_eq(name, name_len, b"exe") {
                    return alloc_procfs_vnode(ctx, VT_LNK, ProcfsKind::PidExe, pid);
                }
                if name_eq(name, name_len, b"cmdline") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidCmdline, pid);
                }
                if name_eq(name, name_len, b"comm") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidComm, pid);
                }
                if name_eq(name, name_len, b"statm") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidStatm, pid);
                }
                if name_eq(name, name_len, b"io") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidIo, pid);
                }
                if name_eq(name, name_len, b"smaps") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidSmaps, pid);
                }
                if name_eq(name, name_len, b"cgroup") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidCgroup, pid);
                }
                if name_eq(name, name_len, b"oom_score") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::PidOomScore, pid);
                }

                Ok(Ready(VnodeHandle::INVALID))
            }

            ProcfsKind::NetDir => {
                if name_eq(name, name_len, b"route") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::NetRoute, 0);
                }
                if name_eq(name, name_len, b"arp") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::NetArp, 0);
                }
                if name_eq(name, name_len, b"dev") {
                    return alloc_procfs_vnode(ctx, VT_REG, ProcfsKind::NetDev, 0);
                }

                Ok(Ready(VnodeHandle::INVALID))
            }

            ProcfsKind::SysDir => {
                // /proc/sys/ delegation: look up child in the sysctlfs MIB tree.
                let node_ptr = (*dvd).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlNode;
                if node_ptr.is_null() {
                    return Ok(Ready(VnodeHandle::INVALID));
                }

                // Linux → FreeBSD namespace mapping: "kernel" → "kern".
                let mapped_name: &[u8];
                let mut name_buf_storage = [0u8; 32];
                let name_slice = core::slice::from_raw_parts(name, name_len as usize);
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

                // Try child node first (sub-directory).
                if let Some(child) = node.find_child_node(mapped_name) {
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VT_DIR,
                        ProcfsKind::SysDir,
                        child as *const _ as *const u8,
                    );
                }

                // Try leaf (regular file).
                if let Some(leaf) = node.find_leaf(mapped_name) {
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VT_REG,
                        ProcfsKind::SysLeaf,
                        leaf as *const _ as *const u8,
                    );
                }

                // Try Dynamic directory.
                if let Some(dyn_dir) = node.find_dynamic(mapped_name) {
                    return alloc_procfs_sys_vnode(
                        ctx,
                        VT_DIR,
                        ProcfsKind::SysDynDir,
                        dyn_dir as *const _ as *const u8,
                    );
                }

                Ok(Ready(VnodeHandle::INVALID))
            }

            ProcfsKind::SysDynDir => {
                // Delegate to the DynamicDir lookup function.
                let dyn_ptr = (*dvd).sys_ptr as *const crate::fs::sysctlfs::tree::DynamicDir;
                if dyn_ptr.is_null() {
                    return Ok(Ready(VnodeHandle::INVALID));
                }
                let dyn_dir = &*dyn_ptr;
                let name_slice = core::slice::from_raw_parts(name, name_len as usize);
                let mut buf = [0u8; 4096];
                match (dyn_dir.lookup)(name, name_len as usize, buf.as_mut_ptr(), 4096) {
                    None => Ok(Ready(VnodeHandle::INVALID)),
                    Some(_content_len) => {
                        let (vh, vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
                        (*vp).vtype = VT_REG;
                        (*vp).flags = VN_NOCACHE;
                        (*vp).id = encode_sys_dynleaf_id((*dvd).sys_ptr, name_slice);
                        (*vp)
                            .mount
                            .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
                        (*vp).fs_instance_id = (*ctx.mount).fs_instance_id;
                        (*vp).ops = (*ctx.vnode).ops;
                        (*vp).nlink = 1;
                        let vd = alloc_vdata(ctx.mount_data);
                        if vd.is_null() {
                            return Err(VfsError::NoSpace);
                        }
                        (*vd).kind = ProcfsKind::SysDynLeaf;
                        (*vd).pid = 0;
                        (*vd).sys_ptr = (*dvd).sys_ptr;
                        let copy_len = (name_len as usize).min(32);
                        core::ptr::copy_nonoverlapping(name, (*vd).dyn_name.as_mut_ptr(), copy_len);
                        (*vd).dyn_name_len = copy_len as u8;
                        (*vp).data = vd as *mut u8;
                        Ok(Ready(vh))
                    }
                }
            }

            _ => Err(VfsError::NotDir),
        }
    }
}

// =========================================================================
// MetaOps — Getattr
// =========================================================================

unsafe fn procfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);

        (*attr).uid = 0;
        (*attr).gid = 0;
        (*attr).nlink = (*ctx.vnode).nlink;
        (*attr).atime = 0;
        (*attr).mtime = 0;
        (*attr).ctime = 0;
        (*attr).btime = 0;
        (*attr).blocks = 0;
        (*attr).dev_id = 0;
        (*attr).rdev = 0;
        (*attr).size = 0;

        match (*vd).kind {
            ProcfsKind::Root
            | ProcfsKind::PidDir
            | ProcfsKind::NetDir
            | ProcfsKind::SysDir
            | ProcfsKind::SysDynDir => {
                (*attr).mode = S_IFDIR_L | 0o555;
                (*attr).nlink = 2;
            }

            ProcfsKind::SelfLink | ProcfsKind::PidExe => {
                (*attr).mode = S_IFLNK_L | 0o777;
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
            | ProcfsKind::PidOomScore
            | ProcfsKind::NetRoute
            | ProcfsKind::NetArp
            | ProcfsKind::NetDev
            | ProcfsKind::SysLeaf
            | ProcfsKind::SysDynLeaf
            | ProcfsKind::SysStat
            | ProcfsKind::SysMeminfo
            | ProcfsKind::SysUptime
            | ProcfsKind::SysCpuinfo
            | ProcfsKind::SysLoadavg => {
                (*attr).mode = S_IFREG_L | 0o444;
            }
        }

        Ok(Ready(()))
    }
}

// =========================================================================
// MetaOps — Access / Open / Close / Readlink / Inactive
// =========================================================================

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

/// Read the target of a procfs symlink vnode.
///
/// - SelfLink → `/proc/<pid>` where pid comes from `cred.pid`.
/// - PidExe → executable path from procmgr IPC.
unsafe fn procfs_readlink(
    ctx: &mut OwnerVopCtx<'_>,
    buf: *mut u8,
    buf_len: usize,
    cred: *const VfsCred,
) -> VopOutcome<usize> {
    unsafe {
        let vd = vdata(ctx);

        match (*vd).kind {
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
                let pid = (*vd).pid;
                let mut exe_path = [0u8; MAX_PATH_LEN];
                let exe_len = proc_get_exe_path(pid, &mut exe_path).ok_or(VfsError::NotFound)?;
                let copy = if exe_len < buf_len { exe_len } else { buf_len };
                for i in 0..copy {
                    *buf.add(i) = exe_path[i];
                }
                Ok(Ready(copy))
            }

            _ => Err(VfsError::Inval),
        }
    }
}

unsafe fn procfs_inactive(_ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    Ok(Ready(()))
}

// =========================================================================
// DataOps — Readdir
// =========================================================================

/// Enumerate directory entries.
///
/// `cookie` is an opaque cursor: 0 = start, incremented per entry.
///
/// - Root: ".", "..", "self", "net", "sys", then PIDs from procmgr.
/// - PidDir: ".", "..", "stat", "status", "maps", "exe", "cmdline", "comm".
/// - NetDir: ".", "..", "route", "arp", "dev".
/// - SysDir: ".", "..", then child nodes + leaves + dynamic dirs from sysctlfs MIB tree.
/// - SysDynDir: ".", "..", then entries from DynamicDir.list callback.
unsafe fn procfs_readdir(
    ctx: &WorkerIoCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        let mut pos = *cookie;
        let attr = VAttr::zeroed();

        match (*vd).kind {
            ProcfsKind::Root => {
                let root_id = ctx.id;

                // "."
                if pos == 0 {
                    if !emit(root_id, b".".as_ptr(), 1, 4 /* DT_DIR */, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // ".."
                if pos == 1 {
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // "self"
                if pos == 2 {
                    if !emit(0, b"self".as_ptr(), 4, 10 /* DT_LNK */, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // "net"
                if pos == 3 {
                    if !emit(0, b"net".as_ptr(), 3, 4 /* DT_DIR */, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // "sys"
                if pos == 4 {
                    if !emit(0, b"sys".as_ptr(), 3, 4 /* DT_DIR */, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // System-wide Linux-format files.
                let sys_entries: &[&[u8]] =
                    &[b"stat", b"meminfo", b"uptime", b"cpuinfo", b"loadavg"];
                let sys_base = 5u64;
                for (i, name) in sys_entries.iter().enumerate() {
                    let entry_pos = sys_base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    if !emit(
                        0,
                        name.as_ptr(),
                        name.len() as u8,
                        8, /* DT_REG */
                        &attr,
                    ) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                // PIDs from procmgr.
                let mut pids = [0u32; 19];
                let count = proc_list_pids(&mut pids);
                let base = sys_base + sys_entries.len() as u64;
                let idx_start = if pos >= base {
                    (pos - base) as usize
                } else {
                    0
                };
                for i in idx_start..count {
                    let entry_pos = base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }

                    let mut nbuf = [0u8; 10];
                    let nlen = fmt_u32(pids[i], &mut nbuf);

                    if !emit(
                        pids[i] as u64,
                        nbuf.as_ptr(),
                        nlen as u8,
                        4, // DT_DIR
                        &attr,
                    ) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(Ready(()))
            }

            ProcfsKind::PidDir => {
                let entries: &[(&[u8], u8)] = &[
                    (b"stat", 8),      // DT_REG
                    (b"status", 8),    // DT_REG
                    (b"maps", 8),      // DT_REG
                    (b"exe", 10),      // DT_LNK
                    (b"cmdline", 8),   // DT_REG
                    (b"comm", 8),      // DT_REG
                    (b"statm", 8),     // DT_REG
                    (b"io", 8),        // DT_REG
                    (b"smaps", 8),     // DT_REG
                    (b"cgroup", 8),    // DT_REG
                    (b"oom_score", 8), // DT_REG
                ];

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // ".." — root id is encode_id(Root, 0) = 0.
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
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
                let entries: &[&[u8]] = &[b"route", b"arp", b"dev"];

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // ".." — root id.
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
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
                    if !emit(
                        0,
                        name.as_ptr(),
                        name.len() as u8,
                        8, // DT_REG
                        &attr,
                    ) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(Ready(()))
            }

            ProcfsKind::SysDir => {
                let node_ptr = (*vd).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlNode;
                if node_ptr.is_null() {
                    return Err(VfsError::NotDir);
                }
                let node = &*node_ptr;
                let (node_count, leaf_count, dyn_count) = node.entry_counts();

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // ".." — root id.
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                let base = 2u64;

                // Emit child nodes (directories). Apply reverse mapping:
                // MIB "kern" → Linux "kernel".
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
                    if !emit(0, emit_name.as_ptr(), emit_len, 4 /* DT_DIR */, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                // Emit leaves (regular files).
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
                    if !emit(
                        0,
                        leaf_name.as_ptr(),
                        leaf.name_len,
                        8, /* DT_REG */
                        &attr,
                    ) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                // Emit dynamic directories.
                let dyn_base = leaf_base + leaf_count as u64;
                for i in 0..dyn_count {
                    let entry_pos = dyn_base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let Some(dyn_dir) = node.dynamic_at(i) else {
                        break;
                    };
                    if !emit(
                        0,
                        dyn_dir.name.as_ptr(),
                        dyn_dir.name_len,
                        4, /* DT_DIR */
                        &attr,
                    ) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(Ready(()))
            }

            ProcfsKind::SysDynDir => {
                let dyn_ptr = (*vd).sys_ptr as *const crate::fs::sysctlfs::tree::DynamicDir;
                if dyn_ptr.is_null() {
                    return Err(VfsError::NotDir);
                }
                let dyn_dir = &*dyn_ptr;

                const MAX_DYN: usize = 64;
                let mut names = [crate::fs::sysctlfs::tree::DynamicName {
                    bytes: [0; 32],
                    len: 0,
                }; MAX_DYN];
                let count = (dyn_dir.list)(names.as_mut_ptr(), MAX_DYN);

                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = 2;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }
                let base = 2u64;
                for i in 0..count {
                    let entry_pos = base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let n = &names[i];
                    if !emit(0, n.bytes.as_ptr(), n.len, 8 /* DT_REG */, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                }
                *cookie = pos;
                Ok(Ready(()))
            }

            _ => Err(VfsError::NotDir),
        }
    }
}

// =========================================================================
// DataOps — Read
// =========================================================================

/// Read from a procfs regular file vnode.
///
/// Content is generated into a stack buffer on every read call.
unsafe fn procfs_read(ctx: &WorkerIoCtx, offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        let pid = (*vd).pid;

        // SysDynLeaf: re-invoke DynamicDir.lookup to generate content.
        if (*vd).kind == ProcfsKind::SysDynLeaf {
            let dyn_ptr = (*vd).sys_ptr as *const crate::fs::sysctlfs::tree::DynamicDir;
            if dyn_ptr.is_null() {
                return Err(VfsError::Io);
            }
            let dyn_dir = &*dyn_ptr;
            let mut content = [0u8; 4096];
            let name = (*vd).dyn_name.as_ptr();
            let name_len = (*vd).dyn_name_len as usize;
            let content_len = match (dyn_dir.lookup)(name, name_len, content.as_mut_ptr(), 4096) {
                Some(n) => n,
                None => return Err(VfsError::Io),
            };
            if offset as usize >= content_len {
                return Ok(Ready(0));
            }
            let available = content_len - offset as usize;
            let to_copy = (len as usize).min(available);
            core::ptr::copy_nonoverlapping(content.as_ptr().add(offset as usize), dst, to_copy);
            return Ok(Ready(to_copy as u64));
        }

        let mut content = [0u8; PROC_TEXT_BUF_SIZE];
        let content_len = match (*vd).kind {
            ProcfsKind::PidStat => proc_gen_stat(pid, &mut content),
            ProcfsKind::PidStatus => proc_gen_status(pid, &mut content),
            ProcfsKind::PidMaps => proc_gen_maps(pid, &mut content),
            ProcfsKind::PidCmdline => proc_gen_cmdline(pid, &mut content),
            ProcfsKind::PidComm => proc_gen_comm(pid, &mut content),
            ProcfsKind::PidStatm => proc_gen_statm(pid, &mut content),
            ProcfsKind::PidIo => proc_gen_io(pid, &mut content),
            ProcfsKind::PidSmaps => proc_gen_smaps(pid, &mut content),
            ProcfsKind::PidCgroup => proc_gen_cgroup(pid, &mut content),
            ProcfsKind::PidOomScore => proc_gen_oom_score(pid, &mut content),
            ProcfsKind::SysStat => super::sysnode::proc_gen_stat(&mut content),
            ProcfsKind::SysMeminfo => super::sysnode::proc_gen_meminfo(&mut content),
            ProcfsKind::SysUptime => super::sysnode::proc_gen_uptime(&mut content),
            ProcfsKind::SysCpuinfo => super::sysnode::proc_gen_cpuinfo(&mut content),
            ProcfsKind::SysLoadavg => super::sysnode::proc_gen_loadavg(&mut content),
            ProcfsKind::NetRoute => proc_gen_route(&mut content),
            ProcfsKind::NetArp => proc_gen_arp(&mut content),
            ProcfsKind::NetDev => proc_gen_net_dev(&mut content),
            ProcfsKind::SysLeaf => {
                let leaf_ptr = (*vd).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlLeaf;
                if leaf_ptr.is_null() {
                    return Err(VfsError::Io);
                }
                let leaf = &*leaf_ptr;
                match leaf.read_fn {
                    Some(read_fn) => read_fn(content.as_mut_ptr(), PROC_TEXT_BUF_SIZE),
                    None => 0,
                }
            }
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

// =========================================================================
// DataOps — Statfs
// =========================================================================

unsafe fn procfs_statfs(_ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = 0;
        (*out).ffree = 0;
        (*out).fs_type = [0; 16];
        (&mut (*out).fs_type)[..6].copy_from_slice(b"procfs");
        (*out).flags = 0;
        (*out).name_max = 255;
        Ok(Ready(()))
    }
}

// =========================================================================
// Static dispatch table
// =========================================================================

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
        read_mode: DataExecMode::WorkerSafe,
        readdir_mode: DataExecMode::WorkerSafe,
        readdir: procfs_readdir,
        read: procfs_read,
        statfs: procfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
