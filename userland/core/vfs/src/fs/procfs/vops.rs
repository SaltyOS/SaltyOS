// SPDX-License-Identifier: GPL-2.0-only
//! procfs `VopVector` — per-vnode operations for the process information filesystem.
//!
//! All content is generated dynamically from IPC queries to procmgr and netsrv.
//! Every non-root vnode carries `VN_NOCACHE` and is reclaimed after last close.

use crate::server::consts::MAX_PATH_LEN;
use crate::personality::posix::consts::{S_IFDIR_L, S_IFLNK_L, S_IFREG_L};
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::vnode::{VnodeHandle, VN_NOCACHE, VT_DIR, VT_LNK, VT_REG};
use crate::vfs_core::vop::{
    ReaddirEmit, VopDataOps, VopMetaOps, VopVector, DATA_OPS_DEFAULT, META_OPS_DEFAULT,
};
use crate::vfs_core::vop_context::{VopContext, VopDataContext};

use super::generators::{fmt_u32, parse_pid};
use super::net::{proc_gen_arp, proc_gen_net_dev, proc_gen_route};
use super::pid::{
    proc_gen_cmdline, proc_gen_comm, proc_gen_maps, proc_gen_stat,
    proc_gen_status, proc_get_exe_path, proc_list_pids, proc_pid_exists,
};
use super::{alloc_vdata, encode_id, encode_sys_id, ProcfsKind, ProcfsVnodeData};

/// Content generation buffer size.
const PROC_TEXT_BUF_SIZE: usize = 2048;

// =========================================================================
// Helpers
// =========================================================================

#[inline]
unsafe fn vdata(ctx: &VopContext) -> *mut ProcfsVnodeData {
    ctx.data as *mut ProcfsVnodeData
}

#[inline]
unsafe fn vdata_d(ctx: &VopDataContext) -> *mut ProcfsVnodeData {
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
    ctx: &VopContext,
    vtype: u8,
    kind: ProcfsKind,
    pid: u32,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
        (*vp).vtype = vtype;
        (*vp).flags = VN_NOCACHE;
        (*vp).id = encode_id(kind, pid);
        (*vp).mount = ctx.mount_handle;
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

        Ok(vh)
    }
}

/// Allocate an ephemeral procfs vnode with a sys_ptr (SysDir/SysLeaf).
unsafe fn alloc_procfs_sys_vnode(
    ctx: &VopContext,
    vtype: u8,
    kind: ProcfsKind,
    sys_ptr: *const u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let (vh, vp) = (ctx.alloc)().ok_or(VfsError::NoSpace)?;
        (*vp).vtype = vtype;
        (*vp).flags = VN_NOCACHE;
        (*vp).id = encode_sys_id(kind, sys_ptr);
        (*vp).mount = ctx.mount_handle;
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

        Ok(vh)
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
/// - SysDir: delegates to sysctlfs MIB tree (child nodes + leaves).
unsafe fn procfs_lookup(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(ctx.handle);
        }

        // ".." — parent. Root's parent is itself (mount layer handles cross-mount).
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            match (*dvd).kind {
                ProcfsKind::PidDir | ProcfsKind::NetDir | ProcfsKind::SysDir => {
                    let root_vh = (*ctx.mount).root_vnode;
                    if root_vh.is_valid() {
                        return Ok(root_vh);
                    }
                    return Ok(ctx.handle);
                }
                _ => {
                    return Ok(ctx.handle);
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

                // Numeric PID → PidDir (validate via procmgr IPC).
                let pid_slice = core::slice::from_raw_parts(name, name_len as usize);
                let (pid, ok) = parse_pid(pid_slice);
                if !ok {
                    return Ok(VnodeHandle::INVALID);
                }

                if !proc_pid_exists(pid) {
                    return Ok(VnodeHandle::INVALID);
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

                Ok(VnodeHandle::INVALID)
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

                Ok(VnodeHandle::INVALID)
            }

            ProcfsKind::SysDir => {
                // /proc/sys/ delegation: look up child in the sysctlfs MIB tree.
                let node_ptr = (*dvd).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlNode;
                if node_ptr.is_null() {
                    return Ok(VnodeHandle::INVALID);
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
                        return Ok(VnodeHandle::INVALID);
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

                Ok(VnodeHandle::INVALID)
            }

            _ => Err(VfsError::NotDir),
        }
    }
}

// =========================================================================
// MetaOps — Getattr
// =========================================================================

unsafe fn procfs_getattr(ctx: &VopContext, attr: *mut VAttr) -> VfsResult<()> {
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
            ProcfsKind::Root | ProcfsKind::PidDir | ProcfsKind::NetDir | ProcfsKind::SysDir => {
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
            | ProcfsKind::NetRoute
            | ProcfsKind::NetArp
            | ProcfsKind::NetDev
            | ProcfsKind::SysLeaf => {
                (*attr).mode = S_IFREG_L | 0o444;
            }
        }

        Ok(())
    }
}

// =========================================================================
// MetaOps — Access / Open / Close / Readlink / Inactive
// =========================================================================

unsafe fn procfs_access(
    _ctx: &VopContext,
    _mode: u32,
    _cred: *const VfsCred,
) -> VfsResult<()> {
    Ok(())
}

unsafe fn procfs_open(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

unsafe fn procfs_close(_ctx: &VopContext, _flags: u32) -> VfsResult<()> {
    Ok(())
}

/// Read the target of a procfs symlink vnode.
///
/// - SelfLink → `/proc/<pid>` where pid comes from `cred.pid`.
/// - PidExe → executable path from procmgr IPC.
unsafe fn procfs_readlink(
    ctx: &VopContext,
    buf: *mut u8,
    buf_len: usize,
    cred: *const VfsCred,
) -> VfsResult<usize> {
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
                Ok(total)
            }

            ProcfsKind::PidExe => {
                let pid = (*vd).pid;
                let mut exe_path = [0u8; MAX_PATH_LEN];
                let exe_len =
                    proc_get_exe_path(pid, &mut exe_path).ok_or(VfsError::NotFound)?;
                let copy = if exe_len < buf_len { exe_len } else { buf_len };
                for i in 0..copy {
                    *buf.add(i) = exe_path[i];
                }
                Ok(copy)
            }

            _ => Err(VfsError::Inval),
        }
    }
}

unsafe fn procfs_inactive(_ctx: &VopContext) {}

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
/// - SysDir: ".", "..", then child nodes + leaves from sysctlfs MIB tree.
unsafe fn procfs_readdir(
    ctx: &VopDataContext,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VfsResult<()> {
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
                        return Ok(());
                    }
                    pos += 1;
                }

                // ".."
                if pos == 1 {
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // "self"
                if pos == 2 {
                    if !emit(0, b"self".as_ptr(), 4, 10 /* DT_LNK */, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // "net"
                if pos == 3 {
                    if !emit(0, b"net".as_ptr(), 3, 4 /* DT_DIR */, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // "sys"
                if pos == 4 {
                    if !emit(0, b"sys".as_ptr(), 3, 4 /* DT_DIR */, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // PIDs from procmgr.
                let mut pids = [0u32; 19];
                let count = proc_list_pids(&mut pids);
                let base = 5u64;
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
                        return Ok(());
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(())
            }

            ProcfsKind::PidDir => {
                let entries: &[(&[u8], u8)] = &[
                    (b"stat", 8),    // DT_REG
                    (b"status", 8),  // DT_REG
                    (b"maps", 8),    // DT_REG
                    (b"exe", 10),    // DT_LNK
                    (b"cmdline", 8), // DT_REG
                    (b"comm", 8),    // DT_REG
                ];

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // ".." — root id is encode_id(Root, 0) = 0.
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
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
                        return Ok(());
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(())
            }

            ProcfsKind::NetDir => {
                let entries: &[&[u8]] = &[b"route", b"arp", b"dev"];

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // ".." — root id.
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
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
                        return Ok(());
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(())
            }

            ProcfsKind::SysDir => {
                let node_ptr = (*vd).sys_ptr as *const crate::fs::sysctlfs::tree::SysctlNode;
                if node_ptr.is_null() {
                    return Err(VfsError::NotDir);
                }
                let node = &*node_ptr;

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                // ".." — root id.
                if pos == 1 {
                    let root_id = encode_id(ProcfsKind::Root, 0);
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(());
                    }
                    pos += 1;
                }

                let base = 2u64;

                // Emit child nodes (directories). Apply reverse mapping:
                // MIB "kern" → Linux "kernel".
                let child_count = node.child_node_count;
                for i in 0..child_count {
                    let entry_pos = base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let child = &*node.child_nodes.add(i);
                    let child_name = &child.name[..child.name_len as usize];
                    let (emit_name, emit_len): (&[u8], u8) = if child_name == b"kern" {
                        (b"kernel", 6)
                    } else {
                        (child_name, child.name_len)
                    };
                    if !emit(0, emit_name.as_ptr(), emit_len, 4 /* DT_DIR */, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(());
                    }
                    pos = entry_pos + 1;
                }

                // Emit leaves (regular files).
                let leaf_base = base + child_count as u64;
                let leaf_count = node.leaf_count;
                for i in 0..leaf_count {
                    let entry_pos = leaf_base + i as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    let leaf = &node.leaves[i];
                    let leaf_name = &leaf.name[..leaf.name_len as usize];
                    if !emit(0, leaf_name.as_ptr(), leaf.name_len, 8 /* DT_REG */, &attr) {
                        *cookie = entry_pos + 1;
                        return Ok(());
                    }
                    pos = entry_pos + 1;
                }

                *cookie = pos;
                Ok(())
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
unsafe fn procfs_read(
    ctx: &VopDataContext,
    offset: u64,
    dst: *mut u8,
    len: u64,
) -> VfsResult<u64> {
    unsafe {
        let vd = vdata_d(ctx);
        let pid = (*vd).pid;

        let mut content = [0u8; PROC_TEXT_BUF_SIZE];
        let content_len = match (*vd).kind {
            ProcfsKind::PidStat => proc_gen_stat(pid, &mut content),
            ProcfsKind::PidStatus => proc_gen_status(pid, &mut content),
            ProcfsKind::PidMaps => proc_gen_maps(pid, &mut content),
            ProcfsKind::PidCmdline => proc_gen_cmdline(pid, &mut content),
            ProcfsKind::PidComm => proc_gen_comm(pid, &mut content),
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
            return Ok(0);
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
        Ok(to_copy as u64)
    }
}

// =========================================================================
// DataOps — Statfs
// =========================================================================

unsafe fn procfs_statfs(_ctx: &VopDataContext, out: *mut VStatfs) -> VfsResult<()> {
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
        Ok(())
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
        readdir: procfs_readdir,
        read: procfs_read,
        statfs: procfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
