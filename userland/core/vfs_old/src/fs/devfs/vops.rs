// SPDX-License-Identifier: GPL-2.0-only
//! devfs `VopVector` — per-vnode operations for the device filesystem.
//!
//! Lookup and readdir handle both the root directory (static registration
//! table + synthetic `pts/` entry) and the `pts/` subdirectory (dynamic
//! PTY slave entries synthesized on-the-fly).
//!
//! Read/write dispatch per-device I/O:
//! - `Console` → IPC to `console` server.
//! - `Null` → read returns 0 (EOF), write swallows bytes.
//! - `Zero` → read fills with zeroes, write swallows bytes.
//! - `Urandom` → read from ChaCha20 CSPRNG, write swallows bytes.
//! - `Fb0` → not supported for sequential read/write (mmap only).
//! - `Ptmx` / `PtySlave` → IPC to `posix_ttysrv`.
//! - `Tty` → resolved at open time to the caller's controlling tty.

use trona_kernel::core_types::*;
use trona_kernel::ipc;
use trona_protocol::posix::server::*;
use uapi::*;

use crate::server::consts::posix_ttysrv_ep;
use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::VfsError;
use crate::vfs_core::file::{VAttr, VStatfs};
use crate::vfs_core::outcome::{Ready, VopOutcome};
use crate::vfs_core::vnode::{VT_CHR, VT_DIR, VnodeHandle};
use crate::vfs_core::vop::ReaddirEmit;
use crate::vfs_core::vop_context::{OwnerVopCtx, WorkerIoCtx};

use super::{
    DEVFS_REGISTRATIONS, DevKind, DevfsMountData, DevfsVnodeData, alloc_vdata, record_vnode,
};

// =========================================================================
// Helpers
// =========================================================================

/// Extract the `DevfsVnodeData` pointer from a VopContext.
#[inline]
unsafe fn vdata(ctx: &OwnerVopCtx<'_>) -> *mut DevfsVnodeData {
    ctx.data as *mut DevfsVnodeData
}

/// Extract the `DevfsVnodeData` pointer from a WorkerIoCtx.
#[inline]
unsafe fn vdata_d(ctx: &WorkerIoCtx) -> *mut DevfsVnodeData {
    ctx.data as *mut DevfsVnodeData
}

/// Extract the `DevfsMountData` pointer from a VopContext.
#[inline]
unsafe fn mdata(ctx: &OwnerVopCtx<'_>) -> *mut DevfsMountData {
    ctx.mount_data as *mut DevfsMountData
}

/// Extract the `DevfsMountData` pointer from a WorkerIoCtx.
#[inline]
unsafe fn mdata_d(ctx: &WorkerIoCtx) -> *mut DevfsMountData {
    ctx.mount_data as *mut DevfsMountData
}

/// Compare two byte slices for equality.
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

/// Format a u32 into a decimal ASCII buffer. Returns the number of bytes written.
fn u32_to_ascii(val: u32, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = val;
    let mut i = 0usize;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    if i > buf.len() {
        return 0;
    }
    for j in 0..i {
        buf[j] = tmp[i - 1 - j];
    }
    i
}

/// Parse a decimal ASCII string to u32. Returns `None` on invalid input.
fn ascii_to_u32(ptr: *const u8, len: u8) -> Option<u32> {
    if len == 0 || len > 10 {
        return None;
    }
    let mut val: u32 = 0;
    for i in 0..len as usize {
        let ch = unsafe { *ptr.add(i) };
        if ch < b'0' || ch > b'9' {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((ch - b'0') as u32)?;
    }
    Some(val)
}

/// Get the IPC context.
#[inline]
fn ipc_ctx() -> *mut IpcContext {
    crate::ipc_ctx()
}

// =========================================================================
// Lookup
// =========================================================================

/// Look up a child by name in a devfs directory vnode.
///
/// For the root directory: searches `DEVFS_REGISTRATIONS` by name, plus the
/// synthetic `pts` entry and `.` / `..`.
///
/// For the `pts/` directory: parses the name as a decimal integer and
/// returns the vnode for `/dev/pts/N`. Lazily allocates the PTY slave
/// vnode on first access via the arena alloc callback.
unsafe fn devfs_lookup(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe {
        let dvd = vdata(ctx);
        let md = mdata(ctx);

        // "." — self reference.
        if name_len == 1 && *name == b'.' {
            return Ok(Ready(ctx.handle));
        }

        // ".." — parent. Root's parent is itself.
        if name_len == 2 && *name == b'.' && *name.add(1) == b'.' {
            if (*dvd).kind == DevKind::PtsDir {
                // Parent of pts/ is the devfs root — handle at index 0.
                return Ok(Ready((*md).vnode_handles[0]));
            }
            return Ok(Ready(ctx.handle));
        }

        match (*dvd).kind {
            DevKind::PtsDir => {
                // Parse "N" → PTY slave index.
                let slot = ascii_to_u32(name, name_len).ok_or(VfsError::NotFound)?;

                // Authoritative existence check against posix_ttysrv.
                // Without this, devfs would fabricate a vnode for any
                // numeric name regardless of whether the slot is live.
                let mut lookup_req = TronaMsg::zeroed();
                let mut lookup_reply = TronaMsg::zeroed();
                lookup_req.label = POSIX_TTYSRV_PTY_LOOKUP;
                lookup_req.length = 1;
                lookup_req.regs[0] = slot as u64;
                let err = ipc::call_ctx(
                    ipc_ctx(),
                    posix_ttysrv_ep(),
                    &raw const lookup_req,
                    &raw mut lookup_reply,
                );
                if err != 0 || lookup_reply.label != TRONA_OK {
                    return Err(VfsError::NotFound);
                }
                let generation = lookup_reply.regs[0] as u32;

                // Check if a vnode already exists for this PTY slot.
                // Refresh generation on the existing vdata so a caller
                // that missed a reallocation cycle sees the latest
                // value and `devfs_open` validates correctly.
                for i in 0..(*md).count {
                    let vd = &mut (*md).vdata[i];
                    if vd.kind == DevKind::PtySlave && vd.sub_id == slot {
                        vd.generation = generation;
                        return Ok(Ready((*md).vnode_handles[i]));
                    }
                }

                // Lazy-allocate a vnode for this PTY slave via the arena.
                let id = (*md).count as u64;
                let vd = alloc_vdata(ctx.mount_data);
                if vd.is_null() {
                    return Err(VfsError::NoSpace);
                }
                (*vd).kind = DevKind::PtySlave;
                (*vd).sub_id = slot;
                (*vd).mode = 0o020666;
                (*vd).generation = generation;

                let (child_vh, child_vp) = ctx.alloc_vnode().ok_or(VfsError::NoSpace)?;
                (*child_vp).vtype = VT_CHR;
                (*child_vp).id = id;
                (*child_vp).nlink = 1;
                (*child_vp)
                    .mount
                    .set((*ctx.mount).fs_instance_id, ctx.mount_handle);
                (*child_vp).fs_instance_id = (*ctx.mount).fs_instance_id;
                (*child_vp).ops = (*ctx.vnode).ops;
                (*child_vp).data = vd as *mut u8;

                record_vnode(ctx.mount_data, child_vh, id);

                Ok(Ready(child_vh))
            }
            _ => {
                // Root directory lookup: search static registrations.
                // id=0 is root, id=1..N are registrations, id=N+1 is pts dir.
                let reg_count = DEVFS_REGISTRATIONS.len();
                for (idx, reg) in DEVFS_REGISTRATIONS.iter().enumerate() {
                    if name_eq(name, name_len, reg.name) {
                        let vnode_idx = idx + 1; // +1 because id=0 is root
                        return Ok(Ready((*md).vnode_handles[vnode_idx]));
                    }
                }

                // Check "pts" directory.
                if name_eq(name, name_len, b"pts") {
                    let pts_idx = reg_count + 1; // root(0) + regs(1..N) + pts
                    return Ok(Ready((*md).vnode_handles[pts_idx]));
                }

                // Not found.
                Ok(Ready(VnodeHandle::INVALID))
            }
        }
    }
}

// =========================================================================
// Readdir
// =========================================================================

/// Enumerate directory entries.
///
/// `cookie` is an opaque cursor: 0 = start, incremented by 1 per entry.
/// Entries are emitted in a stable order:
/// - Root: ".", "..", then each registration name, then "pts".
/// - pts/: ".", "..", then one entry per allocated PTY slave vnode.
unsafe fn devfs_readdir(
    ctx: &WorkerIoCtx,
    cookie: *mut u64,
    emit: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);
        let md = mdata_d(ctx);
        let mut pos = *cookie;

        match (*vd).kind {
            DevKind::PtsDir => {
                let attr = VAttr::zeroed();

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4 /* DT_DIR */, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // ".."
                if pos == 1 {
                    let root_id = (*md).vnode_ids[0];
                    if !emit(root_id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // Dynamic PTY slave entries.
                let base = 2u64;
                for i in 0..(*md).count {
                    let vd_i = &(*md).vdata[i];
                    if vd_i.kind != DevKind::PtySlave {
                        continue;
                    }
                    let entry_pos = base + vd_i.sub_id as u64;
                    if pos > entry_pos {
                        continue;
                    }
                    if pos < entry_pos {
                        pos = entry_pos;
                    }

                    let mut nbuf = [0u8; 10];
                    let nlen = u32_to_ascii(vd_i.sub_id, &mut nbuf);
                    if nlen == 0 {
                        continue;
                    }
                    if !emit(
                        (*md).vnode_ids[i],
                        nbuf.as_ptr(),
                        nlen as u8,
                        2, // DT_CHR
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
            _ => {
                // Root directory.
                let attr = VAttr::zeroed();
                let reg_count = DEVFS_REGISTRATIONS.len();

                // "."
                if pos == 0 {
                    if !emit(ctx.id, b".".as_ptr(), 1, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // ".."
                if pos == 1 {
                    if !emit(ctx.id, b"..".as_ptr(), 2, 4, &attr) {
                        *cookie = pos + 1;
                        return Ok(Ready(()));
                    }
                    pos += 1;
                }

                // Static device entries.
                let mut idx = (pos as usize).saturating_sub(2);
                while idx < reg_count {
                    let entry_pos = (idx + 2) as u64;
                    if pos > entry_pos {
                        idx += 1;
                        continue;
                    }
                    let reg = &DEVFS_REGISTRATIONS[idx];
                    if !emit(
                        (idx + 1) as u64,
                        reg.name.as_ptr(),
                        reg.name.len() as u8,
                        2, // DT_CHR
                        &attr,
                    ) {
                        *cookie = entry_pos + 1;
                        return Ok(Ready(()));
                    }
                    pos = entry_pos + 1;
                    idx += 1;
                }

                // "pts" directory entry.
                let pts_pos = (2 + reg_count) as u64;
                if pos <= pts_pos {
                    emit(
                        (reg_count + 1) as u64,
                        b"pts".as_ptr(),
                        3,
                        4, // DT_DIR
                        &attr,
                    );
                    pos = pts_pos + 1;
                }

                *cookie = pos;
                Ok(Ready(()))
            }
        }
    }
}

// =========================================================================
// Getattr
// =========================================================================

unsafe fn devfs_getattr(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()> {
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

        match (*vd).kind {
            DevKind::PtsDir => {
                (*attr).mode = 0o040755;
                (*attr).size = 0;
                (*attr).rdev = 0;
            }
            _ if (*ctx.vnode).vtype == VT_DIR => {
                // Root directory.
                (*attr).mode = 0o040755;
                (*attr).size = 0;
                (*attr).rdev = 0;
            }
            _ => {
                // Character device.
                (*attr).mode = (*vd).mode;
                (*attr).size = 0;
                // Encode rdev as (kind << 8 | sub_id) for consumer identification.
                (*attr).rdev = (((*vd).kind as u32) << 8) | ((*vd).sub_id & 0xFF);
            }
        }

        Ok(Ready(()))
    }
}

// =========================================================================
// Access
// =========================================================================

unsafe fn devfs_access(
    _ctx: &mut OwnerVopCtx<'_>,
    _mode: u32,
    _cred: *const VfsCred,
) -> VopOutcome<()> {
    Ok(Ready(()))
}

// =========================================================================
// Open / Close
// =========================================================================

unsafe fn devfs_open(ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    unsafe {
        let vd = vdata(ctx);
        if (*vd).kind == DevKind::PtySlave {
            let mut treq = TronaMsg::zeroed();
            let mut treply = TronaMsg::zeroed();
            treq.label = POSIX_TTYSRV_PTY_OPEN_SLAVE;
            treq.regs[0] = (*vd).sub_id as u64;
            treq.regs[1] = (*vd).generation as u64;
            treq.length = 2;
            let err = ipc::call_ctx(
                ipc_ctx(),
                posix_ttysrv_ep(),
                &raw const treq,
                &raw mut treply,
            );
            if err != 0 {
                return Err(VfsError::Io);
            }
            if treply.label == TRONA_NOT_FOUND {
                // Slot was reallocated or torn down since lookup —
                // mark this vdata stale so the next lookup refreshes.
                (*vd).generation = 0;
                return Err(VfsError::NotFound);
            }
            if treply.label != TRONA_OK {
                return Err(VfsError::Io);
            }
        }
    }
    Ok(Ready(()))
}

unsafe fn devfs_close(_ctx: &mut OwnerVopCtx<'_>, _flags: u32) -> VopOutcome<()> {
    Ok(Ready(()))
}

// =========================================================================
// Read
// =========================================================================

unsafe fn devfs_read(ctx: &WorkerIoCtx, _offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);

        match (*vd).kind {
            DevKind::Console => {
                let mut creq = TronaMsg::zeroed();
                let mut creply = TronaMsg::zeroed();
                creq.label = CONSOLE_READ;
                creq.length = 0;

                let err = ipc::call_ctx(
                    ipc_ctx(),
                    trona_runtime::client::caps::console_ep(),
                    &raw const creq,
                    &raw mut creply,
                );
                if err != 0 || creply.label != TRONA_OK {
                    return Err(VfsError::Io);
                }

                let read_count = creply.regs[0];
                if read_count == 0 {
                    return Ok(Ready(0));
                }

                let actual = if read_count > len { len } else { read_count };
                let src = &creply.regs[1] as *const u64 as *const u8;
                for i in 0..actual as usize {
                    *dst.add(i) = *src.add(i);
                }
                Ok(Ready(actual))
            }

            DevKind::Null => Ok(Ready(0)),

            DevKind::Zero => {
                for i in 0..len as usize {
                    *dst.add(i) = 0;
                }
                Ok(Ready(len))
            }

            DevKind::Urandom => {
                let mut i: u64 = 0;
                while i + 8 <= len {
                    let v = crate::urandom_next();
                    let bytes = v.to_le_bytes();
                    for j in 0..8 {
                        *dst.add(i as usize + j) = bytes[j];
                    }
                    i += 8;
                }
                if i < len {
                    let v = crate::urandom_next();
                    let bytes = v.to_le_bytes();
                    let mut j = 0usize;
                    while i < len {
                        *dst.add(i as usize) = bytes[j];
                        i += 1;
                        j += 1;
                    }
                }
                Ok(Ready(len))
            }

            DevKind::Fb0 => Err(VfsError::NotSupported),
            DevKind::Tty => Err(VfsError::NotSupported),

            DevKind::PtySlave => {
                let pty_id = (*vd).sub_id as u64;
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_READ;
                treq.regs[0] = pty_id;
                treq.regs[1] = len;
                treq.length = 2;

                let err = ipc::call_ctx(
                    ipc_ctx(),
                    posix_ttysrv_ep(),
                    &raw const treq,
                    &raw mut treply,
                );
                if err != 0 || treply.label != TRONA_OK {
                    return Err(VfsError::Io);
                }

                let actual = treply.regs[0];
                if actual > 0 {
                    let src = &treply.regs[1] as *const u64 as *const u8;
                    for i in 0..actual as usize {
                        *dst.add(i) = *src.add(i);
                    }
                }
                Ok(Ready(actual))
            }

            DevKind::Ptmx => {
                let pty_id = (*vd).sub_id as u64;
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_READ;
                treq.regs[0] = pty_id;
                treq.regs[1] = len;
                treq.regs[2] = 1; // master side
                treq.length = 3;

                let err = ipc::call_ctx(
                    ipc_ctx(),
                    posix_ttysrv_ep(),
                    &raw const treq,
                    &raw mut treply,
                );
                if err != 0 || treply.label != TRONA_OK {
                    return Err(VfsError::Io);
                }

                let actual = treply.regs[0];
                if actual > 0 {
                    let src = &treply.regs[1] as *const u64 as *const u8;
                    for i in 0..actual as usize {
                        *dst.add(i) = *src.add(i);
                    }
                }
                Ok(Ready(actual))
            }

            DevKind::PtsDir => Err(VfsError::IsDir),
        }
    }
}

// =========================================================================
// Write
// =========================================================================

unsafe fn devfs_write(
    ctx: &WorkerIoCtx,
    _offset: u64,
    src: *const u8,
    len: u64,
) -> VopOutcome<u64> {
    unsafe {
        let vd = vdata_d(ctx);

        match (*vd).kind {
            DevKind::Console => {
                let mut sent: u64 = 0;
                while sent < len {
                    let mut creq = TronaMsg::zeroed();
                    let mut creply = TronaMsg::zeroed();
                    let mut chunk = len - sent;
                    if chunk > 24 {
                        chunk = 24;
                    }

                    creq.label = CONSOLE_WRITE;
                    creq.length = 1 + (chunk + 7) / 8;
                    creq.regs[0] = chunk;

                    let cdst = &raw mut creq.regs[1] as *mut u8;
                    for i in 0..chunk as usize {
                        *cdst.add(i) = *src.add(sent as usize + i);
                    }

                    let err = ipc::call_ctx(
                        ipc_ctx(),
                        trona_runtime::client::caps::console_ep(),
                        &raw const creq,
                        &raw mut creply,
                    );
                    if err != 0 || creply.label != TRONA_OK {
                        break;
                    }
                    sent += chunk;
                }
                if sent > 0 {
                    Ok(Ready(sent))
                } else {
                    Err(VfsError::Io)
                }
            }

            DevKind::Null | DevKind::Zero | DevKind::Urandom => Ok(Ready(len)),

            DevKind::Fb0 => Err(VfsError::NotSupported),
            DevKind::Tty => Err(VfsError::NotSupported),

            DevKind::PtySlave => {
                let pty_id = (*vd).sub_id as u64;
                let mut sent: u64 = 0;
                while sent < len {
                    let mut treq = TronaMsg::zeroed();
                    let mut treply = TronaMsg::zeroed();
                    let mut chunk = len - sent;
                    if chunk > 136 {
                        chunk = 136;
                    }
                    treq.label = POSIX_TTYSRV_PTY_WRITE;
                    treq.regs[0] = pty_id;
                    treq.regs[1] = chunk;
                    let tdst = &raw mut treq.regs[2] as *mut u8;
                    for i in 0..chunk as usize {
                        *tdst.add(i) = *src.add(sent as usize + i);
                    }
                    treq.length = 2 + (chunk + 7) / 8;
                    let err = ipc::call_ctx(
                        ipc_ctx(),
                        posix_ttysrv_ep(),
                        &raw const treq,
                        &raw mut treply,
                    );
                    if err != 0 || treply.label != TRONA_OK {
                        break;
                    }
                    sent += chunk;
                }
                if sent > 0 {
                    Ok(Ready(sent))
                } else {
                    Err(VfsError::Io)
                }
            }

            DevKind::Ptmx => {
                let pty_id = (*vd).sub_id as u64;
                let mut sent: u64 = 0;
                while sent < len {
                    let mut treq = TronaMsg::zeroed();
                    let mut treply = TronaMsg::zeroed();
                    let mut chunk = len - sent;
                    if chunk > 136 {
                        chunk = 136;
                    }
                    treq.label = POSIX_TTYSRV_PTY_MASTER_WRITE;
                    treq.regs[0] = pty_id;
                    treq.regs[1] = chunk;
                    let tdst = &raw mut treq.regs[2] as *mut u8;
                    for i in 0..chunk as usize {
                        *tdst.add(i) = *src.add(sent as usize + i);
                    }
                    treq.length = 2 + (chunk + 7) / 8;
                    let err = ipc::call_ctx(
                        ipc_ctx(),
                        posix_ttysrv_ep(),
                        &raw const treq,
                        &raw mut treply,
                    );
                    if err != 0 || treply.label != TRONA_OK {
                        break;
                    }
                    sent += chunk;
                }
                if sent > 0 || len == 0 {
                    Ok(Ready(sent))
                } else {
                    Err(VfsError::Io)
                }
            }

            DevKind::PtsDir => Err(VfsError::IsDir),
        }
    }
}

// =========================================================================
// Ioctl
// =========================================================================

unsafe fn devfs_ioctl(
    ctx: &WorkerIoCtx,
    cmd: u32,
    arg: u64,
    reply: *mut TronaMsg,
) -> VopOutcome<()> {
    unsafe {
        let vd = vdata_d(ctx);

        match (*vd).kind {
            DevKind::PtySlave | DevKind::Ptmx => {
                let pty_id = (*vd).sub_id as u64;
                let mut treq = TronaMsg::zeroed();
                let mut treply = TronaMsg::zeroed();
                treq.label = POSIX_TTYSRV_PTY_IOCTL;
                treq.regs[0] = pty_id;
                treq.regs[1] = cmd as u64;
                treq.regs[2] = arg;
                treq.length = 3;

                let err = ipc::call_ctx(
                    ipc_ctx(),
                    posix_ttysrv_ep(),
                    &raw const treq,
                    &raw mut treply,
                );
                if err != 0 || treply.label != TRONA_OK {
                    return Err(VfsError::Io);
                }
                if !reply.is_null() {
                    *reply = treply;
                }
                Ok(Ready(()))
            }
            DevKind::Fb0 => Err(VfsError::NotSupported),
            _ => Err(VfsError::NotSupported),
        }
    }
}

// =========================================================================
// Statfs (data-level — pseudo-filesystem)
// =========================================================================

unsafe fn devfs_statfs(ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()> {
    unsafe {
        let md = mdata_d(ctx);
        (*out).bsize = 4096;
        (*out).blocks = 0;
        (*out).bfree = 0;
        (*out).bavail = 0;
        (*out).files = (*md).count as u64;
        (*out).ffree = (super::MAX_DEVFS_VNODES - (*md).count) as u64;
        (*out).fs_type = [0; 16];
        let ft = &mut (*out).fs_type;
        ft[..5].copy_from_slice(b"devfs");
        (*out).flags = 0;
        (*out).name_max = 255;
        Ok(Ready(()))
    }
}

// =========================================================================
// Inactive
// =========================================================================

/// devfs vnodes live for the lifetime of the mount — inactive is a no-op.
unsafe fn devfs_inactive(_ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    Ok(Ready(()))
}

// =========================================================================
// Static dispatch table
// =========================================================================

use crate::vfs_core::vop::{
    DATA_OPS_DEFAULT, DataExecMode, META_OPS_DEFAULT, VopDataOps, VopMetaOps, VopVector,
};

pub(super) static DEVFS_VOPS: VopVector = VopVector {
    meta: VopMetaOps {
        lookup: devfs_lookup,
        getattr: devfs_getattr,
        access: devfs_access,
        open: devfs_open,
        close: devfs_close,
        inactive: devfs_inactive,
        ..META_OPS_DEFAULT
    },
    data: VopDataOps {
        read_mode: DataExecMode::WorkerSafe,
        write_mode: DataExecMode::WorkerSafe,
        readdir_mode: DataExecMode::WorkerSafe,
        read: devfs_read,
        write: devfs_write,
        readdir: devfs_readdir,
        ioctl: devfs_ioctl,
        statfs: devfs_statfs,
        ..DATA_OPS_DEFAULT
    },
};
