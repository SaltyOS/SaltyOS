// SPDX-License-Identifier: GPL-2.0-only
//! `VopVector` — per-filesystem vnode operation table.
//!
//! A `VopVector` is split into two halves:
//!
//! - [`VopMetaOps`] — owner-thread-only metadata operations (lookup, create,
//!   unlink, getattr, ...). Receive `&mut OwnerVopCtx<'_>`.
//! - [`VopDataOps`] — async-capable data operations (read, write, readdir,
//!   fsync, xattr, ...). Receive `&WorkerIoCtx`.
//!
//! Backends provide one static `VopVector` and install it on every vnode they
//! allocate via `Vnode.ops`. The dispatch layer knows which half to use.

use trona_kernel::core_types::TronaMsg;

use super::cred::VfsCred;
use super::error::VfsError;
use super::file::{VAttr, VStatfs};
use super::outcome::{Ready, VopOutcome};
use super::vnode::VnodeHandle;
use super::vop_context::{OwnerVopCtx, WorkerIoCtx};

// =========================================================================
// Readdir emit callback
// =========================================================================

/// Callback invoked once per directory entry by `VopDataOps::readdir`.
///
/// Arguments: `(ino, name, name_len, d_type, attr)`.
/// Return `true` to continue iteration, `false` to stop.
pub(crate) type ReaddirEmit<'a> = &'a mut dyn FnMut(u64, *const u8, u8, u8, &VAttr) -> bool;

// =========================================================================
// Xattr flags
// =========================================================================

/// Fail if the attribute already exists.
pub(crate) const XATTR_CREATE: u32 = 1 << 0;
/// Fail if the attribute does not already exist.
pub(crate) const XATTR_REPLACE: u32 = 1 << 1;

// =========================================================================
// VopMetaOps — owner-thread-only metadata operations
// =========================================================================

/// Metadata operations called synchronously on the owner thread. All ops
/// receive `&mut OwnerVopCtx<'_>` which carries the borrowed `&mut VfsState`
/// plus pre-resolved raw pointers to the target vnode, its mount, and the
/// backend-private data blobs.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopMetaOps {
    // -----------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------
    pub(crate) lookup: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
    ) -> VopOutcome<VnodeHandle>,

    pub(crate) lookup_ci: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
    ) -> VopOutcome<VnodeHandle>,

    // -----------------------------------------------------------------
    // Creation / removal / linkage
    // -----------------------------------------------------------------
    pub(crate) create: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
        mode: u32,
        cred: *const VfsCred,
    ) -> VopOutcome<VnodeHandle>,

    pub(crate) mkdir: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
        mode: u32,
        cred: *const VfsCred,
    ) -> VopOutcome<VnodeHandle>,

    pub(crate) symlink: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
        target: *const u8,
        target_len: u8,
        cred: *const VfsCred,
    ) -> VopOutcome<VnodeHandle>,

    pub(crate) unlink:
        unsafe fn(ctx: &mut OwnerVopCtx<'_>, name: *const u8, name_len: u8) -> VopOutcome<()>,

    pub(crate) rmdir:
        unsafe fn(ctx: &mut OwnerVopCtx<'_>, name: *const u8, name_len: u8) -> VopOutcome<()>,

    pub(crate) link: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
        target: VnodeHandle,
    ) -> VopOutcome<()>,

    /// `ctx` is the OLD parent directory ctx. `new_dir` is the new parent
    /// directory handle; backends resolve it via `ctx.resolve_vnode(new_dir)`
    /// when they need to read its fields. Cross-mount rename is rejected
    /// by the dispatcher before this entry fires, so both directories
    /// share the same owning mount.
    pub(crate) rename: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        old_name: *const u8,
        old_len: u8,
        new_dir: VnodeHandle,
        new_name: *const u8,
        new_len: u8,
    ) -> VopOutcome<()>,

    // -----------------------------------------------------------------
    // Open / close
    // -----------------------------------------------------------------
    pub(crate) open: unsafe fn(ctx: &mut OwnerVopCtx<'_>, flags: u32) -> VopOutcome<()>,
    pub(crate) close: unsafe fn(ctx: &mut OwnerVopCtx<'_>, flags: u32) -> VopOutcome<()>,

    // -----------------------------------------------------------------
    // Attributes
    // -----------------------------------------------------------------
    pub(crate) getattr: unsafe fn(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()>,
    pub(crate) setattr: unsafe fn(ctx: &mut OwnerVopCtx<'_>, attr: *const VAttr) -> VopOutcome<()>,
    pub(crate) access:
        unsafe fn(ctx: &mut OwnerVopCtx<'_>, mode: u32, cred: *const VfsCred) -> VopOutcome<()>,

    // -----------------------------------------------------------------
    // Symbolic link
    // -----------------------------------------------------------------
    pub(crate) readlink: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        buf: *mut u8,
        buf_len: usize,
        cred: *const VfsCred,
    ) -> VopOutcome<usize>,

    // -----------------------------------------------------------------
    // Truncate
    // -----------------------------------------------------------------
    pub(crate) truncate: unsafe fn(ctx: &mut OwnerVopCtx<'_>, new_size: u64) -> VopOutcome<()>,

    // -----------------------------------------------------------------
    // Reclaim
    // -----------------------------------------------------------------
    pub(crate) inactive: unsafe fn(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()>,
}

// =========================================================================
// VopDataOps — async-capable data operations
// =========================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) enum DataExecMode {
    OwnerOnly = 0,
    WorkerSafe = 1,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopDataOps {
    pub(crate) read_mode: DataExecMode,
    pub(crate) write_mode: DataExecMode,
    pub(crate) readdir_mode: DataExecMode,
    pub(crate) read:
        unsafe fn(ctx: &WorkerIoCtx, offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64>,

    pub(crate) write:
        unsafe fn(ctx: &WorkerIoCtx, offset: u64, src: *const u8, len: u64) -> VopOutcome<u64>,

    pub(crate) fsync: unsafe fn(ctx: &WorkerIoCtx) -> VopOutcome<()>,

    pub(crate) readdir:
        unsafe fn(ctx: &WorkerIoCtx, cookie: *mut u64, emit: ReaddirEmit<'_>) -> VopOutcome<()>,

    pub(crate) getxattr: unsafe fn(
        ctx: &WorkerIoCtx,
        name: *const u8,
        name_len: u8,
        buf: *mut u8,
        buf_len: usize,
    ) -> VopOutcome<usize>,

    pub(crate) setxattr: unsafe fn(
        ctx: &WorkerIoCtx,
        name: *const u8,
        name_len: u8,
        value: *const u8,
        value_len: usize,
        flags: u32,
    ) -> VopOutcome<()>,

    pub(crate) listxattr:
        unsafe fn(ctx: &WorkerIoCtx, buf: *mut u8, buf_len: usize) -> VopOutcome<usize>,

    pub(crate) removexattr:
        unsafe fn(ctx: &WorkerIoCtx, name: *const u8, name_len: u8) -> VopOutcome<()>,

    pub(crate) ioctl:
        unsafe fn(ctx: &WorkerIoCtx, cmd: u32, arg: u64, reply: *mut TronaMsg) -> VopOutcome<()>,

    pub(crate) mmap_get_page: unsafe fn(
        ctx: &WorkerIoCtx,
        page_idx: u64,
        write: bool,
        out_cap: *mut u64,
    ) -> VopOutcome<()>,

    pub(crate) statfs: unsafe fn(ctx: &WorkerIoCtx, out: *mut VStatfs) -> VopOutcome<()>,
}

// =========================================================================
// VopVector — unified container
// =========================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopVector {
    pub(crate) meta: VopMetaOps,
    pub(crate) data: VopDataOps,
}

// =========================================================================
// Default stubs — MetaOps
// =========================================================================

macro_rules! meta_notsup {
    ($name:ident, ($($arg:ident : $t:ty),* $(,)?) -> $ret:ty) => {
        unsafe fn $name($($arg: $t),*) -> VopOutcome<$ret> {
            $(let _ = $arg;)*
            Err(VfsError::NotSupported)
        }
    };
}

meta_notsup!(default_meta_lookup, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8) -> VnodeHandle);
meta_notsup!(default_meta_create, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_mkdir, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_symlink, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _t: *const u8, _tl: u8, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_unlink, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8) -> ());
meta_notsup!(default_meta_rmdir, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8) -> ());
meta_notsup!(default_meta_link, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _t: VnodeHandle) -> ());
meta_notsup!(default_meta_rename, (_ctx: &mut OwnerVopCtx<'_>, _on: *const u8, _ol: u8, _nd: VnodeHandle, _nn: *const u8, _nl: u8) -> ());
meta_notsup!(default_meta_open, (_ctx: &mut OwnerVopCtx<'_>, _f: u32) -> ());
meta_notsup!(default_meta_close, (_ctx: &mut OwnerVopCtx<'_>, _f: u32) -> ());
meta_notsup!(default_meta_getattr, (_ctx: &mut OwnerVopCtx<'_>, _a: *mut VAttr) -> ());
meta_notsup!(default_meta_setattr, (_ctx: &mut OwnerVopCtx<'_>, _a: *const VAttr) -> ());
meta_notsup!(default_meta_access, (_ctx: &mut OwnerVopCtx<'_>, _m: u32, _c: *const VfsCred) -> ());
meta_notsup!(default_meta_readlink, (_ctx: &mut OwnerVopCtx<'_>, _b: *mut u8, _bl: usize, _c: *const VfsCred) -> usize);
meta_notsup!(default_meta_truncate, (_ctx: &mut OwnerVopCtx<'_>, _s: u64) -> ());

unsafe fn default_meta_inactive(_ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    Ok(Ready(()))
}

unsafe fn default_meta_lookup_ci(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    unsafe { super::casefold::readdir_casefold_scan(ctx, name, name_len).map(Ready) }
}

pub(crate) static META_OPS_DEFAULT: VopMetaOps = VopMetaOps {
    lookup: default_meta_lookup,
    lookup_ci: default_meta_lookup_ci,
    create: default_meta_create,
    mkdir: default_meta_mkdir,
    symlink: default_meta_symlink,
    unlink: default_meta_unlink,
    rmdir: default_meta_rmdir,
    link: default_meta_link,
    rename: default_meta_rename,
    open: default_meta_open,
    close: default_meta_close,
    getattr: default_meta_getattr,
    setattr: default_meta_setattr,
    access: default_meta_access,
    readlink: default_meta_readlink,
    truncate: default_meta_truncate,
    inactive: default_meta_inactive,
};

// =========================================================================
// Default stubs — DataOps
// =========================================================================

macro_rules! data_notsup {
    ($name:ident, ($($arg:ident : $t:ty),* $(,)?) -> $ret:ty) => {
        unsafe fn $name($($arg: $t),*) -> VopOutcome<$ret> {
            $(let _ = $arg;)*
            Err(VfsError::NotSupported)
        }
    };
}

data_notsup!(default_data_read, (_ctx: &WorkerIoCtx, _o: u64, _d: *mut u8, _l: u64) -> u64);
data_notsup!(default_data_write, (_ctx: &WorkerIoCtx, _o: u64, _s: *const u8, _l: u64) -> u64);
data_notsup!(default_data_fsync, (_ctx: &WorkerIoCtx) -> ());

unsafe fn default_data_readdir(
    _ctx: &WorkerIoCtx,
    _c: *mut u64,
    _e: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    Err(VfsError::NotSupported)
}

data_notsup!(default_data_getxattr, (_ctx: &WorkerIoCtx, _n: *const u8, _nl: u8, _b: *mut u8, _bl: usize) -> usize);
data_notsup!(default_data_setxattr, (_ctx: &WorkerIoCtx, _n: *const u8, _nl: u8, _v: *const u8, _vl: usize, _f: u32) -> ());
data_notsup!(default_data_listxattr, (_ctx: &WorkerIoCtx, _b: *mut u8, _bl: usize) -> usize);
data_notsup!(default_data_removexattr, (_ctx: &WorkerIoCtx, _n: *const u8, _nl: u8) -> ());
data_notsup!(default_data_ioctl, (_ctx: &WorkerIoCtx, _c: u32, _a: u64, _r: *mut TronaMsg) -> ());
data_notsup!(default_data_mmap_get_page, (_ctx: &WorkerIoCtx, _p: u64, _w: bool, _o: *mut u64) -> ());
data_notsup!(default_data_statfs, (_ctx: &WorkerIoCtx, _o: *mut VStatfs) -> ());

pub(crate) static DATA_OPS_DEFAULT: VopDataOps = VopDataOps {
    read_mode: DataExecMode::OwnerOnly,
    write_mode: DataExecMode::OwnerOnly,
    readdir_mode: DataExecMode::OwnerOnly,
    read: default_data_read,
    write: default_data_write,
    fsync: default_data_fsync,
    readdir: default_data_readdir,
    getxattr: default_data_getxattr,
    setxattr: default_data_setxattr,
    listxattr: default_data_listxattr,
    removexattr: default_data_removexattr,
    ioctl: default_data_ioctl,
    mmap_get_page: default_data_mmap_get_page,
    statfs: default_data_statfs,
};

pub(crate) static VOPS_DEFAULT: VopVector = VopVector {
    meta: META_OPS_DEFAULT,
    data: DATA_OPS_DEFAULT,
};
