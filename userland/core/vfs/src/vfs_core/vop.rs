// SPDX-License-Identifier: GPL-2.0-only
//! `VopVector` — per-filesystem vnode operation table.
//!
//! A `VopVector` is split into two halves:
//!
//! - [`VopMetaOps`] — owner-thread-only metadata operations (lookup, create,
//!   unlink, getattr, ...). Called synchronously in the VFS main loop.
//! - [`VopDataOps`] — async-capable data operations (read, write, readdir,
//!   fsync, xattr, ...). May be dispatched to worker threads for blocking
//!   backends (saltyfs, device I/O).
//!
//! Backends provide one static `VopVector` and install it on every vnode they
//! allocate via `Vnode.ops`. The dispatch layer knows which half to use.
//!
//! # Default operations
//!
//! [`META_OPS_DEFAULT`] and [`DATA_OPS_DEFAULT`] provide stubs that return
//! `VfsError::NotSupported`. Backends construct their vectors by const-copying
//! the defaults and overriding only the ops they implement:
//!
//! ```ignore
//! pub(crate) static RAMFS_VOPS: VopVector = VopVector {
//!     meta: VopMetaOps {
//!         lookup: ramfs_lookup,
//!         create: ramfs_create,
//!         ..META_OPS_DEFAULT
//!     },
//!     data: VopDataOps {
//!         read: ramfs_read,
//!         write: ramfs_write,
//!         ..DATA_OPS_DEFAULT
//!     },
//! };
//! ```

use trona::types::core::TronaMsg;

use super::cred::VfsCred;
use super::error::{VfsError, VfsResult};
use super::file::{VAttr, VStatfs};
use super::vnode::{Vnode, VnodeHandle};
use super::vop_context::{VopContext, VopDataContext};

// =========================================================================
// Readdir emit callback
// =========================================================================

/// Callback invoked once per directory entry by `VopDataOps::readdir`.
///
/// Arguments: `(ino, name, name_len, d_type, attr)`.
/// Return `true` to continue iteration, `false` to stop.
pub(crate) type ReaddirEmit<'a> =
    &'a mut dyn FnMut(u64, *const u8, u8, u8, &VAttr) -> bool;

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

/// Metadata operations called synchronously in the VFS main loop.
///
/// All functions receive a `&VopContext` containing resolved pointers and
/// an allocation callback. They return `VnodeHandle` for operations that
/// produce new vnodes (lookup, create, mkdir, symlink).
///
/// Name parameters remain `*const u8, u8` (raw pointer + length) for
/// zero-copy from IPC message registers.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopMetaOps {
    // -----------------------------------------------------------------
    // Path resolution
    // -----------------------------------------------------------------
    /// Look up a single directory component. Returns a `VnodeHandle`, or
    /// `Ok(VnodeHandle::INVALID)` on clean ENOENT, or `Err(Io)` on
    /// backend failure.
    pub(crate) lookup: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
    ) -> VfsResult<VnodeHandle>,

    /// Case-insensitive variant of `lookup`.
    pub(crate) lookup_ci: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
    ) -> VfsResult<VnodeHandle>,

    // -----------------------------------------------------------------
    // Creation / removal / linkage
    // -----------------------------------------------------------------
    pub(crate) create: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
        mode: u32,
        cred: *const VfsCred,
    ) -> VfsResult<VnodeHandle>,

    pub(crate) mkdir: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
        mode: u32,
        cred: *const VfsCred,
    ) -> VfsResult<VnodeHandle>,

    pub(crate) symlink: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
        target: *const u8,
        target_len: u8,
        cred: *const VfsCred,
    ) -> VfsResult<VnodeHandle>,

    pub(crate) unlink: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
    ) -> VfsResult<()>,

    pub(crate) rmdir: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
    ) -> VfsResult<()>,

    pub(crate) link: unsafe fn(
        ctx: &VopContext,
        name: *const u8,
        name_len: u8,
        target: VnodeHandle,
    ) -> VfsResult<()>,

    pub(crate) rename: unsafe fn(
        old_ctx: &VopContext,
        old_name: *const u8,
        old_len: u8,
        new_ctx: &VopContext,
        new_name: *const u8,
        new_len: u8,
    ) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Open / close
    // -----------------------------------------------------------------
    pub(crate) open: unsafe fn(ctx: &VopContext, flags: u32) -> VfsResult<()>,
    pub(crate) close: unsafe fn(ctx: &VopContext, flags: u32) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Attributes
    // -----------------------------------------------------------------
    pub(crate) getattr: unsafe fn(ctx: &VopContext, attr: *mut VAttr) -> VfsResult<()>,
    pub(crate) setattr: unsafe fn(ctx: &VopContext, attr: *const VAttr) -> VfsResult<()>,
    pub(crate) access: unsafe fn(
        ctx: &VopContext,
        mode: u32,
        cred: *const VfsCred,
    ) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Symbolic link
    // -----------------------------------------------------------------
    pub(crate) readlink: unsafe fn(
        ctx: &VopContext,
        buf: *mut u8,
        buf_len: usize,
        cred: *const VfsCred,
    ) -> VfsResult<usize>,

    // -----------------------------------------------------------------
    // Truncate
    // -----------------------------------------------------------------
    pub(crate) truncate: unsafe fn(ctx: &VopContext, new_size: u64) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Reclaim
    // -----------------------------------------------------------------
    /// Called when the last open-file reference drops and the vnode should
    /// be reclaimed. The backend releases state hanging off `ctx.data`.
    pub(crate) inactive: unsafe fn(ctx: &VopContext),
}

// =========================================================================
// VopDataOps — async-capable data operations
// =========================================================================

/// Data operations that may be dispatched to worker threads.
///
/// All functions receive a `&VopDataContext` containing an immutable
/// snapshot of the vnode identity and backend data pointers. The snapshot
/// is safe to send to a worker because arenas are non-moving and the
/// vnode's flight count prevents slot recycling.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopDataOps {
    // -----------------------------------------------------------------
    // I/O
    // -----------------------------------------------------------------
    pub(crate) read: unsafe fn(
        ctx: &VopDataContext,
        offset: u64,
        dst: *mut u8,
        len: u64,
    ) -> VfsResult<u64>,

    pub(crate) write: unsafe fn(
        ctx: &VopDataContext,
        offset: u64,
        src: *const u8,
        len: u64,
    ) -> VfsResult<u64>,

    pub(crate) fsync: unsafe fn(ctx: &VopDataContext) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Directory iteration
    // -----------------------------------------------------------------
    pub(crate) readdir: unsafe fn(
        ctx: &VopDataContext,
        cookie: *mut u64,
        emit: ReaddirEmit<'_>,
    ) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Extended attributes
    // -----------------------------------------------------------------
    pub(crate) getxattr: unsafe fn(
        ctx: &VopDataContext,
        name: *const u8,
        name_len: u8,
        buf: *mut u8,
        buf_len: usize,
    ) -> VfsResult<usize>,

    pub(crate) setxattr: unsafe fn(
        ctx: &VopDataContext,
        name: *const u8,
        name_len: u8,
        value: *const u8,
        value_len: usize,
        flags: u32,
    ) -> VfsResult<()>,

    pub(crate) listxattr: unsafe fn(
        ctx: &VopDataContext,
        buf: *mut u8,
        buf_len: usize,
    ) -> VfsResult<usize>,

    pub(crate) removexattr: unsafe fn(
        ctx: &VopDataContext,
        name: *const u8,
        name_len: u8,
    ) -> VfsResult<()>,

    // -----------------------------------------------------------------
    // Device / misc
    // -----------------------------------------------------------------
    pub(crate) ioctl: unsafe fn(
        ctx: &VopDataContext,
        cmd: u32,
        arg: u64,
        reply: *mut TronaMsg,
    ) -> VfsResult<()>,

    pub(crate) mmap_get_page: unsafe fn(
        ctx: &VopDataContext,
        page_idx: u64,
        write: bool,
        out_cap: *mut u64,
    ) -> VfsResult<()>,

    pub(crate) statfs: unsafe fn(ctx: &VopDataContext, out: *mut VStatfs) -> VfsResult<()>,
}

// =========================================================================
// VopVector — unified container
// =========================================================================

/// Per-filesystem vnode operation dispatch table.
///
/// Contains both metadata ops (owner-thread) and data ops (async-capable).
/// Every vnode stores a `*const VopVector` pointing to a static instance
/// provided by its filesystem backend.
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
        unsafe fn $name($($arg: $t),*) -> VfsResult<$ret> {
            $(let _ = $arg;)*
            Err(VfsError::NotSupported)
        }
    };
}

meta_notsup!(default_meta_lookup, (_ctx: &VopContext, _n: *const u8, _nl: u8) -> VnodeHandle);
meta_notsup!(default_meta_create, (_ctx: &VopContext, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_mkdir, (_ctx: &VopContext, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_symlink, (_ctx: &VopContext, _n: *const u8, _nl: u8, _t: *const u8, _tl: u8, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_unlink, (_ctx: &VopContext, _n: *const u8, _nl: u8) -> ());
meta_notsup!(default_meta_rmdir, (_ctx: &VopContext, _n: *const u8, _nl: u8) -> ());
meta_notsup!(default_meta_link, (_ctx: &VopContext, _n: *const u8, _nl: u8, _t: VnodeHandle) -> ());
meta_notsup!(default_meta_rename, (_oc: &VopContext, _on: *const u8, _ol: u8, _nc: &VopContext, _nn: *const u8, _nl: u8) -> ());
meta_notsup!(default_meta_open, (_ctx: &VopContext, _f: u32) -> ());
meta_notsup!(default_meta_close, (_ctx: &VopContext, _f: u32) -> ());
meta_notsup!(default_meta_getattr, (_ctx: &VopContext, _a: *mut VAttr) -> ());
meta_notsup!(default_meta_setattr, (_ctx: &VopContext, _a: *const VAttr) -> ());
meta_notsup!(default_meta_access, (_ctx: &VopContext, _m: u32, _c: *const VfsCred) -> ());
meta_notsup!(default_meta_readlink, (_ctx: &VopContext, _b: *mut u8, _bl: usize, _c: *const VfsCred) -> usize);
meta_notsup!(default_meta_truncate, (_ctx: &VopContext, _s: u64) -> ());

unsafe fn default_meta_inactive(_ctx: &VopContext) {}

unsafe fn default_meta_lookup_ci(
    ctx: &VopContext,
    name: *const u8,
    name_len: u8,
) -> VfsResult<VnodeHandle> {
    unsafe { super::casefold::readdir_casefold_scan(ctx, name, name_len) }
}

/// Default MetaOps — all ops return `NotSupported` except `inactive` (no-op)
/// and `lookup_ci` (delegates to exact lookup).
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
        unsafe fn $name($($arg: $t),*) -> VfsResult<$ret> {
            $(let _ = $arg;)*
            Err(VfsError::NotSupported)
        }
    };
}

data_notsup!(default_data_read, (_ctx: &VopDataContext, _o: u64, _d: *mut u8, _l: u64) -> u64);
data_notsup!(default_data_write, (_ctx: &VopDataContext, _o: u64, _s: *const u8, _l: u64) -> u64);
data_notsup!(default_data_fsync, (_ctx: &VopDataContext) -> ());

unsafe fn default_data_readdir(
    _ctx: &VopDataContext,
    _c: *mut u64,
    _e: ReaddirEmit<'_>,
) -> VfsResult<()> {
    Err(VfsError::NotSupported)
}

data_notsup!(default_data_getxattr, (_ctx: &VopDataContext, _n: *const u8, _nl: u8, _b: *mut u8, _bl: usize) -> usize);
data_notsup!(default_data_setxattr, (_ctx: &VopDataContext, _n: *const u8, _nl: u8, _v: *const u8, _vl: usize, _f: u32) -> ());
data_notsup!(default_data_listxattr, (_ctx: &VopDataContext, _b: *mut u8, _bl: usize) -> usize);
data_notsup!(default_data_removexattr, (_ctx: &VopDataContext, _n: *const u8, _nl: u8) -> ());
data_notsup!(default_data_ioctl, (_ctx: &VopDataContext, _c: u32, _a: u64, _r: *mut TronaMsg) -> ());
data_notsup!(default_data_mmap_get_page, (_ctx: &VopDataContext, _p: u64, _w: bool, _o: *mut u64) -> ());
data_notsup!(default_data_statfs, (_ctx: &VopDataContext, _o: *mut VStatfs) -> ());

/// Default DataOps — all ops return `NotSupported`.
pub(crate) static DATA_OPS_DEFAULT: VopDataOps = VopDataOps {
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

/// Default VopVector with both halves defaulted.
pub(crate) static VOPS_DEFAULT: VopVector = VopVector {
    meta: META_OPS_DEFAULT,
    data: DATA_OPS_DEFAULT,
};
