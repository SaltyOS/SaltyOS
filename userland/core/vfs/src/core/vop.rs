// SPDX-License-Identifier: GPL-2.0-only
//
//! `VopVector` — per-filesystem vnode operation table.
//!
//! Split into two halves:
//!
//! * [`VopMetaOps`] — owner-thread-only metadata operations
//!   (lookup, create, unlink, getattr, ...). Receive
//!   `&mut OwnerVopCtx<'_>`.
//! * [`VopDataOps`] — async-capable data operations (read,
//!   write, readdir, fsync, xattr, ...). Receive
//!   `&VopDataCtx`.
//!
//! Backends provide one static `VopVector` and install it on every
//! vnode they allocate via `Vnode.ops`. The dispatch layer knows
//! which half to use.
//!
//! Mount-level operations live in [`VfsOps`]; backends pin a
//! `VfsOps *` on `Mount.vfsops` at mount time.

use super::cred::VfsCred;
use super::error::VfsError;
use super::file::{VAttr, VStatfs};
use super::outcome::{Ready, VopOutcome};
use super::vnode::VnodeHandle;
use super::vop_context::{OwnerMountCtx, OwnerVopCtx, VopDataCtx};

// ---------------------------------------------------------------------------
// Ioctl reply — personality-neutral payload buffer
// ---------------------------------------------------------------------------

/// Personality-neutral output of `VopDataOps::ioctl`.
///
/// The vop fills `words[..word_count]` with raw u64 payload words
/// and sets `byte_count` to the byte length of the payload (for
/// sub-u64 structs like `struct winsize`). The personality layer
/// then projects the buffer onto its wire shape:
///
/// - POSIX `VFS_IOCTL` reply: regs[0..word_count] echoed verbatim.
/// - NT `NtDeviceIoControlFile` reply: payload bytes copied into
///   the caller's OutputBuffer; `byte_count` lands in
///   `IoStatusBlock.Information`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct IoctlReply {
    pub words: [u64; 28],
    pub word_count: u8,
    pub byte_count: u32,
}

impl IoctlReply {
    pub(crate) const EMPTY: Self = Self {
        words: [0; 28],
        word_count: 0,
        byte_count: 0,
    };
}

pub(crate) type IoctlResult = VopOutcome<IoctlReply>;

// ---------------------------------------------------------------------------
// Readdir emit callback
// ---------------------------------------------------------------------------

/// Callback invoked once per directory entry by
/// `VopDataOps::readdir`. Arguments: `(ino, name, name_len,
/// d_type, attr)`. Return `true` to continue, `false` to stop.
pub(crate) type ReaddirEmit<'a> = &'a mut dyn FnMut(u64, *const u8, u8, u8, &VAttr) -> bool;

// ---------------------------------------------------------------------------
// Xattr flags
// ---------------------------------------------------------------------------

/// Fail if the attribute already exists (`XATTR_CREATE`).
pub(crate) const XATTR_CREATE: u32 = 1 << 0;
/// Fail if the attribute does not already exist (`XATTR_REPLACE`).
pub(crate) const XATTR_REPLACE: u32 = 1 << 1;

// ---------------------------------------------------------------------------
// VopMetaOps — owner-thread-only metadata operations
// ---------------------------------------------------------------------------

/// Metadata operations called synchronously on the owner thread.
/// Each receives `&mut OwnerVopCtx<'_>` carrying the borrowed
/// `&mut VfsState` plus pre-resolved raw pointers to the target
/// vnode, its mount, and the backend-private data blobs.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopMetaOps {
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

    /// Create a FIFO inode at `name` under the parent directory.
    /// Mirrors `mkdir`/`symlink`: the resulting vnode's
    /// `VnodeKind` is `Fifo`, after which `open(O_RDONLY)` /
    /// `open(O_WRONLY)` route through the regular pipe machinery.
    /// Backends that do not support FIFO storage (devfs, procfs,
    /// sysctlfs) return `VfsError::NotSup`.
    pub(crate) mkfifo: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        name: *const u8,
        name_len: u8,
        mode: u32,
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

    /// `ctx` is the OLD parent directory ctx. `new_dir` is the
    /// new parent directory handle; backends resolve it via
    /// `ctx.resolve_vnode(new_dir)` when they need to read its
    /// fields. Cross-mount rename is rejected by the dispatcher
    /// before this entry fires, so both directories share the
    /// same owning mount.
    pub(crate) rename: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        old_name: *const u8,
        old_len: u8,
        new_dir: VnodeHandle,
        new_name: *const u8,
        new_len: u8,
    ) -> VopOutcome<()>,

    pub(crate) open: unsafe fn(ctx: &mut OwnerVopCtx<'_>, flags: u32) -> VopOutcome<()>,
    pub(crate) close: unsafe fn(ctx: &mut OwnerVopCtx<'_>, flags: u32) -> VopOutcome<()>,

    pub(crate) getattr: unsafe fn(ctx: &mut OwnerVopCtx<'_>, attr: *mut VAttr) -> VopOutcome<()>,
    pub(crate) setattr: unsafe fn(ctx: &mut OwnerVopCtx<'_>, attr: *const VAttr) -> VopOutcome<()>,
    pub(crate) access:
        unsafe fn(ctx: &mut OwnerVopCtx<'_>, mode: u32, cred: *const VfsCred) -> VopOutcome<()>,

    pub(crate) readlink: unsafe fn(
        ctx: &mut OwnerVopCtx<'_>,
        buf: *mut u8,
        buf_len: usize,
        cred: *const VfsCred,
    ) -> VopOutcome<usize>,

    pub(crate) truncate: unsafe fn(ctx: &mut OwnerVopCtx<'_>, new_size: u64) -> VopOutcome<()>,

    /// Cached file size in bytes. Owner-thread synchronous; returns
    /// the backend's most recently observed size without issuing any
    /// backend round-trip. Used by the file-backed mmap path
    /// (`MoBinding` install) to size the backing MO without parking
    /// on a `getattr` reply. Backends that have no notion of a file
    /// size (sysctlfs, procfs, devfs, pipefs, anon pipes) return 0,
    /// which the mmap path treats as "not mappable".
    pub(crate) data_size: unsafe fn(ctx: &mut OwnerVopCtx<'_>) -> u64,

    pub(crate) inactive: unsafe fn(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()>,
}

// ---------------------------------------------------------------------------
// VopDataOps — async-capable data operations
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopDataOps {
    pub(crate) read:
        unsafe fn(ctx: &VopDataCtx, offset: u64, dst: *mut u8, len: u64) -> VopOutcome<u64>,

    pub(crate) write:
        unsafe fn(ctx: &VopDataCtx, offset: u64, src: *const u8, len: u64) -> VopOutcome<u64>,

    /// Page-cache / MAP_SHARED writeback hook.
    ///
    /// The default is the normal `write` implementation, but backends may
    /// override it when the writeback path has stricter reactor rules than a
    /// user `write(2)`. In particular, this hook must not synchronously call
    /// back into mmsrv: mmsrv may be holding the originating `munmap` / `msync`
    /// request as a parked continuation while waiting for this writeback token.
    pub(crate) writeback:
        unsafe fn(ctx: &VopDataCtx, offset: u64, src: *const u8, len: u64) -> VopOutcome<u64>,

    pub(crate) fsync: unsafe fn(ctx: &VopDataCtx) -> VopOutcome<()>,

    pub(crate) readdir:
        unsafe fn(ctx: &VopDataCtx, cookie: *mut u64, emit: ReaddirEmit<'_>) -> VopOutcome<()>,

    pub(crate) getxattr: unsafe fn(
        ctx: &VopDataCtx,
        name: *const u8,
        name_len: u8,
        buf: *mut u8,
        buf_len: usize,
    ) -> VopOutcome<usize>,

    pub(crate) setxattr: unsafe fn(
        ctx: &VopDataCtx,
        name: *const u8,
        name_len: u8,
        value: *const u8,
        value_len: usize,
        flags: u32,
    ) -> VopOutcome<()>,

    pub(crate) listxattr:
        unsafe fn(ctx: &VopDataCtx, buf: *mut u8, buf_len: usize) -> VopOutcome<usize>,

    pub(crate) removexattr:
        unsafe fn(ctx: &VopDataCtx, name: *const u8, name_len: u8) -> VopOutcome<()>,

    pub(crate) ioctl: unsafe fn(ctx: &VopDataCtx, cmd: u32, arg: u64) -> IoctlResult,

    pub(crate) mmap_get_page: unsafe fn(
        ctx: &VopDataCtx,
        page_idx: u64,
        write: bool,
        out_cap: *mut u64,
    ) -> VopOutcome<()>,

    pub(crate) statfs: unsafe fn(ctx: &VopDataCtx, out: *mut VStatfs) -> VopOutcome<()>,
}

// ---------------------------------------------------------------------------
// VopVector — unified container
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VopVector {
    pub(crate) meta: VopMetaOps,
    pub(crate) data: VopDataOps,
}

// ---------------------------------------------------------------------------
// VfsOps — mount-level operations
// ---------------------------------------------------------------------------

/// Mount-level operations. One static `VfsOps` per backend
/// (saltyfs / ramfs / tmpfs / devfs / procfs / sysctlfs / pipefs).
/// Backends install `&VFS_OPS` on every `Mount` they construct
/// via `Mount.vfsops`.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VfsOps {
    /// Mount the filesystem. The backend allocates its
    /// per-mount data blob, attaches it to `mount.data`, and
    /// returns the root vnode handle.
    pub(crate) mount: unsafe fn(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError>,
    /// Unmount the filesystem. Backend tears down its session
    /// and frees per-mount data. Called only when the mount's
    /// `vnode_refcount` has reached zero.
    pub(crate) unmount: unsafe fn(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError>,
    /// Return the root vnode handle for this mount (cheap
    /// accessor; backends usually echo `mount.root`).
    pub(crate) root: unsafe fn(ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError>,
    /// Look up a vnode by inode number. Used at namei cross-mount
    /// boundaries and during mount finalization for the root
    /// vnode rebind.
    pub(crate) vget:
        unsafe fn(ctx: &mut OwnerMountCtx<'_>, ino: u64) -> Result<VnodeHandle, VfsError>,
    /// Filesystem-wide statistics (block counts, free blocks,
    /// inode counts).
    pub(crate) statfs:
        unsafe fn(ctx: &mut OwnerMountCtx<'_>, out: *mut VStatfs) -> Result<(), VfsError>,
    /// Flush dirty state to backing storage. Called by `sync(2)`
    /// and at unmount time before tearing down.
    pub(crate) sync: unsafe fn(ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError>,
}

// ---------------------------------------------------------------------------
// Default stubs — MetaOps
// ---------------------------------------------------------------------------

macro_rules! meta_notsup {
    ($name:ident, ($($arg:ident : $t:ty),* $(,)?) -> $ret:ty) => {
        unsafe fn $name($($arg: $t),*) -> VopOutcome<$ret> {
            $(let _ = $arg;)*
            Err(VfsError::NotSup)
        }
    };
}

meta_notsup!(default_meta_lookup, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8) -> VnodeHandle);
meta_notsup!(default_meta_create, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_mkdir, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_symlink, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _t: *const u8, _tl: u8, _c: *const VfsCred) -> VnodeHandle);
meta_notsup!(default_meta_mkfifo, (_ctx: &mut OwnerVopCtx<'_>, _n: *const u8, _nl: u8, _m: u32, _c: *const VfsCred) -> VnodeHandle);
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

unsafe fn default_meta_data_size(_ctx: &mut OwnerVopCtx<'_>) -> u64 {
    0
}

unsafe fn default_meta_inactive(ctx: &mut OwnerVopCtx<'_>) -> VopOutcome<()> {
    unsafe {
        crate::owner::pager_rpc::release_mo_binding_for_vnode(ctx.state, ctx.handle);
    }
    Ok(Ready(()))
}

unsafe fn default_meta_lookup_ci(
    ctx: &mut OwnerVopCtx<'_>,
    name: *const u8,
    name_len: u8,
) -> VopOutcome<VnodeHandle> {
    // Default case-insensitive lookup falls through to the case-
    // sensitive variant. Filesystems that want true case-folding
    // (HFS+ / NTFS / ExFAT compatibility) override with their own
    // implementation.
    unsafe { default_meta_lookup(ctx, name, name_len) }
}

pub(crate) static META_OPS_DEFAULT: VopMetaOps = VopMetaOps {
    lookup: default_meta_lookup,
    lookup_ci: default_meta_lookup_ci,
    create: default_meta_create,
    mkdir: default_meta_mkdir,
    symlink: default_meta_symlink,
    mkfifo: default_meta_mkfifo,
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
    data_size: default_meta_data_size,
    inactive: default_meta_inactive,
};

// ---------------------------------------------------------------------------
// Default stubs — DataOps
// ---------------------------------------------------------------------------

macro_rules! data_notsup {
    ($name:ident, ($($arg:ident : $t:ty),* $(,)?) -> $ret:ty) => {
        unsafe fn $name($($arg: $t),*) -> VopOutcome<$ret> {
            $(let _ = $arg;)*
            Err(VfsError::NotSup)
        }
    };
}

data_notsup!(default_data_read, (_ctx: &VopDataCtx, _o: u64, _d: *mut u8, _l: u64) -> u64);
data_notsup!(default_data_write, (_ctx: &VopDataCtx, _o: u64, _s: *const u8, _l: u64) -> u64);
data_notsup!(default_data_fsync, (_ctx: &VopDataCtx) -> ());

unsafe fn default_data_readdir(
    _ctx: &VopDataCtx,
    _c: *mut u64,
    _e: ReaddirEmit<'_>,
) -> VopOutcome<()> {
    Err(VfsError::NotSup)
}

data_notsup!(default_data_getxattr, (_ctx: &VopDataCtx, _n: *const u8, _nl: u8, _b: *mut u8, _bl: usize) -> usize);
data_notsup!(default_data_setxattr, (_ctx: &VopDataCtx, _n: *const u8, _nl: u8, _v: *const u8, _vl: usize, _f: u32) -> ());
data_notsup!(default_data_listxattr, (_ctx: &VopDataCtx, _b: *mut u8, _bl: usize) -> usize);
data_notsup!(default_data_removexattr, (_ctx: &VopDataCtx, _n: *const u8, _nl: u8) -> ());
data_notsup!(default_data_ioctl, (_ctx: &VopDataCtx, _c: u32, _a: u64) -> IoctlReply);
data_notsup!(default_data_mmap_get_page, (_ctx: &VopDataCtx, _p: u64, _w: bool, _o: *mut u64) -> ());
data_notsup!(default_data_statfs, (_ctx: &VopDataCtx, _o: *mut VStatfs) -> ());

pub(crate) static DATA_OPS_DEFAULT: VopDataOps = VopDataOps {
    read: default_data_read,
    write: default_data_write,
    writeback: default_data_write,
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

// ---------------------------------------------------------------------------
// Default stubs — VfsOps
// ---------------------------------------------------------------------------

unsafe fn default_vfs_mount(_ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    Err(VfsError::NotSup)
}
unsafe fn default_vfs_unmount(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Err(VfsError::NotSup)
}
unsafe fn default_vfs_root(_ctx: &mut OwnerMountCtx<'_>) -> Result<VnodeHandle, VfsError> {
    Err(VfsError::NotSup)
}
unsafe fn default_vfs_vget(
    _ctx: &mut OwnerMountCtx<'_>,
    _ino: u64,
) -> Result<VnodeHandle, VfsError> {
    Err(VfsError::NotSup)
}
unsafe fn default_vfs_statfs(
    _ctx: &mut OwnerMountCtx<'_>,
    _out: *mut VStatfs,
) -> Result<(), VfsError> {
    Err(VfsError::NotSup)
}
unsafe fn default_vfs_sync(_ctx: &mut OwnerMountCtx<'_>) -> Result<(), VfsError> {
    Err(VfsError::NotSup)
}

pub(crate) static VFS_OPS_DEFAULT: VfsOps = VfsOps {
    mount: default_vfs_mount,
    unmount: default_vfs_unmount,
    root: default_vfs_root,
    vget: default_vfs_vget,
    statfs: default_vfs_statfs,
    sync: default_vfs_sync,
};
