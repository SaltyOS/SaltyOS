// SPDX-License-Identifier: GPL-2.0-only
//! tmpfs — synchronous in-memory filesystem.
//!
//! Each mounted tmpfs instance owns three arenas: per-vnode metadata
//! (`TmpfsVnodeState`), an intrusive directory-entry list
//! (`TmpfsDirEntry`), and a fixed-cap symlink target store
//! (`TmpfsSymlinkBuf`). Regular-file content lives in a retyped
//! `MemoryObject` mapped into vfs's own VSpace so the same cap can be
//! transferred to mmsrv for direct client mappings.

use trona_posix::consts::{DT_DIR, DT_LNK, DT_REG, S_IFDIR, S_IFLNK, S_IFMT, S_IFREG};
use trona_runtime::core::server_consts::MMAP_BACKING_TMPFS;
use uapi::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::server::mo;
use crate::server::types::ClientHandle;
use crate::vfs_core::cached_ref::CachedRef;
use crate::vfs_core::casefold;
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::mount::{
    MNT_CASEFOLD, MNT_NOATIME, MNT_RDONLY, MOUNT_BACKEND_TMPFS, Mount, MountHandle,
};
use crate::vfs_core::mount_options;
use crate::vfs_core::vfsops::{BackingResolution, StatfsSnapshot, VfsOps};
use crate::vfs_core::vnode::{
    VN_DOOMED, VNODE_BACKEND_TMPFS, VT_DIR, VT_LNK, VT_REG, Vnode, VnodeHandle,
};
use crate::vfs_core::vops::{VfsOpResult, VfsResult, VnodeOps};

pub(crate) const TMPFS_NAME_MAX: usize = 255;
pub(crate) const TMPFS_SYMLINK_MAX: usize = 1024;
const TMPFS_PAGE_BYTES: u64 = 4096;
const TMPFS_BLOCK_BYTES: u64 = TMPFS_PAGE_BYTES;

pub(crate) type TmpfsMountHandle = Handle<TmpfsMountData>;
pub(crate) type TmpfsNodeHandle = Handle<TmpfsVnodeState>;
pub(crate) type TmpfsDirEntryHandle = Handle<TmpfsDirEntry>;
pub(crate) type TmpfsSymlinkHandle = Handle<TmpfsSymlinkBuf>;

#[repr(C)]
pub(crate) struct TmpfsMountData {
    pub(crate) owner_mount: MountHandle,
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) root_vnode: VnodeHandle,
    pub(crate) next_inode: u64,
    /// Quota: max bytes (page-aligned MO capacity sum). Zero = unlimited.
    pub(crate) max_bytes: u64,
    /// Quota: max inodes. Zero = unlimited.
    pub(crate) max_inodes: u64,
    /// Live page-aligned byte capacity sum across regular files.
    pub(crate) accounted_bytes: u64,
    /// Live `TmpfsVnodeState` count.
    pub(crate) used_inodes: u64,
    /// Cached `mount.flags & MNT_CASEFOLD` so vops can avoid touching
    /// the mount entry on every lookup.
    pub(crate) casefold: bool,
    pub(crate) _pad0: [u8; 7],
}

impl TmpfsMountData {
    pub(crate) const fn zeroed() -> Self {
        Self {
            owner_mount: MountHandle::INVALID,
            fs_instance_id: FsInstanceId::INVALID,
            root_vnode: VnodeHandle::INVALID,
            next_inode: 0,
            max_bytes: 0,
            max_inodes: 0,
            accounted_bytes: 0,
            used_inodes: 0,
            casefold: false,
            _pad0: [0; 7],
        }
    }
}

#[repr(C)]
pub(crate) struct TmpfsVnodeState {
    pub(crate) owner_mount: MountHandle,
    pub(crate) vnode: VnodeHandle,
    pub(crate) parent: TmpfsNodeHandle,
    pub(crate) kind: u8,
    pub(crate) name_len: u8,
    _pad0: [u8; 6],
    pub(crate) name: [u8; TMPFS_NAME_MAX],
    pub(crate) _name_pad: [u8; 1],

    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) nlink: u32,
    pub(crate) atime_ns: u64,
    pub(crate) mtime_ns: u64,
    pub(crate) ctime_ns: u64,
    pub(crate) size: u64,

    /// VT_REG: lazy MemoryObject backing.
    /// All four fields are zero until the first `write_regular` /
    /// `truncate(>0)` call lands. mmap (RESOLVE_BACKING) also forces a
    /// 1-page lazy allocation so the cap is non-zero before transfer.
    pub(crate) mo_cap: u64,
    pub(crate) mo_handle: u64,
    pub(crate) mo_capacity: u64,
    pub(crate) local_mapping: *mut u8,

    /// VT_DIR: head of intrusive directory entry list and live count.
    pub(crate) children_head: TmpfsDirEntryHandle,
    pub(crate) children_count: u32,
    pub(crate) _children_pad: [u8; 4],

    /// VT_LNK: target buffer handle.
    pub(crate) symlink: TmpfsSymlinkHandle,

    /// Number of outstanding `MMAP_BACKING_TMPFS` cap exports to mmsrv.
    /// `tmpfs_resolve_backing` bumps this once per mmap; mmsrv sends
    /// `VFS_BACKEND_RELEASE_TMPFS` when its last region for this vnode
    /// drops, which decrements the counter. The arena entry + MO must
    /// outlive both `open_count` *and* this counter so mmsrv can hold a
    /// live cap on a `MAP_SHARED` mapping after `unlink + close`.
    pub(crate) mmap_export_refs: u32,
    /// Set when the generic vnode reclaim path has fired but
    /// `mmap_export_refs > 0` kept the storage alive. The next
    /// release notification that brings the counter to zero performs
    /// the deferred free.
    pub(crate) pending_release: u8,
    pub(crate) _release_pad: [u8; 3],
    /// Persistent inode value stamped at allocation time. After
    /// `tmpfs_reclaim_vnode` clears `vnode`, the in-tree `Vnode.id`
    /// is no longer reachable; mmsrv's `VFS_BACKEND_RELEASE_TMPFS`
    /// notification carries `(fs_instance_id, ino)` and we match on
    /// this field to find the deferred entry.
    pub(crate) mmap_id: u64,
}

impl TmpfsVnodeState {
    pub(crate) const fn zeroed() -> Self {
        Self {
            owner_mount: MountHandle::INVALID,
            vnode: VnodeHandle::INVALID,
            parent: TmpfsNodeHandle::INVALID,
            kind: 0,
            name_len: 0,
            _pad0: [0; 6],
            name: [0; TMPFS_NAME_MAX],
            _name_pad: [0; 1],
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 0,
            atime_ns: 0,
            mtime_ns: 0,
            ctime_ns: 0,
            size: 0,
            mo_cap: 0,
            mo_handle: 0,
            mo_capacity: 0,
            local_mapping: core::ptr::null_mut(),
            children_head: TmpfsDirEntryHandle::INVALID,
            children_count: 0,
            _children_pad: [0; 4],
            symlink: TmpfsSymlinkHandle::INVALID,
            mmap_export_refs: 0,
            pending_release: 0,
            _release_pad: [0; 3],
            mmap_id: 0,
        }
    }

    #[inline]
    pub(crate) fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

#[repr(C)]
pub(crate) struct TmpfsDirEntry {
    pub(crate) parent: TmpfsNodeHandle,
    pub(crate) child: TmpfsNodeHandle,
    pub(crate) next: TmpfsDirEntryHandle,
    pub(crate) name_len: u8,
    _pad0: [u8; 7],
    pub(crate) name: [u8; TMPFS_NAME_MAX],
    pub(crate) _name_pad: [u8; 1],
}

impl TmpfsDirEntry {
    pub(crate) const fn zeroed() -> Self {
        Self {
            parent: TmpfsNodeHandle::INVALID,
            child: TmpfsNodeHandle::INVALID,
            next: TmpfsDirEntryHandle::INVALID,
            name_len: 0,
            _pad0: [0; 7],
            name: [0; TMPFS_NAME_MAX],
            _name_pad: [0; 1],
        }
    }

    #[inline]
    pub(crate) fn name_slice(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

#[repr(C)]
pub(crate) struct TmpfsSymlinkBuf {
    pub(crate) target_len: u16,
    _pad0: [u8; 6],
    pub(crate) target: [u8; TMPFS_SYMLINK_MAX],
}

impl TmpfsSymlinkBuf {
    pub(crate) const fn zeroed() -> Self {
        Self {
            target_len: 0,
            _pad0: [0; 6],
            target: [0; TMPFS_SYMLINK_MAX],
        }
    }

    #[inline]
    pub(crate) fn target_slice(&self) -> &[u8] {
        &self.target[..self.target_len as usize]
    }
}

static TMPFS_VFSOPS: VfsOps = VfsOps {
    statfs: Some(tmpfs_statfs),
    sync: None,
    remount: Some(tmpfs_remount),
    resolve_backing: Some(tmpfs_resolve_backing),
    reclaim_vnode: Some(tmpfs_reclaim_vnode),
};

static TMPFS_VOPS: VnodeOps = VnodeOps {
    lookup_child: Some(lookup_child),
    build_path: Some(build_path_for_vnode),
    ensure_symlink_target: Some(ensure_symlink_target),
    readlink_inline: Some(readlink_inline),
    read_regular: Some(read_regular_vop),
    write_regular: Some(write_regular_vop),
    create_regular_child: Some(create_regular_child),
    mkdir_child: Some(mkdir_child),
    symlink_child: Some(symlink_child),
    remove_child: Some(remove_child),
    rename_child: Some(rename_child_vop),
    link_vnode_into: Some(link_vnode_into_vop),
    set_mode: Some(set_mode_vnode),
    set_owner: Some(set_owner_vnode),
    set_times: Some(set_times_vnode),
    truncate: Some(truncate_vnode),
    validate_open_regular: Some(validate_open_regular_vop),
    readdir_dir: Some(readdir_dir_vop),
    supports_pager_backing: None,
};

#[inline]
pub(crate) fn mount_is_tmpfs(mount: &Mount) -> bool {
    mount.backend_kind == MOUNT_BACKEND_TMPFS
}

#[inline]
pub(crate) fn tmpfs_vfsops() -> *const () {
    &raw const TMPFS_VFSOPS as *const VfsOps as *const ()
}

#[inline]
pub(crate) fn tmpfs_vops() -> *const () {
    &raw const TMPFS_VOPS as *const VnodeOps as *const ()
}

fn page_align_up(bytes: u64) -> u64 {
    (bytes + (TMPFS_PAGE_BYTES - 1)) & !(TMPFS_PAGE_BYTES - 1)
}

fn parse_size_with_suffix(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let (digits, multiplier) = match *value.last().unwrap() {
        b'k' | b'K' => (&value[..value.len() - 1], 1024u64),
        b'm' | b'M' => (&value[..value.len() - 1], 1024 * 1024),
        b'g' | b'G' => (&value[..value.len() - 1], 1024 * 1024 * 1024),
        _ => (value, 1u64),
    };
    let mut acc: u64 = 0;
    for &b in digits {
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    acc.checked_mul(multiplier)
}

fn parse_decimal(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in value {
        if !(b'0'..=b'9').contains(&b) {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

#[inline]
fn name_eq(a: &[u8], b: &[u8], folded: bool) -> bool {
    casefold::name_eq(a, b, folded)
}

fn find_mount_data_handle(state: &VfsState, owner_mount: MountHandle) -> Option<TmpfsMountHandle> {
    let mut found = TmpfsMountHandle::INVALID;
    state.tmpfs_mounts.for_each_active(|handle, data| {
        if data.owner_mount == owner_mount {
            found = handle;
            return false;
        }
        true
    });
    found.is_valid().then_some(found)
}

fn mount_data_for_vnode(state: &VfsState, vnode: VnodeHandle) -> Option<TmpfsMountHandle> {
    let mount = state.vnodes.get(vnode)?.mount.handle;
    if !mount.is_valid() {
        return None;
    }
    find_mount_data_handle(state, mount)
}

fn vnode_is_tmpfs(state: &VfsState, vnode: VnodeHandle) -> bool {
    state
        .vnodes
        .get(vnode)
        .map(|vn| vn.backend_kind == VNODE_BACKEND_TMPFS)
        .unwrap_or(false)
}

fn find_node_handle_by_vnode(state: &VfsState, vnode: VnodeHandle) -> Option<TmpfsNodeHandle> {
    let vnode_ref = state.vnodes.get(vnode)?;
    let handle = vnode_ref.backend_ref::<TmpfsVnodeState>();
    if !handle.is_valid() {
        return None;
    }
    state
        .tmpfs_nodes
        .get(handle)
        .filter(|node| node.vnode == vnode)
        .map(|_| handle)
}

fn casefold_for_mount(state: &VfsState, mount: MountHandle) -> bool {
    state
        .mounts
        .get(mount)
        .map(|m| (m.flags & MNT_CASEFOLD) != 0)
        .unwrap_or(false)
}

fn now_ns() -> u64 {
    use trona_kernel::syscall;
    syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as u64, 0, 0, 0, 0, 0).value
}

fn next_inode(state: &mut VfsState, mount: MountHandle) -> Option<u64> {
    let data_h = find_mount_data_handle(state, mount)?;
    let data = state.tmpfs_mounts.get_mut(data_h)?;
    let inode = data.next_inode;
    data.next_inode = data.next_inode.checked_add(1).unwrap_or(2);
    Some(inode)
}

pub(crate) fn alloc_inode(state: &mut VfsState, owner_mount: MountHandle) -> Option<u64> {
    next_inode(state, owner_mount)
}

fn try_account_inode(state: &mut VfsState, mount: MountHandle) -> Result<TmpfsMountHandle, u64> {
    let data_h = find_mount_data_handle(state, mount).ok_or(TRONA_INVALID_OPERATION)?;
    let data = state
        .tmpfs_mounts
        .get_mut(data_h)
        .ok_or(TRONA_INVALID_OPERATION)?;
    if data.max_inodes != 0 && data.used_inodes >= data.max_inodes {
        return Err(TRONA_NO_SPACE);
    }
    data.used_inodes = data.used_inodes.saturating_add(1);
    Ok(data_h)
}

fn release_inode_account(state: &mut VfsState, mount: MountHandle) {
    if let Some(data_h) = find_mount_data_handle(state, mount) {
        if let Some(data) = state.tmpfs_mounts.get_mut(data_h) {
            data.used_inodes = data.used_inodes.saturating_sub(1);
        }
    }
}

fn try_account_bytes(state: &mut VfsState, mount: MountHandle, delta: u64) -> Result<(), u64> {
    if delta == 0 {
        return Ok(());
    }
    let data_h = find_mount_data_handle(state, mount).ok_or(TRONA_INVALID_OPERATION)?;
    let data = state
        .tmpfs_mounts
        .get_mut(data_h)
        .ok_or(TRONA_INVALID_OPERATION)?;
    if data.max_bytes != 0 && data.accounted_bytes.saturating_add(delta) > data.max_bytes {
        return Err(TRONA_NO_SPACE);
    }
    data.accounted_bytes = data.accounted_bytes.saturating_add(delta);
    Ok(())
}

fn release_bytes_account(state: &mut VfsState, mount: MountHandle, bytes: u64) {
    if bytes == 0 {
        return;
    }
    if let Some(data_h) = find_mount_data_handle(state, mount) {
        if let Some(data) = state.tmpfs_mounts.get_mut(data_h) {
            data.accounted_bytes = data.accounted_bytes.saturating_sub(bytes);
        }
    }
}

/// Returns `None` for fields the caller did not mention so callers can
/// differentiate "leave as-is" from "set to unlimited". `casefold`
/// stays a bool because flag-level merging happens upstream and the
/// only signal worth forwarding is "did the opt set it".
fn parse_mount_opts(opts: &[u8]) -> ParsedTmpfsOpts {
    let mut parsed = ParsedTmpfsOpts {
        max_bytes: None,
        max_inodes: None,
        casefold: None,
    };
    mount_options::for_each_token(opts, |token| {
        if token == b"nocase" || token == b"casefold" {
            parsed.casefold = Some(true);
            return;
        }
        if let Some((key, value)) = mount_options::split_kv(token) {
            if key == b"size" {
                if let Some(v) = parse_size_with_suffix(value) {
                    parsed.max_bytes = Some(page_align_up(v));
                }
            } else if key == b"nr_inodes" {
                if let Some(v) = parse_decimal(value) {
                    parsed.max_inodes = Some(v);
                }
            }
        }
    });
    parsed
}

struct ParsedTmpfsOpts {
    max_bytes: Option<u64>,
    max_inodes: Option<u64>,
    casefold: Option<bool>,
}

pub(crate) fn alloc_mount(
    state: &mut VfsState,
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Option<MountHandle> {
    let parsed = parse_mount_opts(opts);
    let casefold = parsed.casefold.unwrap_or(false) || (flags & MNT_CASEFOLD) != 0;
    let max_bytes = parsed.max_bytes.unwrap_or(0);
    let max_inodes = parsed.max_inodes.unwrap_or(0);

    let root_vh = state.vnodes.alloc()?;
    let mh = state.mounts.alloc()?;
    let data_h = state.tmpfs_mounts.alloc()?;
    let root_node_h = state.tmpfs_nodes.alloc()?;
    let fs_id = state.alloc_fs_instance_id();

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
        vnode.backend_kind = VNODE_BACKEND_TMPFS;
        vnode.id = 1;
        vnode.ops = tmpfs_vops();
        vnode.mode = (S_IFDIR as u32) | 0o1777;
        vnode.nlink = 2;
        vnode.set_backend_ref(root_node_h);
    }
    state.cache_vnode_key(root_vh);

    {
        let mount = state.mounts.get_mut(mh)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            flags | if casefold { MNT_CASEFOLD } else { 0 },
            fs_id,
            root_vh,
            b"tmpfs",
            mount_path,
        );
        mount.backend_kind = MOUNT_BACKEND_TMPFS;
        mount.vfsops = tmpfs_vfsops();
        mount.vops = tmpfs_vops();
    }

    let now = now_ns();
    let data_ptr = {
        let data = state.tmpfs_mounts.get_mut(data_h)?;
        *data = TmpfsMountData {
            owner_mount: mh,
            fs_instance_id: fs_id,
            root_vnode: root_vh,
            next_inode: 2,
            max_bytes,
            max_inodes,
            accounted_bytes: 0,
            used_inodes: 1,
            casefold,
            _pad0: [0; 7],
        };
        data as *mut TmpfsMountData as *mut u8
    };

    {
        let node = state.tmpfs_nodes.get_mut(root_node_h)?;
        *node = TmpfsVnodeState::zeroed();
        node.owner_mount = mh;
        node.vnode = root_vh;
        node.kind = VT_DIR;
        node.mode = (S_IFDIR as u32) | 0o1777;
        node.nlink = 2;
        node.atime_ns = now;
        node.mtime_ns = now;
        node.ctime_ns = now;
        node.mmap_id = 1;
    }

    {
        let mount = state.mounts.get_mut(mh)?;
        mount.data = data_ptr;
    }
    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        vnode.mount = CachedRef::new(fs_id, mh);
        vnode.atime_ns = now;
        vnode.mtime_ns = now;
    }

    Some(mh)
}

/// Batch size for the multi-pass cleanup that releases every per-mount
/// node and dir entry. The arena does not expose a "release while
/// iterating" cursor, so we collect a chunk of handles, release them
/// outside the iterator, and re-scan until no work remains. Picking 64
/// keeps the temporary on the kernel stack tiny while bounding total
/// passes to `arena_size / 64`.
const TMPFS_CLEANUP_BATCH: usize = 64;

pub(crate) fn release_mount(state: &mut VfsState, owner_mount: MountHandle) -> bool {
    loop {
        let mut entries = [TmpfsDirEntryHandle::INVALID; TMPFS_CLEANUP_BATCH];
        let mut count = 0usize;
        state.tmpfs_dir_entries.for_each_active(|handle, entry| {
            let parent = entry.parent;
            let belongs = state
                .tmpfs_nodes
                .get(parent)
                .map(|n| n.owner_mount == owner_mount)
                .unwrap_or(false);
            if belongs {
                entries[count] = handle;
                count += 1;
                if count == entries.len() {
                    return false;
                }
            }
            true
        });
        if count == 0 {
            break;
        }
        for idx in 0..count {
            let _ = state.tmpfs_dir_entries.release(entries[idx]);
        }
    }

    loop {
        let mut nodes = [TmpfsNodeHandle::INVALID; TMPFS_CLEANUP_BATCH];
        let mut count = 0usize;
        state.tmpfs_nodes.for_each_active(|handle, node| {
            if node.owner_mount == owner_mount {
                nodes[count] = handle;
                count += 1;
                if count == nodes.len() {
                    return false;
                }
            }
            true
        });
        if count == 0 {
            break;
        }
        for idx in 0..count {
            let h = nodes[idx];
            release_node_storage(state, h);
            let symlink = state
                .tmpfs_nodes
                .get(h)
                .map(|n| n.symlink)
                .unwrap_or(TmpfsSymlinkHandle::INVALID);
            if symlink.is_valid() {
                let _ = state.tmpfs_symlinks.release(symlink);
            }
            let _ = state.tmpfs_nodes.release(h);
        }
    }

    let Some(data_h) = find_mount_data_handle(state, owner_mount) else {
        return true;
    };
    state.tmpfs_mounts.release(data_h)
}

fn release_node_storage(state: &mut VfsState, node_h: TmpfsNodeHandle) {
    let (mount, mo_cap, mo_handle, capacity, mapping) = match state.tmpfs_nodes.get(node_h) {
        Some(node) => (
            node.owner_mount,
            node.mo_cap,
            node.mo_handle,
            node.mo_capacity,
            node.local_mapping,
        ),
        None => return,
    };
    if !mapping.is_null() && capacity != 0 {
        unsafe {
            mo::unmap_local(mapping, capacity / TMPFS_PAGE_BYTES);
        }
    }
    if mo_cap != 0 {
        let _ = unsafe { mo::free(mo_cap, mo_handle) };
    }
    if capacity != 0 {
        release_bytes_account(state, mount, capacity);
    }
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        node.local_mapping = core::ptr::null_mut();
        node.mo_cap = 0;
        node.mo_handle = 0;
        node.mo_capacity = 0;
        node.size = 0;
    }
}

/// Tear down the tmpfs-side state for a vnode the generic reclaim path
/// has decided is unreachable. Called from `reclaim_bootstrap_vnode`
/// after it confirms `nlink == 0`, `open_count == 0`, and no pinned
/// references remain. Releases the per-file MO, byte/inode accounting,
/// the symlink buffer (if any), and the arena entry. The caller still
/// owns the `Vnode` slot release.
pub(crate) fn release_node_for_vnode(state: &mut VfsState, vnode: VnodeHandle) {
    if !vnode_is_tmpfs(state, vnode) {
        return;
    }
    let Some(node_h) = find_node_handle_by_vnode(state, vnode) else {
        return;
    };
    let (mount, symlink_h) = match state.tmpfs_nodes.get(node_h) {
        Some(node) => (node.owner_mount, node.symlink),
        None => return,
    };
    release_node_storage(state, node_h);
    if symlink_h.is_valid() {
        let _ = state.tmpfs_symlinks.release(symlink_h);
    }
    let _ = state.tmpfs_nodes.release(node_h);
    if let Some(vn) = state.vnodes.get_mut(vnode) {
        vn.clear_backend_ref();
    }
    release_inode_account(state, mount);
}

/// Round `pages` up to the next power of two so MO grow steps line up
/// with rsrcsrv's `size_bits` allocator and amortise resize cost.
fn pow2_pages(pages: u64) -> u64 {
    if pages <= 1 {
        return 1;
    }
    let mut sb = 0u32;
    while (1u64 << sb) < pages {
        sb += 1;
    }
    1u64 << sb
}

/// Grow the per-vnode MO so that at least `needed` bytes of storage
/// are addressable through `node.local_mapping`. Preserves the MO cap
/// across grows so any client `mmap` mapping stays attached to the
/// same backing object.
fn ensure_mo_capacity(
    state: &mut VfsState,
    node_h: TmpfsNodeHandle,
    needed: u64,
) -> Result<(), u64> {
    let (mount, old_cap, old_handle, old_capacity, old_mapping) = {
        let node = state
            .tmpfs_nodes
            .get(node_h)
            .ok_or(TRONA_INVALID_OPERATION)?;
        (
            node.owner_mount,
            node.mo_cap,
            node.mo_handle,
            node.mo_capacity,
            node.local_mapping,
        )
    };
    let target_bytes = page_align_up(needed.max(TMPFS_PAGE_BYTES));
    if target_bytes <= old_capacity {
        return Ok(());
    }
    let target_pages = pow2_pages(target_bytes / TMPFS_PAGE_BYTES);
    let new_capacity = target_pages * TMPFS_PAGE_BYTES;
    let delta = new_capacity - old_capacity;
    try_account_bytes(state, mount, delta)?;

    if old_cap == 0 {
        let alloc_result = unsafe { mo::alloc(target_pages) };
        let (new_cap, new_handle, actual_pages) = match alloc_result {
            Ok(triple) => triple,
            Err(err) => {
                release_bytes_account(state, mount, delta);
                return Err(err);
            }
        };
        let map_result = unsafe { mo::map_local(new_cap, actual_pages, true) };
        let new_mapping = match map_result {
            Ok(ptr) => ptr,
            Err(err) => {
                let _ = unsafe { mo::free(new_cap, new_handle) };
                release_bytes_account(state, mount, delta);
                return Err(err);
            }
        };
        if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
            node.mo_cap = new_cap;
            node.mo_handle = new_handle;
            node.mo_capacity = actual_pages * TMPFS_PAGE_BYTES;
            node.local_mapping = new_mapping;
        }
        return Ok(());
    }

    let old_pages = old_capacity / TMPFS_PAGE_BYTES;
    if let Err(err) = unsafe { mo::resize(old_cap, old_pages, target_pages) } {
        release_bytes_account(state, mount, delta);
        return Err(err);
    }

    let new_mapping = match unsafe { mo::map_local(old_cap, target_pages, true) } {
        Ok(ptr) => ptr,
        Err(err) => {
            release_bytes_account(state, mount, delta);
            let _ = unsafe { mo::resize(old_cap, target_pages, old_pages) };
            return Err(err);
        }
    };

    if !old_mapping.is_null() && old_capacity != 0 {
        unsafe {
            mo::unmap_local(old_mapping, old_capacity / TMPFS_PAGE_BYTES);
        }
    }

    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        node.mo_capacity = new_capacity;
        node.local_mapping = new_mapping;
        let _ = old_handle;
    }
    Ok(())
}

/// `VfsOps::resolve_backing` callback. Forces a one-page lazy allocation
/// when the file has no MO yet so the cap handed to the requester is
/// always non-zero — there's no path to upgrade `mo_cap == 0` once the
/// reply has left the server. Bumps `mmap_export_refs` so reclaim
/// knows mmsrv still holds a copy of the cap.
fn tmpfs_resolve_backing(
    state: &mut VfsState,
    vnode: VnodeHandle,
) -> Result<Option<BackingResolution>, u64> {
    let Some(node_h) = find_node_handle_by_vnode(state, vnode) else {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] mmap backing failed component=tmpfs op=resolve_backing stage=node_lookup vnode=");
            _lb.dec(vnode.slot() as u64);
            _lb.str(b":");
            _lb.dec(vnode.epoch() as u64);
            _lb.str(b" label=");
            _lb.hex(TRONA_NOT_FOUND);
            _lb.str(b"\n");
        });
        return Err(TRONA_NOT_FOUND);
    };
    let kind = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| n.kind)
        .ok_or_else(|| {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] mmap backing failed component=tmpfs op=resolve_backing stage=node_state vnode=");
                _lb.dec(vnode.slot() as u64);
                _lb.str(b":");
                _lb.dec(vnode.epoch() as u64);
                _lb.str(b" label=");
                _lb.hex(TRONA_INVALID_OPERATION);
                _lb.str(b"\n");
            });
            TRONA_INVALID_OPERATION
        })?;
    if kind != VT_REG {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(
                b"[VFS] mmap backing failed component=tmpfs op=resolve_backing stage=kind vnode=",
            );
            _lb.dec(vnode.slot() as u64);
            _lb.str(b":");
            _lb.dec(vnode.epoch() as u64);
            _lb.str(b" kind=");
            _lb.dec(kind as u64);
            _lb.str(b" label=");
            _lb.hex(TRONA_INVALID_OPERATION);
            _lb.str(b"\n");
        });
        return Err(TRONA_INVALID_OPERATION);
    }
    let current = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| n.mo_capacity)
        .unwrap_or(0);
    if current == 0 {
        if let Err(err) = ensure_mo_capacity(state, node_h, TMPFS_PAGE_BYTES) {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] mmap backing failed component=tmpfs op=resolve_backing stage=ensure_mo vnode=");
                _lb.dec(vnode.slot() as u64);
                _lb.str(b":");
                _lb.dec(vnode.epoch() as u64);
                _lb.str(b" label=");
                _lb.hex(err);
                _lb.str(b"\n");
            });
            return Err(err);
        }
    }
    let mo_cap = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| n.mo_cap)
        .ok_or_else(|| {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] mmap backing failed component=tmpfs op=resolve_backing stage=mo_lookup vnode=");
                _lb.dec(vnode.slot() as u64);
                _lb.str(b":");
                _lb.dec(vnode.epoch() as u64);
                _lb.str(b" label=");
                _lb.hex(TRONA_INVALID_OPERATION);
                _lb.str(b"\n");
            });
            TRONA_INVALID_OPERATION
        })?;
    if mo_cap == 0 {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(
                b"[VFS] mmap backing failed component=tmpfs op=resolve_backing stage=mo_cap vnode=",
            );
            _lb.dec(vnode.slot() as u64);
            _lb.str(b":");
            _lb.dec(vnode.epoch() as u64);
            _lb.str(b" label=");
            _lb.hex(TRONA_INVALID_OPERATION);
            _lb.str(b"\n");
        });
        return Err(TRONA_INVALID_OPERATION);
    }
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        node.mmap_export_refs = node.mmap_export_refs.saturating_add(1);
    }
    Ok(Some(BackingResolution {
        kind: MMAP_BACKING_TMPFS,
        mo_cap,
    }))
}

/// `VfsOps::reclaim_vnode` callback. Generic reclaim invokes this once
/// it has confirmed `nlink == 0` and `open_count == 0`; if mmsrv still
/// holds an exported MO cap (`mmap_export_refs > 0`) the actual MO /
/// arena release is deferred to `release_export_ref` so the underlying
/// pages stay live for the surviving mapping. The bookkeeping (vnode
/// backend_ref, used_inodes) gets cleared either way so the slot can
/// be recycled by the generic `vnodes.release` that runs right after.
fn tmpfs_reclaim_vnode(state: &mut VfsState, vnode: VnodeHandle) {
    let Some(node_h) = find_node_handle_by_vnode(state, vnode) else {
        return;
    };
    let exported = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| n.mmap_export_refs)
        .unwrap_or(0);
    if exported > 0 {
        if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
            node.pending_release = 1;
            // Detach the vnode link so the arena entry no longer
            // pretends to belong to a live `Vnode` slot. Future
            // `find_node_handle_by_vnode` calls return `None`, which
            // is the correct semantics — the file is unreachable;
            // only mmsrv's mapping keeps the MO alive.
            node.vnode = VnodeHandle::INVALID;
        }
        if let Some(vn) = state.vnodes.get_mut(vnode) {
            vn.clear_backend_ref();
        }
        // Inode account stays charged until the mmap drops. Bytes
        // also stay accounted — they are still consuming kernel pages.
        return;
    }
    release_node_for_vnode(state, vnode);
}

/// Bump the export refcount by `delta` from a notification path
/// (e.g. mmsrv after `fork(2)` duplicated a `MAP_SHARED` region).
/// Mirrors `release_export_ref` so the wire is symmetric.
pub(crate) fn acquire_export_ref(state: &mut VfsState, fs_id: u64, ino: u64, delta: u64) -> u64 {
    let Some(node_h) = find_node_by_fs_inode(state, fs_id, ino) else {
        return TRONA_NOT_FOUND;
    };
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        let bump = u32::try_from(delta).unwrap_or(u32::MAX);
        node.mmap_export_refs = node.mmap_export_refs.saturating_add(bump);
    }
    TRONA_OK
}

/// Drop one reference held by mmsrv on a tmpfs vnode's MO. When the
/// counter falls to zero and the vnode was already reclaimed, the
/// deferred storage / arena cleanup runs here.
pub(crate) fn release_export_ref(state: &mut VfsState, fs_id: u64, ino: u64) -> u64 {
    let Some(node_h) = find_node_by_fs_inode(state, fs_id, ino) else {
        return TRONA_NOT_FOUND;
    };
    let pending = {
        let node = match state.tmpfs_nodes.get_mut(node_h) {
            Some(n) => n,
            None => return TRONA_NOT_FOUND,
        };
        if node.mmap_export_refs == 0 {
            return TRONA_INVALID_OPERATION;
        }
        node.mmap_export_refs -= 1;
        node.mmap_export_refs == 0 && node.pending_release != 0
    };
    if pending {
        finalize_pending_release(state, node_h);
    }
    TRONA_OK
}

fn find_node_by_fs_inode(state: &VfsState, fs_id: u64, ino: u64) -> Option<TmpfsNodeHandle> {
    let mut found = TmpfsNodeHandle::INVALID;
    state.tmpfs_nodes.for_each_active(|handle, node| {
        // Match by mount fs_instance_id + the inode the parent vnode
        // carried. After `tmpfs_reclaim_vnode` zeroes `node.vnode`
        // we cannot consult the original `Vnode.id`; `mmap_id` below
        // is the persistent copy stamped at allocation time.
        let mount_fs_id = state
            .mounts
            .get(node.owner_mount)
            .map(|m| m.fs_instance_id.0)
            .unwrap_or(u64::MAX);
        if mount_fs_id == fs_id && node.mmap_id == ino {
            found = handle;
            return false;
        }
        true
    });
    found.is_valid().then_some(found)
}

fn finalize_pending_release(state: &mut VfsState, node_h: TmpfsNodeHandle) {
    let (mount, symlink) = match state.tmpfs_nodes.get(node_h) {
        Some(n) => (n.owner_mount, n.symlink),
        None => return,
    };
    release_node_storage(state, node_h);
    if symlink.is_valid() {
        let _ = state.tmpfs_symlinks.release(symlink);
    }
    let _ = state.tmpfs_nodes.release(node_h);
    release_inode_account(state, mount);
}

/// Populate `vnode_h` for a freshly created tmpfs child. Sole owner of
/// `Vnode` field initialization across mkdir / create / symlink / link
/// so the layout decision (no `VN_ROOT`, `pin_count = 0`, backend ops
/// pre-installed) lives in one place.
fn init_tmpfs_child_vnode(
    state: &mut VfsState,
    vnode_h: VnodeHandle,
    fs_id: FsInstanceId,
    parent_mount: MountHandle,
    node_h: TmpfsNodeHandle,
    kind: u8,
    inode: u64,
    mode: u32,
    now: u64,
) {
    if let Some(vnode) = state.vnodes.get_mut(vnode_h) {
        vnode.vtype = kind;
        vnode.backend_kind = VNODE_BACKEND_TMPFS;
        vnode.flags = 0;
        vnode.pin_count = 0;
        vnode.mode = mode;
        vnode.id = inode;
        vnode.backend_seq = 0;
        vnode.uid = 0;
        vnode.gid = 0;
        vnode.atime_ns = now;
        vnode.mtime_ns = now;
        vnode.size = 0;
        vnode.fs_instance_id = fs_id;
        vnode.mount = CachedRef::new(fs_id, parent_mount);
        vnode.covered_by = CachedRef::<FsInstanceId, MountHandle>::INVALID;
        vnode.ops = tmpfs_vops();
        vnode.data = core::ptr::null_mut();
        vnode.open_count = 0;
        vnode.nlink = if kind == VT_DIR { 2 } else { 1 };
        vnode.set_backend_ref(node_h);
    }
}

fn allocate_child_node(
    state: &mut VfsState,
    parent_node: TmpfsNodeHandle,
    parent_mount: MountHandle,
    name: &[u8],
    mode: u32,
    kind: u8,
) -> Result<(TmpfsNodeHandle, VnodeHandle), u64> {
    if name.is_empty() || name.len() > TMPFS_NAME_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let _data_h = try_account_inode(state, parent_mount)?;

    let entry_h = match state.tmpfs_dir_entries.alloc() {
        Some(h) => h,
        None => {
            release_inode_account(state, parent_mount);
            return Err(TRONA_OUT_OF_MEMORY);
        }
    };
    let node_h = match state.tmpfs_nodes.alloc() {
        Some(h) => h,
        None => {
            let _ = state.tmpfs_dir_entries.release(entry_h);
            release_inode_account(state, parent_mount);
            return Err(TRONA_OUT_OF_MEMORY);
        }
    };
    let vnode_h = match state.vnodes.alloc() {
        Some(h) => h,
        None => {
            let _ = state.tmpfs_nodes.release(node_h);
            let _ = state.tmpfs_dir_entries.release(entry_h);
            release_inode_account(state, parent_mount);
            return Err(TRONA_OUT_OF_MEMORY);
        }
    };

    let inode = next_inode(state, parent_mount).unwrap_or(0);
    let now = now_ns();
    let fs_id = state
        .mounts
        .get(parent_mount)
        .map(|m| m.fs_instance_id)
        .unwrap_or(FsInstanceId::INVALID);

    {
        let entry = state.tmpfs_dir_entries.get_mut(entry_h).unwrap();
        *entry = TmpfsDirEntry::zeroed();
        entry.parent = parent_node;
        entry.child = node_h;
        entry.name_len = name.len() as u8;
        entry.name[..name.len()].copy_from_slice(name);
    }

    {
        let node = state.tmpfs_nodes.get_mut(node_h).unwrap();
        *node = TmpfsVnodeState::zeroed();
        node.owner_mount = parent_mount;
        node.vnode = vnode_h;
        node.parent = parent_node;
        node.kind = kind;
        node.name_len = name.len() as u8;
        node.name[..name.len()].copy_from_slice(name);
        node.mode = mode;
        node.nlink = if kind == VT_DIR { 2 } else { 1 };
        node.atime_ns = now;
        node.mtime_ns = now;
        node.ctime_ns = now;
        node.mmap_id = inode;
    }

    {
        let parent = state.tmpfs_nodes.get_mut(parent_node).unwrap();
        let prev_head = parent.children_head;
        parent.children_head = entry_h;
        parent.children_count = parent.children_count.saturating_add(1);
        parent.mtime_ns = now;
        parent.ctime_ns = now;
        if kind == VT_DIR {
            parent.nlink = parent.nlink.saturating_add(1);
        }
        let entry = state.tmpfs_dir_entries.get_mut(entry_h).unwrap();
        entry.next = prev_head;
    }

    init_tmpfs_child_vnode(
        state,
        vnode_h,
        fs_id,
        parent_mount,
        node_h,
        kind,
        inode,
        mode,
        now,
    );
    state.cache_vnode_key(vnode_h);

    Ok((node_h, vnode_h))
}

fn detach_dir_entry(
    state: &mut VfsState,
    parent_node: TmpfsNodeHandle,
    name: &[u8],
    casefold: bool,
) -> Option<(TmpfsDirEntryHandle, TmpfsNodeHandle)> {
    let mut prev = TmpfsDirEntryHandle::INVALID;
    let mut current = state.tmpfs_nodes.get(parent_node)?.children_head;
    while current.is_valid() {
        let entry = state.tmpfs_dir_entries.get(current)?;
        let next = entry.next;
        if name_eq(entry.name_slice(), name, casefold) {
            let child = entry.child;
            if prev.is_valid() {
                let prev_entry = state.tmpfs_dir_entries.get_mut(prev)?;
                prev_entry.next = next;
            } else if let Some(parent) = state.tmpfs_nodes.get_mut(parent_node) {
                parent.children_head = next;
            }
            if let Some(parent) = state.tmpfs_nodes.get_mut(parent_node) {
                parent.children_count = parent.children_count.saturating_sub(1);
            }
            return Some((current, child));
        }
        prev = current;
        current = next;
    }
    None
}

fn find_dir_entry(
    state: &VfsState,
    parent_node: TmpfsNodeHandle,
    name: &[u8],
    casefold: bool,
) -> Option<TmpfsDirEntryHandle> {
    let mut current = state.tmpfs_nodes.get(parent_node)?.children_head;
    while current.is_valid() {
        let entry = state.tmpfs_dir_entries.get(current)?;
        if name_eq(entry.name_slice(), name, casefold) {
            return Some(current);
        }
        current = entry.next;
    }
    None
}

fn child_vnode_handle(state: &VfsState, child_node: TmpfsNodeHandle) -> Option<VnodeHandle> {
    state.tmpfs_nodes.get(child_node).map(|n| n.vnode)
}

fn lookup_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
) -> VfsResult<Option<VnodeHandle>> {
    if !vnode_is_tmpfs(state, parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let parent_node = match find_node_handle_by_vnode(state, parent) {
        Some(h) => h,
        None => return Ok(VfsOpResult::Complete(None)),
    };
    let mount = state
        .vnodes
        .get(parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let casefold = casefold_for_mount(state, mount);
    let entry_h = match find_dir_entry(state, parent_node, name, casefold) {
        Some(h) => h,
        None => return Ok(VfsOpResult::Complete(None)),
    };
    let child_node = state
        .tmpfs_dir_entries
        .get(entry_h)
        .map(|e| e.child)
        .unwrap_or(TmpfsNodeHandle::INVALID);
    Ok(VfsOpResult::Complete(child_vnode_handle(state, child_node)))
}

fn build_path_for_vnode(state: &VfsState, vnode: VnodeHandle, out: &mut [u8]) -> Option<usize> {
    let mut node_h = find_node_handle_by_vnode(state, vnode)?;
    let mut segments = [TmpfsNodeHandle::INVALID; 64];
    let mut depth = 0usize;
    while node_h.is_valid() {
        if depth >= segments.len() {
            return None;
        }
        segments[depth] = node_h;
        depth += 1;
        let parent = state.tmpfs_nodes.get(node_h)?.parent;
        if !parent.is_valid() {
            break;
        }
        node_h = parent;
    }

    let mut pos = 0usize;
    if depth == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'/';
        return Some(1);
    }
    let mut idx = depth;
    while idx > 0 {
        idx -= 1;
        let node = state.tmpfs_nodes.get(segments[idx])?;
        let name = node.name_slice();
        if name.is_empty() {
            continue;
        }
        if pos + 1 + name.len() > out.len() {
            return None;
        }
        out[pos] = b'/';
        pos += 1;
        out[pos..pos + name.len()].copy_from_slice(name);
        pos += name.len();
    }
    if pos == 0 {
        if out.is_empty() {
            return None;
        }
        out[0] = b'/';
        return Some(1);
    }
    Some(pos)
}

fn ensure_symlink_target(state: &mut VfsState, vnode: VnodeHandle) -> VfsResult<bool> {
    let Some(node_h) = find_node_handle_by_vnode(state, vnode) else {
        return Ok(VfsOpResult::Complete(false));
    };
    Ok(VfsOpResult::Complete(
        state
            .tmpfs_nodes
            .get(node_h)
            .map(|n| n.kind == VT_LNK && n.symlink.is_valid())
            .unwrap_or(false),
    ))
}

fn readlink_inline(
    state: &VfsState,
    _cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    out: *mut u8,
    cap: usize,
) -> VfsResult<usize> {
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let symlink_h = state
        .tmpfs_nodes
        .get(node_h)
        .filter(|n| n.kind == VT_LNK)
        .map(|n| n.symlink)
        .ok_or(TRONA_INVALID_OPERATION)?;
    if !symlink_h.is_valid() {
        return Err(TRONA_INVALID_OPERATION);
    }
    let buf = state
        .tmpfs_symlinks
        .get(symlink_h)
        .ok_or(TRONA_INVALID_OPERATION)?;
    let target = buf.target_slice();
    let copy_len = core::cmp::min(target.len(), cap);
    if copy_len > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(target.as_ptr(), out, copy_len);
        }
    }
    Ok(VfsOpResult::Complete(target.len()))
}

unsafe fn read_regular_vop(
    state: &VfsState,
    _cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    file_offset: u64,
    out: *mut u8,
    cap: usize,
) -> VfsResult<usize> {
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let node = state
        .tmpfs_nodes
        .get(node_h)
        .filter(|n| n.kind == VT_REG)
        .ok_or(TRONA_INVALID_OPERATION)?;
    if file_offset >= node.size {
        return Ok(VfsOpResult::Complete(0));
    }
    let available = node.size - file_offset;
    let to_copy = core::cmp::min(available as usize, cap);
    if to_copy == 0 {
        return Ok(VfsOpResult::Complete(0));
    }
    if node.local_mapping.is_null() {
        return Err(TRONA_INVALID_OPERATION);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(node.local_mapping.add(file_offset as usize), out, to_copy);
    }
    Ok(VfsOpResult::Complete(to_copy))
}

unsafe fn write_regular_vop(
    state: &mut VfsState,
    vnode: VnodeHandle,
    file_offset: u64,
    src: *const u8,
    len: usize,
) -> VfsResult<u64> {
    ensure_writable(state, vnode)?;
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let kind = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| n.kind)
        .ok_or(TRONA_INVALID_OPERATION)?;
    if kind != VT_REG {
        return Err(TRONA_INVALID_OPERATION);
    }
    if len == 0 {
        return Ok(VfsOpResult::Complete(0));
    }
    let end = file_offset
        .checked_add(len as u64)
        .ok_or(TRONA_INVALID_ARGUMENT)?;
    ensure_mo_capacity(state, node_h, end)?;
    let now = now_ns();
    let new_size = {
        let node = state
            .tmpfs_nodes
            .get_mut(node_h)
            .ok_or(TRONA_INVALID_OPERATION)?;
        unsafe {
            core::ptr::copy_nonoverlapping(src, node.local_mapping.add(file_offset as usize), len);
        }
        node.mtime_ns = now;
        node.ctime_ns = now;
        if end > node.size {
            node.size = end;
        }
        node.size
    };
    if let Some(vn) = state.vnodes.get_mut(vnode) {
        vn.size = new_size;
        vn.mtime_ns = now;
    }
    Ok(VfsOpResult::Complete(len as u64))
}

fn create_regular_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    if !vnode_is_tmpfs(state, parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent)?;
    let parent_node = find_node_handle_by_vnode(state, parent).ok_or(TRONA_NOT_FOUND)?;
    let parent_mount = state
        .vnodes
        .get(parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let casefold = casefold_for_mount(state, parent_mount);
    if find_dir_entry(state, parent_node, name, casefold).is_some() {
        return Err(TRONA_ALREADY_EXISTS);
    }
    let resolved_mode = (mode & !(S_IFMT as u32)) | (S_IFREG as u32);
    let (_, vnode_h) = allocate_child_node(
        state,
        parent_node,
        parent_mount,
        name,
        resolved_mode,
        VT_REG,
    )?;
    Ok(VfsOpResult::Complete(vnode_h))
}

/// External entry points for callers that bypass the `VnodeOps`
/// dispatch table — primarily the bootstrap layer when it has to
/// create children inside an already-mounted tmpfs (e.g. `/tmp/shm`).
/// Without these the bootstrap shadow tree would diverge from the
/// tmpfs view of the same parent.
pub(crate) fn mkdir_child_external(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    mkdir_child(state, parent, name, mode)
}

pub(crate) fn create_regular_child_external(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    create_regular_child(state, parent, name, mode)
}

pub(crate) fn symlink_child_external(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
    target: &[u8],
) -> VfsResult<VnodeHandle> {
    let _ = mode;
    symlink_child(state, parent, name, target)
}

fn mkdir_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    if !vnode_is_tmpfs(state, parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent)?;
    let parent_node = find_node_handle_by_vnode(state, parent).ok_or(TRONA_NOT_FOUND)?;
    let parent_mount = state
        .vnodes
        .get(parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let casefold = casefold_for_mount(state, parent_mount);
    if find_dir_entry(state, parent_node, name, casefold).is_some() {
        return Err(TRONA_ALREADY_EXISTS);
    }
    let resolved_mode = (mode & !(S_IFMT as u32)) | (S_IFDIR as u32);
    let (_, vnode_h) = allocate_child_node(
        state,
        parent_node,
        parent_mount,
        name,
        resolved_mode,
        VT_DIR,
    )?;
    Ok(VfsOpResult::Complete(vnode_h))
}

fn symlink_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    target: &[u8],
) -> VfsResult<VnodeHandle> {
    if !vnode_is_tmpfs(state, parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if target.is_empty() || target.len() > TMPFS_SYMLINK_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent)?;
    let parent_node = find_node_handle_by_vnode(state, parent).ok_or(TRONA_NOT_FOUND)?;
    let parent_mount = state
        .vnodes
        .get(parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let casefold = casefold_for_mount(state, parent_mount);
    if find_dir_entry(state, parent_node, name, casefold).is_some() {
        return Err(TRONA_ALREADY_EXISTS);
    }

    let symlink_h = state.tmpfs_symlinks.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    {
        let buf = state
            .tmpfs_symlinks
            .get_mut(symlink_h)
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        *buf = TmpfsSymlinkBuf::zeroed();
        buf.target_len = target.len() as u16;
        buf.target[..target.len()].copy_from_slice(target);
    }

    let resolved_mode = (S_IFLNK as u32) | 0o777;
    let result = allocate_child_node(
        state,
        parent_node,
        parent_mount,
        name,
        resolved_mode,
        VT_LNK,
    );
    let (node_h, vnode_h) = match result {
        Ok(pair) => pair,
        Err(err) => {
            let _ = state.tmpfs_symlinks.release(symlink_h);
            return Err(err);
        }
    };
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        node.symlink = symlink_h;
        node.size = target.len() as u64;
    }
    if let Some(vn) = state.vnodes.get_mut(vnode_h) {
        vn.size = target.len() as u64;
    }
    Ok(VfsOpResult::Complete(vnode_h))
}

/// `VnodeOps::link_vnode_into` callback. The vops contract is
/// `(state, source, new_parent, name)` — the source vnode becomes
/// reachable as `name` inside `new_parent`. tmpfs only allows
/// non-directory sources, so a directory in the source position
/// returns `TRONA_INVALID_OPERATION`.
fn link_vnode_into_vop(
    state: &mut VfsState,
    source: VnodeHandle,
    new_parent: VnodeHandle,
    name: &[u8],
) -> VfsResult<()> {
    if !vnode_is_tmpfs(state, source) || !vnode_is_tmpfs(state, new_parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, new_parent)?;
    let parent_node = find_node_handle_by_vnode(state, new_parent).ok_or(TRONA_NOT_FOUND)?;
    let source_node = find_node_handle_by_vnode(state, source).ok_or(TRONA_NOT_FOUND)?;
    let parent_mount = state
        .vnodes
        .get(new_parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let source_mount = state
        .vnodes
        .get(source)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    if parent_mount != source_mount {
        return Err(TRONA_CROSS_DEVICE);
    }
    if name.is_empty() || name.len() > TMPFS_NAME_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let casefold = casefold_for_mount(state, parent_mount);
    if find_dir_entry(state, parent_node, name, casefold).is_some() {
        return Err(TRONA_ALREADY_EXISTS);
    }
    let source_kind = state
        .tmpfs_nodes
        .get(source_node)
        .map(|n| n.kind)
        .ok_or(TRONA_INVALID_OPERATION)?;
    if source_kind == VT_DIR {
        return Err(TRONA_INVALID_OPERATION);
    }

    let entry_h = state.tmpfs_dir_entries.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    let now = now_ns();
    {
        let entry = state.tmpfs_dir_entries.get_mut(entry_h).unwrap();
        *entry = TmpfsDirEntry::zeroed();
        entry.parent = parent_node;
        entry.child = source_node;
        entry.name_len = name.len() as u8;
        entry.name[..name.len()].copy_from_slice(name);
    }
    {
        let parent_state = state.tmpfs_nodes.get_mut(parent_node).unwrap();
        let prev_head = parent_state.children_head;
        parent_state.children_head = entry_h;
        parent_state.children_count = parent_state.children_count.saturating_add(1);
        parent_state.mtime_ns = now;
        parent_state.ctime_ns = now;
        let entry = state.tmpfs_dir_entries.get_mut(entry_h).unwrap();
        entry.next = prev_head;
    }
    if let Some(node) = state.tmpfs_nodes.get_mut(source_node) {
        node.nlink = node.nlink.saturating_add(1);
        node.ctime_ns = now;
    }
    if let Some(vn) = state.vnodes.get_mut(source) {
        vn.nlink = vn.nlink.saturating_add(1);
    }
    Ok(VfsOpResult::Complete(()))
}

/// Returns `true` when the mount has `MNT_RDONLY` set and no further
/// mutating operation should land on it.
fn mount_is_readonly(state: &VfsState, mount: MountHandle) -> bool {
    state
        .mounts
        .get(mount)
        .map(|m| (m.flags & MNT_RDONLY) != 0)
        .unwrap_or(false)
}

/// `MNT_RDONLY` guard for any vop that intends to mutate filesystem
/// state. Returns `Err(TRONA_READONLY)` when the owning mount is
/// read-only so callers can just `?` the result.
fn ensure_writable(state: &VfsState, vnode: VnodeHandle) -> Result<(), u64> {
    let mount = state
        .vnodes
        .get(vnode)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    if mount_is_readonly(state, mount) {
        Err(TRONA_READONLY)
    } else {
        Ok(())
    }
}

fn remove_child(
    state: &mut VfsState,
    parent: VnodeHandle,
    name: &[u8],
    remove_dir: bool,
) -> VfsResult<()> {
    if !vnode_is_tmpfs(state, parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent)?;
    let parent_node = find_node_handle_by_vnode(state, parent).ok_or(TRONA_NOT_FOUND)?;
    let parent_mount = state
        .vnodes
        .get(parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let casefold = casefold_for_mount(state, parent_mount);
    let entry_h = find_dir_entry(state, parent_node, name, casefold).ok_or(TRONA_NOT_FOUND)?;
    let child = state
        .tmpfs_dir_entries
        .get(entry_h)
        .map(|e| e.child)
        .unwrap_or(TmpfsNodeHandle::INVALID);
    let kind = state.tmpfs_nodes.get(child).map(|n| n.kind).unwrap_or(0);
    if remove_dir {
        if kind != VT_DIR {
            return Err(TRONA_INVALID_OPERATION);
        }
        let count = state
            .tmpfs_nodes
            .get(child)
            .map(|n| n.children_count)
            .unwrap_or(0);
        if count != 0 {
            return Err(TRONA_INVALID_OPERATION);
        }
    } else if kind == VT_DIR {
        return Err(TRONA_IS_DIRECTORY);
    }

    let detached = detach_dir_entry(state, parent_node, name, casefold);
    let (entry_handle, child_handle) = detached.ok_or(TRONA_NOT_FOUND)?;
    let _ = state.tmpfs_dir_entries.release(entry_handle);
    let now = now_ns();
    if let Some(parent_state) = state.tmpfs_nodes.get_mut(parent_node) {
        parent_state.mtime_ns = now;
        parent_state.ctime_ns = now;
        if kind == VT_DIR {
            parent_state.nlink = parent_state.nlink.saturating_sub(1);
        }
    }

    let (child_vnode, fully_unlinked) = {
        let node = match state.tmpfs_nodes.get_mut(child_handle) {
            Some(n) => n,
            None => return Ok(VfsOpResult::Complete(())),
        };
        // Empty directories start at nlink=2 (`.` self link plus the
        // directory entry from the parent). `rmdir` consumes both —
        // the entry detach above plus the implicit `.` self link —
        // so drop straight to zero. Regular files / symlinks decrement
        // by one (only the dir entry).
        if kind == VT_DIR {
            node.nlink = 0;
        } else {
            node.nlink = node.nlink.saturating_sub(1);
        }
        node.ctime_ns = now;
        (node.vnode, node.nlink == 0)
    };

    if let Some(vn) = state.vnodes.get_mut(child_vnode) {
        if fully_unlinked {
            vn.nlink = 0;
            vn.flags |= VN_DOOMED;
        } else {
            vn.nlink = vn.nlink.saturating_sub(1);
        }
    }

    // POSIX unlink-while-open: storage and the arena entry must outlive
    // the dir-entry detach when something still holds the vnode (open fd,
    // pending mmap). The reclaim path runs `tmpfs_reclaim_vnode` once
    // `open_count` drops to zero. Drop the path-lookup index immediately
    // so future opens cannot resurrect the doomed vnode by name.
    if fully_unlinked {
        state.uncache_vnode_key(child_vnode);
        state.reclaim_bootstrap_vnode(child_vnode);
    }

    Ok(VfsOpResult::Complete(()))
}

fn rename_child_vop(
    state: &mut VfsState,
    old_parent: VnodeHandle,
    old_name: &[u8],
    new_parent: VnodeHandle,
    new_name: &[u8],
) -> VfsResult<()> {
    if !vnode_is_tmpfs(state, old_parent) || !vnode_is_tmpfs(state, new_parent) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, old_parent)?;
    ensure_writable(state, new_parent)?;
    let old_parent_node = find_node_handle_by_vnode(state, old_parent).ok_or(TRONA_NOT_FOUND)?;
    let new_parent_node = find_node_handle_by_vnode(state, new_parent).ok_or(TRONA_NOT_FOUND)?;
    let old_mount = state
        .vnodes
        .get(old_parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let new_mount = state
        .vnodes
        .get(new_parent)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    if old_mount != new_mount {
        return Err(TRONA_CROSS_DEVICE);
    }
    if new_name.is_empty() || new_name.len() > TMPFS_NAME_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let casefold = casefold_for_mount(state, old_mount);
    let src_entry =
        find_dir_entry(state, old_parent_node, old_name, casefold).ok_or(TRONA_NOT_FOUND)?;
    let src_child = state
        .tmpfs_dir_entries
        .get(src_entry)
        .map(|e| e.child)
        .unwrap_or(TmpfsNodeHandle::INVALID);
    if let Some(existing) = find_dir_entry(state, new_parent_node, new_name, casefold) {
        let existing_child = state
            .tmpfs_dir_entries
            .get(existing)
            .map(|e| e.child)
            .unwrap_or(TmpfsNodeHandle::INVALID);
        if existing_child == src_child {
            return Ok(VfsOpResult::Complete(()));
        }
        let existing_kind = state
            .tmpfs_nodes
            .get(existing_child)
            .map(|n| n.kind)
            .unwrap_or(0);
        let src_kind = state
            .tmpfs_nodes
            .get(src_child)
            .map(|n| n.kind)
            .unwrap_or(0);
        if existing_kind == VT_DIR {
            if src_kind != VT_DIR {
                return Err(TRONA_IS_DIRECTORY);
            }
            let children = state
                .tmpfs_nodes
                .get(existing_child)
                .map(|n| n.children_count)
                .unwrap_or(0);
            if children != 0 {
                return Err(TRONA_INVALID_OPERATION);
            }
        } else if src_kind == VT_DIR {
            return Err(TRONA_INVALID_OPERATION);
        }
        let remove_dir = existing_kind == VT_DIR;
        match remove_child(state, new_parent, new_name, remove_dir)? {
            VfsOpResult::Complete(()) => {}
            VfsOpResult::Deferred(op_id) => {
                // tmpfs is in-memory and never yields a deferred op,
                // so this branch is unreachable today. Reclaim `op_id`
                // explicitly anyway to keep the leak audit invariant
                // honest if a future tmpfs vop ever returns Deferred.
                unsafe {
                    crate::owner::pending_ops::free(op_id);
                }
                return Err(TRONA_INVALID_OPERATION);
            }
        }
    }

    let detached = detach_dir_entry(state, old_parent_node, old_name, casefold);
    let (entry_h, child_h) = detached.ok_or(TRONA_NOT_FOUND)?;
    let now = now_ns();
    {
        let entry = state.tmpfs_dir_entries.get_mut(entry_h).unwrap();
        entry.parent = new_parent_node;
        entry.name = [0; TMPFS_NAME_MAX];
        entry.name_len = new_name.len() as u8;
        entry.name[..new_name.len()].copy_from_slice(new_name);
    }
    {
        let new_parent_state = state.tmpfs_nodes.get_mut(new_parent_node).unwrap();
        let prev_head = new_parent_state.children_head;
        new_parent_state.children_head = entry_h;
        new_parent_state.children_count = new_parent_state.children_count.saturating_add(1);
        new_parent_state.mtime_ns = now;
        new_parent_state.ctime_ns = now;
        let entry = state.tmpfs_dir_entries.get_mut(entry_h).unwrap();
        entry.next = prev_head;
    }
    if old_parent_node != new_parent_node {
        let child_kind = state.tmpfs_nodes.get(child_h).map(|n| n.kind).unwrap_or(0);
        if let Some(node) = state.tmpfs_nodes.get_mut(child_h) {
            node.parent = new_parent_node;
        }
        if let Some(parent) = state.tmpfs_nodes.get_mut(old_parent_node) {
            parent.mtime_ns = now;
            parent.ctime_ns = now;
            // Cross-directory move of a directory: the child carried
            // a `..` link to its old parent, so its departure removes
            // one nlink from the source directory and the new parent
            // gains one. Files / symlinks have no such link and the
            // counts stay put.
            if child_kind == VT_DIR {
                parent.nlink = parent.nlink.saturating_sub(1);
            }
        }
        if child_kind == VT_DIR {
            if let Some(parent) = state.tmpfs_nodes.get_mut(new_parent_node) {
                parent.nlink = parent.nlink.saturating_add(1);
            }
        }
    }
    if let Some(node) = state.tmpfs_nodes.get_mut(child_h) {
        node.name = [0; TMPFS_NAME_MAX];
        node.name_len = new_name.len() as u8;
        node.name[..new_name.len()].copy_from_slice(new_name);
        node.ctime_ns = now;
    }
    Ok(VfsOpResult::Complete(()))
}

fn set_mode_vnode(state: &mut VfsState, vnode: VnodeHandle, mode: u32) -> VfsResult<()> {
    ensure_writable(state, vnode)?;
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let now = now_ns();
    let new_full_mode = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| (n.mode & (S_IFMT as u32)) | (mode & 0o7777))
        .ok_or(TRONA_NOT_FOUND)?;
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        node.mode = new_full_mode;
        node.ctime_ns = now;
    }
    if let Some(vn) = state.vnodes.get_mut(vnode) {
        vn.mode = new_full_mode;
    }
    Ok(VfsOpResult::Complete(()))
}

fn set_owner_vnode(state: &mut VfsState, vnode: VnodeHandle, uid: u32, gid: u32) -> VfsResult<()> {
    ensure_writable(state, vnode)?;
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let now = now_ns();
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        if uid != u32::MAX {
            node.uid = uid;
        }
        if gid != u32::MAX {
            node.gid = gid;
        }
        node.ctime_ns = now;
    }
    if let Some(vn) = state.vnodes.get_mut(vnode) {
        if uid != u32::MAX {
            vn.uid = uid;
        }
        if gid != u32::MAX {
            vn.gid = gid;
        }
    }
    Ok(VfsOpResult::Complete(()))
}

fn set_times_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
    atime_ns: Option<u64>,
    mtime_ns: Option<u64>,
) -> VfsResult<()> {
    ensure_writable(state, vnode)?;
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let now = now_ns();
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        if let Some(t) = atime_ns {
            node.atime_ns = t;
        }
        if let Some(t) = mtime_ns {
            node.mtime_ns = t;
        }
        node.ctime_ns = now;
    }
    if let Some(vn) = state.vnodes.get_mut(vnode) {
        if let Some(t) = atime_ns {
            vn.atime_ns = t;
        }
        if let Some(t) = mtime_ns {
            vn.mtime_ns = t;
        }
    }
    Ok(VfsOpResult::Complete(()))
}

fn truncate_vnode(state: &mut VfsState, vnode: VnodeHandle, new_size: u64) -> VfsResult<()> {
    ensure_writable(state, vnode)?;
    let node_h = find_node_handle_by_vnode(state, vnode).ok_or(TRONA_NOT_FOUND)?;
    let kind = state
        .tmpfs_nodes
        .get(node_h)
        .map(|n| n.kind)
        .ok_or(TRONA_NOT_FOUND)?;
    if kind != VT_REG {
        return Err(TRONA_INVALID_OPERATION);
    }
    let now = now_ns();
    if new_size == 0 {
        release_node_storage(state, node_h);
        if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
            node.mtime_ns = now;
            node.ctime_ns = now;
        }
        if let Some(vn) = state.vnodes.get_mut(vnode) {
            vn.size = 0;
            vn.mtime_ns = now;
        }
        return Ok(VfsOpResult::Complete(()));
    }
    ensure_mo_capacity(state, node_h, new_size)?;
    let (capacity, current_size, mapping) = match state.tmpfs_nodes.get(node_h) {
        Some(n) => (n.mo_capacity, n.size, n.local_mapping),
        None => return Err(TRONA_NOT_FOUND),
    };
    if new_size > current_size && !mapping.is_null() {
        let zero_start = current_size as usize;
        let zero_end = core::cmp::min(new_size, capacity) as usize;
        if zero_end > zero_start {
            unsafe {
                core::ptr::write_bytes(mapping.add(zero_start), 0, zero_end - zero_start);
            }
        }
    }
    if let Some(node) = state.tmpfs_nodes.get_mut(node_h) {
        node.size = new_size;
        node.mtime_ns = now;
        node.ctime_ns = now;
    }
    if let Some(vn) = state.vnodes.get_mut(vnode) {
        vn.size = new_size;
        vn.mtime_ns = now;
    }
    Ok(VfsOpResult::Complete(()))
}

fn validate_open_regular_vop(_state: &VfsState, _vnode: VnodeHandle, _flags: u32) -> u64 {
    TRONA_OK
}

fn readdir_dir_vop(
    state: &VfsState,
    _cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    cursor: u64,
    _ignore_case: bool,
    name_out: &mut [u8; 128],
) -> crate::vfs_core::vops::ReaddirResult {
    let Some(node_h) = find_node_handle_by_vnode(state, vnode) else {
        return Err(TRONA_NOT_FOUND);
    };
    if state.tmpfs_nodes.get(node_h).map(|n| n.kind) != Some(VT_DIR) {
        return Err(TRONA_INVALID_OPERATION);
    }
    let mut head = state.tmpfs_nodes.get(node_h).unwrap().children_head;
    let mut idx = 0u64;
    while head.is_valid() {
        let entry = match state.tmpfs_dir_entries.get(head) {
            Some(e) => e,
            None => return Ok(VfsOpResult::Complete(None)),
        };
        if idx == cursor {
            let name = entry.name_slice();
            let copy_len = core::cmp::min(name.len(), name_out.len());
            for slot in name_out.iter_mut() {
                *slot = 0;
            }
            name_out[..copy_len].copy_from_slice(&name[..copy_len]);
            let child_h = entry.child;
            let (kind, ino) = match state.tmpfs_nodes.get(child_h) {
                Some(n) => (n.kind, state.vnodes.get(n.vnode).map(|v| v.id).unwrap_or(0)),
                None => return Ok(VfsOpResult::Complete(None)),
            };
            let dt = match kind {
                VT_DIR => DT_DIR,
                VT_LNK => DT_LNK,
                _ => DT_REG,
            };
            return Ok(VfsOpResult::Complete(Some(
                crate::vfs_core::vops::ReaddirEntry {
                    next_cursor: idx + 1,
                    eof_after: !entry.next.is_valid(),
                    name_len: copy_len as u8,
                    ino,
                    d_type: dt,
                },
            )));
        }
        idx += 1;
        head = entry.next;
    }
    Ok(VfsOpResult::Complete(None))
}

/// Bits the tmpfs backend accepts on remount. Anything outside this
/// mask flipping triggers `TRONA_INVALID_OPERATION` so callers fail
/// loudly instead of silently drifting state. The set covers the
/// transitions tmpfs can honor without a full re-mount: read-only
/// flip, atime suppression, and case-fold mode.
const TMPFS_REMOUNT_FLAG_MASK: u32 = MNT_CASEFOLD | MNT_NOATIME | MNT_RDONLY;

/// Re-apply mount options to an already-mounted tmpfs. tmpfs accepts
/// `size=` / `nr_inodes=` / `nocase` / `casefold` / `noatime`. Other
/// flag transitions return `TRONA_INVALID_OPERATION`; unknown opt
/// tokens are silently ignored to match `mount(8) -o remount`.
///
/// Quota policy: a new `max_bytes` smaller than `accounted_bytes`
/// (resp. `max_inodes < used_inodes`) is accepted as "deny future
/// growth"; existing data stays in place. Future `try_account_*`
/// calls naturally hit `TRONA_NO_SPACE` until usage drops back below
/// the new ceiling.
fn tmpfs_remount(state: &mut VfsState, mount: MountHandle, new_flags: u32, opts: &[u8]) -> u64 {
    let current_flags = state.mounts.get(mount).map(|m| m.flags).unwrap_or(0);
    let changed = current_flags ^ new_flags;
    if changed & !TMPFS_REMOUNT_FLAG_MASK != 0 {
        return TRONA_INVALID_OPERATION;
    }
    // Refuse `MNT_RDONLY` flips when any file in this mount still has
    // an exported MO cap (mmsrv may be holding a writable shared
    // mapping). PTE downgrade for existing mappings is a separate
    // mmsrv-side workstream; the conservative guard here at least
    // prevents new writes through `write(2)` from racing with the
    // remount while mappings stay live.
    let going_rdonly = (current_flags & MNT_RDONLY) == 0 && (new_flags & MNT_RDONLY) != 0;
    if going_rdonly {
        let mut has_export = false;
        state.tmpfs_nodes.for_each_active(|_, node| {
            if node.owner_mount == mount && node.mmap_export_refs > 0 {
                has_export = true;
                return false;
            }
            true
        });
        if has_export {
            return TRONA_BUSY;
        }
    }
    let parsed = parse_mount_opts(opts);
    let Some(data_h) = find_mount_data_handle(state, mount) else {
        return TRONA_INVALID_OPERATION;
    };
    if let Some(data) = state.tmpfs_mounts.get_mut(data_h) {
        // None == "caller did not name this option" → keep the
        // pre-remount value so `mount -o remount,noatime` cannot
        // accidentally clear `size=64M`. Casefold likewise honors the
        // mount-flag word (already merged into `new_flags` upstream)
        // when no opt token is present.
        if let Some(v) = parsed.max_bytes {
            data.max_bytes = v;
        }
        if let Some(v) = parsed.max_inodes {
            data.max_inodes = v;
        }
        let casefold_token = parsed.casefold.unwrap_or(false);
        data.casefold = casefold_token || (new_flags & MNT_CASEFOLD) != 0;
    }
    TRONA_OK
}

fn tmpfs_statfs(state: &VfsState, mount: MountHandle, out: &mut StatfsSnapshot) -> u64 {
    let data_h = match find_mount_data_handle(state, mount) {
        Some(h) => h,
        None => return TRONA_INVALID_OPERATION,
    };
    let data = match state.tmpfs_mounts.get(data_h) {
        Some(d) => d,
        None => return TRONA_INVALID_OPERATION,
    };
    let fs_id = data.fs_instance_id.0;
    let flags = state.mounts.get(mount).map(|m| m.flags).unwrap_or(0);

    out.f_bsize = TMPFS_PAGE_BYTES;
    out.f_frsize = TMPFS_PAGE_BYTES;
    out.f_namemax = TMPFS_NAME_MAX as u64;
    out.f_fsid = fs_id;
    out.f_flag = flags as u64;

    if data.max_bytes != 0 {
        out.f_blocks = data.max_bytes / TMPFS_PAGE_BYTES;
        let free_bytes = data.max_bytes.saturating_sub(data.accounted_bytes);
        out.f_bfree = free_bytes / TMPFS_PAGE_BYTES;
        out.f_bavail = out.f_bfree;
    } else {
        // Unlimited tmpfs reports the global PMM picture so callers
        // (e.g. `df`) see realistic numbers rather than a zeroed mount.
        let mut snap = trona_kernel::core_types::sysinfo::TronaSysMemInfo::zeroed();
        let rc = trona_kernel::syscall::sys_sysmeminfo(&raw mut snap);
        if rc == TRONA_OK {
            out.f_blocks = snap.pages_total;
            out.f_bfree = snap.pages_free;
            out.f_bavail = snap.pages_free;
        } else {
            out.f_blocks = 0;
            out.f_bfree = 0;
            out.f_bavail = 0;
        }
    }

    if data.max_inodes != 0 {
        out.f_files = data.max_inodes;
        out.f_ffree = data.max_inodes.saturating_sub(data.used_inodes);
        out.f_favail = out.f_ffree;
    } else {
        out.f_files = state.tmpfs_nodes.capacity() as u64;
        out.f_ffree = state
            .tmpfs_nodes
            .capacity()
            .saturating_sub(state.tmpfs_nodes.len()) as u64;
        out.f_favail = out.f_ffree;
    }

    TRONA_OK
}
