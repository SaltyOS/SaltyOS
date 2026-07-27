// SPDX-License-Identifier: GPL-2.0-only
//! saltyfs — remote root filesystem bridge.
//!
//! The rebuilt VFS keeps saltyfs deliberately simple: one mounted
//! session, stable vnode identity keyed by `(fs_instance_id, remote
//! ino, seq)`, and deferred backend RPCs driven by the owner's worker
//! pool via `enqueue_saltyfs_op`. The owner thread never blocks on a
//! saltyfs IPC during a client request — every vop that needs to talk
//! to the backend yields a `Deferred(op_id)` and a worker drives the
//! actual `call_ctx`. The bootstrap path (initial mount, fs
//! registration) is the only place that calls the synchronous
//! `*_sync` helpers directly; runtime client requests must go through
//! the deferred framework.

use trona_kernel::core_types::*;
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_posix::consts::{DT_DIR, DT_LNK, DT_REG, PROT_READ, PROT_WRITE, S_IFMT};
use trona_protocol::posix::*;
use uapi::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;
use crate::vfs_core::cached_ref::CachedRef;
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};
use crate::vfs_core::mount::{MOUNT_BACKEND_SALTYFS, Mount, MountHandle};
use crate::vfs_core::vnode::{
    VNODE_BACKEND_SALTYFS, VT_CHR, VT_DIR, VT_FIFO, VT_LNK, VT_REG, VT_SOCK, Vnode, VnodeHandle,
};
use crate::vfs_core::vops::{VfsOpResult, VfsResult, VnodeOps};

pub(crate) type SaltyfsMountHandle = Handle<SaltyfsMountData>;
pub(crate) type SaltyfsNodeHandle = Handle<SaltyfsVnodeState>;

const SALTYFS_NAME_MAX: usize = 144;
const SALTYFS_SHM_VADDR: u64 = 0x0000_0000_5000_0000;
const SALTYFS_SHM_PAGES: u64 = 256;
const SALTYFS_SHM_ID: u64 = 0x56534653;
const SALTYFS_READDIR_ENTRY_BYTES: usize = 96;
const SALTYFS_READDIR_NAME_MAX: usize = 44;
const SALTYFS_NODE_PATH_ROOT: u8 = 0;
const SALTYFS_NODE_PATH_CHILD: u8 = 1;
const SALTYFS_CREATE_NAME_WIRE_MAX: usize = 136;
const SALTYFS_SYMLINK_NAME_WIRE_MAX: usize = 72;
const SALTYFS_RENAME_NAME_WIRE_MAX: usize = 64;
const SALTYFS_TARGET_INLINE_MAX: usize = 64;
const SALTYFS_DEFER_OP_NONE: u32 = 0;
const SALTYFS_DEFER_OP_CREATE: u32 = 1;
const SALTYFS_DEFER_OP_MKDIR: u32 = 2;
const SALTYFS_DEFER_OP_SYMLINK: u32 = 3;
const SALTYFS_DEFER_OP_UNLINK: u32 = 4;
const SALTYFS_DEFER_OP_RMDIR: u32 = 5;
const SALTYFS_DEFER_OP_RENAME: u32 = 6;
const SALTYFS_DEFER_OP_LINK: u32 = 7;
const SALTYFS_DEFER_OP_SETATTR: u32 = 8;

#[repr(C)]
#[derive(Clone, Copy)]
struct SaltyfsDeferredArgs {
    op: u32,
    mode: u32,
    flags: u32,
    name_a_len: u16,
    name_b_len: u16,
    target_len: u16,
    _pad0: [u8; 6],
    name_a: [u8; SALTYFS_NAME_MAX],
    name_b: [u8; SALTYFS_NAME_MAX],
    target: [u8; SALTYFS_TARGET_INLINE_MAX],
}

impl SaltyfsDeferredArgs {
    const fn zeroed() -> Self {
        Self {
            op: SALTYFS_DEFER_OP_NONE,
            mode: 0,
            flags: 0,
            name_a_len: 0,
            name_b_len: 0,
            target_len: 0,
            _pad0: [0; 6],
            name_a: [0; SALTYFS_NAME_MAX],
            name_b: [0; SALTYFS_NAME_MAX],
            target: [0; SALTYFS_TARGET_INLINE_MAX],
        }
    }

    fn with_name(op: u32, name: &[u8], mode: u32, flags: u32) -> Option<Self> {
        if name.len() > SALTYFS_NAME_MAX {
            return None;
        }
        let mut args = Self::zeroed();
        args.op = op;
        args.mode = mode;
        args.flags = flags;
        args.name_a_len = name.len() as u16;
        args.name_a[..name.len()].copy_from_slice(name);
        Some(args)
    }

    fn with_symlink(name: &[u8], target: &[u8]) -> Option<Self> {
        if name.len() > SALTYFS_NAME_MAX || target.len() > SALTYFS_TARGET_INLINE_MAX {
            return None;
        }
        let mut args = Self::zeroed();
        args.op = SALTYFS_DEFER_OP_SYMLINK;
        args.name_a_len = name.len() as u16;
        args.target_len = target.len() as u16;
        args.name_a[..name.len()].copy_from_slice(name);
        args.target[..target.len()].copy_from_slice(target);
        Some(args)
    }

    fn with_two_names(op: u32, name_a: &[u8], name_b: &[u8]) -> Option<Self> {
        if name_a.len() > SALTYFS_NAME_MAX || name_b.len() > SALTYFS_NAME_MAX {
            return None;
        }
        let mut args = Self::zeroed();
        args.op = op;
        args.name_a_len = name_a.len() as u16;
        args.name_b_len = name_b.len() as u16;
        args.name_a[..name_a.len()].copy_from_slice(name_a);
        args.name_b[..name_b.len()].copy_from_slice(name_b);
        Some(args)
    }

    fn name_a(&self) -> &[u8] {
        &self.name_a[..(self.name_a_len as usize).min(self.name_a.len())]
    }

    fn name_b(&self) -> &[u8] {
        &self.name_b[..(self.name_b_len as usize).min(self.name_b.len())]
    }

    fn target(&self) -> &[u8] {
        &self.target[..(self.target_len as usize).min(self.target.len())]
    }
}

const _SALTYFS_DEFERRED_ARGS_FITS: () = assert!(
    core::mem::size_of::<SaltyfsDeferredArgs>() <= crate::owner::pending_ops::PAYLOAD_BUF_BYTES
);

#[derive(Clone, Copy)]
struct SaltyfsLookupSnapshot {
    ino: u64,
    seq: u32,
    mode: u32,
    size: u64,
    nlink: u32,
    mtime: u64,
    uid: u32,
    gid: u32,
    dir_type: u8,
    blocks: u64,
}

#[derive(Clone, Copy)]
struct SaltyfsAttrSnapshot {
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    nlink: u32,
    atime: u64,
    mtime: u64,
}

static SALTYFS_VFSOPS: crate::vfs_core::vfsops::VfsOps = crate::vfs_core::vfsops::VfsOps {
    statfs: None,
    sync: None,
    remount: Some(saltyfs_remount),
    resolve_backing: None,
    reclaim_vnode: None,
};
static SALTYFS_VOPS: VnodeOps = VnodeOps {
    lookup_child: Some(lookup_child),
    build_path: Some(build_path_for_vnode),
    ensure_symlink_target: Some(ensure_symlink_target),
    readlink_inline: None,
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

#[repr(C)]
pub(crate) struct SaltyfsMountData {
    pub(crate) owner_mount: MountHandle,
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) root_vnode: VnodeHandle,
    pub(crate) fs_cap: u64,
    pub(crate) session_id: u32,
    pub(crate) max_inflight: u16,
    _pad0: [u8; 2],
    pub(crate) root_node: BackendNodeId,
    pub(crate) feature_bits: u64,
    pub(crate) shm_active: u8,
    /// Suppress access-time updates. Set when `noatime` appears in the
    /// mount opts or `MNT_NOATIME` is in the flag word; honored by
    /// `refresh_vnode_attrs` and the open-time atime stamp.
    pub(crate) noatime: u8,
    _pad1: [u8; 6],
    pub(crate) shm_vaddr: u64,
    pub(crate) shm_size: u64,
}

impl SaltyfsMountData {
    pub(crate) const fn zeroed() -> Self {
        Self {
            owner_mount: MountHandle::INVALID,
            fs_instance_id: FsInstanceId::INVALID,
            root_vnode: VnodeHandle::INVALID,
            fs_cap: 0,
            session_id: 0,
            max_inflight: 0,
            _pad0: [0; 2],
            root_node: BackendNodeId::INVALID,
            feature_bits: 0,
            shm_active: 0,
            noatime: 0,
            _pad1: [0; 6],
            shm_vaddr: 0,
            shm_size: 0,
        }
    }
}

/// Read-only-mount guard for the saltyfs vops. The authoritative
/// signal is `Mount.flags & MNT_RDONLY`; the per-mount-data
/// `readonly` byte stays in sync via remount and exists only as a
/// fast-path snapshot for paths that already hold a `SaltyfsMountData`
/// reference and want to avoid a second mount-table lookup.
fn ensure_writable(state: &VfsState, vnode: VnodeHandle) -> Result<(), u64> {
    let mount = state
        .vnodes
        .get(vnode)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let read_only = state
        .mounts
        .get(mount)
        .map(|m| (m.flags & crate::vfs_core::mount::MNT_RDONLY) != 0)
        .unwrap_or(false);
    if read_only {
        Err(TRONA_READONLY)
    } else {
        Ok(())
    }
}

/// Returns true when the saltyfs mount carrying `vnode` was mounted
/// with `noatime` semantics. atime-update sites consult this to skip
/// the syscall round-trip the server would otherwise charge.
pub(crate) fn mount_is_noatime(state: &VfsState, vnode: VnodeHandle) -> bool {
    mount_data_for_vnode(state, vnode)
        .map(|(md, _)| md.noatime != 0)
        .unwrap_or(false)
}

#[repr(C)]
pub(crate) struct SaltyfsVnodeState {
    pub(crate) owner_mount: MountHandle,
    pub(crate) vnode: VnodeHandle,
    pub(crate) node_id: BackendNodeId,
    pub(crate) parent_node: SaltyfsNodeHandle,
    pub(crate) blocks: u64,
    pub(crate) path_kind: u8,
    pub(crate) name_len: u8,
    _pad0: [u8; 6],
    pub(crate) name: [u8; SALTYFS_NAME_MAX],
}

impl SaltyfsVnodeState {
    pub(crate) const fn zeroed() -> Self {
        Self {
            owner_mount: MountHandle::INVALID,
            vnode: VnodeHandle::INVALID,
            node_id: BackendNodeId::INVALID,
            parent_node: SaltyfsNodeHandle::INVALID,
            blocks: 0,
            path_kind: SALTYFS_NODE_PATH_ROOT,
            name_len: 0,
            _pad0: [0; 6],
            name: [0; SALTYFS_NAME_MAX],
        }
    }
}

enum MountPrefixSource {
    CoveredAnchor(crate::vfs_core::namei::PathAnchor),
    CanonicalMountPath,
}

enum SaltyfsPathRole {
    MountedRoot(MountHandle),
    Child(SaltyfsNodeHandle),
}

#[inline]
pub(crate) fn mount_is_saltyfs(mount: &Mount) -> bool {
    mount.backend_kind == MOUNT_BACKEND_SALTYFS
}

#[inline]
pub(crate) fn saltyfs_vfsops() -> *const () {
    &raw const SALTYFS_VFSOPS as *const crate::vfs_core::vfsops::VfsOps as *const ()
}

#[inline]
pub(crate) fn saltyfs_vops() -> *const () {
    &raw const SALTYFS_VOPS as *const VnodeOps as *const ()
}

fn find_mount_data_handle(
    state: &VfsState,
    owner_mount: MountHandle,
) -> Option<SaltyfsMountHandle> {
    let mut found = SaltyfsMountHandle::INVALID;
    state.saltyfs_mounts.for_each_active(|handle, data| {
        if data.owner_mount == owner_mount {
            found = handle;
            return false;
        }
        true
    });
    found.is_valid().then_some(found)
}

fn find_node_handle_by_vnode(state: &VfsState, vnode: VnodeHandle) -> Option<SaltyfsNodeHandle> {
    let vnode_ref = state.vnodes.get(vnode)?;
    let handle = vnode_ref.backend_ref::<SaltyfsVnodeState>();
    state
        .saltyfs_nodes
        .get(handle)
        .filter(|node| node.vnode == vnode)
        .map(|_| handle)
}

fn find_node_handle_by_vnode_mut(
    state: &mut VfsState,
    vnode: VnodeHandle,
) -> Option<SaltyfsNodeHandle> {
    let found = find_node_handle_by_vnode(state, vnode)?;
    if let Some(vnode_ref) = state.vnodes.get_mut(vnode) {
        vnode_ref.set_backend_ref(found);
    }
    Some(found)
}

fn find_child_node_handle_by_name(
    state: &VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
) -> Option<SaltyfsNodeHandle> {
    let parent_node = find_node_handle_by_vnode(state, parent_vh)?;
    let mut found = SaltyfsNodeHandle::INVALID;
    state.saltyfs_nodes.for_each_active(|handle, node| {
        let node_name_len = node.name_len as usize;
        if node.parent_node == parent_node
            && node_name_len == name.len()
            && &node.name[..node_name_len] == name
        {
            found = handle;
            return false;
        }
        true
    });
    found.is_valid().then_some(found)
}

fn mark_cached_child_unlinked(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    remove_dir: bool,
) {
    let Some(node_h) = find_child_node_handle_by_name(state, parent_vh, name) else {
        return;
    };
    let child_vh = state
        .saltyfs_nodes
        .get(node_h)
        .map(|node| node.vnode)
        .unwrap_or(VnodeHandle::INVALID);
    if let Some(vn) = state.vnodes.get_mut(child_vh) {
        if remove_dir {
            vn.nlink = 0;
        } else {
            vn.nlink = vn.nlink.saturating_sub(1);
        }
    }
    state.uncache_vnode_key(child_vh);
    if let Some(node) = state.saltyfs_nodes.get_mut(node_h) {
        node.name_len = 0;
        node.name = [0; SALTYFS_NAME_MAX];
    }
}

fn note_cached_child_renamed(
    state: &mut VfsState,
    old_parent_vh: VnodeHandle,
    old_name: &[u8],
    new_parent_vh: VnodeHandle,
    new_name: &[u8],
) {
    let moved = find_child_node_handle_by_name(state, old_parent_vh, old_name);
    let overwritten = find_child_node_handle_by_name(state, new_parent_vh, new_name);
    if let Some(overwritten_h) = overwritten {
        if Some(overwritten_h) != moved {
            let overwritten_vh = state
                .saltyfs_nodes
                .get(overwritten_h)
                .map(|node| node.vnode)
                .unwrap_or(VnodeHandle::INVALID);
            if let Some(vn) = state.vnodes.get_mut(overwritten_vh) {
                vn.nlink = 0;
            }
            state.uncache_vnode_key(overwritten_vh);
            if let Some(node) = state.saltyfs_nodes.get_mut(overwritten_h) {
                node.name_len = 0;
                node.name = [0; SALTYFS_NAME_MAX];
            }
        }
    }
    let Some(moved_h) = moved else {
        return;
    };
    let Some(new_parent_node) = find_node_handle_by_vnode_mut(state, new_parent_vh) else {
        return;
    };
    if let Some(node) = state.saltyfs_nodes.get_mut(moved_h) {
        node.parent_node = new_parent_node;
        node.name = [0; SALTYFS_NAME_MAX];
        let copy_len = core::cmp::min(new_name.len(), SALTYFS_NAME_MAX);
        node.name_len = copy_len as u8;
        node.name[..copy_len].copy_from_slice(&new_name[..copy_len]);
    }
}

fn page_align_up(bytes: u64) -> u64 {
    (bytes + 4095) & !4095
}

fn mode_to_vtype(mode: u32, dir_type: u8) -> u8 {
    match (mode as u64) & S_IFMT {
        trona_posix::consts::S_IFDIR => VT_DIR,
        trona_posix::consts::S_IFREG => VT_REG,
        trona_posix::consts::S_IFLNK => VT_LNK,
        trona_posix::consts::S_IFCHR => VT_CHR,
        trona_posix::consts::S_IFIFO => VT_FIFO,
        trona_posix::consts::S_IFSOCK => VT_SOCK,
        _ => match dir_type {
            DT_DIR => VT_DIR,
            DT_REG => VT_REG,
            DT_LNK => VT_LNK,
            _ => VT_REG,
        },
    }
}

fn readdir_dtype(mode: u32, raw_dtype: u8) -> u8 {
    if raw_dtype != 0 {
        return raw_dtype;
    }
    match mode_to_vtype(mode, 0) {
        VT_DIR => trona_posix::consts::DT_DIR,
        VT_REG => trona_posix::consts::DT_REG,
        VT_LNK => trona_posix::consts::DT_LNK,
        VT_CHR => trona_posix::consts::DT_CHR,
        VT_FIFO => trona_posix::consts::DT_FIFO,
        VT_SOCK => trona_posix::consts::DT_SOCK,
        _ => trona_posix::consts::DT_UNKNOWN,
    }
}

unsafe fn resolve_endpoint() -> Result<u64, u64> {
    unsafe {
        if trona_runtime::client::caps::namesrv_ep() == 0 {
            return Err(TRONA_NOT_FOUND);
        }

        let slot = match trona_runtime::core::slot_alloc::slot_alloc() {
            Some(slot) => slot,
            None => return Err(TRONA_OUT_OF_MEMORY),
        };
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            crate::ipc_ctx(),
            CAP_SELF_CSPACE,
            slot,
            0,
        );

        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        let name = b"saltyfs";
        req.label = NAMESRV_LOOKUP;
        req.regs[0] = name.len() as u64;
        req.length = 1 + ((name.len() as u64) + 7) / 8;
        let dst = &raw mut req.regs[1] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }

        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep(),
            &raw const req,
            &raw mut reply,
        );
        if err != 0 || reply.label != TRONA_OK {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, slot);
            let _ = trona_runtime::core::slot_alloc::slot_free(slot);
            return Err(TRONA_NOT_FOUND);
        }

        Ok(slot)
    }
}

unsafe fn open_session(fs_cap: u64, flags: u32) -> Result<BackendOpenSessionReply, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_OPEN_SESSION;
        req.length = 1;
        req.regs[0] = if (flags & 1) != 0 { 1 } else { 0 };

        let err = ipc::call_ctx(crate::ipc_ctx(), fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK && reply.label != TRONA_ALREADY_EXISTS {
            return Err(reply.label);
        }
        Ok(BackendOpenSessionReply::decode_regs([
            reply.regs[0],
            reply.regs[1],
            reply.regs[2],
            reply.regs[3],
        ]))
    }
}

unsafe fn setup_shm(md: &mut SaltyfsMountData) {
    unsafe {
        let mut create = TronaMsg::zeroed();
        let mut create_reply = TronaMsg::zeroed();
        create.label = MM_SHM_CREATE;
        create.length = 2;
        create.regs[0] = SALTYFS_SHM_ID;
        create.regs[1] = SALTYFS_SHM_PAGES;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const create,
            &raw mut create_reply,
        );
        if err != 0
            || (create_reply.label != TRONA_OK && create_reply.label != TRONA_ALREADY_EXISTS)
        {
            return;
        }

        let mut map = TronaMsg::zeroed();
        let mut map_reply = TronaMsg::zeroed();
        map.label = MM_SHM_MAP;
        map.length = 4;
        map.regs[0] = SALTYFS_SHM_ID;
        map.regs[1] = 0;
        map.regs[2] = SALTYFS_SHM_VADDR;
        map.regs[3] = (PROT_READ | PROT_WRITE) as u64;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::mmsrv_ep(),
            &raw const map,
            &raw mut map_reply,
        );
        if err != 0 || map_reply.label != TRONA_OK {
            return;
        }

        let mut setup = TronaMsg::zeroed();
        let mut setup_reply = TronaMsg::zeroed();
        setup.label = BACKEND_SHM_SETUP;
        setup.length = 1;
        setup.regs[0] = SALTYFS_SHM_ID;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            md.fs_cap,
            &raw const setup,
            &raw mut setup_reply,
        );
        if err != 0 || setup_reply.label != TRONA_OK {
            let mut unmap = TronaMsg::zeroed();
            let mut unmap_reply = TronaMsg::zeroed();
            unmap.label = MM_SHM_UNMAP;
            unmap.length = 3;
            unmap.regs[0] = SALTYFS_SHM_ID;
            unmap.regs[1] = 0;
            unmap.regs[2] = SALTYFS_SHM_VADDR;
            let _ = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const unmap,
                &raw mut unmap_reply,
            );
            return;
        }

        md.shm_active = 1;
        md.shm_vaddr = SALTYFS_SHM_VADDR;
        md.shm_size = SALTYFS_SHM_PAGES * 4096;
    }
}

fn mount_data_for_vnode<'a>(
    state: &'a VfsState,
    vnode: VnodeHandle,
) -> Option<(&'a SaltyfsMountData, MountHandle)> {
    let vnode_ref = state.vnodes.get(vnode)?;
    let mount = vnode_ref.mount.handle;
    let mount_ref = state.mounts.get(mount)?;
    if !mount_is_saltyfs(mount_ref) {
        return None;
    }
    let data_h = find_mount_data_handle(state, mount)?;
    Some((state.saltyfs_mounts.get(data_h)?, mount))
}

unsafe fn alloc_saltyfs_backend_op() -> Result<crate::owner::pending_ops::PendingOpId, u64> {
    unsafe {
        let Some(op_id) = crate::owner::pending_ops::alloc(
            crate::owner::pending_ops::PO_KIND_BACKEND_RPC,
            0,
            crate::server::types::ClientHandle::INVALID,
            0,
        ) else {
            return Err(TRONA_OUT_OF_MEMORY);
        };
        if !crate::owner::continuation::init_continuation_payload_done(
            op_id,
            VnodeHandle::INVALID,
            crate::owner::namei::NAMEI_AUX_NONE,
            crate::owner::namei::namei_aux_none(),
        ) {
            crate::owner::pending_ops::free(op_id);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        Ok(op_id)
    }
}

unsafe fn write_saltyfs_args(
    op_id: crate::owner::pending_ops::PendingOpId,
    args: &SaltyfsDeferredArgs,
) -> bool {
    unsafe {
        let Some(args_payload_ref) = crate::owner::pending_ops::alloc_payload() else {
            return false;
        };
        let Some(buf) = crate::owner::pending_ops::payload_bytes_mut(args_payload_ref) else {
            crate::owner::pending_ops::release_payload(args_payload_ref);
            return false;
        };
        core::ptr::write(buf.as_mut_ptr() as *mut SaltyfsDeferredArgs, *args);
        let Some(op) = crate::owner::pending_ops::get_mut(op_id) else {
            crate::owner::pending_ops::release_payload(args_payload_ref);
            return false;
        };
        op.args_payload_ref = args_payload_ref;
        true
    }
}

unsafe fn read_saltyfs_args(
    op_id: crate::owner::pending_ops::PendingOpId,
) -> Option<SaltyfsDeferredArgs> {
    unsafe {
        let args_payload_ref = crate::owner::pending_ops::get(op_id)?.args_payload_ref;
        let buf = crate::owner::pending_ops::payload_bytes(args_payload_ref)?;
        Some(core::ptr::read(buf.as_ptr() as *const SaltyfsDeferredArgs))
    }
}

unsafe fn set_saved_current_vnode(
    op_id: crate::owner::pending_ops::PendingOpId,
    vnode: VnodeHandle,
) -> bool {
    unsafe {
        let payload_ref = crate::owner::pending_ops::get(op_id)
            .map(|op| op.payload_ref)
            .unwrap_or(crate::owner::pending_ops::INVALID_PAYLOAD_REF);
        let Some(buf) = crate::owner::pending_ops::payload_bytes_mut(payload_ref) else {
            return false;
        };
        let state_ptr = buf.as_mut_ptr() as *mut crate::owner::namei::NameiResumeState;
        (*state_ptr).resume_step = crate::owner::namei::NAMEI_STEP_DONE;
        (*state_ptr).current_packed = pack_vh(vnode);
        true
    }
}

unsafe fn pending_op_kind(
    op_id: crate::owner::pending_ops::PendingOpId,
) -> crate::owner::pending_ops::PendingOpKind {
    unsafe {
        crate::owner::pending_ops::get(op_id)
            .map(|op| op.kind)
            .unwrap_or(crate::owner::pending_ops::PO_KIND_NONE)
    }
}

unsafe fn finish_saltyfs_continuation(op_id: crate::owner::pending_ops::PendingOpId, label: u64) {
    unsafe {
        let mut reply = TronaMsg::zeroed();
        reply.label = label;
        crate::owner::continuation::finish_continuation(op_id, reply);
    }
}

unsafe fn finish_saltyfs_completion_error(
    op_id: crate::owner::pending_ops::PendingOpId,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let reply = (*completion).backend_reply;
        if (*completion).backend_err == 0 && reply.label == TRONA_OK {
            return false;
        }
        let label = if (*completion).backend_err != 0 {
            TRONA_IO_ERROR
        } else {
            reply.label
        };
        finish_saltyfs_continuation(op_id, label);
        true
    }
}

fn parse_lookup_snapshot(reply: &TronaMsg) -> Option<SaltyfsLookupSnapshot> {
    if reply.label != TRONA_OK || reply.length < 10 {
        return None;
    }
    Some(SaltyfsLookupSnapshot {
        ino: reply.regs[0],
        seq: reply.regs[1] as u32,
        mode: reply.regs[2] as u32,
        size: reply.regs[3],
        nlink: reply.regs[4] as u32,
        mtime: reply.regs[5],
        uid: reply.regs[6] as u32,
        gid: reply.regs[7] as u32,
        dir_type: reply.regs[8] as u8,
        blocks: reply.regs[9],
    })
}

fn parse_attr_snapshot(reply: &TronaMsg) -> Option<SaltyfsAttrSnapshot> {
    if reply.label != TRONA_OK || reply.length < BACKEND_SETATTR_REPLY_REG_COUNT as u64 {
        return None;
    }
    Some(SaltyfsAttrSnapshot {
        mode: reply.regs[0] as u32,
        uid: reply.regs[1] as u32,
        gid: reply.regs[2] as u32,
        size: reply.regs[3],
        nlink: reply.regs[4] as u32,
        atime: reply.regs[5],
        mtime: reply.regs[6],
    })
}

unsafe fn enqueue_saltyfs_request(
    backend_op: crate::owner::backend_rpc::BackendOpKind,
    fs_cap: u64,
    request: TronaMsg,
    ctx_data: [u64; 6],
    args: Option<&SaltyfsDeferredArgs>,
) -> Result<crate::owner::pending_ops::PendingOpId, u64> {
    unsafe {
        let op_id = alloc_saltyfs_backend_op()?;
        if let Some(args) = args {
            if !write_saltyfs_args(op_id, args) {
                crate::owner::pending_ops::free(op_id);
                return Err(TRONA_OUT_OF_MEMORY);
            }
        }
        if !crate::owner::backend_rpc::enqueue_saltyfs_op(
            op_id, backend_op, fs_cap, request, ctx_data,
        ) {
            crate::owner::pending_ops::free(op_id);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        Ok(op_id)
    }
}

unsafe fn stat_sync(
    md: &SaltyfsMountData,
    ino: u64,
) -> Result<(u64, u32, u32, u64, u64, u32, u32, u32), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_STAT;
        req.length = 1;
        req.regs[0] = ino;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok((
            reply.regs[1],
            reply.regs[2] as u32,
            reply.regs[3] as u32,
            reply.regs[4],
            reply.regs[5],
            reply.regs[6] as u32,
            reply.regs[7] as u32,
            reply.regs[8] as u32,
        ))
    }
}

unsafe fn lookup_sync(
    md: &SaltyfsMountData,
    parent_ino: u64,
    name: &[u8],
) -> Result<Option<(u64, u32, u32, u64, u32, u64, u32, u32, u8, u64)>, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_LOOKUP;
        req.regs[0] = parent_ino;
        req.regs[1] = name.len() as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }
        req.length = 2 + ((name.len() as u64) + 7) / 8;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        match reply.label {
            TRONA_OK => Ok(Some((
                reply.regs[0],
                reply.regs[1] as u32,
                reply.regs[2] as u32,
                reply.regs[3],
                reply.regs[4] as u32,
                reply.regs[5],
                reply.regs[6] as u32,
                reply.regs[7] as u32,
                reply.regs[8] as u8,
                reply.regs[9],
            ))),
            TRONA_NOT_FOUND => Ok(None),
            other => Err(other),
        }
    }
}

#[allow(dead_code)]
unsafe fn readlink_sync(
    md: &SaltyfsMountData,
    ino: u64,
) -> Result<([u8; INLINE_TRANSFER_WIRE_MAX as usize], usize), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_READLINK;
        req.length = 1;
        req.regs[0] = ino;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        let len = core::cmp::min(reply.regs[0] as usize, INLINE_TRANSFER_WIRE_MAX as usize);
        let mut out = [0u8; INLINE_TRANSFER_WIRE_MAX as usize];
        let src = &raw const reply.regs[1] as *const u64 as *const u8;
        for (idx, dst) in out.iter_mut().enumerate().take(len) {
            *dst = *src.add(idx);
        }
        Ok((out, len))
    }
}

unsafe fn read_sync(
    md: &SaltyfsMountData,
    ino: u64,
    file_offset: u64,
    out: *mut u8,
    cap: usize,
) -> Result<usize, u64> {
    unsafe {
        let use_shm = md.shm_active != 0 && cap > INLINE_TRANSFER_WIRE_MAX as usize;
        let transfer = if use_shm {
            TransferDescriptor::shm(0, cap as u64)
        } else {
            TransferDescriptor::inline(core::cmp::min(cap as u64, INLINE_TRANSFER_WIRE_MAX))
        };

        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_READ;
        req.length = 5;
        req.regs[0] = ino;
        req.regs[1] = file_offset;
        let regs = transfer.encode_regs();
        req.regs[2] = regs[0];
        req.regs[3] = regs[1];
        req.regs[4] = regs[2];

        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        let actual = core::cmp::min(reply.regs[0] as usize, cap);
        if actual == 0 {
            return Ok(0);
        }
        if use_shm {
            let src = md.shm_vaddr as *const u8;
            core::ptr::copy_nonoverlapping(src, out, actual);
        } else {
            let src = &raw const reply.regs[1] as *const u64 as *const u8;
            core::ptr::copy_nonoverlapping(src, out, actual);
        }
        Ok(actual)
    }
}

unsafe fn readdir_sync(
    md: &SaltyfsMountData,
    dir_ino: u64,
    cursor: u64,
) -> Result<(u64, usize, usize, u64), u64> {
    unsafe {
        if md.shm_active == 0
            || md.shm_vaddr == 0
            || md.shm_size < SALTYFS_READDIR_ENTRY_BYTES as u64
        {
            return Err(TRONA_INVALID_OPERATION);
        }
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_READDIR;
        req.length = 4;
        req.regs[0] = dir_ino;
        req.regs[1] = cursor;
        req.regs[2] = 0;
        req.regs[3] = SALTYFS_READDIR_ENTRY_BYTES as u64;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok((
            reply.regs[0],
            reply.regs[1] as usize,
            reply.regs[2] as usize,
            reply.regs[3],
        ))
    }
}

#[allow(dead_code)]
unsafe fn setattr_sync(
    md: &SaltyfsMountData,
    ino: u64,
    mask: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    size: u64,
) -> Result<(u32, u32, u32, u64, u32, u64, u64), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_SETATTR;
        req.length = BACKEND_SETATTR_REG_COUNT as u64;
        req.regs[0] = ino;
        req.regs[1] = mask as u64;
        req.regs[2] = mode as u64;
        req.regs[3] = (uid as u64) | ((gid as u64) << 32);
        req.regs[4] = atime;
        req.regs[5] = mtime;
        req.regs[6] = size;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok((
            reply.regs[0] as u32,
            reply.regs[1] as u32,
            reply.regs[2] as u32,
            reply.regs[3],
            reply.regs[4] as u32,
            reply.regs[5],
            reply.regs[6],
        ))
    }
}

#[allow(dead_code)]
unsafe fn truncate_sync(md: &SaltyfsMountData, ino: u64, new_size: u64) -> Result<(), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_TRUNCATE;
        req.length = 2;
        req.regs[0] = ino;
        req.regs[1] = new_size;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

unsafe fn write_sync(
    md: &SaltyfsMountData,
    ino: u64,
    file_offset: u64,
    src: *const u8,
    len: usize,
) -> Result<u64, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        let desc = TransferDescriptor::inline(len as u64).encode_regs();
        req.label = BACKEND_WRITE;
        req.regs[0] = ino;
        req.regs[1] = file_offset;
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG] = desc[0];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 1] = desc[1];
        req.regs[BACKEND_RW_REQ_DESCRIPTOR_REG + 2] = desc[2];
        let dst = &raw mut req.regs[BACKEND_WRITE_INLINE_PAYLOAD_REG] as *mut u8;
        for idx in 0..len {
            *dst.add(idx) = *src.add(idx);
        }
        req.length = (BACKEND_WRITE_INLINE_PAYLOAD_REG as u64) + ((len as u64 + 7) / 8);
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

#[allow(dead_code)]
unsafe fn create_sync(
    md: &SaltyfsMountData,
    parent_ino: u64,
    name: &[u8],
    mode: u32,
) -> Result<u64, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_CREATE;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = name.len() as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }
        req.length = 3 + ((name.len() as u64) + 7) / 8;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

unsafe fn mkdir_sync(
    md: &SaltyfsMountData,
    parent_ino: u64,
    name: &[u8],
    mode: u32,
) -> Result<u64, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_MKDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = mode as u64;
        req.regs[2] = name.len() as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }
        req.length = 3 + ((name.len() as u64) + 7) / 8;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

#[allow(dead_code)]
unsafe fn symlink_sync(
    md: &SaltyfsMountData,
    parent_ino: u64,
    name: &[u8],
    target: &[u8],
) -> Result<u64, u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_SYMLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name.len() as u64;
        req.regs[2] = target.len() as u64;
        let dst_name = &raw mut req.regs[3] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst_name.add(idx) = *byte;
        }
        let dst_target = &raw mut req.regs[12] as *mut u8;
        for (idx, byte) in target.iter().enumerate() {
            *dst_target.add(idx) = *byte;
        }
        req.length = 20;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(reply.regs[0])
    }
}

#[allow(dead_code)]
unsafe fn unlink_sync(md: &SaltyfsMountData, parent_ino: u64, name: &[u8]) -> Result<(), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_UNLINK;
        req.regs[0] = parent_ino;
        req.regs[1] = name.len() as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }
        req.length = 2 + ((name.len() as u64) + 7) / 8;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

#[allow(dead_code)]
unsafe fn rmdir_sync(md: &SaltyfsMountData, parent_ino: u64, name: &[u8]) -> Result<(), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_RMDIR;
        req.regs[0] = parent_ino;
        req.regs[1] = name.len() as u64;
        let dst = &raw mut req.regs[2] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }
        req.length = 2 + ((name.len() as u64) + 7) / 8;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

#[allow(dead_code)]
unsafe fn rename_sync(
    md: &SaltyfsMountData,
    old_parent_ino: u64,
    old_name: &[u8],
    new_parent_ino: u64,
    new_name: &[u8],
) -> Result<(), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_RENAME;
        req.regs[0] = old_parent_ino;
        req.regs[1] = old_name.len() as u64;
        req.regs[2] = new_parent_ino;
        req.regs[3] = new_name.len() as u64;
        let dst_old = &raw mut req.regs[4] as *mut u8;
        for (idx, byte) in old_name.iter().enumerate() {
            *dst_old.add(idx) = *byte;
        }
        let dst_new = &raw mut req.regs[12] as *mut u8;
        for (idx, byte) in new_name.iter().enumerate() {
            *dst_new.add(idx) = *byte;
        }
        req.length = 20;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

#[allow(dead_code)]
unsafe fn link_sync(
    md: &SaltyfsMountData,
    existing_ino: u64,
    new_parent_ino: u64,
    name: &[u8],
) -> Result<(), u64> {
    unsafe {
        let mut req = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        req.label = BACKEND_LINK;
        req.regs[0] = existing_ino;
        req.regs[1] = new_parent_ino;
        req.regs[2] = name.len() as u64;
        let dst = &raw mut req.regs[3] as *mut u8;
        for (idx, byte) in name.iter().enumerate() {
            *dst.add(idx) = *byte;
        }
        req.length = 3 + ((name.len() as u64) + 7) / 8;
        let err = ipc::call_ctx(crate::ipc_ctx(), md.fs_cap, &raw const req, &raw mut reply);
        if err != 0 {
            return Err(TRONA_IO_ERROR);
        }
        if reply.label != TRONA_OK {
            return Err(reply.label);
        }
        Ok(())
    }
}

fn update_symlink_payload(state: &mut VfsState, vnode: VnodeHandle, bytes: &[u8]) -> bool {
    let Some(vn) = state.vnodes.get_mut(vnode) else {
        return false;
    };
    if !vn.data.is_null() && vn.size != 0 {
        let _ = unsafe { crate::server::mem::unmap(vn.data, page_align_up(vn.size)) };
        vn.data = core::ptr::null_mut();
        vn.size = 0;
    }
    if bytes.is_empty() {
        return true;
    }
    let alloc = page_align_up(bytes.len() as u64);
    let ptr = unsafe { crate::server::mem::map_anon(alloc) };
    if ptr.is_null() || ptr == usize::MAX as *mut u8 {
        return false;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
    }
    vn.data = ptr;
    vn.size = bytes.len() as u64;
    true
}

fn install_node_state(
    state: &mut VfsState,
    owner_mount: MountHandle,
    vnode: VnodeHandle,
    node_id: BackendNodeId,
    parent_node: SaltyfsNodeHandle,
    name: &[u8],
    blocks: u64,
) -> Option<SaltyfsNodeHandle> {
    let handle = if let Some(existing) = find_node_handle_by_vnode_mut(state, vnode) {
        existing
    } else {
        state.saltyfs_nodes.alloc()?
    };
    {
        let node = state.saltyfs_nodes.get_mut(handle)?;
        *node = SaltyfsVnodeState::zeroed();
        node.owner_mount = owner_mount;
        node.vnode = vnode;
        node.node_id = node_id;
        node.parent_node = parent_node;
        node.blocks = blocks;
        node.path_kind = if parent_node.is_valid() {
            SALTYFS_NODE_PATH_CHILD
        } else {
            SALTYFS_NODE_PATH_ROOT
        };
        let copy_len = core::cmp::min(name.len(), SALTYFS_NAME_MAX);
        node.name_len = copy_len as u8;
        node.name[..copy_len].copy_from_slice(&name[..copy_len]);
    }
    let vnode_ref = state.vnodes.get_mut(vnode)?;
    vnode_ref.set_backend_ref(handle);
    state.cache_vnode_key(vnode);
    Some(handle)
}

fn lookup_created_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    owner_mount: MountHandle,
    name: &[u8],
) -> Result<VnodeHandle, u64> {
    let parent_ino = match state.vnodes.get(parent_vh) {
        Some(vn) => vn.id,
        None => return Err(TRONA_NOT_FOUND),
    };
    let child = {
        let Some((md, _)) = mount_data_for_vnode(state, parent_vh) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        unsafe { lookup_sync(md, parent_ino, name) }?
    };
    let Some((ino, seq, mode, size, nlink, mtime, uid, gid, dir_type, blocks)) = child else {
        return Err(TRONA_NOT_FOUND);
    };
    materialize_child_vnode(
        state,
        owner_mount,
        parent_vh,
        name,
        ino,
        seq,
        mode,
        size,
        nlink,
        mtime,
        uid,
        gid,
        dir_type,
        blocks,
    )
    .ok_or(TRONA_OUT_OF_MEMORY)
}

fn refresh_vnode_attrs(state: &mut VfsState, vnode: VnodeHandle) -> Result<(), u64> {
    let ino = match state.vnodes.get(vnode) {
        Some(vn) => vn.id,
        None => return Err(TRONA_NOT_FOUND),
    };
    let old_key = state
        .vnodes
        .get(vnode)
        .map(|vn| vn.vnode_key())
        .unwrap_or(VnodeKey::INVALID);
    let stat = {
        let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        unsafe { stat_sync(md, ino) }?
    };
    let Some(vn) = state.vnodes.get_mut(vnode) else {
        return Err(TRONA_NOT_FOUND);
    };
    vn.size = stat.0;
    vn.mode = stat.1;
    vn.nlink = stat.2;
    vn.mtime_ns = stat.3.saturating_mul(1_000_000_000);
    vn.atime_ns = stat.3.saturating_mul(1_000_000_000);
    vn.uid = stat.5;
    vn.gid = stat.6;
    vn.backend_seq = stat.7;
    vn.vtype = mode_to_vtype(stat.1, 0);
    if vn.vtype != VT_LNK && !vn.data.is_null() && vn.size != 0 {
        let _ = unsafe { crate::server::mem::unmap(vn.data, page_align_up(vn.size)) };
        vn.data = core::ptr::null_mut();
    }
    state.refresh_vnode_key(vnode, old_key);
    Ok(())
}

fn apply_attr_snapshot(
    state: &mut VfsState,
    vnode: VnodeHandle,
    snapshot: SaltyfsAttrSnapshot,
) -> Result<(), u64> {
    let old_key = state
        .vnodes
        .get(vnode)
        .map(|vn| vn.vnode_key())
        .unwrap_or(VnodeKey::INVALID);
    let Some(vn) = state.vnodes.get_mut(vnode) else {
        return Err(TRONA_NOT_FOUND);
    };
    vn.mode = snapshot.mode;
    vn.uid = snapshot.uid;
    vn.gid = snapshot.gid;
    vn.size = snapshot.size;
    vn.nlink = snapshot.nlink;
    vn.atime_ns = snapshot.atime.saturating_mul(1_000_000_000);
    vn.mtime_ns = snapshot.mtime.saturating_mul(1_000_000_000);
    vn.vtype = mode_to_vtype(snapshot.mode, 0);
    if vn.vtype != VT_LNK && !vn.data.is_null() && vn.size != 0 {
        let _ = unsafe { crate::server::mem::unmap(vn.data, page_align_up(vn.size)) };
        vn.data = core::ptr::null_mut();
    }
    state.refresh_vnode_key(vnode, old_key);
    Ok(())
}

fn materialize_child_vnode(
    state: &mut VfsState,
    owner_mount: MountHandle,
    parent_vh: VnodeHandle,
    name: &[u8],
    ino: u64,
    seq: u32,
    mode: u32,
    size: u64,
    nlink: u32,
    mtime: u64,
    uid: u32,
    gid: u32,
    dir_type: u8,
    blocks: u64,
) -> Option<VnodeHandle> {
    let mount = state.mounts.get(owner_mount)?;
    let fs_id = mount.fs_instance_id;
    let key = VnodeKey {
        fs_instance_id: fs_id,
        backend_id: BackendNodeId::new(ino, seq),
    };
    let vtype = mode_to_vtype(mode, dir_type);
    let parent_node = find_node_handle_by_vnode_mut(state, parent_vh)?;
    let vnode = if let Some(existing) = state.vnode_by_key(key) {
        existing
    } else {
        state.vnodes.alloc()?
    };
    let old_key = state
        .vnodes
        .get(vnode)
        .map(|vn| vn.vnode_key())
        .unwrap_or(VnodeKey::INVALID);

    {
        let vn = state.vnodes.get_mut(vnode)?;
        if vn.mount.handle == MountHandle::INVALID || vn.fs_instance_id != fs_id {
            *vn = match vtype {
                VT_DIR => Vnode::new_bootstrap_dir(fs_id, owner_mount),
                VT_LNK => Vnode::new_bootstrap_symlink(fs_id, owner_mount, mode),
                VT_FIFO => Vnode::new_bootstrap_fifo(fs_id, owner_mount, mode),
                VT_SOCK => Vnode::new_bootstrap_socket(fs_id, owner_mount, mode),
                VT_CHR => Vnode::new_bootstrap_char_device(fs_id, owner_mount, mode, ino, seq),
                _ => Vnode::new_bootstrap_file(fs_id, owner_mount, mode),
            };
        }
        vn.vtype = vtype;
        vn.mode = mode;
        vn.id = ino;
        vn.backend_seq = seq;
        vn.uid = uid;
        vn.gid = gid;
        vn.nlink = nlink;
        vn.size = size;
        vn.atime_ns = mtime.saturating_mul(1_000_000_000);
        vn.mtime_ns = mtime.saturating_mul(1_000_000_000);
        vn.fs_instance_id = fs_id;
        vn.mount = CachedRef::new(fs_id, owner_mount);
        vn.backend_kind = VNODE_BACKEND_SALTYFS;
        vn.ops = saltyfs_vops();
    }
    state.refresh_vnode_key(vnode, old_key);

    let _ = install_node_state(
        state,
        owner_mount,
        vnode,
        key.backend_id,
        parent_node,
        name,
        blocks,
    )?;
    Some(vnode)
}

fn materialize_snapshot_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    snapshot: SaltyfsLookupSnapshot,
) -> Option<VnodeHandle> {
    let Some((_md, owner_mount)) = mount_data_for_vnode(state, parent_vh) else {
        return None;
    };
    materialize_child_vnode(
        state,
        owner_mount,
        parent_vh,
        name,
        snapshot.ino,
        snapshot.seq,
        snapshot.mode,
        snapshot.size,
        snapshot.nlink,
        snapshot.mtime,
        snapshot.uid,
        snapshot.gid,
        snapshot.dir_type,
        snapshot.blocks,
    )
}

fn is_bootstrap_overlay_name(
    state: &VfsState,
    dir_vh: VnodeHandle,
    name: &[u8],
    ignore_case: bool,
) -> bool {
    state
        .bootstrap_lookup_child_with_case(dir_vh, name, ignore_case)
        .is_some()
}

pub(crate) fn vnode_is_saltyfs(state: &VfsState, vnode: VnodeHandle) -> bool {
    state
        .vnodes
        .get(vnode)
        .map(|vnode_ref| vnode_ref.backend_kind == VNODE_BACKEND_SALTYFS)
        .unwrap_or(false)
}

fn render_mount_prefix_path(
    state: &VfsState,
    owner_mount: MountHandle,
    out: &mut [u8],
) -> Option<usize> {
    let prefix = mount_prefix_source(state, owner_mount)?;
    let mount = state.mounts.get(owner_mount)?;
    if let MountPrefixSource::CoveredAnchor(anchor) = prefix {
        return state.render_anchor_path(anchor, out);
    }

    let len = mount.mount_path_len as usize;
    if len == 0 || len > out.len() {
        return None;
    }
    out[..len].copy_from_slice(&mount.mount_path[..len]);
    Some(len)
}

#[inline]
fn mount_prefix_source(state: &VfsState, owner_mount: MountHandle) -> Option<MountPrefixSource> {
    let mount = state.mounts.get(owner_mount)?;
    let covered = if mount.covered.handle.is_valid() {
        Some(mount.covered.handle)
    } else if mount.covered.id != VnodeKey::INVALID {
        state.vnode_by_key(mount.covered.id)
    } else {
        None
    };
    if let Some(covered_vh) = covered {
        let anchor = state.anchor_for_vnode(covered_vh)?;
        return Some(MountPrefixSource::CoveredAnchor(anchor));
    }
    if mount.mount_path_len != 0 {
        return Some(MountPrefixSource::CanonicalMountPath);
    }
    None
}

#[inline]
fn node_path_role(state: &VfsState, node_h: SaltyfsNodeHandle) -> Option<SaltyfsPathRole> {
    let node = state.saltyfs_nodes.get(node_h)?;
    match node.path_kind {
        SALTYFS_NODE_PATH_ROOT => Some(SaltyfsPathRole::MountedRoot(node.owner_mount)),
        SALTYFS_NODE_PATH_CHILD if node.parent_node.is_valid() => {
            Some(SaltyfsPathRole::Child(node.parent_node))
        }
        _ => None,
    }
}

pub(crate) fn build_path_for_vnode(
    state: &VfsState,
    vnode: VnodeHandle,
    out: &mut [u8],
) -> Option<usize> {
    let node_h = find_node_handle_by_vnode(state, vnode)?;
    let mut chain = [SaltyfsNodeHandle::INVALID; 64];
    let mut depth = 0usize;
    let mut current_h = node_h;
    let owner_mount = loop {
        match node_path_role(state, current_h)? {
            SaltyfsPathRole::MountedRoot(owner_mount) => break owner_mount,
            SaltyfsPathRole::Child(parent_node) => {
                if depth >= chain.len() {
                    return None;
                }
                chain[depth] = current_h;
                depth += 1;
                current_h = parent_node;
            }
        }
    };

    let mut len = render_mount_prefix_path(state, owner_mount, out)?;

    for idx in (0..depth).rev() {
        let node = state.saltyfs_nodes.get(chain[idx])?;
        let name_len = node.name_len as usize;
        if name_len == 0 {
            return None;
        }
        if len > 1 {
            if len >= out.len() {
                return None;
            }
            out[len] = b'/';
            len += 1;
        }
        if len + name_len > out.len() {
            return None;
        }
        out[len..len + name_len].copy_from_slice(&node.name[..name_len]);
        len += name_len;
    }

    Some(len)
}

pub(crate) fn lookup_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
) -> VfsResult<Option<VnodeHandle>> {
    let Some(parent_vn) = state.vnodes.get(parent_vh) else {
        return Err(TRONA_NOT_FOUND);
    };
    if parent_vn.vtype != VT_DIR {
        return Err(TRONA_NOT_DIRECTORY);
    }
    let Some((md, _owner_mount)) = mount_data_for_vnode(state, parent_vh) else {
        return Ok(VfsOpResult::Complete(None));
    };
    let parent_ino = parent_vn.id;
    let fs_cap = md.fs_cap;
    let copy_len = core::cmp::min(name.len(), SALTYFS_NAME_MAX);

    let op_id = unsafe { alloc_saltyfs_backend_op()? };

    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_LOOKUP;
    req.regs[0] = parent_ino;
    req.regs[1] = copy_len as u64;
    let dst = &raw mut req.regs[2] as *mut u8;
    for (idx, byte) in name.iter().take(copy_len).enumerate() {
        unsafe {
            *dst.add(idx) = *byte;
        }
    }
    req.length = 2 + ((copy_len as u64) + 7) / 8;

    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(parent_vh);
    ctx_data[1] = copy_len as u64;

    if !unsafe {
        crate::owner::backend_rpc::enqueue_saltyfs_op(
            op_id,
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_LOOKUP_CHILD,
            fs_cap,
            req,
            ctx_data,
        )
    } {
        unsafe {
            crate::owner::pending_ops::free(op_id);
        }
        return Err(TRONA_OUT_OF_MEMORY);
    }

    Ok(VfsOpResult::Deferred(op_id))
}

pub(crate) fn ensure_dir_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> Option<VnodeHandle> {
    match lookup_child(state, parent_vh, name) {
        Ok(VfsOpResult::Complete(Some(vh))) => return Some(vh),
        Ok(VfsOpResult::Complete(None)) => {}
        Ok(VfsOpResult::Deferred(op_id)) => {
            // `ensure_dir_child` is a sync bootstrap helper; it has no
            // continuation slot to carry a deferred lookup. Reclaim
            // the op so the worker-side state is not orphaned and let
            // the caller fall back to its own error handling.
            unsafe {
                crate::owner::pending_ops::free(op_id);
            }
            return None;
        }
        Err(_) => return None,
    }

    let (parent_ino, owner_mount) = {
        let parent_vn = state.vnodes.get(parent_vh)?;
        (parent_vn.id, parent_vn.mount.handle)
    };
    {
        let Some((md, _)) = mount_data_for_vnode(state, parent_vh) else {
            return None;
        };
        if unsafe { mkdir_sync(md, parent_ino, name, mode) }.is_err() {
            return None;
        }
    }
    lookup_created_child(state, parent_vh, owner_mount, name).ok()
}

unsafe fn read_regular_vop(
    state: &VfsState,
    _cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    file_offset: u64,
    out: *mut u8,
    cap: usize,
) -> VfsResult<usize> {
    read_regular(state, vnode, file_offset, out, cap).map(VfsOpResult::Complete)
}

unsafe fn write_regular_vop(
    state: &mut VfsState,
    vnode: VnodeHandle,
    file_offset: u64,
    src: *const u8,
    len: usize,
) -> VfsResult<u64> {
    ensure_writable(state, vnode)?;
    write_vnode(state, vnode, file_offset, src, len).map(VfsOpResult::Complete)
}

pub(crate) fn mkdir_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    if !vnode_is_saltyfs(state, parent_vh) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if name.is_empty() || name.len() > SALTYFS_CREATE_NAME_WIRE_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent_vh)?;
    let (parent_ino, fs_cap) = {
        let parent_vn = state.vnodes.get(parent_vh).ok_or(TRONA_NOT_FOUND)?;
        let Some((md, _)) = mount_data_for_vnode(state, parent_vh) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        (parent_vn.id, md.fs_cap)
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_MKDIR;
    req.regs[0] = parent_ino;
    req.regs[1] = mode as u64;
    req.regs[2] = name.len() as u64;
    let dst = &raw mut req.regs[3] as *mut u8;
    for (idx, byte) in name.iter().enumerate() {
        unsafe {
            *dst.add(idx) = *byte;
        }
    }
    req.length = 3 + ((name.len() as u64) + 7) / 8;
    let args = SaltyfsDeferredArgs::with_name(SALTYFS_DEFER_OP_MKDIR, name, mode, 0)
        .ok_or(TRONA_INVALID_ARGUMENT)?;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(parent_vh);
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_MKDIR,
            fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

pub(crate) fn create_regular_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    if !vnode_is_saltyfs(state, parent_vh) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if name.is_empty() || name.len() > SALTYFS_CREATE_NAME_WIRE_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent_vh)?;
    let (parent_ino, fs_cap) = {
        let parent_vn = state.vnodes.get(parent_vh).ok_or(TRONA_NOT_FOUND)?;
        let Some((md, _)) = mount_data_for_vnode(state, parent_vh) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        (parent_vn.id, md.fs_cap)
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_CREATE;
    req.regs[0] = parent_ino;
    req.regs[1] = mode as u64;
    req.regs[2] = name.len() as u64;
    let dst = &raw mut req.regs[3] as *mut u8;
    for (idx, byte) in name.iter().enumerate() {
        unsafe {
            *dst.add(idx) = *byte;
        }
    }
    req.length = 3 + ((name.len() as u64) + 7) / 8;
    let args = SaltyfsDeferredArgs::with_name(SALTYFS_DEFER_OP_CREATE, name, mode, 0)
        .ok_or(TRONA_INVALID_ARGUMENT)?;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(parent_vh);
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_CREATE,
            fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

pub(crate) fn symlink_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    target: &[u8],
) -> VfsResult<VnodeHandle> {
    if !vnode_is_saltyfs(state, parent_vh) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if name.is_empty()
        || name.len() > SALTYFS_SYMLINK_NAME_WIRE_MAX
        || target.is_empty()
        || target.len() > SALTYFS_TARGET_INLINE_MAX
    {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent_vh)?;
    let (parent_ino, fs_cap) = {
        let parent_vn = state.vnodes.get(parent_vh).ok_or(TRONA_NOT_FOUND)?;
        let Some((md, _)) = mount_data_for_vnode(state, parent_vh) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        (parent_vn.id, md.fs_cap)
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_SYMLINK;
    req.regs[0] = parent_ino;
    req.regs[1] = name.len() as u64;
    req.regs[2] = target.len() as u64;
    let dst_name = &raw mut req.regs[3] as *mut u8;
    for (idx, byte) in name.iter().enumerate() {
        unsafe {
            *dst_name.add(idx) = *byte;
        }
    }
    let dst_target = &raw mut req.regs[12] as *mut u8;
    for (idx, byte) in target.iter().enumerate() {
        unsafe {
            *dst_target.add(idx) = *byte;
        }
    }
    req.length = 20;
    let args = SaltyfsDeferredArgs::with_symlink(name, target).ok_or(TRONA_INVALID_ARGUMENT)?;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(parent_vh);
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SYMLINK,
            fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

pub(crate) fn remove_child(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    remove_dir: bool,
) -> VfsResult<()> {
    if !vnode_is_saltyfs(state, parent_vh) {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    if name.is_empty() || name.len() > SALTYFS_NAME_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    ensure_writable(state, parent_vh)?;
    let (parent_ino, fs_cap) = {
        let parent_ino = state
            .vnodes
            .get(parent_vh)
            .map(|vn| vn.id)
            .ok_or(TRONA_NOT_FOUND)?;
        let Some((md, _)) = mount_data_for_vnode(state, parent_vh) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        (parent_ino, md.fs_cap)
    };
    let mut req = TronaMsg::zeroed();
    req.label = if remove_dir {
        BACKEND_RMDIR
    } else {
        BACKEND_UNLINK
    };
    req.regs[0] = parent_ino;
    req.regs[1] = name.len() as u64;
    let dst = &raw mut req.regs[2] as *mut u8;
    for (idx, byte) in name.iter().enumerate() {
        unsafe {
            *dst.add(idx) = *byte;
        }
    }
    req.length = 2 + ((name.len() as u64) + 7) / 8;
    let args = SaltyfsDeferredArgs::with_name(
        if remove_dir {
            SALTYFS_DEFER_OP_RMDIR
        } else {
            SALTYFS_DEFER_OP_UNLINK
        },
        name,
        0,
        if remove_dir { 1 } else { 0 },
    )
    .ok_or(TRONA_INVALID_ARGUMENT)?;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(parent_vh);
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_UNLINK,
            fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

fn rename_child_vop(
    state: &mut VfsState,
    old_parent_vh: VnodeHandle,
    old_name: &[u8],
    new_parent_vh: VnodeHandle,
    new_name: &[u8],
) -> VfsResult<()> {
    if !vnode_is_saltyfs(state, old_parent_vh) || !vnode_is_saltyfs(state, new_parent_vh) {
        return Err(TRONA_CROSS_DEVICE);
    }
    ensure_writable(state, old_parent_vh)?;
    ensure_writable(state, new_parent_vh)?;
    let (old_parent_mount, old_parent_ino, new_parent_mount, new_parent_ino) = match (
        state.vnodes.get(old_parent_vh),
        state.vnodes.get(new_parent_vh),
    ) {
        (Some(old_vn), Some(new_vn)) => (
            old_vn.mount.handle,
            old_vn.id,
            new_vn.mount.handle,
            new_vn.id,
        ),
        _ => return Err(TRONA_NOT_FOUND),
    };
    if old_parent_mount != new_parent_mount {
        return Err(TRONA_INVALID_OPERATION);
    }

    if old_name.is_empty()
        || new_name.is_empty()
        || old_name.len() > SALTYFS_RENAME_NAME_WIRE_MAX
        || new_name.len() > SALTYFS_RENAME_NAME_WIRE_MAX
    {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let Some((md, _)) = mount_data_for_vnode(state, old_parent_vh) else {
        return Err(TRONA_INVALID_ARGUMENT);
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_RENAME;
    req.regs[0] = old_parent_ino;
    req.regs[1] = old_name.len() as u64;
    req.regs[2] = new_parent_ino;
    req.regs[3] = new_name.len() as u64;
    let dst_old = &raw mut req.regs[4] as *mut u8;
    for (idx, byte) in old_name.iter().enumerate() {
        unsafe {
            *dst_old.add(idx) = *byte;
        }
    }
    let dst_new = &raw mut req.regs[12] as *mut u8;
    for (idx, byte) in new_name.iter().enumerate() {
        unsafe {
            *dst_new.add(idx) = *byte;
        }
    }
    req.length = 20;
    let args = SaltyfsDeferredArgs::with_two_names(SALTYFS_DEFER_OP_RENAME, old_name, new_name)
        .ok_or(TRONA_INVALID_ARGUMENT)?;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(old_parent_vh);
    ctx_data[1] = pack_vh(new_parent_vh);
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_RENAME,
            md.fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

fn link_vnode_into_vop(
    state: &mut VfsState,
    source_vh: VnodeHandle,
    parent_vh: VnodeHandle,
    name: &[u8],
) -> VfsResult<()> {
    if !vnode_is_saltyfs(state, source_vh) || !vnode_is_saltyfs(state, parent_vh) {
        return Err(TRONA_CROSS_DEVICE);
    }
    ensure_writable(state, parent_vh)?;
    let (source_ino, source_mount, parent_ino, parent_mount) =
        match (state.vnodes.get(source_vh), state.vnodes.get(parent_vh)) {
            (Some(src), Some(parent)) => (src.id, src.mount.handle, parent.id, parent.mount.handle),
            _ => return Err(TRONA_NOT_FOUND),
        };
    if source_mount != parent_mount {
        return Err(TRONA_INVALID_OPERATION);
    }
    if name.is_empty() || name.len() > SALTYFS_CREATE_NAME_WIRE_MAX {
        return Err(TRONA_INVALID_ARGUMENT);
    }
    let Some((md, _)) = mount_data_for_vnode(state, source_vh) else {
        return Err(TRONA_INVALID_ARGUMENT);
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_LINK;
    req.regs[0] = source_ino;
    req.regs[1] = parent_ino;
    req.regs[2] = name.len() as u64;
    let dst = &raw mut req.regs[3] as *mut u8;
    for (idx, byte) in name.iter().enumerate() {
        unsafe {
            *dst.add(idx) = *byte;
        }
    }
    req.length = 3 + ((name.len() as u64) + 7) / 8;
    let args = SaltyfsDeferredArgs::with_name(SALTYFS_DEFER_OP_LINK, name, 0, 0)
        .ok_or(TRONA_INVALID_ARGUMENT)?;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(parent_vh);
    ctx_data[1] = pack_vh(source_vh);
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_LINK,
            md.fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

fn validate_open_regular_vop(_state: &VfsState, _vnode: VnodeHandle, flags: u32) -> u64 {
    let accmode = flags & trona_posix::consts::O_ACCMODE;
    if accmode > trona_posix::consts::O_RDWR {
        return TRONA_INVALID_ARGUMENT;
    }
    if (flags & trona_posix::consts::O_APPEND) != 0 {
        return TRONA_NOT_SUPPORTED;
    }
    TRONA_OK
}

fn readdir_dir_vop(
    state: &VfsState,
    _cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    cursor: u64,
    ignore_case: bool,
    name_out: &mut [u8; 128],
) -> crate::vfs_core::vops::ReaddirResult {
    readdir_entry(state, vnode, cursor, ignore_case, name_out)
}

pub(crate) fn set_mode_vnode(state: &mut VfsState, vnode: VnodeHandle, mode: u32) -> VfsResult<()> {
    enqueue_setattr_vnode(state, vnode, SETATTR_MASK_MODE, mode, 0, 0, 0, 0, 0)
}

pub(crate) fn set_owner_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
    uid: u32,
    gid: u32,
) -> VfsResult<()> {
    enqueue_setattr_vnode(
        state,
        vnode,
        SETATTR_MASK_UID | SETATTR_MASK_GID,
        0,
        uid,
        gid,
        0,
        0,
        0,
    )
}

pub(crate) fn set_times_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
    atime: Option<u64>,
    mtime: Option<u64>,
) -> VfsResult<()> {
    let mut mask = 0u32;
    // `noatime` only suppresses *implicit* atime updates (the kernel
    // tick that fires on read). Explicit `utimensat`/`futimens` callers
    // are setting policy themselves and must reach the backend.
    if atime.is_some() {
        mask |= SETATTR_MASK_ATIME;
    }
    if mtime.is_some() {
        mask |= SETATTR_MASK_MTIME;
    }
    if mask == 0 {
        return Ok(VfsOpResult::Complete(()));
    }
    enqueue_setattr_vnode(
        state,
        vnode,
        mask,
        0,
        0,
        0,
        atime.unwrap_or(0) / 1_000_000_000,
        mtime.unwrap_or(0) / 1_000_000_000,
        0,
    )
}

pub(crate) fn truncate_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
    new_size: u64,
) -> VfsResult<()> {
    ensure_writable(state, vnode)?;
    let (ino, fs_cap) = {
        let ino = state
            .vnodes
            .get(vnode)
            .map(|vn| vn.id)
            .ok_or(TRONA_NOT_FOUND)?;
        let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        (ino, md.fs_cap)
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_SETATTR;
    req.length = BACKEND_SETATTR_REG_COUNT as u64;
    req.regs[0] = ino;
    req.regs[1] = SETATTR_MASK_SIZE as u64;
    req.regs[6] = new_size;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(vnode);
    let args = SaltyfsDeferredArgs {
        op: SALTYFS_DEFER_OP_SETATTR,
        ..SaltyfsDeferredArgs::zeroed()
    };
    let op_id = unsafe {
        enqueue_saltyfs_request(
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_TRUNCATE,
            fs_cap,
            req,
            ctx_data,
            Some(&args),
        )?
    };
    Ok(VfsOpResult::Deferred(op_id))
}

fn enqueue_setattr_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
    mask: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    atime: u64,
    mtime: u64,
    size: u64,
) -> VfsResult<()> {
    ensure_writable(state, vnode)?;
    let (ino, fs_cap) = {
        let ino = state
            .vnodes
            .get(vnode)
            .map(|vn| vn.id)
            .ok_or(TRONA_NOT_FOUND)?;
        let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        (ino, md.fs_cap)
    };
    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_SETATTR;
    req.length = BACKEND_SETATTR_REG_COUNT as u64;
    req.regs[0] = ino;
    req.regs[1] = mask as u64;
    req.regs[2] = mode as u64;
    req.regs[3] = (uid as u64) | ((gid as u64) << 32);
    req.regs[4] = atime;
    req.regs[5] = mtime;
    req.regs[6] = size;
    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(vnode);
    let args = SaltyfsDeferredArgs {
        op: SALTYFS_DEFER_OP_SETATTR,
        ..SaltyfsDeferredArgs::zeroed()
    };
    let backend_op = if (mask & SETATTR_MASK_MODE) != 0 {
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SETMODE
    } else if (mask & (SETATTR_MASK_UID | SETATTR_MASK_GID)) != 0 {
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SETOWNER
    } else {
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SETTIMES
    };
    let op_id = unsafe { enqueue_saltyfs_request(backend_op, fs_cap, req, ctx_data, Some(&args))? };
    Ok(VfsOpResult::Deferred(op_id))
}

pub(crate) fn write_vnode(
    state: &mut VfsState,
    vnode: VnodeHandle,
    file_offset: u64,
    src: *const u8,
    len: usize,
) -> Result<u64, u64> {
    let ino = match state.vnodes.get(vnode) {
        Some(vn) => vn.id,
        None => return Err(TRONA_NOT_FOUND),
    };
    let written = {
        let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
            return Err(TRONA_INVALID_ARGUMENT);
        };
        unsafe { write_sync(md, ino, file_offset, src, len) }?
    };
    refresh_vnode_attrs(state, vnode)?;
    Ok(written)
}

pub(crate) fn ensure_symlink_target(state: &mut VfsState, vnode: VnodeHandle) -> VfsResult<bool> {
    let Some(vn) = state.vnodes.get(vnode) else {
        return Ok(VfsOpResult::Complete(false));
    };
    if vn.vtype != VT_LNK {
        return Ok(VfsOpResult::Complete(false));
    }
    if !vn.data.is_null() {
        return Ok(VfsOpResult::Complete(true));
    }
    let ino = vn.id;
    let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
        return Ok(VfsOpResult::Complete(false));
    };
    let fs_cap = md.fs_cap;

    let op_id = unsafe { alloc_saltyfs_backend_op()? };
    if !unsafe { set_saved_current_vnode(op_id, vnode) } {
        unsafe {
            crate::owner::pending_ops::free(op_id);
        }
        return Err(TRONA_OUT_OF_MEMORY);
    }

    let mut req = TronaMsg::zeroed();
    req.label = BACKEND_READLINK;
    req.length = 1;
    req.regs[0] = ino;

    let mut ctx_data = [0u64; 6];
    ctx_data[0] = pack_vh(vnode);

    if !unsafe {
        crate::owner::backend_rpc::enqueue_saltyfs_op(
            op_id,
            crate::owner::backend_rpc::BACKEND_OP_SALTYFS_READLINK,
            fs_cap,
            req,
            ctx_data,
        )
    } {
        unsafe {
            crate::owner::pending_ops::free(op_id);
        }
        return Err(TRONA_OUT_OF_MEMORY);
    }

    Ok(VfsOpResult::Deferred(op_id))
}

pub(crate) fn read_regular(
    state: &VfsState,
    vnode: VnodeHandle,
    file_offset: u64,
    out: *mut u8,
    cap: usize,
) -> Result<usize, u64> {
    let Some(vn) = state.vnodes.get(vnode) else {
        return Err(TRONA_NOT_FOUND);
    };
    let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
        return Err(TRONA_INVALID_ARGUMENT);
    };
    unsafe { read_sync(md, vn.id, file_offset, out, cap) }
}

pub(crate) fn readdir_entry(
    state: &VfsState,
    vnode: VnodeHandle,
    cursor: u64,
    ignore_case: bool,
    name_out: &mut [u8; 128],
) -> crate::vfs_core::vops::ReaddirResult {
    let Some(vn) = state.vnodes.get(vnode) else {
        return Err(TRONA_NOT_FOUND);
    };
    if vn.vtype != VT_DIR {
        return Err(TRONA_NOT_DIRECTORY);
    }
    let Some((md, _)) = mount_data_for_vnode(state, vnode) else {
        return Err(TRONA_INVALID_ARGUMENT);
    };
    let (next_cursor, entries_written, bytes_written, flags) =
        unsafe { readdir_sync(md, vn.id, cursor) }?;
    let eof_after = (flags & BACKEND_READDIR_F_EOF) != 0;
    if entries_written == 0 || bytes_written < SALTYFS_READDIR_ENTRY_BYTES {
        return Ok(VfsOpResult::Complete(None));
    }

    let base = md.shm_vaddr as *const u8;
    let entry_ino = unsafe { core::ptr::read_unaligned(base.add(0) as *const u64) };
    let entry_mode = unsafe { core::ptr::read_unaligned(base.add(32) as *const u32) };
    let raw_dtype = unsafe { *base.add(48) };
    let mut name_len = unsafe { *base.add(49) as usize };
    name_len = core::cmp::min(name_len, SALTYFS_READDIR_NAME_MAX);
    let name_ptr = unsafe { base.add(52) };
    for idx in 0..name_len {
        name_out[idx] = unsafe { *name_ptr.add(idx) };
    }
    if is_bootstrap_overlay_name(state, vnode, &name_out[..name_len], ignore_case) {
        if eof_after {
            return Ok(VfsOpResult::Complete(None));
        }
        return readdir_entry(state, vnode, next_cursor, ignore_case, name_out);
    }
    Ok(VfsOpResult::Complete(Some(
        crate::vfs_core::vops::ReaddirEntry {
            next_cursor,
            eof_after,
            name_len: name_len as u8,
            ino: entry_ino,
            d_type: readdir_dtype(entry_mode, raw_dtype),
        },
    )))
}

struct ParsedSaltyfsOpts {
    readonly: bool,
    noatime: bool,
    readonly_set: bool,
    noatime_set: bool,
}

fn parse_saltyfs_opts(opts: &[u8]) -> ParsedSaltyfsOpts {
    let mut parsed = ParsedSaltyfsOpts {
        readonly: false,
        noatime: false,
        readonly_set: false,
        noatime_set: false,
    };
    crate::vfs_core::mount_options::for_each_token(opts, |token| match token {
        b"ro" | b"readonly" => {
            parsed.readonly = true;
            parsed.readonly_set = true;
        }
        b"rw" => {
            parsed.readonly = false;
            parsed.readonly_set = true;
        }
        b"noatime" => {
            parsed.noatime = true;
            parsed.noatime_set = true;
        }
        b"atime" => {
            parsed.noatime = false;
            parsed.noatime_set = true;
        }
        _ => {}
    });
    parsed
}

/// `VfsOps::remount` callback. Refreshes the per-mount `noatime` /
/// `readonly` snapshot from the new opts string. Generic flag bit
/// transitions (`MNT_RDONLY`, `MNT_NOATIME`) already landed on
/// `Mount.flags` upstream — this just keeps `SaltyfsMountData` in sync
/// for code paths that read the cached field directly.
fn saltyfs_remount(state: &mut VfsState, mount: MountHandle, new_flags: u32, opts: &[u8]) -> u64 {
    let parsed = parse_saltyfs_opts(opts);
    let Some(handle) = find_mount_data_handle(state, mount) else {
        return TRONA_INVALID_OPERATION;
    };
    if let Some(data) = state.saltyfs_mounts.get_mut(handle) {
        // `MNT_RDONLY` enforcement reads `Mount.flags` directly, so
        // we don't snapshot it here. `noatime` is the only field
        // saltyfs caches per-mount today; resolve the new value from
        // either the explicit opt token or the merged flag word.
        let flag_noatime = (new_flags & crate::vfs_core::mount::MNT_NOATIME) != 0;
        let opt_noatime = if parsed.noatime_set {
            Some(parsed.noatime)
        } else {
            None
        };
        data.noatime = if opt_noatime.unwrap_or(flag_noatime) {
            1
        } else {
            0
        };
    }
    let _ = parsed.readonly;
    let _ = parsed.readonly_set;
    TRONA_OK
}

pub(crate) fn alloc_mount(
    state: &mut VfsState,
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Result<MountHandle, u64> {
    let parsed_opts = parse_saltyfs_opts(opts);
    let effective_flags = flags
        | if parsed_opts.readonly {
            crate::vfs_core::mount::MNT_RDONLY
        } else {
            0
        }
        | if parsed_opts.noatime {
            crate::vfs_core::mount::MNT_NOATIME
        } else {
            0
        };

    let fs_cap = unsafe { resolve_endpoint()? };
    let session = unsafe { open_session(fs_cap, effective_flags)? };

    let root_vh = state.vnodes.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    let mh = state.mounts.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    let data_h = state.saltyfs_mounts.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    let fs_id = state.alloc_fs_instance_id();

    let root_stat = unsafe {
        stat_sync(
            &SaltyfsMountData {
                owner_mount: mh,
                fs_instance_id: fs_id,
                root_vnode: root_vh,
                fs_cap,
                session_id: session.session_id,
                max_inflight: session.max_inflight,
                _pad0: [0; 2],
                root_node: session.root_node,
                feature_bits: session.feature_bits,
                shm_active: 0,
                noatime: 0,
                _pad1: [0; 6],
                shm_vaddr: 0,
                shm_size: 0,
            },
            session.root_node.ino,
        )
    }
    .ok();

    {
        let vnode = state.vnodes.get_mut(root_vh).ok_or(TRONA_OUT_OF_MEMORY)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
        vnode.backend_kind = VNODE_BACKEND_SALTYFS;
        vnode.id = session.root_node.ino;
        vnode.backend_seq = session.root_node.seq;
        vnode.mount = CachedRef::new(fs_id, mh);
        vnode.ops = saltyfs_vops();
        if let Some((size, mode, nlink, mtime, blocks, uid, gid, seq)) = root_stat {
            vnode.vtype = mode_to_vtype(mode, DT_DIR);
            vnode.mode = mode;
            vnode.size = size;
            vnode.nlink = nlink;
            vnode.uid = uid;
            vnode.gid = gid;
            vnode.backend_seq = seq;
            vnode.atime_ns = mtime.saturating_mul(1_000_000_000);
            vnode.mtime_ns = mtime.saturating_mul(1_000_000_000);
            let _ = blocks;
        }
    }

    {
        let mount = state.mounts.get_mut(mh).ok_or(TRONA_OUT_OF_MEMORY)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            effective_flags,
            fs_id,
            root_vh,
            b"saltyfs",
            mount_path,
        );
        mount.backend_kind = MOUNT_BACKEND_SALTYFS;
        mount.vfsops = saltyfs_vfsops();
        mount.vops = saltyfs_vops();
    }

    let data_ptr = {
        let data = state
            .saltyfs_mounts
            .get_mut(data_h)
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        *data = SaltyfsMountData::zeroed();
        data.owner_mount = mh;
        data.fs_instance_id = fs_id;
        data.root_vnode = root_vh;
        data.fs_cap = fs_cap;
        data.session_id = session.session_id;
        data.max_inflight = session.max_inflight;
        data.root_node = session.root_node;
        data.feature_bits = session.feature_bits;
        data.noatime = if parsed_opts.noatime || (flags & crate::vfs_core::mount::MNT_NOATIME) != 0
        {
            1
        } else {
            0
        };
        unsafe { setup_shm(data) };
        data as *mut SaltyfsMountData as *mut u8
    };
    {
        let mount = state.mounts.get_mut(mh).ok_or(TRONA_OUT_OF_MEMORY)?;
        mount.data = data_ptr;
    }

    if install_node_state(
        state,
        mh,
        root_vh,
        session.root_node,
        SaltyfsNodeHandle::INVALID,
        b"",
        root_stat.map(|s| s.4).unwrap_or(0),
    )
    .is_none()
    {
        return Err(TRONA_OUT_OF_MEMORY);
    }

    Ok(mh)
}

pub(crate) fn release_mount(state: &mut VfsState, owner_mount: MountHandle) -> bool {
    let Some(data_h) = find_mount_data_handle(state, owner_mount) else {
        return true;
    };
    let (fs_cap, session_id, shm_active, shm_vaddr, fs_id) = match state.saltyfs_mounts.get(data_h)
    {
        Some(data) => (
            data.fs_cap,
            data.session_id,
            data.shm_active != 0,
            data.shm_vaddr,
            data.fs_instance_id,
        ),
        None => return true,
    };

    if fs_cap != 0 {
        unsafe {
            let mut req = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            req.label = BACKEND_CLOSE_SESSION;
            req.length = 1;
            req.regs[0] = session_id as u64;
            let _ = ipc::call_ctx(crate::ipc_ctx(), fs_cap, &raw const req, &raw mut reply);
        }
    }
    if shm_active && shm_vaddr != 0 {
        unsafe {
            let mut unmap = TronaMsg::zeroed();
            let mut reply = TronaMsg::zeroed();
            unmap.label = MM_SHM_UNMAP;
            unmap.length = 3;
            unmap.regs[0] = SALTYFS_SHM_ID;
            unmap.regs[1] = 0;
            unmap.regs[2] = shm_vaddr;
            let _ = ipc::call_ctx(
                crate::ipc_ctx(),
                trona_runtime::client::caps::mmsrv_ep(),
                &raw const unmap,
                &raw mut reply,
            );
        }
    }

    let mut nodes = [SaltyfsNodeHandle::INVALID; 512];
    let mut count = 0usize;
    state.saltyfs_nodes.for_each_active(|handle, node| {
        if count < nodes.len() {
            let Some(vnode) = state.vnodes.get(node.vnode) else {
                return true;
            };
            if vnode.fs_instance_id == fs_id {
                nodes[count] = handle;
                count += 1;
            }
        }
        true
    });
    for handle in nodes.into_iter().take(count) {
        if let Some(node) = state.saltyfs_nodes.get(handle) {
            if let Some(vn) = state.vnodes.get(node.vnode) {
                if vn.vtype == VT_LNK && !vn.data.is_null() && vn.size != 0 {
                    let _ = unsafe { crate::server::mem::unmap(vn.data, page_align_up(vn.size)) };
                }
            }
            if node.vnode.is_valid() {
                if let Some(vn) = state.vnodes.get_mut(node.vnode) {
                    vn.clear_backend_ref();
                }
                state.uncache_vnode_key(node.vnode);
                let _ = state.vnodes.release(node.vnode);
            }
        }
        let _ = state.saltyfs_nodes.release(handle);
    }

    state.saltyfs_mounts.release(data_h)
}

/// Pack a `VnodeHandle` into a `u64` for transport via
/// `BackendOpCtx.data`. Matches `unpack_vh` below.
#[inline]
fn pack_vh(vh: VnodeHandle) -> u64 {
    ((vh.epoch() as u64) << 32) | (vh.slot() as u64)
}

/// Reverse of `pack_vh`. The packed value preserves epoch+slot so a
/// stale handle is detected by the arena's generation check at lookup.
#[inline]
fn unpack_vh(packed: u64) -> VnodeHandle {
    VnodeHandle::new(packed as u32, (packed >> 32) as u32)
}

/// Backend RPC completion routing for saltyfs disk-IO ops.
///
/// Returns `true` when the per-op handler has shipped the saved reply
/// itself (terminal syscall). Returns `false` to let the cascade fall
/// through to `complete_namei_resume`, which re-drives the namei walk
/// from the updated `NameiResumeState` (advanced `current_packed` /
/// `pos`) the per-op handler wrote.
pub(crate) unsafe fn complete_saltyfs_op(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let backend_op = (*completion).op_kind;
    match backend_op {
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_LOOKUP_CHILD => unsafe {
            complete_saltyfs_lookup_child(state, completion)
        },
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_READLINK => unsafe {
            complete_saltyfs_readlink(state, completion)
        },
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_CREATE
        | crate::owner::backend_rpc::BACKEND_OP_SALTYFS_MKDIR
        | crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SYMLINK
        | crate::owner::backend_rpc::BACKEND_OP_SALTYFS_LINK => unsafe {
            complete_saltyfs_create_like(state, completion)
        },
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_UNLINK => unsafe {
            complete_saltyfs_unlink_like(state, completion)
        },
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_RENAME => unsafe {
            complete_saltyfs_rename_like(state, completion)
        },
        crate::owner::backend_rpc::BACKEND_OP_SALTYFS_TRUNCATE
        | crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SETMODE
        | crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SETOWNER
        | crate::owner::backend_rpc::BACKEND_OP_SALTYFS_SETTIMES => unsafe {
            complete_saltyfs_setattr_like(state, completion)
        },
        _ => false,
    }
}

/// Per-op handler for `BACKEND_OP_SALTYFS_LOOKUP_CHILD`. Materialises
/// the child vnode on the owner side, advances the saved
/// `NameiResumeState` past the consumed component, and returns `false`
/// so `complete_namei_resume` re-drives the walk from the new
/// `current_packed` / `pos`. Errors and `NOT_FOUND` mark the saved
/// state as `NAMEI_STEP_DONE` with `current_packed = INVALID`, which
/// `complete_namei_resume` routes to the `complete_*_continuation`
/// dispatcher (or, for `PO_KIND_NAMEI_RESUME`, drops the reply slot).
/// If no syscall continuation adopted the lookup op, the completion is
/// consumed and the orphaned op is freed instead of falling through to
/// the generic unknown-backend path.
unsafe fn complete_saltyfs_lookup_child(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let op_id = crate::owner::pending_ops::PendingOpId::from_raw((*completion).op_id);
    let parent_vh = unpack_vh((*completion).ctx.data[0]);

    let (payload_ref, op_kind) = match crate::owner::pending_ops::get(op_id) {
        Some(op) => (op.payload_ref, op.kind),
        None => return true,
    };
    let Some(buf) = crate::owner::pending_ops::payload_bytes(payload_ref) else {
        crate::owner::pending_ops::free(op_id);
        return true;
    };
    let saved: crate::owner::namei::NameiResumeState =
        core::ptr::read(buf.as_ptr() as *const crate::owner::namei::NameiResumeState);
    if op_kind == crate::owner::pending_ops::PO_KIND_BACKEND_RPC {
        crate::owner::pending_ops::free(op_id);
        return true;
    }

    let path_len = (saved.path_len as usize).min(saved.path.len());
    let component_start = (saved.pos as usize).min(path_len);
    let mut component_end = component_start;
    while component_end < path_len && saved.path[component_end] != b'/' {
        component_end += 1;
    }
    let mut next_pos = component_end;
    while next_pos < path_len && saved.path[next_pos] == b'/' {
        next_pos += 1;
    }

    let reply = (*completion).backend_reply;

    // Only mutate the saved state on success — for `NOT_FOUND` and
    // backend errors we leave `resume_step = NAMEI_STEP_AFTER_LOOKUP_CHILD`
    // so `lookup_path_dynamic_resume` can read the completion's
    // reply label and decide between `Complete(None)` and `Err`. If
    // we mutated `current_packed = INVALID` here, the walk would
    // re-drive `lookup_child(parent, name)` and re-enqueue forever.
    if (*completion).backend_err == 0 && reply.label == TRONA_OK {
        let ino = reply.regs[0];
        let seq = reply.regs[1] as u32;
        let mode = reply.regs[2] as u32;
        let size = reply.regs[3];
        let nlink = reply.regs[4] as u32;
        let mtime = reply.regs[5];
        let uid = reply.regs[6] as u32;
        let gid = reply.regs[7] as u32;
        let dir_type = reply.regs[8] as u8;
        let blocks = reply.regs[9];

        let Some((_md, owner_mount)) = mount_data_for_vnode(state, parent_vh) else {
            return false;
        };
        let component = &saved.path[component_start..component_end];
        let Some(child_vh) = materialize_child_vnode(
            state,
            owner_mount,
            parent_vh,
            component,
            ino,
            seq,
            mode,
            size,
            nlink,
            mtime,
            uid,
            gid,
            dir_type,
            blocks,
        ) else {
            return false;
        };

        let Some(buf_mut) = crate::owner::pending_ops::payload_bytes_mut(payload_ref) else {
            return false;
        };
        let state_ptr = buf_mut.as_mut_ptr() as *mut crate::owner::namei::NameiResumeState;
        (*state_ptr).current_packed = pack_vh(child_vh);
        (*state_ptr).pos = next_pos as u16;
    }

    // Adopted lookup ops fall through to `complete_namei_resume`; the
    // cascade's own reply-routing reads the (possibly advanced) saved
    // state and the completion's `reply.label` to drive the walk to its
    // final resolution.
    false
}

/// Per-op handler for `BACKEND_OP_SALTYFS_READLINK`. On success,
/// installs the link-target bytes into the symlink vnode's `data` so
/// the namei walk can dereference it on resume. Returns `false` so
/// `complete_namei_resume` reads `completion.backend_reply.label`
/// (the NAMEI_STEP_AFTER_ENSURE_SYMLINK arm in
/// `lookup_path_dynamic_resume`) and routes errors / NOT_FOUND
/// without re-driving the readlink RPC.
unsafe fn complete_saltyfs_readlink(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    let vnode = unpack_vh((*completion).ctx.data[0]);

    if (*completion).backend_err != 0 {
        return false;
    }
    let reply = (*completion).backend_reply;
    if reply.label != TRONA_OK {
        return false;
    }

    let max = INLINE_TRANSFER_WIRE_MAX as usize;
    let len = core::cmp::min(reply.regs[0] as usize, max);
    if len == 0 {
        return false;
    }
    let mut bytes = [0u8; INLINE_TRANSFER_WIRE_MAX as usize];
    let src = &raw const reply.regs[1] as *const u64 as *const u8;
    for idx in 0..len {
        bytes[idx] = *src.add(idx);
    }

    let _ = update_symlink_payload(state, vnode, &bytes[..len]);
    false
}

unsafe fn complete_saltyfs_create_like(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let op_id = crate::owner::pending_ops::PendingOpId::from_raw((*completion).op_id);
        if finish_saltyfs_completion_error(op_id, completion) {
            return true;
        }
        let reply = (*completion).backend_reply;
        let Some(snapshot) = parse_lookup_snapshot(&reply) else {
            finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
            return true;
        };
        let Some(args) = read_saltyfs_args(op_id) else {
            finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
            return true;
        };
        let parent_vh = unpack_vh((*completion).ctx.data[0]);
        let Some(child_vh) = materialize_snapshot_child(state, parent_vh, args.name_a(), snapshot)
        else {
            finish_saltyfs_continuation(op_id, TRONA_OUT_OF_MEMORY);
            return true;
        };
        if args.op == SALTYFS_DEFER_OP_SYMLINK
            && !update_symlink_payload(state, child_vh, args.target())
        {
            finish_saltyfs_continuation(op_id, TRONA_OUT_OF_MEMORY);
            return true;
        }

        if pending_op_kind(op_id) == crate::owner::pending_ops::PO_KIND_OPEN_CONT {
            if !set_saved_current_vnode(op_id, child_vh) {
                finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
                return true;
            }
            return false;
        }

        finish_saltyfs_continuation(op_id, TRONA_OK);
        true
    }
}

unsafe fn complete_saltyfs_unlink_like(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let op_id = crate::owner::pending_ops::PendingOpId::from_raw((*completion).op_id);
        if finish_saltyfs_completion_error(op_id, completion) {
            return true;
        }
        let Some(args) = read_saltyfs_args(op_id) else {
            finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
            return true;
        };
        let parent_vh = unpack_vh((*completion).ctx.data[0]);
        mark_cached_child_unlinked(
            state,
            parent_vh,
            args.name_a(),
            args.op == SALTYFS_DEFER_OP_RMDIR,
        );
        finish_saltyfs_continuation(op_id, TRONA_OK);
        true
    }
}

unsafe fn complete_saltyfs_rename_like(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let op_id = crate::owner::pending_ops::PendingOpId::from_raw((*completion).op_id);
        if finish_saltyfs_completion_error(op_id, completion) {
            return true;
        }
        let Some(args) = read_saltyfs_args(op_id) else {
            finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
            return true;
        };
        let old_parent_vh = unpack_vh((*completion).ctx.data[0]);
        let new_parent_vh = unpack_vh((*completion).ctx.data[1]);
        note_cached_child_renamed(
            state,
            old_parent_vh,
            args.name_a(),
            new_parent_vh,
            args.name_b(),
        );
        finish_saltyfs_continuation(op_id, TRONA_OK);
        true
    }
}

unsafe fn complete_saltyfs_setattr_like(
    state: &mut VfsState,
    completion: &crate::owner::backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let op_id = crate::owner::pending_ops::PendingOpId::from_raw((*completion).op_id);
        if finish_saltyfs_completion_error(op_id, completion) {
            return true;
        }
        let reply = (*completion).backend_reply;
        let Some(snapshot) = parse_attr_snapshot(&reply) else {
            finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
            return true;
        };
        let vnode = unpack_vh((*completion).ctx.data[0]);
        if let Err(err) = apply_attr_snapshot(state, vnode, snapshot) {
            finish_saltyfs_continuation(op_id, err);
            return true;
        }

        if pending_op_kind(op_id) == crate::owner::pending_ops::PO_KIND_OPEN_CONT {
            if !set_saved_current_vnode(op_id, vnode) {
                finish_saltyfs_continuation(op_id, TRONA_INVALID_OPERATION);
                return true;
            }
            return false;
        }

        finish_saltyfs_continuation(op_id, TRONA_OK);
        true
    }
}
