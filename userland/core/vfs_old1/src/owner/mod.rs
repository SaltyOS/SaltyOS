// SPDX-License-Identifier: GPL-2.0-only
//! `VfsState` — the single owner of all mutable VFS state.
//!
//! Namespace structure lives here: vnode table, mount table, mount
//! namespaces, and the bootstrap scaffold used by the FHS layout and the
//! eventual `pivot_root` handoff from the initramfs-style boot root to
//! the real root filesystem.

pub(crate) mod backend_rpc;
pub(crate) mod bootstrap;
pub(crate) mod cancel;
pub(crate) mod clients;
pub(crate) mod continuation;
pub(crate) mod dispatch;
pub(crate) mod loop_;
pub(crate) mod namei;
pub(crate) mod objects;
pub(crate) mod pending_ops;
pub(crate) mod vnode_index;
pub(crate) mod worker;

use trona_kernel::core_types::*;
use trona_posix::consts::*;
use uapi::*;

use crate::arena::Arena;
use crate::boot::rootfs::RootfsState;
use crate::fs::devfs::DevfsMountData;
use crate::fs::pipefs::PipefsMountData;
use crate::fs::procfs::ProcfsMountData;
use crate::fs::saltyfs::{SaltyfsMountData, SaltyfsVnodeState};
use crate::fs::sysctlfs::SysctlfsMountData;
use crate::fs::tmpfs::{TmpfsDirEntry, TmpfsMountData, TmpfsSymlinkBuf, TmpfsVnodeState};
use crate::server::epoll_object::EpollState;
use crate::server::fifo_object::FifoState;
use crate::server::open_file::OpenFile;
use crate::server::pipe_object::PipeState;
use crate::server::proc_object::ProcNodeState;
use crate::server::shm_object::ShmState;
use crate::server::sysctl_object::SysctlLeafState;
use crate::server::types::{ClientHandle, ClientState, PERS_WIN32};
use crate::server::unix_socket_object::UnixSocketState;
use crate::vfs_core::bootstrap::BootstrapLayout;
use crate::vfs_core::cached_ref::CachedRef;
use crate::vfs_core::device::BOOTSTRAP_DEV_NODES;
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};
use crate::vfs_core::mount::{Mount, MountHandle};
use crate::vfs_core::mount_ns::{MountNamespace, MountNsHandle};
use crate::vfs_core::namei::{ParentLookup, PathAnchor};
use crate::vfs_core::vnode::{VN_PINNED, VN_ROOT, VT_DIR, Vnode, VnodeHandle};

const MM_PAGE_SIZE: u64 = 4096;
const BOOTSTRAP_PATH_MAX: usize = 256;
const BOOTSTRAP_PATH_DEPTH_MAX: usize = 64;
const BOOTSTRAP_SYMLINK_DEPTH_MAX: u8 = 8;
const SOCK_SEQPACKET: i32 = 5;

const INITIAL_VNODE_CAP: u32 = 256;
const INITIAL_VNODE_KEY_INDEX_CAP: u32 = 1024;
const INITIAL_MOUNT_CAP: u32 = 32;
const INITIAL_MOUNT_NS_CAP: u32 = 8;
const INITIAL_CLIENT_CAP: u32 = 32;
const INITIAL_OPEN_FILE_CAP: u32 = 256;
const INITIAL_FIFO_CAP: u32 = 64;
const INITIAL_PIPE_CAP: u32 = 64;
const INITIAL_SHM_CAP: u32 = 64;
const INITIAL_EPOLL_CAP: u32 = 16;
const INITIAL_UNIX_SOCKET_CAP: u32 = 64;
const INITIAL_PIPEFS_MOUNT_CAP: u32 = 4;
const INITIAL_DEVFS_MOUNT_CAP: u32 = 4;
const INITIAL_PROCFS_MOUNT_CAP: u32 = 4;
const INITIAL_SYSCTLFS_MOUNT_CAP: u32 = 4;
const INITIAL_SYSCTL_LEAF_CAP: u32 = 32;
const INITIAL_PROC_NODE_CAP: u32 = 256;
const INITIAL_TMPFS_MOUNT_CAP: u32 = 8;
const INITIAL_TMPFS_NODE_CAP: u32 = 512;
const INITIAL_TMPFS_DIR_ENTRY_CAP: u32 = 1024;
const INITIAL_TMPFS_SYMLINK_CAP: u32 = 64;
const INITIAL_SALTYFS_MOUNT_CAP: u32 = 4;
const INITIAL_SALTYFS_NODE_CAP: u32 = 512;

/// All mutable VFS state, owned exclusively by the owner loop.
/// Workers do not mutate this struct directly.
pub(crate) struct VfsState {
    /// Global vnode table. Every namespace-visible filesystem object is
    /// represented here exactly once per live cache entry.
    pub(crate) vnodes: Arena<Vnode>,
    /// Fast structural-identity lookup for live vnodes.
    pub(crate) vnode_key_index: vnode_index::VnodeKeyIndex,
    /// Mount table. Mount-path ownership and root swaps (`pivot_root`,
    /// bind overlays, pseudo-filesystem grafts) are expressed here.
    pub(crate) mounts: Arena<Mount>,
    /// Mount-namespace table. The default namespace is shared by system
    /// services; future per-client namespaces fork from this root.
    pub(crate) mount_namespaces: Arena<MountNamespace>,
    /// Authoritative root mount for the global namespace.
    pub(crate) root_mount: MountHandle,
    /// Global namespace handle used by bootstrap services and as the
    /// template for client namespace attachment.
    pub(crate) global_ns: MountNsHandle,
    /// Shared open-file descriptions backing client descriptor slots.
    pub(crate) open_files: Arena<OpenFile>,
    /// Named FIFO vnode-to-pipe associations.
    pub(crate) fifos: Arena<FifoState>,
    /// Anonymous pipe backing store.
    pub(crate) pipes: Arena<PipeState>,
    /// Mounted pipefs instances.
    pub(crate) pipefs_mounts: Arena<PipefsMountData>,
    /// Mounted devfs instances.
    pub(crate) devfs_mounts: Arena<DevfsMountData>,
    /// Mounted procfs instances.
    pub(crate) procfs_mounts: Arena<ProcfsMountData>,
    /// Mounted saltyfs instances.
    pub(crate) saltyfs_mounts: Arena<SaltyfsMountData>,
    /// Cached saltyfs vnode identity/state.
    pub(crate) saltyfs_nodes: Arena<SaltyfsVnodeState>,
    /// Mounted sysctlfs instances.
    pub(crate) sysctlfs_mounts: Arena<SysctlfsMountData>,
    /// sysctlfs generated regular-file leaves.
    pub(crate) sysctl_leaves: Arena<SysctlLeafState>,
    /// procfs generated root/pid nodes.
    pub(crate) proc_nodes: Arena<ProcNodeState>,
    /// Mounted tmpfs instances and their inode allocators.
    pub(crate) tmpfs_mounts: Arena<TmpfsMountData>,
    /// Per-vnode tmpfs metadata.
    pub(crate) tmpfs_nodes: Arena<TmpfsVnodeState>,
    /// Intrusive directory-entry list backing tmpfs directories.
    pub(crate) tmpfs_dir_entries: Arena<TmpfsDirEntry>,
    /// Fixed-size symlink target storage shared by every tmpfs mount.
    pub(crate) tmpfs_symlinks: Arena<TmpfsSymlinkBuf>,
    /// POSIX shared-memory descriptors.
    pub(crate) shms: Arena<ShmState>,
    /// Immediate epoll interest lists.
    pub(crate) epolls: Arena<EpollState>,
    /// Local AF_UNIX socketpair endpoints.
    pub(crate) unix_sockets: Arena<UnixSocketState>,
    /// Per-client namespace/cwd/personality state.
    pub(crate) clients: Arena<ClientState>,
    /// Plain endpoint cap published to netsrv for NET_COMPLETE
    /// callbacks. netsrv mints a badged alias keyed with
    /// `NETSRV_CALLBACK_BADGE` after `NET_REGISTER_VFS`.
    pub(crate) netsrv_callback_ep: Cap,
    /// Idempotency guard for `register_with_netsrv` so reconnect logic
    /// (if any) does not re-mint badges.
    pub(crate) netsrv_registered: bool,
    /// Win32 current-drive and per-drive cwd sidecar.
    pub(crate) win32_cwd: crate::personality::win32::cwd_table::Win32CwdTable,
    /// Bootstrap scaffold state: the FHS mountpoints and `put_old`
    /// location used during rootfs handoff live here.
    pub(crate) bootstrap: BootstrapLayout,
    /// Real-root retry state driven from the timed owner loop.
    pub(crate) rootfs: RootfsState,
    /// Monotonic mount-instance allocator. `0` remains the invalid
    /// sentinel so zeroed fields are trivially recognisable as unset.
    pub(crate) next_fs_instance_id: FsInstanceId,
    /// Dedicated receive slot for the owner thread's service endpoint.
    pub(crate) owner_recv_slot: Cap,
    /// Per-worker receive slots. Owner and worker IPC streams must remain
    /// disjoint even when they target the same backend service.
    pub(crate) worker_recv_slots: [Cap; worker::MAX_WORKERS],
    /// Number of workers successfully spawned at boot.
    pub(crate) workers_spawned: usize,
}

impl VfsState {
    /// Construct the owner state and its non-moving namespace arenas.
    pub(crate) fn new() -> Option<Self> {
        Some(VfsState {
            vnodes: Arena::new(INITIAL_VNODE_CAP)?,
            vnode_key_index: vnode_index::VnodeKeyIndex::new(INITIAL_VNODE_KEY_INDEX_CAP)?,
            mounts: Arena::new(INITIAL_MOUNT_CAP)?,
            mount_namespaces: Arena::new(INITIAL_MOUNT_NS_CAP)?,
            open_files: Arena::new(INITIAL_OPEN_FILE_CAP)?,
            fifos: Arena::new(INITIAL_FIFO_CAP)?,
            pipes: Arena::new(INITIAL_PIPE_CAP)?,
            pipefs_mounts: Arena::new(INITIAL_PIPEFS_MOUNT_CAP)?,
            devfs_mounts: Arena::new(INITIAL_DEVFS_MOUNT_CAP)?,
            procfs_mounts: Arena::new(INITIAL_PROCFS_MOUNT_CAP)?,
            saltyfs_mounts: Arena::new(INITIAL_SALTYFS_MOUNT_CAP)?,
            saltyfs_nodes: Arena::new(INITIAL_SALTYFS_NODE_CAP)?,
            sysctlfs_mounts: Arena::new(INITIAL_SYSCTLFS_MOUNT_CAP)?,
            sysctl_leaves: Arena::new(INITIAL_SYSCTL_LEAF_CAP)?,
            proc_nodes: Arena::new(INITIAL_PROC_NODE_CAP)?,
            tmpfs_mounts: Arena::new(INITIAL_TMPFS_MOUNT_CAP)?,
            tmpfs_nodes: Arena::new(INITIAL_TMPFS_NODE_CAP)?,
            tmpfs_dir_entries: Arena::new(INITIAL_TMPFS_DIR_ENTRY_CAP)?,
            tmpfs_symlinks: Arena::new(INITIAL_TMPFS_SYMLINK_CAP)?,
            shms: Arena::new(INITIAL_SHM_CAP)?,
            epolls: Arena::new(INITIAL_EPOLL_CAP)?,
            unix_sockets: Arena::new(INITIAL_UNIX_SOCKET_CAP)?,
            clients: Arena::new(INITIAL_CLIENT_CAP)?,
            netsrv_callback_ep: 0,
            netsrv_registered: false,
            win32_cwd: crate::personality::win32::cwd_table::Win32CwdTable::zeroed(),
            root_mount: MountHandle::INVALID,
            global_ns: MountNsHandle::INVALID,
            bootstrap: BootstrapLayout::zeroed(),
            rootfs: RootfsState::zeroed(),
            next_fs_instance_id: FsInstanceId::new(1),
            owner_recv_slot: 0,
            worker_recv_slots: [0; worker::MAX_WORKERS],
            workers_spawned: 0,
        })
    }

    #[inline]
    pub(crate) fn alloc_fs_instance_id(&mut self) -> FsInstanceId {
        let current = self.next_fs_instance_id;
        let next_raw = current.0.wrapping_add(1);
        self.next_fs_instance_id = FsInstanceId::new(if next_raw == 0 { 1 } else { next_raw });
        current
    }

    fn apply_mount_vnode_defaults(&mut self, vnode: VnodeHandle, fallback_vtype: u8) {
        let (mount_handle, fallback_id) = match self.vnodes.get(vnode) {
            Some(vn) => (
                vn.mount.handle,
                Self::bootstrap_dynamic_vnode_id(vnode, fallback_vtype),
            ),
            None => return,
        };
        if !mount_handle.is_valid() {
            if let Some(vn) = self.vnodes.get_mut(vnode) {
                if vn.id == 0 {
                    vn.id = fallback_id;
                }
            }
            return;
        }

        let (vops, backend_kind, is_tmpfs) = match self.mounts.get(mount_handle) {
            Some(mount) => (
                mount.vops,
                mount.backend_kind,
                crate::fs::tmpfs::mount_is_tmpfs(mount),
            ),
            None => (
                core::ptr::null(),
                crate::vfs_core::vnode::VNODE_BACKEND_NONE,
                false,
            ),
        };
        let assigned_id = if is_tmpfs {
            crate::fs::tmpfs::alloc_inode(self, mount_handle).unwrap_or(fallback_id)
        } else {
            fallback_id
        };

        if let Some(vn) = self.vnodes.get_mut(vnode) {
            if vn.id == 0 {
                vn.id = assigned_id;
            }
            if vn.ops.is_null() {
                vn.ops = vops;
            }
            if vn.backend_kind == crate::vfs_core::vnode::VNODE_BACKEND_NONE {
                vn.backend_kind = backend_kind;
            }
        }
        self.cache_vnode_key(vnode);
    }

    #[inline]
    pub(crate) fn cache_vnode_key(&self, vnode: VnodeHandle) {
        let Some(vn) = self.vnodes.get(vnode) else {
            return;
        };
        let key = vn.vnode_key();
        if vnode_index::VnodeKeyIndex::key_is_indexable(key) {
            let _ = self.vnode_key_index.insert(key, vnode);
        }
    }

    #[inline]
    pub(crate) fn uncache_vnode_key(&self, vnode: VnodeHandle) {
        let Some(vn) = self.vnodes.get(vnode) else {
            return;
        };
        let key = vn.vnode_key();
        if vnode_index::VnodeKeyIndex::key_is_indexable(key) {
            let _ = self.vnode_key_index.remove(key, Some(vnode));
        }
    }

    #[inline]
    pub(crate) fn refresh_vnode_key(&self, vnode: VnodeHandle, old_key: VnodeKey) {
        if vnode_index::VnodeKeyIndex::key_is_indexable(old_key) {
            let _ = self.vnode_key_index.remove(old_key, Some(vnode));
        }
        self.cache_vnode_key(vnode);
    }

    pub(crate) fn reclaim_bootstrap_vnode(&mut self, vnode: VnodeHandle) {
        let ephemeral_proc = crate::fs::procfs::node_is_ephemeral(self, vnode);
        let (data, size) = {
            let Some(vn) = self.vnodes.get(vnode) else {
                return;
            };
            if (vn.flags & (VN_PINNED | VN_ROOT)) != 0
                || (!ephemeral_proc && vn.nlink != 0)
                || vn.open_count != 0
                || vn.covered_by.handle.is_valid()
            {
                return;
            }
            (vn.data, vn.size)
        };

        self.release_fifo_state_if_unused(vnode);
        crate::fs::procfs::release_node_for_vnode(self, vnode);
        crate::fs::sysctlfs::release_leaf_for_vnode(self, vnode);
        // Backend reclaim hook: tmpfs (and any future first-class
        // backend) tears down its per-vnode arena state and MO cap
        // here, after the generic reclaim path confirmed there are no
        // pinned references left.
        if let Some(ops) = crate::vfs_core::vfsops::vfsops_for_vnode(self, vnode) {
            if let Some(callback) = ops.reclaim_vnode {
                callback(self, vnode);
            }
        }
        self.uncache_vnode_key(vnode);
        if !self.vnodes.release(vnode) {
            return;
        }
        let bytes = Self::page_align_up(size);
        if !data.is_null() && bytes != 0 {
            let _ = unsafe { crate::server::mem::unmap(data, bytes) };
        }
    }

    fn initialize_bootstrap_scaffold(
        &mut self,
        root_vh: VnodeHandle,
        root_mh: MountHandle,
        fs_id: FsInstanceId,
    ) -> bool {
        let dirs = crate::vfs_core::bootstrap::BOOTSTRAP_ROOT_DIRS;
        for (dir_idx, name) in dirs.iter().enumerate() {
            let vh = match self.ensure_bootstrap_dir(
                root_vh,
                root_mh,
                fs_id,
                name,
                (dir_idx as u64) + 2,
            ) {
                Some(vh) => vh,
                None => return false,
            };

            match *name {
                b"etc" => self.bootstrap.etc_dir = vh,
                b"dev" => self.bootstrap.dev_dir = vh,
                b"proc" => self.bootstrap.proc_dir = vh,
                b"sys" => self.bootstrap.sys_dir = vh,
                b"tmp" => self.bootstrap.tmp_dir = vh,
                b"pipe" => self.bootstrap.pipe_dir = vh,
                b"initramfs" => {
                    self.bootstrap.initramfs_dir = vh;
                    self.bootstrap.put_old_dir = vh;
                }
                b"newroot" => self.bootstrap.new_root_dir = vh,
                _ => {}
            }
        }
        true
    }

    fn initialize_bootstrap_seed_files(
        &mut self,
        root_mh: MountHandle,
        fs_id: FsInstanceId,
    ) -> bool {
        let etc_vh = self.bootstrap.etc_dir;
        if !etc_vh.is_valid() {
            return false;
        }
        for (idx, file) in crate::vfs_core::bootstrap::BOOTSTRAP_ETC_FILES
            .iter()
            .enumerate()
        {
            let vnode_id = 0x200 + idx as u64;
            if self
                .create_bootstrap_file(
                    etc_vh,
                    root_mh,
                    fs_id,
                    file.name,
                    vnode_id,
                    file.mode,
                    file.content,
                )
                .is_none()
            {
                return false;
            }
        }
        true
    }

    fn initialize_bootstrap_devfs_nodes(&mut self) -> bool {
        let Some(dev_root) = self.bootstrap_lookup_path(b"/dev") else {
            return false;
        };
        let (dev_mount, dev_fs_id) = match self.vnodes.get(dev_root) {
            Some(vn) => (vn.mount.handle, vn.fs_instance_id),
            None => return false,
        };
        if !dev_mount.is_valid() {
            return false;
        }

        if self
            .ensure_bootstrap_dir(dev_root, dev_mount, dev_fs_id, b"pts", 0x310)
            .is_none()
        {
            return false;
        }

        for spec in BOOTSTRAP_DEV_NODES {
            if self
                .create_bootstrap_char_device(
                    dev_root, dev_mount, dev_fs_id, spec.name, spec.mode, spec.kind, 0, 0,
                )
                .is_none()
            {
                return false;
            }
        }
        if self.bootstrap_lookup_path(b"/dev/random").is_none()
            && self
                .bootstrap_create_symlink_path(
                    b"/dev/random",
                    (S_IFLNK as u32) | 0o777,
                    b"/dev/urandom",
                )
                .is_err()
        {
            return false;
        }
        if self.bootstrap_lookup_path(b"/dev/fb").is_none()
            && self
                .bootstrap_create_symlink_path(b"/dev/fb", (S_IFLNK as u32) | 0o777, b"/dev/fb0")
                .is_err()
        {
            return false;
        }
        if self.bootstrap_lookup_path(b"/dev/tty0").is_none()
            && self
                .bootstrap_create_symlink_path(
                    b"/dev/tty0",
                    (S_IFLNK as u32) | 0o777,
                    b"/dev/console",
                )
                .is_err()
        {
            return false;
        }
        if self.bootstrap_lookup_path(b"/dev/pts/ptmx").is_none()
            && self
                .bootstrap_create_symlink_path(
                    b"/dev/pts/ptmx",
                    (S_IFLNK as u32) | 0o777,
                    b"/dev/ptmx",
                )
                .is_err()
        {
            return false;
        }
        true
    }

    fn ensure_bootstrap_overlay_dir(
        &mut self,
        parent: VnodeHandle,
        mount: MountHandle,
        fs_id: FsInstanceId,
        name: &[u8],
        vnode_id: u64,
    ) -> Option<VnodeHandle> {
        if let Some(vh) = self.bootstrap_lookup_child(parent, name) {
            return Some(vh);
        }

        let vh = self.create_bootstrap_dir(
            parent,
            mount,
            fs_id,
            name,
            vnode_id,
            crate::vfs_core::bootstrap::bootstrap_dir_mode(name),
        )?;
        if let Some(vn) = self.vnodes.get_mut(vh) {
            vn.id = Self::bootstrap_dynamic_vnode_id(vh, VT_DIR);
        }
        self.cache_vnode_key(vh);
        Some(vh)
    }

    fn prepare_post_pivot_scaffold(
        &mut self,
        new_root_mh: MountHandle,
    ) -> Option<[VnodeHandle; 6]> {
        let new_root_vh = self.mounts.get(new_root_mh)?.root_vnode;
        let new_root_fs_id = self.mounts.get(new_root_mh)?.fs_instance_id;
        let mut result = [VnodeHandle::INVALID; 6];

        for (idx, name) in crate::vfs_core::bootstrap::POST_PIVOT_DIRS
            .iter()
            .enumerate()
        {
            let vh = self.ensure_bootstrap_overlay_dir(
                new_root_vh,
                new_root_mh,
                new_root_fs_id,
                name,
                0x100 + idx as u64,
            )?;
            result[idx] = vh;
        }

        Some(result)
    }

    fn clear_mount_covering_link(&mut self, target_vh: VnodeHandle) {
        if let Some(vn) = self.vnodes.get_mut(target_vh) {
            vn.flags &= !crate::vfs_core::vnode::VN_COVERED;
            vn.covered_by = CachedRef::<FsInstanceId, MountHandle>::INVALID;
            vn.unpin();
        }
    }

    pub(crate) fn attach_mount_at_vnode(
        &mut self,
        mount_handle: MountHandle,
        parent_mh: MountHandle,
        target_vh: VnodeHandle,
        path: &[u8],
    ) -> bool {
        let target_key = match self.vnodes.get(target_vh) {
            Some(vnode) => vnode.vnode_key(),
            None => return false,
        };
        let parent_fs_id = match self.mounts.get(parent_mh) {
            Some(mount) => mount.fs_instance_id,
            None => return false,
        };
        let child_fs_id = match self.mounts.get(mount_handle) {
            Some(mount) => mount.fs_instance_id,
            None => return false,
        };

        let old_target = match self.mounts.get(mount_handle) {
            Some(mount) => mount.covered.handle,
            None => return false,
        };
        if old_target.is_valid() {
            self.clear_mount_covering_link(old_target);
        }

        {
            let mount = match self.mounts.get_mut(mount_handle) {
                Some(mount) => mount,
                None => return false,
            };
            mount.parent = CachedRef::new(parent_fs_id, parent_mh);
            mount.covered = CachedRef::new(target_key, target_vh);
            if !mount.set_mount_path(path) {
                return false;
            }
        }

        if let Some(vn) = self.vnodes.get_mut(target_vh) {
            vn.flags |= crate::vfs_core::vnode::VN_COVERED;
            vn.covered_by = CachedRef::new(child_fs_id, mount_handle);
            vn.pin();
            true
        } else {
            false
        }
    }

    /// Attach a mounted filesystem to an already-resolved namespace vnode.
    ///
    /// Runtime `mount(2)` calls must not depend on the bootstrap shadow
    /// tree: the current mount namespace and backend lookup are the source
    /// of truth. `path` remains the display / policy path stored on the
    /// mount for introspection and pivot reattachment.
    pub(crate) fn graft_mount_at_vnode(
        &mut self,
        mount_handle: MountHandle,
        target_vh: VnodeHandle,
        path: &[u8],
    ) -> bool {
        let parent_mh = match self.vnodes.get(target_vh) {
            Some(vnode) if vnode.mount.handle.is_valid() => vnode.mount.handle,
            _ => self.root_mount,
        };
        self.attach_mount_at_vnode(mount_handle, parent_mh, target_vh, path)
    }

    /// Attach a mounted filesystem to a bootstrap path such as `/newroot`.
    pub(crate) fn graft_mount_at_bootstrap_path(
        &mut self,
        mount_handle: MountHandle,
        path: &[u8],
    ) -> bool {
        let target_vh = match self.bootstrap_lookup_path(path) {
            Some(vh) => vh,
            None => return false,
        };
        let parent_mh = self.root_mount;
        if !self.attach_mount_at_vnode(mount_handle, parent_mh, target_vh, path) {
            return false;
        }

        if path == b"/newroot" {
            self.bootstrap.real_root_mount = mount_handle;
        }
        true
    }

    /// Promote the grafted real root mount to `/` and move the previous
    /// root under `/initramfs` of the new root tree.
    pub(crate) fn pivot_root_to_real_root(&mut self) -> bool {
        let new_root_mh = self.bootstrap.real_root_mount;
        let old_root_mh = self.root_mount;
        if !new_root_mh.is_valid() || !old_root_mh.is_valid() || new_root_mh == old_root_mh {
            return false;
        }

        let new_targets = match self.prepare_post_pivot_scaffold(new_root_mh) {
            Some(targets) => targets,
            None => return false,
        };
        let put_old_vh = new_targets[5];
        let old_root_fs_id = match self.mounts.get(old_root_mh) {
            Some(mount) => mount.fs_instance_id,
            None => return false,
        };

        let new_cover_target = match self.mounts.get(new_root_mh) {
            Some(mount) => mount.covered.handle,
            None => return false,
        };

        let mut child_mounts = [MountHandle::INVALID; 5];
        let mut child_count = 0usize;
        self.mounts.for_each_active(|mh, mount| {
            if mh == old_root_mh || mh == new_root_mh {
                return true;
            }
            if mount.parent.id != old_root_fs_id {
                return true;
            }
            let path = &mount.mount_path[..mount.mount_path_len as usize];
            for expected in crate::vfs_core::bootstrap::PIVOT_REATTACH_DIRS {
                let full = if *expected == b"dev" {
                    b"/dev".as_slice()
                } else if *expected == b"proc" {
                    b"/proc".as_slice()
                } else if *expected == b"tmp" {
                    b"/tmp".as_slice()
                } else if *expected == b"sys" {
                    b"/sys".as_slice()
                } else {
                    b"/pipe".as_slice()
                };
                if path == full && child_count < child_mounts.len() {
                    child_mounts[child_count] = mh;
                    child_count += 1;
                    break;
                }
            }
            true
        });

        for idx in 0..child_count {
            let child = child_mounts[idx];
            let mut path_buf = [0u8; crate::vfs_core::mount::MOUNT_PATH_MAX];
            let path_len = match self.mounts.get(child) {
                Some(mount) => {
                    let len = mount.mount_path_len as usize;
                    path_buf[..len].copy_from_slice(&mount.mount_path[..len]);
                    len
                }
                None => return false,
            };
            let path = &path_buf[..path_len];
            let target = if path == b"/dev" {
                new_targets[0]
            } else if path == b"/proc" {
                new_targets[1]
            } else if path == b"/tmp" {
                new_targets[2]
            } else if path == b"/sys" {
                new_targets[3]
            } else {
                new_targets[4]
            };
            if !self.attach_mount_at_vnode(child, new_root_mh, target, path) {
                return false;
            }
        }

        if !self.attach_mount_at_vnode(old_root_mh, new_root_mh, put_old_vh, b"/initramfs") {
            return false;
        }

        if new_cover_target.is_valid() {
            self.clear_mount_covering_link(new_cover_target);
        }

        self.root_mount = new_root_mh;
        if let Some(ns) = self.mount_namespaces.get_mut(self.global_ns) {
            ns.root_mount = new_root_mh;
            if ns.mount_count != 0 {
                ns.mounts[0] = new_root_mh;
            }
        } else {
            return false;
        }

        {
            let new_root = match self.mounts.get_mut(new_root_mh) {
                Some(mount) => mount,
                None => return false,
            };
            new_root.parent = CachedRef::<FsInstanceId, MountHandle>::INVALID;
            new_root.covered = CachedRef::<VnodeKey, VnodeHandle>::INVALID;
            if !new_root.set_mount_path(b"/") {
                return false;
            }
        }

        self.bootstrap.dev_dir = new_targets[0];
        self.bootstrap.proc_dir = new_targets[1];
        self.bootstrap.tmp_dir = new_targets[2];
        self.bootstrap.sys_dir = new_targets[3];
        self.bootstrap.pipe_dir = new_targets[4];
        self.bootstrap.initramfs_dir = put_old_vh;
        self.bootstrap.put_old_dir = put_old_vh;
        unsafe {
            crate::personality::win32::drives::init_drives(self);
        }

        true
    }

    /// Resolve the current namespace root vnode.
    pub(crate) fn root_vnode(&self) -> Option<VnodeHandle> {
        self.mounts
            .get(self.root_mount)
            .map(|mount| mount.root_vnode)
    }

    fn normalize_bootstrap_absolute_path(
        &self,
        path: &[u8],
        out: &mut [u8; BOOTSTRAP_PATH_MAX],
    ) -> Option<usize> {
        if path.is_empty() {
            return None;
        }

        let mut raw = [0u8; BOOTSTRAP_PATH_MAX];
        let mut raw_len = 0usize;
        if path[0] != b'/' {
            raw[0] = b'/';
            raw_len = 1;
        }
        for byte in path {
            if raw_len >= raw.len() {
                return None;
            }
            raw[raw_len] = *byte;
            raw_len += 1;
        }

        let mut out_len = 1usize;
        out[0] = b'/';
        let mut comp_starts = [0usize; BOOTSTRAP_PATH_DEPTH_MAX];
        let mut depth = 0usize;
        let mut pos = if raw_len > 0 && raw[0] == b'/' { 1 } else { 0 };

        while pos < raw_len {
            while pos < raw_len && raw[pos] == b'/' {
                pos += 1;
            }
            if pos >= raw_len {
                break;
            }

            let start = pos;
            while pos < raw_len && raw[pos] != b'/' {
                pos += 1;
            }
            let seg_len = pos - start;
            if seg_len == 0 {
                continue;
            }
            if seg_len == 1 && raw[start] == b'.' {
                continue;
            }
            if seg_len == 2 && raw[start] == b'.' && raw[start + 1] == b'.' {
                if depth > 0 {
                    depth -= 1;
                    out_len = comp_starts[depth];
                    if out_len == 0 {
                        out_len = 1;
                        out[0] = b'/';
                    }
                }
                continue;
            }
            if depth >= comp_starts.len() {
                return None;
            }
            comp_starts[depth] = out_len;
            depth += 1;
            if out_len > 1 {
                if out_len >= out.len() {
                    return None;
                }
                out[out_len] = b'/';
                out_len += 1;
            }
            if out_len + seg_len > out.len() {
                return None;
            }
            out[out_len..out_len + seg_len].copy_from_slice(&raw[start..start + seg_len]);
            out_len += seg_len;
        }

        Some(out_len)
    }

    pub(crate) fn render_anchor_path(&self, anchor: PathAnchor, out: &mut [u8]) -> Option<usize> {
        crate::owner::namei::render_anchor_path(self, anchor, out)
    }

    fn bootstrap_lookup_path_inner(
        &self,
        path: &[u8],
        depth: u8,
        follow_final_symlink: bool,
        ignore_case: bool,
        skip_posix_only: bool,
        skip_win32_only: bool,
    ) -> Option<VnodeHandle> {
        crate::owner::namei::bootstrap_lookup_path_inner(
            self,
            path,
            depth,
            follow_final_symlink,
            ignore_case,
            skip_posix_only,
            skip_win32_only,
        )
    }

    /// Resolve an absolute path inside the bootstrap tree.
    pub(crate) fn bootstrap_lookup_path(&self, path: &[u8]) -> Option<VnodeHandle> {
        self.bootstrap_lookup_path_inner(path, 0, true, false, false, true)
    }

    pub(crate) fn bootstrap_lookup_path_for_personality(
        &self,
        path: &[u8],
        no_follow: bool,
        personality: u8,
    ) -> Option<VnodeHandle> {
        let ignore_case = personality == PERS_WIN32;
        let skip_posix_only = personality == PERS_WIN32;
        let skip_win32_only = personality != PERS_WIN32;
        self.bootstrap_lookup_path_inner(
            path,
            0,
            !no_follow,
            ignore_case,
            skip_posix_only,
            skip_win32_only,
        )
    }

    pub(crate) fn lookup_live_pty_generation(&self, pty_id: u32) -> Option<u32> {
        crate::owner::namei::lookup_live_pty_generation(self, pty_id)
    }

    pub(crate) fn lookup_path_dynamic_for_client(
        &mut self,
        cli_handle: ClientHandle,
        path: &[u8],
        no_follow: bool,
    ) -> crate::vfs_core::vops::VfsResult<Option<VnodeHandle>> {
        crate::owner::namei::lookup_path_dynamic_for_client(self, cli_handle, path, no_follow)
    }

    pub(crate) fn lookup_path_dynamic_absolute(
        &mut self,
        path: &[u8],
        no_follow: bool,
    ) -> crate::vfs_core::vops::VfsResult<Option<VnodeHandle>> {
        crate::owner::namei::lookup_path_dynamic_absolute(self, path, no_follow)
    }

    /// Build the initial namespace root.
    ///
    /// The boot namespace starts as a single mounted directory root. FHS
    /// scaffold directories and pseudo-filesystem grafts hang off this
    /// mount later, but the root mount / root namespace objects must exist
    /// from the first request onward so `pivot_root` has stable anchors.
    pub(crate) fn initialize_bootstrap_namespace(&mut self) -> bool {
        let root_vh = match self.vnodes.alloc() {
            Some(handle) => handle,
            None => return false,
        };
        let root_mh = match self.mounts.alloc() {
            Some(handle) => handle,
            None => return false,
        };
        let global_ns = match self.mount_namespaces.alloc() {
            Some(handle) => handle,
            None => return false,
        };

        let fs_id = self.alloc_fs_instance_id();

        {
            let vnode = match self.vnodes.get_mut(root_vh) {
                Some(vnode) => vnode,
                None => return false,
            };
            *vnode = Vnode::new_root_dir(fs_id);
        }
        self.cache_vnode_key(root_vh);

        {
            let mount = match self.mounts.get_mut(root_mh) {
                Some(mount) => mount,
                None => return false,
            };
            *mount = Mount::new_boot_root(fs_id, root_vh);
        }

        {
            let vnode = match self.vnodes.get_mut(root_vh) {
                Some(vnode) => vnode,
                None => return false,
            };
            vnode.mount = CachedRef::new(fs_id, root_mh);
        }

        {
            let ns = match self.mount_namespaces.get_mut(global_ns) {
                Some(ns) => ns,
                None => return false,
            };
            *ns = MountNamespace::zeroed();
            ns.refcount = 1;
            ns.root_mount = root_mh;
            ns.mounts[0] = root_mh;
            ns.mount_count = 1;
        }

        self.root_mount = root_mh;
        self.global_ns = global_ns;
        self.bootstrap = BootstrapLayout::zeroed();
        self.bootstrap.boot_root_mount = root_mh;
        unsafe {
            crate::personality::win32::drives::init_drives(self);
        }
        if !self.initialize_bootstrap_scaffold(root_vh, root_mh, fs_id) {
            return false;
        }
        if !self.initialize_bootstrap_seed_files(root_mh, fs_id) {
            return false;
        }
        if !crate::vfs_core::mount_ctl::mount_bootstrap_pseudo_filesystems(self) {
            return false;
        }
        let Some(dev_dir) = self.bootstrap_lookup_path(b"/dev") else {
            return false;
        };
        let Some(proc_dir) = self.bootstrap_lookup_path(b"/proc") else {
            return false;
        };
        let Some(tmp_dir) = self.bootstrap_lookup_path(b"/tmp") else {
            return false;
        };
        let Some(sys_dir) = self.bootstrap_lookup_path(b"/sys") else {
            return false;
        };
        let Some(pipe_dir) = self.bootstrap_lookup_path(b"/pipe") else {
            return false;
        };
        self.bootstrap.dev_dir = dev_dir;
        self.bootstrap.proc_dir = proc_dir;
        self.bootstrap.tmp_dir = tmp_dir;
        self.bootstrap.sys_dir = sys_dir;
        self.bootstrap.pipe_dir = pipe_dir;
        if !crate::fs::sysctlfs::populate_bootstrap_tree(self) {
            return false;
        }
        if !crate::fs::procfs::populate_bootstrap_tree(self) {
            return false;
        }
        let shm_dir = match self.bootstrap_lookup_path(b"/tmp/shm") {
            Some(vh) => vh,
            None => match self.bootstrap_mkdir_path(b"/tmp/shm", (S_IFDIR as u32) | 0o1777) {
                Ok(vh) => vh,
                Err(_) => return false,
            },
        };
        if self.bootstrap_set_mode_vnode(shm_dir, 0o1777) != TRONA_OK {
            return false;
        }
        if !self.initialize_bootstrap_devfs_nodes() {
            return false;
        }

        let root_key = match self.vnodes.get(root_vh) {
            Some(vnode) => vnode.vnode_key(),
            None => return false,
        };
        if self.mount_by_fs_instance_id(fs_id) != Some(root_mh) {
            return false;
        }
        if self.vnode_by_key(root_key) != Some(root_vh) {
            return false;
        }
        if self.mount_namespaces.get(global_ns).is_none() {
            return false;
        }
        if self.bootstrap_lookup_path(b"/etc") != Some(self.bootstrap.etc_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/dev") != Some(self.bootstrap.dev_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/dev/console").is_none() {
            return false;
        }
        if self.bootstrap_lookup_path(b"/dev/pts").is_none() {
            return false;
        }
        if self.bootstrap_lookup_path(b"/proc") != Some(self.bootstrap.proc_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/sys") != Some(self.bootstrap.sys_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/tmp") != Some(self.bootstrap.tmp_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/pipe") != Some(self.bootstrap.pipe_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/initramfs") != Some(self.bootstrap.initramfs_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/newroot") != Some(self.bootstrap.new_root_dir) {
            return false;
        }
        if self.bootstrap_lookup_path(b"/etc/passwd").is_none() {
            return false;
        }
        crate::vfs_core::mount_ctl::refresh_global_ns(self);

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] bootstrap namespace ready: root mount=");
            _lb.hex(root_mh.slot() as u64);
            _lb.str(b" root vnode=");
            _lb.hex(root_vh.slot() as u64);
            _lb.str(b" mounts=");
            _lb.dec(
                self.mount_namespaces
                    .get(self.global_ns)
                    .map(|ns| ns.mount_count as u64)
                    .unwrap_or(0),
            );
            _lb.str(b"\n");
        });

        true
    }

    /// Resolve a stable mount identity back to the live arena handle.
    ///
    /// The mount tree uses stable ids in structural links so `pivot_root`
    /// and covered-vnode traversal survive slot recycling.
    pub(crate) fn mount_by_fs_instance_id(&self, id: FsInstanceId) -> Option<MountHandle> {
        let mut found = MountHandle::INVALID;
        self.mounts.for_each_active(|mh, mount| {
            if mount.fs_instance_id == id {
                found = mh;
                return false;
            }
            true
        });
        if found.is_valid() { Some(found) } else { None }
    }

    /// Resolve a stable vnode identity back to the live arena handle.
    ///
    /// Pathwalk and mount covering do not own raw vnode pointers; they own
    /// a `(mount instance, backend node id)` pair and re-resolve as needed.
    pub(crate) fn vnode_by_key(&self, key: VnodeKey) -> Option<VnodeHandle> {
        if let Some(vh) = self.vnode_key_index.lookup(key) {
            if self
                .vnodes
                .get(vh)
                .map(|vnode| vnode.vnode_key() == key)
                .unwrap_or(false)
            {
                return Some(vh);
            }
            let _ = self.vnode_key_index.remove(key, Some(vh));
        }

        let mut found = VnodeHandle::INVALID;
        self.vnodes.for_each_active(|vh, vnode| {
            if vnode.vnode_key() == key {
                found = vh;
                return false;
            }
            true
        });
        if found.is_valid() {
            let _ = self.vnode_key_index.insert(key, found);
            Some(found)
        } else {
            None
        }
    }

    pub(crate) fn anchor_for_vnode(&self, vnode: VnodeHandle) -> Option<PathAnchor> {
        let vnode_ref = self.vnodes.get(vnode)?;
        Some(PathAnchor {
            mount: vnode_ref.mount,
            vnode: vnode_ref.vnode_key(),
        })
    }

    pub(crate) fn resolve_anchor_vnode(&self, anchor: PathAnchor) -> Option<VnodeHandle> {
        if !anchor.is_valid() {
            return None;
        }
        self.vnode_by_key(anchor.vnode)
    }

    pub(crate) fn lookup_parent_for_client(
        &mut self,
        cli_handle: ClientHandle,
        abs_path: &[u8],
    ) -> Option<ParentLookup> {
        crate::owner::namei::lookup_parent_for_client(self, cli_handle, abs_path)
    }

    pub(crate) fn lookup_parent_for_client_deferred(
        &mut self,
        cli_handle: ClientHandle,
        abs_path: &[u8],
    ) -> crate::vfs_core::vops::VfsResult<Option<ParentLookup>> {
        crate::owner::namei::lookup_parent_for_client_deferred(self, cli_handle, abs_path)
    }

    pub(crate) fn lookup_client(&self, badge: u64) -> Option<ClientHandle> {
        let mut found = ClientHandle::INVALID;
        self.clients.for_each_active(|handle, client| {
            if client.badge == badge || ((client.badge & 0xffff) == (badge & 0xffff)) {
                found = handle;
                return false;
            }
            true
        });
        if found.is_valid() { Some(found) } else { None }
    }

    /// Default service dispatch.
    ///
    /// The namespace core is intentionally strict: a request that does
    /// not have a mounted implementation path returns a synchronous error
    /// rather than parking hidden state.
    pub(crate) fn dispatch_request(
        &mut self,
        msg: *const TronaMsg,
        badge: u64,
        source: u32,
        reply: *mut TronaMsg,
    ) {
        crate::owner::dispatch::dispatch_request(self, msg, badge, source, reply);
    }
}
