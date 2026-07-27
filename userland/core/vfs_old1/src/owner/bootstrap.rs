// SPDX-License-Identifier: GPL-2.0-only
//! Bootstrap namespace construction and mutation helpers.

use uapi::*;

use crate::server::types::{ClientHandle, PERS_POSIX, PERS_WIN32};
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::mount::{MNT_POSIX_ONLY, MNT_WIN32_ONLY};
use crate::vfs_core::vnode::{
    VN_DOOMED, VN_ROOT, VT_DIR, VT_FIFO, VT_LNK, VT_REG, VT_SOCK, Vnode, VnodeHandle,
};

use super::{MountHandle, VfsState};

impl VfsState {
    pub(crate) fn add_bootstrap_dir_entry(
        &mut self,
        parent: VnodeHandle,
        vnode: VnodeHandle,
        name: &[u8],
    ) -> bool {
        if name.len() > crate::vfs_core::bootstrap::BOOTSTRAP_NAME_MAX {
            return false;
        }
        let idx = self.bootstrap.entry_count as usize;
        if idx >= crate::vfs_core::bootstrap::BOOTSTRAP_ENTRY_CAP {
            return false;
        }

        let entry = &mut self.bootstrap.entries[idx];
        *entry = crate::vfs_core::bootstrap::BootstrapDirEntry::zeroed();
        entry.active = 1;
        entry.name_len = name.len() as u8;
        entry.parent = parent;
        entry.vnode = vnode;
        entry.name[..name.len()].copy_from_slice(name);
        self.bootstrap.entry_count = (idx + 1) as u8;
        true
    }

    pub(crate) fn bootstrap_entry_index(&self, parent: VnodeHandle, name: &[u8]) -> Option<usize> {
        self.bootstrap_entry_index_with_case(parent, name, false)
    }

    pub(crate) fn bootstrap_lookup_child(
        &self,
        parent: VnodeHandle,
        name: &[u8],
    ) -> Option<VnodeHandle> {
        self.bootstrap_lookup_child_with_case(parent, name, false)
    }

    pub(crate) fn bootstrap_lookup_child_with_case(
        &self,
        parent: VnodeHandle,
        name: &[u8],
        ignore_case: bool,
    ) -> Option<VnodeHandle> {
        let limit = self.bootstrap.entry_count as usize;
        for idx in 0..limit {
            let entry = &self.bootstrap.entries[idx];
            if entry.active == 0 || entry.parent != parent {
                continue;
            }
            if entry.name_len as usize != name.len() {
                continue;
            }
            if self.bootstrap_name_eq(&entry.name[..name.len()], name, ignore_case) {
                return Some(entry.vnode);
            }
        }
        None
    }

    pub(crate) fn bootstrap_name_eq(&self, lhs: &[u8], rhs: &[u8], ignore_case: bool) -> bool {
        crate::vfs_core::casefold::name_eq(lhs, rhs, ignore_case)
    }

    pub(crate) fn bootstrap_entry_index_with_case(
        &self,
        parent: VnodeHandle,
        name: &[u8],
        ignore_case: bool,
    ) -> Option<usize> {
        let limit = self.bootstrap.entry_count as usize;
        for idx in 0..limit {
            let entry = &self.bootstrap.entries[idx];
            if entry.active == 0 || entry.parent != parent {
                continue;
            }
            if entry.name_len as usize != name.len() {
                continue;
            }
            if self.bootstrap_name_eq(&entry.name[..name.len()], name, ignore_case) {
                return Some(idx);
            }
        }
        None
    }

    pub(crate) fn bootstrap_remove_entry(
        &mut self,
        parent: VnodeHandle,
        name: &[u8],
    ) -> Option<VnodeHandle> {
        let idx = self.bootstrap_entry_index(parent, name)?;
        let vnode = self.bootstrap.entries[idx].vnode;
        self.bootstrap.entries[idx] = crate::vfs_core::bootstrap::BootstrapDirEntry::zeroed();
        Some(vnode)
    }

    pub(crate) fn ensure_bootstrap_dir(
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
        if crate::fs::saltyfs::vnode_is_saltyfs(self, parent) {
            return crate::fs::saltyfs::ensure_dir_child(
                self,
                parent,
                name,
                crate::vfs_core::bootstrap::bootstrap_dir_mode(name),
            );
        }

        self.create_bootstrap_dir(
            parent,
            mount,
            fs_id,
            name,
            vnode_id,
            crate::vfs_core::bootstrap::bootstrap_dir_mode(name),
        )
    }

    pub(crate) fn create_bootstrap_dir(
        &mut self,
        parent: VnodeHandle,
        mount: MountHandle,
        fs_id: FsInstanceId,
        name: &[u8],
        vnode_id: u64,
        mode: u32,
    ) -> Option<VnodeHandle> {
        let vh = self.vnodes.alloc()?;
        {
            let vnode = self.vnodes.get_mut(vh)?;
            *vnode = Vnode::new_bootstrap_dir(fs_id, mount);
            vnode.id = vnode_id;
            vnode.mode = mode;
        }
        self.apply_mount_vnode_defaults(vh, VT_DIR);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            return None;
        }
        Some(vh)
    }

    #[inline]
    pub(crate) fn page_align_up(bytes: u64) -> u64 {
        if bytes == 0 {
            0
        } else {
            (bytes + (super::MM_PAGE_SIZE - 1)) & !(super::MM_PAGE_SIZE - 1)
        }
    }

    pub(crate) fn bootstrap_file_storage(&self, content: &[u8]) -> Option<*mut u8> {
        if content.is_empty() {
            return Some(core::ptr::null_mut());
        }
        let bytes = Self::page_align_up(content.len() as u64) as usize;
        let ptr = unsafe { crate::server::mem::map_anon(bytes as u64) };
        if ptr.is_null() || ptr == usize::MAX as *mut u8 {
            return None;
        }
        unsafe {
            for (idx, byte) in content.iter().enumerate() {
                *ptr.add(idx) = *byte;
            }
        }
        Some(ptr)
    }

    pub(crate) fn create_bootstrap_file(
        &mut self,
        parent: VnodeHandle,
        mount: MountHandle,
        fs_id: FsInstanceId,
        name: &[u8],
        vnode_id: u64,
        mode: u32,
        content: &[u8],
    ) -> Option<VnodeHandle> {
        if let Some(vh) = self.bootstrap_lookup_child(parent, name) {
            return Some(vh);
        }

        let data = self.bootstrap_file_storage(content)?;
        let vh = self.vnodes.alloc()?;
        {
            let vnode = self.vnodes.get_mut(vh)?;
            *vnode = Vnode::new_bootstrap_file(
                fs_id,
                mount,
                crate::vfs_core::bootstrap::bootstrap_file_mode(mode),
            );
            vnode.id = vnode_id;
            vnode.size = content.len() as u64;
            vnode.data = data;
        }
        self.apply_mount_vnode_defaults(vh, VT_REG);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            return None;
        }
        Some(vh)
    }

    pub(crate) fn create_bootstrap_char_device(
        &mut self,
        parent: VnodeHandle,
        mount: MountHandle,
        fs_id: FsInstanceId,
        name: &[u8],
        mode: u32,
        kind: u8,
        sub_id: u32,
        generation: u32,
    ) -> Option<VnodeHandle> {
        if let Some(vh) = self.bootstrap_lookup_child(parent, name) {
            return Some(vh);
        }

        let vh = self.vnodes.alloc()?;
        {
            let vnode = self.vnodes.get_mut(vh)?;
            *vnode = Vnode::new_bootstrap_char_device(
                fs_id,
                mount,
                mode,
                crate::vfs_core::device::device_inode(kind, sub_id),
                generation,
            );
        }
        self.apply_mount_vnode_defaults(vh, crate::vfs_core::vnode::VT_CHR);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            self.uncache_vnode_key(vh);
            let _ = self.vnodes.release(vh);
            return None;
        }
        Some(vh)
    }

    #[inline]
    pub(crate) fn personality_ignore_case(personality: u8) -> bool {
        personality == PERS_WIN32
    }

    pub(crate) fn client_personality(&self, client: ClientHandle) -> u8 {
        self.clients
            .get(client)
            .map(|entry| entry.personality)
            .unwrap_or(PERS_POSIX)
    }

    pub(crate) fn bootstrap_lookup_parent_and_name<'a>(
        &self,
        path: &'a [u8],
    ) -> Option<(VnodeHandle, &'a [u8])> {
        crate::owner::namei::bootstrap_lookup_parent_and_name(self, path)
    }

    pub(crate) fn bootstrap_lookup_parent_and_name_for_personality<'a>(
        &self,
        path: &'a [u8],
        personality: u8,
    ) -> Option<(VnodeHandle, &'a [u8])> {
        crate::owner::namei::bootstrap_lookup_parent_and_name_for_personality(
            self,
            path,
            personality,
        )
    }

    pub(crate) fn bootstrap_dir_is_empty(&self, dir_vh: VnodeHandle) -> bool {
        let limit = self.bootstrap.entry_count as usize;
        for idx in 0..limit {
            let entry = &self.bootstrap.entries[idx];
            if entry.active != 0 && entry.parent == dir_vh {
                return false;
            }
        }
        true
    }

    pub(crate) fn bootstrap_dynamic_vnode_id(vh: VnodeHandle, vtype: u8) -> u64 {
        ((vtype as u64) << 56) | ((vh.slot() as u64) << 24) | (vh.epoch() as u64)
    }

    pub(crate) fn bootstrap_create_regular_file_path(
        &mut self,
        path: &[u8],
        mode: u32,
    ) -> Result<VnodeHandle, u64> {
        let (parent, name) = self
            .bootstrap_lookup_parent_and_name(path)
            .ok_or(TRONA_INVALID_ARGUMENT)?;
        let (mount, fs_id, parent_vtype, parent_backend) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
                parent_vn.backend_kind,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if parent_backend == crate::vfs_core::vnode::VNODE_BACKEND_TMPFS {
            return match crate::fs::tmpfs::create_regular_child_external(self, parent, name, mode)?
            {
                crate::vfs_core::vops::VfsOpResult::Complete(vh) => Ok(vh),
                crate::vfs_core::vops::VfsOpResult::Deferred(op_id) => {
                    unsafe {
                        crate::owner::pending_ops::free(op_id);
                    }
                    Err(TRONA_INVALID_OPERATION)
                }
            };
        }
        if self.bootstrap_lookup_child(parent, name).is_some() {
            return Err(TRONA_ALREADY_EXISTS);
        }
        let vh = self
            .create_bootstrap_file(
                parent,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                fs_id,
                name,
                0,
                mode,
                &[],
            )
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        if let Some(vn) = self.vnodes.get_mut(vh) {
            vn.id = Self::bootstrap_dynamic_vnode_id(vh, VT_REG);
        }
        self.cache_vnode_key(vh);
        Ok(vh)
    }

    pub(crate) fn bootstrap_create_regular_child_for_personality(
        &mut self,
        parent: VnodeHandle,
        name: &[u8],
        mode: u32,
        personality: u8,
    ) -> Result<VnodeHandle, u64> {
        let (mount, fs_id, parent_vtype) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if self
            .bootstrap_lookup_child_with_case(
                parent,
                name,
                Self::personality_ignore_case(personality),
            )
            .is_some()
        {
            return Err(TRONA_ALREADY_EXISTS);
        }
        let vh = self
            .create_bootstrap_file(
                parent,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                fs_id,
                name,
                0,
                mode,
                &[],
            )
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        if let Some(vn) = self.vnodes.get_mut(vh) {
            vn.id = Self::bootstrap_dynamic_vnode_id(vh, VT_REG);
        }
        self.cache_vnode_key(vh);
        Ok(vh)
    }

    pub(crate) fn bootstrap_create_fifo_path_for_personality(
        &mut self,
        path: &[u8],
        mode: u32,
        personality: u8,
    ) -> Result<VnodeHandle, u64> {
        let (parent, name) = self
            .bootstrap_lookup_parent_and_name_for_personality(path, personality)
            .ok_or(TRONA_INVALID_ARGUMENT)?;
        let (mount, fs_id, parent_vtype) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if self
            .bootstrap_lookup_child_with_case(
                parent,
                name,
                Self::personality_ignore_case(personality),
            )
            .is_some()
        {
            return Err(TRONA_ALREADY_EXISTS);
        }

        let vh = self.vnodes.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
        {
            let vnode = self.vnodes.get_mut(vh).ok_or(TRONA_OUT_OF_MEMORY)?;
            *vnode = crate::vfs_core::vnode::Vnode::new_bootstrap_fifo(
                fs_id,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                mode,
            );
            vnode.id = Self::bootstrap_dynamic_vnode_id(vh, VT_FIFO);
        }
        self.cache_vnode_key(vh);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            self.reclaim_bootstrap_vnode(vh);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        if self.ensure_fifo_state_for_vnode(vh).is_none() {
            let _ = self.bootstrap_remove_path_for_personality(path, false, personality);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        Ok(vh)
    }

    pub(crate) fn bootstrap_create_socket_path_for_personality(
        &mut self,
        path: &[u8],
        mode: u32,
        personality: u8,
    ) -> Result<VnodeHandle, u64> {
        let (parent, name) = self
            .bootstrap_lookup_parent_and_name_for_personality(path, personality)
            .ok_or(TRONA_INVALID_ARGUMENT)?;
        let (mount, fs_id, parent_vtype) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if self
            .bootstrap_lookup_child_with_case(
                parent,
                name,
                Self::personality_ignore_case(personality),
            )
            .is_some()
        {
            return Err(TRONA_ALREADY_EXISTS);
        }

        let vh = self.vnodes.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
        {
            let vnode = self.vnodes.get_mut(vh).ok_or(TRONA_OUT_OF_MEMORY)?;
            *vnode = crate::vfs_core::vnode::Vnode::new_bootstrap_socket(
                fs_id,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                mode,
            );
            vnode.id = Self::bootstrap_dynamic_vnode_id(vh, VT_SOCK);
        }
        self.cache_vnode_key(vh);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            self.reclaim_bootstrap_vnode(vh);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        Ok(vh)
    }

    pub(crate) fn bootstrap_create_symlink_path(
        &mut self,
        path: &[u8],
        mode: u32,
        target: &[u8],
    ) -> Result<VnodeHandle, u64> {
        let (parent, name) = self
            .bootstrap_lookup_parent_and_name(path)
            .ok_or(TRONA_INVALID_ARGUMENT)?;
        let (mount, fs_id, parent_vtype, parent_backend) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
                parent_vn.backend_kind,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if parent_backend == crate::vfs_core::vnode::VNODE_BACKEND_TMPFS {
            return match crate::fs::tmpfs::symlink_child_external(self, parent, name, mode, target)?
            {
                crate::vfs_core::vops::VfsOpResult::Complete(vh) => Ok(vh),
                crate::vfs_core::vops::VfsOpResult::Deferred(op_id) => {
                    unsafe {
                        crate::owner::pending_ops::free(op_id);
                    }
                    Err(TRONA_INVALID_OPERATION)
                }
            };
        }
        if self.bootstrap_lookup_child(parent, name).is_some() {
            return Err(TRONA_ALREADY_EXISTS);
        }

        let data = self
            .bootstrap_file_storage(target)
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        let vh = self.vnodes.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
        {
            let vnode = self.vnodes.get_mut(vh).ok_or(TRONA_OUT_OF_MEMORY)?;
            *vnode = crate::vfs_core::vnode::Vnode::new_bootstrap_symlink(
                fs_id,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                mode,
            );
            vnode.id = Self::bootstrap_dynamic_vnode_id(vh, VT_LNK);
            vnode.size = target.len() as u64;
            vnode.data = data;
        }
        self.cache_vnode_key(vh);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            self.reclaim_bootstrap_vnode(vh);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        Ok(vh)
    }

    pub(crate) fn bootstrap_create_symlink_child_for_personality(
        &mut self,
        parent: VnodeHandle,
        name: &[u8],
        mode: u32,
        target: &[u8],
        personality: u8,
    ) -> Result<VnodeHandle, u64> {
        let (mount, fs_id, parent_vtype) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if self
            .bootstrap_lookup_child_with_case(
                parent,
                name,
                Self::personality_ignore_case(personality),
            )
            .is_some()
        {
            return Err(TRONA_ALREADY_EXISTS);
        }
        let data = self
            .bootstrap_file_storage(target)
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        let vh = self.vnodes.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
        {
            let vnode = self.vnodes.get_mut(vh).ok_or(TRONA_OUT_OF_MEMORY)?;
            *vnode = crate::vfs_core::vnode::Vnode::new_bootstrap_symlink(
                fs_id,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                mode,
            );
            vnode.id = Self::bootstrap_dynamic_vnode_id(vh, VT_LNK);
            vnode.size = target.len() as u64;
            vnode.data = data;
        }
        self.cache_vnode_key(vh);
        if !self.add_bootstrap_dir_entry(parent, vh, name) {
            self.reclaim_bootstrap_vnode(vh);
            return Err(TRONA_OUT_OF_MEMORY);
        }
        Ok(vh)
    }

    pub(crate) fn bootstrap_link_vnode_child_for_personality(
        &mut self,
        source: VnodeHandle,
        new_parent: VnodeHandle,
        new_name: &[u8],
        personality: u8,
    ) -> u64 {
        let (source_type, source_flags, source_mount, source_covered) =
            match self.vnodes.get(source) {
                Some(vn) => (
                    vn.vtype,
                    vn.flags,
                    vn.fs_instance_id,
                    vn.covered_by.handle.is_valid(),
                ),
                None => return TRONA_NOT_FOUND,
            };
        if source_type == VT_DIR {
            return TRONA_INVALID_OPERATION;
        }
        if self.bootstrap_is_anchor(source) || (source_flags & VN_ROOT) != 0 || source_covered {
            return TRONA_BUSY;
        }

        let (parent_type, parent_mount) = match self.vnodes.get(new_parent) {
            Some(vn) => (vn.vtype, vn.fs_instance_id),
            None => return TRONA_NOT_FOUND,
        };
        if parent_type != VT_DIR {
            return TRONA_NOT_DIRECTORY;
        }
        if source_mount != parent_mount {
            return TRONA_CROSS_DEVICE;
        }
        if self
            .bootstrap_lookup_child_with_case(
                new_parent,
                new_name,
                Self::personality_ignore_case(personality),
            )
            .is_some()
        {
            return TRONA_ALREADY_EXISTS;
        }
        if !self.add_bootstrap_dir_entry(new_parent, source, new_name) {
            return TRONA_OUT_OF_MEMORY;
        }
        if let Some(vn) = self.vnodes.get_mut(source) {
            vn.nlink = vn.nlink.saturating_add(1);
        }
        TRONA_OK
    }

    pub(crate) fn bootstrap_set_mode_vnode(&mut self, vnode: VnodeHandle, mode: u32) -> u64 {
        let Some(vn) = self.vnodes.get_mut(vnode) else {
            return TRONA_NOT_FOUND;
        };
        vn.mode = (vn.mode & !0o7777) | (mode & 0o7777);
        TRONA_OK
    }

    pub(crate) fn bootstrap_set_owner_vnode(
        &mut self,
        vnode: VnodeHandle,
        uid: u32,
        gid: u32,
    ) -> u64 {
        let Some(vn) = self.vnodes.get_mut(vnode) else {
            return TRONA_NOT_FOUND;
        };
        if uid != u32::MAX {
            vn.uid = uid;
        }
        if gid != u32::MAX {
            vn.gid = gid;
        }
        TRONA_OK
    }

    pub(crate) fn bootstrap_set_times_vnode(
        &mut self,
        vnode: VnodeHandle,
        atime_ns: Option<u64>,
        mtime_ns: Option<u64>,
    ) -> u64 {
        let Some(vn) = self.vnodes.get_mut(vnode) else {
            return TRONA_NOT_FOUND;
        };
        if let Some(atime_ns) = atime_ns {
            vn.atime_ns = atime_ns;
        }
        if let Some(mtime_ns) = mtime_ns {
            vn.mtime_ns = mtime_ns;
        }
        TRONA_OK
    }

    pub(crate) fn bootstrap_mkdir_path(
        &mut self,
        path: &[u8],
        mode: u32,
    ) -> Result<VnodeHandle, u64> {
        let (parent, name) = self
            .bootstrap_lookup_parent_and_name(path)
            .ok_or(TRONA_INVALID_ARGUMENT)?;
        let (mount, fs_id, parent_vtype, parent_backend) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
                parent_vn.backend_kind,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }

        // When pathwalk landed inside a real backend (tmpfs today),
        // the new child must live in that backend so subsequent
        // dynamic lookups go through the backend's vop instead of the
        // bootstrap entry table. Otherwise the dir exists as a
        // shadow that backend lookups cannot see.
        if parent_backend == crate::vfs_core::vnode::VNODE_BACKEND_TMPFS {
            return match crate::fs::tmpfs::mkdir_child_external(self, parent, name, mode)? {
                crate::vfs_core::vops::VfsOpResult::Complete(vh) => Ok(vh),
                crate::vfs_core::vops::VfsOpResult::Deferred(op_id) => {
                    unsafe {
                        crate::owner::pending_ops::free(op_id);
                    }
                    Err(TRONA_INVALID_OPERATION)
                }
            };
        }

        if self.bootstrap_lookup_child(parent, name).is_some() {
            return Err(TRONA_ALREADY_EXISTS);
        }
        let vh = self
            .create_bootstrap_dir(
                parent,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                fs_id,
                name,
                0,
                mode,
            )
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        if let Some(vn) = self.vnodes.get_mut(vh) {
            vn.id = Self::bootstrap_dynamic_vnode_id(vh, VT_DIR);
        }
        self.cache_vnode_key(vh);
        Ok(vh)
    }

    pub(crate) fn bootstrap_mkdir_child_for_personality(
        &mut self,
        parent: VnodeHandle,
        name: &[u8],
        mode: u32,
        personality: u8,
    ) -> Result<VnodeHandle, u64> {
        let (mount, fs_id, parent_vtype) = {
            let parent_vn = self.vnodes.get(parent).ok_or(TRONA_NOT_FOUND)?;
            (
                parent_vn.mount.handle,
                parent_vn.fs_instance_id,
                parent_vn.vtype,
            )
        };
        if parent_vtype != VT_DIR {
            return Err(TRONA_NOT_DIRECTORY);
        }
        if self
            .bootstrap_lookup_child_with_case(
                parent,
                name,
                Self::personality_ignore_case(personality),
            )
            .is_some()
        {
            return Err(TRONA_ALREADY_EXISTS);
        }
        let vh = self
            .create_bootstrap_dir(
                parent,
                if mount.is_valid() {
                    mount
                } else {
                    self.root_mount
                },
                fs_id,
                name,
                0,
                mode,
            )
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        if let Some(vn) = self.vnodes.get_mut(vh) {
            vn.id = Self::bootstrap_dynamic_vnode_id(vh, VT_DIR);
        }
        self.cache_vnode_key(vh);
        Ok(vh)
    }

    pub(crate) fn bootstrap_resize_file(&mut self, vnode: VnodeHandle, new_size: u64) -> bool {
        let (old_size, old_data, vtype) = match self.vnodes.get(vnode) {
            Some(vn) => (vn.size, vn.data, vn.vtype),
            None => return false,
        };
        if vtype != VT_REG {
            return false;
        }
        if new_size == old_size {
            return true;
        }

        let new_bytes = Self::page_align_up(new_size);
        let new_data = if new_bytes == 0 {
            core::ptr::null_mut()
        } else {
            let ptr = unsafe { crate::server::mem::map_anon(new_bytes) };
            if ptr.is_null() || ptr == usize::MAX as *mut u8 {
                return false;
            }
            ptr
        };

        let copy_len = core::cmp::min(old_size, new_size) as usize;
        if !new_data.is_null() {
            unsafe {
                if copy_len != 0 && !old_data.is_null() {
                    core::ptr::copy_nonoverlapping(old_data, new_data, copy_len);
                }
                if new_size > copy_len as u64 {
                    core::ptr::write_bytes(
                        new_data.add(copy_len),
                        0,
                        (new_size as usize).saturating_sub(copy_len),
                    );
                }
            }
        }

        if let Some(vn) = self.vnodes.get_mut(vnode) {
            vn.data = new_data;
            vn.size = new_size;
            vn.mtime_ns = vn.mtime_ns.saturating_add(1);
        } else {
            if !new_data.is_null() && new_bytes != 0 {
                let _ = unsafe { crate::server::mem::unmap(new_data, new_bytes) };
            }
            return false;
        }

        let old_bytes = Self::page_align_up(old_size);
        if !old_data.is_null() && old_bytes != 0 {
            let _ = unsafe { crate::server::mem::unmap(old_data, old_bytes) };
        }
        true
    }

    pub(crate) fn bootstrap_write_file(
        &mut self,
        vnode: VnodeHandle,
        offset: u64,
        src: *const u8,
        count: usize,
    ) -> Option<u64> {
        let end = offset.checked_add(count as u64)?;
        let old_size = self.vnodes.get(vnode)?.size;
        if end > old_size && !self.bootstrap_resize_file(vnode, end) {
            return None;
        }

        let vn = self.vnodes.get_mut(vnode)?;
        if vn.vtype != VT_REG {
            return None;
        }
        if count != 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(src, vn.data.add(offset as usize), count);
            }
        }
        vn.mtime_ns = vn.mtime_ns.saturating_add(1);
        Some(count as u64)
    }

    pub(crate) fn bootstrap_remove_path(&mut self, path: &[u8], want_dir: bool) -> u64 {
        let Some((parent, name)) = self.bootstrap_lookup_parent_and_name(path) else {
            return TRONA_INVALID_ARGUMENT;
        };
        let Some(child) = self.bootstrap_lookup_child(parent, name) else {
            return TRONA_NOT_FOUND;
        };

        let (vtype, flags, covered) = match self.vnodes.get(child) {
            Some(vn) => (vn.vtype, vn.flags, vn.covered_by.handle.is_valid()),
            None => return TRONA_NOT_FOUND,
        };
        if want_dir {
            if vtype != VT_DIR {
                return TRONA_NOT_DIRECTORY;
            }
            if !self.bootstrap_dir_is_empty(child) {
                return TRONA_BUSY;
            }
        } else if vtype == VT_DIR {
            return TRONA_IS_DIRECTORY;
        }
        if (flags & VN_ROOT) != 0 || covered {
            return TRONA_BUSY;
        }
        if self.bootstrap_remove_entry(parent, name).is_none() {
            return TRONA_NOT_FOUND;
        }
        if let Some(vn) = self.vnodes.get_mut(child) {
            vn.nlink = vn.nlink.saturating_sub(1);
            if vn.nlink == 0 {
                vn.flags |= VN_DOOMED;
            }
        }
        self.mark_fifo_unlinked(child);
        self.reclaim_bootstrap_vnode(child);
        TRONA_OK
    }

    pub(crate) fn bootstrap_remove_path_for_personality(
        &mut self,
        path: &[u8],
        want_dir: bool,
        personality: u8,
    ) -> u64 {
        let Some((parent, name)) =
            self.bootstrap_lookup_parent_and_name_for_personality(path, personality)
        else {
            return TRONA_INVALID_ARGUMENT;
        };
        let Some(idx) = self.bootstrap_entry_index_with_case(
            parent,
            name,
            Self::personality_ignore_case(personality),
        ) else {
            return TRONA_NOT_FOUND;
        };
        let child = self.bootstrap.entries[idx].vnode;

        let (vtype, flags, covered) = match self.vnodes.get(child) {
            Some(vn) => (vn.vtype, vn.flags, vn.covered_by.handle.is_valid()),
            None => return TRONA_NOT_FOUND,
        };
        if want_dir {
            if vtype != VT_DIR {
                return TRONA_NOT_DIRECTORY;
            }
            if !self.bootstrap_dir_is_empty(child) {
                return TRONA_BUSY;
            }
        } else if vtype == VT_DIR {
            return TRONA_IS_DIRECTORY;
        }
        if (flags & VN_ROOT) != 0 || covered {
            return TRONA_BUSY;
        }
        self.bootstrap.entries[idx] = crate::vfs_core::bootstrap::BootstrapDirEntry::zeroed();
        if let Some(vn) = self.vnodes.get_mut(child) {
            vn.nlink = vn.nlink.saturating_sub(1);
            if vn.nlink == 0 {
                vn.flags |= VN_DOOMED;
            }
        }
        self.mark_fifo_unlinked(child);
        self.reclaim_bootstrap_vnode(child);
        TRONA_OK
    }

    pub(crate) fn bootstrap_remove_child_for_personality(
        &mut self,
        parent: VnodeHandle,
        name: &[u8],
        want_dir: bool,
        personality: u8,
    ) -> u64 {
        let Some(idx) = self.bootstrap_entry_index_with_case(
            parent,
            name,
            Self::personality_ignore_case(personality),
        ) else {
            return TRONA_NOT_FOUND;
        };
        let child = self.bootstrap.entries[idx].vnode;
        let (vtype, flags, covered) = match self.vnodes.get(child) {
            Some(vn) => (vn.vtype, vn.flags, vn.covered_by.handle.is_valid()),
            None => return TRONA_NOT_FOUND,
        };
        if want_dir {
            if vtype != VT_DIR {
                return TRONA_NOT_DIRECTORY;
            }
            if !self.bootstrap_dir_is_empty(child) {
                return TRONA_BUSY;
            }
        } else if vtype == VT_DIR {
            return TRONA_IS_DIRECTORY;
        }
        if (flags & VN_ROOT) != 0 || covered {
            return TRONA_BUSY;
        }
        self.bootstrap.entries[idx] = crate::vfs_core::bootstrap::BootstrapDirEntry::zeroed();
        if let Some(vn) = self.vnodes.get_mut(child) {
            vn.nlink = vn.nlink.saturating_sub(1);
            if vn.nlink == 0 {
                vn.flags |= VN_DOOMED;
            }
        }
        self.mark_fifo_unlinked(child);
        self.reclaim_bootstrap_vnode(child);
        TRONA_OK
    }

    pub(crate) fn bootstrap_is_anchor(&self, vnode: VnodeHandle) -> bool {
        vnode == self.bootstrap.etc_dir
            || vnode == self.bootstrap.dev_dir
            || vnode == self.bootstrap.proc_dir
            || vnode == self.bootstrap.sys_dir
            || vnode == self.bootstrap.tmp_dir
            || vnode == self.bootstrap.pipe_dir
            || vnode == self.bootstrap.initramfs_dir
            || vnode == self.bootstrap.new_root_dir
            || vnode == self.bootstrap.put_old_dir
            || vnode == self.root_vnode().unwrap_or(VnodeHandle::INVALID)
    }

    pub(crate) fn bootstrap_is_descendant_of(
        &self,
        mut vnode: VnodeHandle,
        ancestor: VnodeHandle,
    ) -> bool {
        while vnode.is_valid() {
            if vnode == ancestor {
                return true;
            }
            let parent = self.bootstrap_parent_dir(vnode);
            if parent == vnode || !parent.is_valid() {
                break;
            }
            vnode = parent;
        }
        false
    }

    pub(crate) fn bootstrap_rename_child_for_personality(
        &mut self,
        old_parent: VnodeHandle,
        old_name: &[u8],
        new_parent: VnodeHandle,
        new_name: &[u8],
        personality: u8,
    ) -> u64 {
        let ignore_case = Self::personality_ignore_case(personality);
        let Some(old_idx) = self.bootstrap_entry_index_with_case(old_parent, old_name, ignore_case)
        else {
            return TRONA_NOT_FOUND;
        };

        let moved = self.bootstrap.entries[old_idx].vnode;
        let (moved_type, moved_flags) = match self.vnodes.get(moved) {
            Some(vn) => (vn.vtype, vn.flags),
            None => return TRONA_NOT_FOUND,
        };
        if self.bootstrap_is_anchor(moved)
            || (moved_flags & VN_ROOT) != 0
            || self
                .vnodes
                .get(moved)
                .map(|vn| vn.covered_by.handle.is_valid())
                .unwrap_or(false)
        {
            return TRONA_BUSY;
        }
        if self
            .vnodes
            .get(new_parent)
            .map(|vn| vn.vtype != VT_DIR)
            .unwrap_or(true)
        {
            return TRONA_NOT_DIRECTORY;
        }
        if moved_type == VT_DIR && self.bootstrap_is_descendant_of(new_parent, moved) {
            return TRONA_INVALID_ARGUMENT;
        }

        if let Some(target_idx) =
            self.bootstrap_entry_index_with_case(new_parent, new_name, ignore_case)
        {
            if target_idx != old_idx {
                let target = self.bootstrap.entries[target_idx].vnode;
                let (target_type, target_flags, target_covered) = match self.vnodes.get(target) {
                    Some(vn) => (vn.vtype, vn.flags, vn.covered_by.handle.is_valid()),
                    None => return TRONA_NOT_FOUND,
                };
                if self.bootstrap_is_anchor(target)
                    || (target_flags & VN_ROOT) != 0
                    || target_covered
                {
                    return TRONA_BUSY;
                }
                if moved_type == VT_DIR && target_type != VT_DIR {
                    return TRONA_NOT_DIRECTORY;
                }
                if moved_type != VT_DIR && target_type == VT_DIR {
                    return TRONA_IS_DIRECTORY;
                }
                if target_type == VT_DIR && !self.bootstrap_dir_is_empty(target) {
                    return TRONA_BUSY;
                }
                self.bootstrap.entries[target_idx] =
                    crate::vfs_core::bootstrap::BootstrapDirEntry::zeroed();
                if let Some(vn) = self.vnodes.get_mut(target) {
                    vn.nlink = vn.nlink.saturating_sub(1);
                    if vn.nlink == 0 {
                        vn.flags |= VN_DOOMED;
                    }
                }
                self.reclaim_bootstrap_vnode(target);
            } else {
                let entry = &mut self.bootstrap.entries[old_idx];
                entry.parent = new_parent;
                entry.name = [0; crate::vfs_core::bootstrap::BOOTSTRAP_NAME_MAX];
                entry.name_len = new_name.len() as u8;
                entry.name[..new_name.len()].copy_from_slice(new_name);
                return TRONA_OK;
            }
        }

        let entry = &mut self.bootstrap.entries[old_idx];
        entry.parent = new_parent;
        entry.name = [0; crate::vfs_core::bootstrap::BOOTSTRAP_NAME_MAX];
        entry.name_len = new_name.len() as u8;
        entry.name[..new_name.len()].copy_from_slice(new_name);
        TRONA_OK
    }

    pub(crate) fn bootstrap_parent_dir(&self, child: VnodeHandle) -> VnodeHandle {
        let mut parent = self.root_vnode().unwrap_or(VnodeHandle::INVALID);
        let limit = self.bootstrap.entry_count as usize;
        for idx in 0..limit {
            let entry = &self.bootstrap.entries[idx];
            if entry.active != 0 && entry.vnode == child {
                parent = entry.parent;
                break;
            }
        }
        parent
    }

    fn bootstrap_dtype(&self, vnode: VnodeHandle) -> u8 {
        let Some(vn) = self.vnodes.get(vnode) else {
            return trona_posix::consts::DT_UNKNOWN;
        };
        match vn.vtype {
            VT_DIR => trona_posix::consts::DT_DIR,
            VT_REG => trona_posix::consts::DT_REG,
            crate::vfs_core::vnode::VT_CHR => trona_posix::consts::DT_CHR,
            crate::vfs_core::vnode::VT_BLK => trona_posix::consts::DT_UNKNOWN,
            VT_FIFO => trona_posix::consts::DT_FIFO,
            VT_SOCK => trona_posix::consts::DT_SOCK,
            VT_LNK => trona_posix::consts::DT_LNK,
            _ => trona_posix::consts::DT_UNKNOWN,
        }
    }

    fn bootstrap_entry_visible_for_personality(&self, vnode: VnodeHandle, personality: u8) -> bool {
        let Some(vnode_ref) = self.vnodes.get(vnode) else {
            return false;
        };
        if vnode_ref.covered_by.id == FsInstanceId::INVALID {
            return true;
        }
        let child_mount = if vnode_ref.covered_by.handle.is_valid() {
            Some(vnode_ref.covered_by.handle)
        } else {
            self.mount_by_fs_instance_id(vnode_ref.covered_by.id)
        };
        let Some(child_mount) = child_mount else {
            return true;
        };
        let Some(mount) = self.mounts.get(child_mount) else {
            return true;
        };
        if personality == PERS_WIN32 {
            (mount.flags & MNT_POSIX_ONLY) == 0
        } else {
            (mount.flags & MNT_WIN32_ONLY) == 0
        }
    }

    pub(crate) fn bootstrap_readdir_entry_for_personality(
        &self,
        dir_vh: VnodeHandle,
        cursor: u64,
        name_out: &mut [u8; 128],
        personality: u8,
    ) -> Option<(u64, u8, u64, u8)> {
        let current = self.vnodes.get(dir_vh)?;
        if cursor == 0 {
            name_out[0] = b'.';
            return Some((1, 1, current.id, self.bootstrap_dtype(dir_vh)));
        }
        if cursor == 1 {
            let parent = self.bootstrap_parent_dir(dir_vh);
            let parent_ino = self.vnodes.get(parent).map(|v| v.id).unwrap_or(current.id);
            name_out[0] = b'.';
            name_out[1] = b'.';
            return Some((2, 2, parent_ino, self.bootstrap_dtype(parent)));
        }

        let want = (cursor - 2) as usize;
        let mut seen = 0usize;
        let limit = self.bootstrap.entry_count as usize;
        for idx in 0..limit {
            let entry = &self.bootstrap.entries[idx];
            if entry.active == 0 || entry.parent != dir_vh {
                continue;
            }
            if !self.bootstrap_entry_visible_for_personality(entry.vnode, personality) {
                continue;
            }
            if seen != want {
                seen += 1;
                continue;
            }
            let child = self.vnodes.get(entry.vnode)?;
            let name_len = entry.name_len;
            name_out[..name_len as usize].copy_from_slice(&entry.name[..name_len as usize]);
            return Some((
                cursor + 1,
                name_len,
                child.id,
                self.bootstrap_dtype(entry.vnode),
            ));
        }

        None
    }
}
