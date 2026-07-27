// SPDX-License-Identifier: GPL-2.0-only
//! VFS bootstrap implementation -- `init_boot_env()`.
//!
//! Vnode-native boot sequence using `VopMetaOps` / `VopDataOps` dispatch.

use trona_loader::common::cpio::{self, CpioEntryExt};
use uapi::*;

use crate::fs;
use crate::owner::VfsState;
use crate::personality::posix::consts::*;
use crate::server::consts::*;

use crate::vfs_core::cred::VfsCred;
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::mount_ctl;
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VT_DIR, VnodeHandle};
use crate::vfs_core::vop_context::WorkerIoCtx;

// =========================================================================
// VopVector dispatch helpers (bootstrap uses root credential)
// =========================================================================

/// Root credential for bootstrap and late-mount operations.
pub(crate) static BOOT_CRED: VfsCred = VfsCred::root();

/// Create a directory under `parent_vh` using VopMetaOps dispatch.
unsafe fn boot_mkdir(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let mut ctx = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, parent_vh)
            .ok_or(VfsError::Io)?;
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.mkdir)(
            &mut ctx,
            name.as_ptr(),
            name.len() as u8,
            mode,
            &raw const BOOT_CRED,
        );
        match result {
            Ok(Ready(vh)) => Ok(vh),
            Ok(Parked(_)) => Err(VfsError::Busy),
            Err(e) => Err(e),
        }
    }
}

/// Create a regular file under `parent_vh`.
unsafe fn boot_create(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let mut ctx = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, parent_vh)
            .ok_or(VfsError::Io)?;
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.create)(
            &mut ctx,
            name.as_ptr(),
            name.len() as u8,
            mode,
            &raw const BOOT_CRED,
        );
        match result {
            Ok(Ready(vh)) => Ok(vh),
            Ok(Parked(_)) => Err(VfsError::Busy),
            Err(e) => Err(e),
        }
    }
}

/// Write data to a vnode at the given offset.
unsafe fn boot_write(
    state: &mut VfsState,
    vh: VnodeHandle,
    offset: u64,
    data: &[u8],
) -> VfsResult<u64> {
    unsafe {
        let state_ptr = state as *mut VfsState;
        let mount_handle = state.resolve_vnode_mount(vh).ok_or(VfsError::Io)?;
        let vnode = state.vnodes.get(vh).ok_or(VfsError::Io)?;
        let mount = state.mounts.get(mount_handle).ok_or(VfsError::Io)?;
        let ops = vnode.ops;
        if ops.is_null() {
            return Err(VfsError::Io);
        }
        // Capture the raw state pointer so the data-plane VOP can
        // reach `VfsState` when it needs to reserve pending slots /
        // credit. Bootstrap runs before the owner loop starts and
        // every DataOps callee runs inline on this thread, so the
        // raw pointer is valid for the entire `.write` call.
        let data_ctx = WorkerIoCtx::new(
            vh,
            mount_handle,
            vnode.data,
            mount.data,
            vnode.vtype,
            vnode.id,
            mount.fs_instance_id,
        )
        .with_state(state_ptr);
        match ((*ops).data.write)(&data_ctx, offset, data.as_ptr(), data.len() as u64) {
            Ok(Ready(n)) => Ok(n),
            Ok(Parked(_)) => Err(VfsError::Busy),
            Err(e) => Err(e),
        }
    }
}

/// Create a symlink under `parent_vh`.
unsafe fn boot_symlink(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    target: &[u8],
) -> VfsResult<VnodeHandle> {
    unsafe {
        let mut ctx = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, parent_vh)
            .ok_or(VfsError::Io)?;
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.symlink)(
            &mut ctx,
            name.as_ptr(),
            name.len() as u8,
            target.as_ptr(),
            target.len() as u8,
            &raw const BOOT_CRED,
        );
        match result {
            Ok(Ready(vh)) => Ok(vh),
            Ok(Parked(_)) => Err(VfsError::Busy),
            Err(e) => Err(e),
        }
    }
}

/// Lookup a child by name in a directory vnode.
pub(crate) unsafe fn boot_lookup(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
) -> VfsResult<VnodeHandle> {
    unsafe {
        let mut ctx = crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, parent_vh)
            .ok_or(VfsError::Io)?;
        let ops = &*(*ctx.vnode).ops;
        let result = (ops.meta.lookup)(&mut ctx, name.as_ptr(), name.len() as u8);
        match result {
            Ok(Ready(vh)) => Ok(vh),
            Ok(Parked(_)) => Err(VfsError::Busy),
            Err(e) => Err(e),
        }
    }
}

/// Look up or create a directory under `parent_vh`, then verify that the
/// resolved vnode is a directory.
pub(crate) unsafe fn boot_ensure_dir(
    state: &mut VfsState,
    parent_vh: VnodeHandle,
    name: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let vh = match boot_lookup(state, parent_vh, name) {
            Ok(vh) if vh.is_valid() => vh,
            Ok(_) | Err(VfsError::NotFound) => match boot_mkdir(state, parent_vh, name, mode) {
                Ok(vh) => vh,
                Err(VfsError::Exists) => {
                    let vh = boot_lookup(state, parent_vh, name)?;
                    if !vh.is_valid() {
                        return Err(VfsError::Io);
                    }
                    vh
                }
                Err(e) => return Err(e),
            },
            Err(e) => return Err(e),
        };

        let vnode = state.vnodes.get(vh).ok_or(VfsError::Io)?;
        if vnode.vtype != VT_DIR {
            return Err(VfsError::NotDir);
        }
        Ok(vh)
    }
}

/// Ensure that the target rootfs contains the mountpoints required for
/// post-pivot child mount reattachment.
pub(crate) unsafe fn prepare_post_pivot_scaffold(
    state: &mut VfsState,
    root_vh: VnodeHandle,
) -> VfsResult<()> {
    unsafe {
        for &(name, mode) in FHS_DIRS {
            match name {
                b"dev" | b"proc" | b"tmp" | b"sys" | b"pipe" | b"initramfs" => {
                    let vh = match boot_ensure_dir(state, root_vh, name, mode) {
                        Ok(vh) => vh,
                        Err(e) => {
                            trona_runtime::uerror!(|_lb| {
                                _lb.str(b"[VFS] boot: cannot prepare rootfs mountpoint /");
                                _lb.bytes(name);
                                _lb.str(b" err=");
                                _lb.hex(e.discriminant() as u64);
                                _lb.str(b"\n");
                            });
                            return Err(e);
                        }
                    };
                    let vnode = state.vnodes.get(vh).ok_or(VfsError::Io)?;
                    if vnode.vtype != VT_DIR {
                        trona_runtime::uerror!(|_lb| {
                            _lb.str(b"[VFS] boot: rootfs mountpoint is not a directory /");
                            _lb.bytes(name);
                            _lb.str(b"\n");
                        });
                        return Err(VfsError::NotDir);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

// =========================================================================
// Stage 2: Register builtin filesystem types
// =========================================================================

unsafe fn stage2_register_fs_types() -> VfsResult<()> {
    unsafe {
        fs::ramfs::register()?;
        fs::devfs::register()?;
        fs::procfs::register()?;
        fs::tmpfs::register()?;
        fs::sysctlfs::register()?;
        fs::pipefs::register()?;
        fs::saltyfs_client::register()?;
        Ok(())
    }
}

// =========================================================================
// Stage 3: Mount ramfs as root
// =========================================================================

unsafe fn stage3_mount_root_ramfs(state: &mut VfsState) -> VfsResult<VnodeHandle> {
    unsafe {
        let mh = mount_ctl::do_mount_with_ops_sync(
            state,
            VnodeHandle::INVALID,
            &raw const fs::ramfs::RAMFS_VFSOPS,
            &raw const fs::ramfs::RAMFS_VOPS,
            b"ramfs",
            b"/",
            0,
            0,
            core::ptr::null(),
            0,
        )?;

        state.root_mount = mh;

        let mp = state.mounts.get(mh).ok_or(VfsError::Io)?;
        let root_vh = mp.root_vnode;
        if !root_vh.is_valid() {
            return Err(VfsError::Io);
        }

        Ok(root_vh)
    }
}

// =========================================================================
// Stage 4: Create FHS directory scaffold
// =========================================================================

/// FHS directories to create under the root, with their mode bits.
const FHS_DIRS: &[(&[u8], u32)] = &[
    (b"bin", S_IFDIR_L | 0o755),
    (b"sbin", S_IFDIR_L | 0o755),
    (b"lib", S_IFDIR_L | 0o755),
    (b"usr", S_IFDIR_L | 0o755),
    (b"etc", S_IFDIR_L | 0o755),
    (b"var", S_IFDIR_L | 0o755),
    (b"tmp", S_IFDIR_L | 0o1777),
    (b"dev", S_IFDIR_L | 0o755),
    (b"proc", S_IFDIR_L | 0o555),
    (b"sys", S_IFDIR_L | 0o555),
    (b"home", S_IFDIR_L | 0o755),
    (b"root", S_IFDIR_L | 0o700),
    (b"mnt", S_IFDIR_L | 0o755),
    (b"pipe", S_IFDIR_L | 0o755),
    (b"initramfs", S_IFDIR_L | 0o555),
];

/// Holds vnode handles for directories we need to reference later during
/// mount and /etc population stages.
struct FhsVnodes {
    dev: VnodeHandle,
    proc_: VnodeHandle,
    sys: VnodeHandle,
    tmp: VnodeHandle,
    pipe: VnodeHandle,
    etc: VnodeHandle,
    initramfs: VnodeHandle,
}

unsafe fn stage4_create_fhs_scaffold(
    state: &mut VfsState,
    root_vh: VnodeHandle,
) -> VfsResult<FhsVnodes> {
    let mut result = FhsVnodes {
        dev: VnodeHandle::INVALID,
        proc_: VnodeHandle::INVALID,
        sys: VnodeHandle::INVALID,
        tmp: VnodeHandle::INVALID,
        pipe: VnodeHandle::INVALID,
        etc: VnodeHandle::INVALID,
        initramfs: VnodeHandle::INVALID,
    };

    for &(name, mode) in FHS_DIRS {
        let vh = unsafe { boot_ensure_dir(state, root_vh, name, mode)? };

        match name {
            b"dev" => result.dev = vh,
            b"proc" => result.proc_ = vh,
            b"sys" => result.sys = vh,
            b"tmp" => result.tmp = vh,
            b"pipe" => result.pipe = vh,
            b"etc" => result.etc = vh,
            b"initramfs" => result.initramfs = vh,
            _ => {}
        }
    }

    Ok(result)
}

// =========================================================================
// Stage 5: Create /etc seed files
// =========================================================================

/// Create a writable file with initial content.
unsafe fn create_etc_file(
    state: &mut VfsState,
    etc_vh: VnodeHandle,
    name: &[u8],
    content: &[u8],
    mode: u32,
) -> VfsResult<VnodeHandle> {
    unsafe {
        let vh = boot_create(state, etc_vh, name, mode)?;
        if !content.is_empty() {
            let _ = boot_write(state, vh, 0, content);
        }
        Ok(vh)
    }
}

unsafe fn stage5_create_etc_seed_files(state: &mut VfsState, etc_vh: VnodeHandle) -> VfsResult<()> {
    unsafe {
        let _ = create_etc_file(
            state,
            etc_vh,
            b"passwd",
            b"root:x:0:0:root:/root:/bin/bash\n",
            S_IFREG_L | 0o644,
        )?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"shadow",
            b"root::0:0:99999:7:::\n",
            S_IFREG_L | 0o600,
        )?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"group",
            b"root:x:0:\nwheel:x:10:root\n",
            S_IFREG_L | 0o644,
        )?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"sudoers",
            b"root ALL=(ALL:ALL) ALL\n%wheel ALL=(ALL:ALL) ALL\n",
            S_IFREG_L | 0o440,
        )?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"master.passwd",
            b"root:x:0:0:root:0:0:root:/root:/bin/bash\n",
            S_IFREG_L | 0o600,
        )?;

        let _ = create_etc_file(state, etc_vh, b"login.conf", b"", S_IFREG_L | 0o644)?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"hosts",
            b"127.0.0.1\tlocalhost\n::1\t\tlocalhost\n",
            S_IFREG_L | 0o444,
        )?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"host",
            b"127.0.0.1\tlocalhost\n::1\t\tlocalhost\n",
            S_IFREG_L | 0o444,
        )?;

        let _ = create_etc_file(
            state,
            etc_vh,
            b"resolv.conf",
            b"nameserver 10.0.2.3\n",
            S_IFREG_L | 0o444,
        )?;

        Ok(())
    }
}

// =========================================================================
// Stage 6: CPIO initrd extraction
// =========================================================================

const FREEZE_STACK_CAP: usize = 64;

/// Post-extraction pass: mark every vnode-data under the initramfs root as
/// readonly. Walks the ramfs internal vdata tree directly (no arena vnodes
/// needed — we only modify the `readonly` flag on RamfsVnodeData).
unsafe fn freeze_initrd_tree(state: &mut VfsState, root_vh: VnodeHandle) {
    unsafe {
        let mount_handle = match state.resolve_vnode_mount(root_vh) {
            Some(mh) => mh,
            None => return,
        };
        let vnode = match state.vnodes.get(root_vh) {
            Some(v) => v,
            None => return,
        };
        let mount_data_ptr = match state.mounts.get(mount_handle) {
            Some(m) => m.data as *mut fs::ramfs::RamfsMountData,
            None => return,
        };

        // Walk vdata using inode IDs — no vnode allocation needed.
        let root_data = vnode.data;
        if root_data.is_null() {
            return;
        }

        let mut id_stack: [u64; FREEZE_STACK_CAP] = [0; FREEZE_STACK_CAP];
        let mut sp: usize = 0;

        // Seed with root vdata id.
        let root_vd = root_data as *mut fs::ramfs::RamfsVnodeData;
        (*root_vd).readonly = 1;

        if (*root_vd).ftype == VT_DIR {
            let dirents = (*root_vd).dirents;
            let cap = (*root_vd).dirents_cap as usize;
            if !dirents.is_null() {
                for i in 0..cap {
                    let ent = dirents.add(i);
                    if (*ent).active != 0 && sp < FREEZE_STACK_CAP {
                        id_stack[sp] = (*ent).ino as u64;
                        sp += 1;
                    }
                }
            }
        }

        while sp > 0 {
            sp -= 1;
            let child_id = id_stack[sp];

            let child_vd = fs::ramfs::pool::find_vdata(mount_data_ptr, child_id);
            if child_vd.is_null() {
                continue;
            }

            (*child_vd).readonly = 1;

            if (*child_vd).ftype != VT_DIR {
                continue;
            }

            let dirents = (*child_vd).dirents;
            let cap = (*child_vd).dirents_cap as usize;
            if dirents.is_null() || cap == 0 {
                continue;
            }

            for i in 0..cap {
                let ent = dirents.add(i);
                if (*ent).active != 0 && sp < FREEZE_STACK_CAP {
                    id_stack[sp] = (*ent).ino as u64;
                    sp += 1;
                }
            }
        }
    }
}

fn read_boot_info_initrd_size() -> usize {
    unsafe {
        let page = BOOTINFO_VADDR as *const u64;
        let magic = core::ptr::read_volatile(page);
        if magic != BOOTINFO_MAGIC {
            return 0;
        }
        core::ptr::read_volatile(page.add(2)) as usize
    }
}

struct InitrdResult {
    file_count: u32,
    fstab_data: *const u8,
    fstab_len: usize,
}

unsafe fn stage6_extract_initrd(
    state: &mut VfsState,
    initramfs_vh: VnodeHandle,
) -> VfsResult<InitrdResult> {
    unsafe {
        let initrd = INITRD_VADDR as *const u8;
        let initrd_size = read_boot_info_initrd_size();

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] Initrd size: ");
            _lb.hex(initrd_size as u64);
            _lb.str(b" bytes\n");
        });

        let mut iter = cpio::CpioIter::new(initrd, initrd_size);
        let mut file_count: u32 = 0;
        let mut fstab_data: *const u8 = core::ptr::null();
        let mut fstab_len: usize = 0;

        while let Some(entry) = iter.next_entry_ext() {
            if entry.name_len == 1 && *entry.name == b'.' {
                continue;
            }

            // Capture fstab pointer from the CPIO entry
            if entry.name_len >= 9 && entry.data_len > 0 {
                let name = core::slice::from_raw_parts(entry.name, entry.name_len);
                let mut s = 0usize;
                while s < name.len() && name[s] == b'/' {
                    s += 1;
                }
                if &name[s..] == b"etc/fstab" {
                    fstab_data = entry.data;
                    fstab_len = entry.data_len;
                }
            }

            if mount_initrd_entry_vnode(state, initramfs_vh, &entry) {
                file_count += 1;
            }
        }

        freeze_initrd_tree(state, initramfs_vh);

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] Mounted ");
            _lb.hex(file_count as u64);
            _lb.str(b" initrd files\n");
        });

        Ok(InitrdResult {
            file_count,
            fstab_data,
            fstab_len,
        })
    }
}

/// Mount a single CPIO entry into the VFS tree rooted at `root_vh`,
/// creating intermediate directories as needed.
unsafe fn mount_initrd_entry_vnode(
    state: &mut VfsState,
    root_vh: VnodeHandle,
    entry: &CpioEntryExt,
) -> bool {
    unsafe {
        if !root_vh.is_valid() || entry.name.is_null() || entry.name_len == 0 {
            return false;
        }

        // Normalize CPIO path: strip leading '/', leading './', trailing '/'
        let mut start = 0usize;
        let mut end = entry.name_len;

        while start < end && *entry.name.add(start) == b'/' {
            start += 1;
        }
        while start + 1 < end
            && *entry.name.add(start) == b'.'
            && *entry.name.add(start + 1) == b'/'
        {
            start += 2;
        }
        while end > start && *entry.name.add(end - 1) == b'/' {
            end -= 1;
        }
        if start >= end {
            return true;
        }

        let mut current = root_vh;
        let mut pos = start;

        while pos < end {
            // Skip slashes
            while pos < end && *entry.name.add(pos) == b'/' {
                pos += 1;
            }
            if pos >= end {
                break;
            }

            let comp_start = pos;
            while pos < end && *entry.name.add(pos) != b'/' {
                pos += 1;
            }
            let comp_len = pos - comp_start;
            if comp_len == 0 || comp_len >= MAX_NAME_LEN {
                return false;
            }

            // Check if this is the leaf component
            let mut next = pos;
            while next < end && *entry.name.add(next) == b'/' {
                next += 1;
            }
            let is_leaf = next >= end;

            let comp_ptr = entry.name.add(comp_start);

            if !is_leaf {
                // Intermediate directory — ensure it exists
                let name_slice = core::slice::from_raw_parts(comp_ptr, comp_len);
                match boot_lookup(state, current, name_slice) {
                    Ok(vh) if vh.is_valid() => {
                        current = vh;
                    }
                    _ => match boot_mkdir(state, current, name_slice, S_IFDIR_L | 0o555) {
                        Ok(vh) => {
                            current = vh;
                        }
                        Err(_) => {
                            return false;
                        }
                    },
                }
                continue;
            }

            // Leaf component — create the actual file/dir/symlink
            let leaf_mode = if entry.mode != 0 {
                entry.mode
            } else {
                S_IFREG_L | 0o444
            };
            let is_dir = (leaf_mode & S_IFMT_L) == S_IFDIR_L;
            let is_symlink = (leaf_mode & S_IFMT_L) == S_IFLNK_L;

            let name_slice = core::slice::from_raw_parts(comp_ptr, comp_len);

            // Check if entry already exists
            if let Ok(existing_vh) = boot_lookup(state, current, name_slice) {
                if existing_vh.is_valid() {
                    // Update metadata on existing entry
                    if let Some(existing) = state.vnodes.get(existing_vh) {
                        let data = existing.data;
                        if !data.is_null() {
                            let vd = data as *mut fs::ramfs::RamfsVnodeData;
                            (*vd).mode = leaf_mode;
                            (*vd).readonly = 1;
                            (*vd).uid = entry.uid;
                            (*vd).gid = entry.gid;
                            if entry.nlink != 0 {
                                (*vd).nlink = entry.nlink;
                            }
                            if !is_dir && !is_symlink {
                                (*vd).size = entry.data_len as u64;
                                (*vd).ro_data = entry.data;
                            }
                        }
                    }
                    // Also update nlink on the vnode itself
                    if entry.nlink != 0 {
                        if let Some(existing) = state.vnodes.get_mut(existing_vh) {
                            existing.nlink = entry.nlink;
                        }
                    }
                    return true;
                }
            }

            let success = if is_dir {
                match boot_mkdir(state, current, name_slice, leaf_mode) {
                    Ok(vh) => {
                        if let Some(vnode) = state.vnodes.get(vh) {
                            let data = vnode.data;
                            if !data.is_null() {
                                let vd = data as *mut fs::ramfs::RamfsVnodeData;
                                (*vd).readonly = 1;
                                (*vd).uid = entry.uid;
                                (*vd).gid = entry.gid;
                                if entry.nlink != 0 {
                                    (*vd).nlink = entry.nlink;
                                }
                            }
                        }
                        if entry.nlink != 0 {
                            if let Some(vnode) = state.vnodes.get_mut(vh) {
                                vnode.nlink = entry.nlink;
                            }
                        }
                        true
                    }
                    Err(_) => false,
                }
            } else if is_symlink {
                let target = core::slice::from_raw_parts(entry.data, entry.data_len);
                match boot_symlink(state, current, name_slice, target) {
                    Ok(vh) => {
                        if let Some(vnode) = state.vnodes.get(vh) {
                            let data = vnode.data;
                            if !data.is_null() {
                                let vd = data as *mut fs::ramfs::RamfsVnodeData;
                                (*vd).readonly = 1;
                                (*vd).uid = entry.uid;
                                (*vd).gid = entry.gid;
                            }
                        }
                        true
                    }
                    Err(_) => false,
                }
            } else {
                // Regular file — zero-copy from initrd
                match boot_create(state, current, name_slice, leaf_mode) {
                    Ok(vh) => {
                        if let Some(vnode) = state.vnodes.get(vh) {
                            let data = vnode.data;
                            if !data.is_null() {
                                let vd = data as *mut fs::ramfs::RamfsVnodeData;
                                (*vd).readonly = 1;
                                (*vd).uid = entry.uid;
                                (*vd).gid = entry.gid;
                                (*vd).size = entry.data_len as u64;
                                (*vd).ro_data = entry.data;
                                if entry.nlink != 0 {
                                    (*vd).nlink = entry.nlink;
                                }
                            }
                        }
                        if entry.nlink != 0 {
                            if let Some(vnode) = state.vnodes.get_mut(vh) {
                                vnode.nlink = entry.nlink;
                            }
                        }
                        true
                    }
                    Err(_) => false,
                }
            };

            return success;
        }

        true
    }
}

// =========================================================================
// Public entry point
// =========================================================================

/// Initialize the VFS boot environment.
///
/// Must be called exactly once from `main()` after VfsState is allocated.
pub(crate) unsafe fn init_boot_env(state: &mut VfsState) {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 2 -- registering filesystem types\n");
    });

    unsafe {
        if let Err(e) = stage2_register_fs_types() {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] FATAL: fs type registration failed: ");
                _lb.hex(e.discriminant() as u64);
                _lb.str(b"\n");
            });
            crate::idle();
        }
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 3 -- mounting ramfs root\n");
    });

    let root_vh = unsafe {
        match stage3_mount_root_ramfs(state) {
            Ok(vh) => vh,
            Err(e) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] FATAL: root mount failed: ");
                    _lb.hex(e.discriminant() as u64);
                    _lb.str(b"\n");
                });
                crate::idle();
            }
        }
    };

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 4 -- creating FHS scaffold\n");
    });

    let fhs = unsafe {
        match stage4_create_fhs_scaffold(state, root_vh) {
            Ok(v) => v,
            Err(e) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] FATAL: FHS scaffold failed: ");
                    _lb.hex(e.discriminant() as u64);
                    _lb.str(b"\n");
                });
                crate::idle();
            }
        }
    };

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 5 -- seeding /etc files\n");
    });

    unsafe {
        if let Err(e) = stage5_create_etc_seed_files(state, fhs.etc) {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] FATAL: /etc seed failed: ");
                _lb.hex(e.discriminant() as u64);
                _lb.str(b"\n");
            });
            crate::idle();
        }
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 6 -- extracting initrd CPIO\n");
    });

    let initrd_result = unsafe {
        match stage6_extract_initrd(state, fhs.initramfs) {
            Ok(r) => r,
            Err(e) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] FATAL: initrd extraction failed: ");
                    _lb.hex(e.discriminant() as u64);
                    _lb.str(b"\n");
                });
                crate::idle();
            }
        }
    };

    // FHS directory handles are no longer needed — handle-based, no vrele.

    // -----------------------------------------------------------------
    // Stage 7: Parse fstab
    // -----------------------------------------------------------------

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 7 -- parsing fstab\n");
    });

    let fstab_entries =
        unsafe { super::fstab::parse(initrd_result.fstab_data, initrd_result.fstab_len) };

    {
        let mut n = 0u32;
        for e in &fstab_entries {
            if e.active != 0 {
                n += 1;
            }
        }
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] boot: parsed ");
            _lb.dec(n as u64);
            _lb.str(b" fstab entries\n");
        });
    }

    // -----------------------------------------------------------------
    // Stage 8: Mount pseudo-filesystems from fstab
    // -----------------------------------------------------------------

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: Stage 8 -- mounting pseudo-filesystems from fstab\n");
    });

    unsafe {
        let root_mp = state.mounts.get(state.root_mount);
        let root_vh = match root_mp {
            Some(mp) => mp.root_vnode,
            None => VnodeHandle::INVALID,
        };

        for entry in &fstab_entries {
            if entry.active == 0 || entry.is_root() {
                continue;
            }

            let target = entry.target_slice();
            let fstype = entry.fstype_slice();

            // Strip leading '/' to get directory name under root
            let dir_name = if target.len() > 1 && target[0] == b'/' {
                &target[1..]
            } else {
                target
            };

            let target_vh = match boot_lookup(state, root_vh, dir_name) {
                Ok(vh) if vh.is_valid() => vh,
                _ => {
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[VFS] boot: fstab target not found: ");
                        _lb.bytes(target);
                        _lb.str(b"\n");
                    });
                    continue;
                }
            };

            match mount_ctl::do_mount_sync(
                state,
                target_vh,
                fstype,
                target,
                0,
                entry.flags,
                core::ptr::null(),
                0,
            ) {
                Ok(_mh) => {
                    trona_runtime::uinfo!(|_lb| {
                        _lb.str(b"[VFS] boot: mounted ");
                        _lb.bytes(fstype);
                        _lb.str(b" on ");
                        _lb.bytes(target);
                        _lb.str(b"\n");
                    });
                }
                Err(_e) => {
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[VFS] boot: failed to mount ");
                        _lb.bytes(fstype);
                        _lb.str(b" on ");
                        _lb.bytes(target);
                        _lb.str(b"\n");
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Win32 drive table initialization
    // -----------------------------------------------------------------

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: initializing Win32 drive table\n");
    });

    unsafe {
        crate::personality::win32::drives::init_drives(state);
    }

    // -----------------------------------------------------------------
    // Stage 9: Attempt root mount from fstab
    // -----------------------------------------------------------------

    let mut saltyfs_mounted = false;

    for entry in &fstab_entries {
        if entry.active == 0 || !entry.is_root() {
            continue;
        }

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] boot: Stage 9 -- attempting root mount (");
            _lb.bytes(entry.fstype_slice());
            _lb.str(b")\n");
        });

        unsafe {
            let root_mp = state.mounts.get(state.root_mount);
            let root_vh = match root_mp {
                Some(mp) => mp.root_vnode,
                None => {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] boot: cannot get root vnode\n");
                    });
                    continue;
                }
            };

            let newroot_vh = match boot_ensure_dir(state, root_vh, b"newroot", S_IFDIR_L | 0o755) {
                Ok(vh) => vh,
                Err(_) => {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] boot: cannot ensure /newroot\n");
                    });
                    continue;
                }
            };

            match mount_ctl::do_mount_sync(
                state,
                newroot_vh,
                entry.fstype_slice(),
                b"/newroot",
                0,
                entry.flags,
                core::ptr::null(),
                0,
            ) {
                Ok(_mh) => {
                    super::late_mount::note_root_mounted_pending_pivot();
                    trona_runtime::uinfo!(|_lb| {
                        _lb.str(b"[VFS] boot: root filesystem mounted on /newroot\n");
                    });
                    saltyfs_mounted = true;
                }
                Err(_e) => {
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[VFS] boot: root mount failed, queueing for retry\n");
                    });
                    super::late_mount::queue_pending(entry, true);
                }
            }
        }

        break;
    }

    // -----------------------------------------------------------------
    // Stage 10: pivot_root (if root mounted)
    // -----------------------------------------------------------------

    if saltyfs_mounted {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] boot: Stage 10 -- pivot_root\n");
        });

        unsafe {
            let root_mp = state.mounts.get(state.root_mount);
            let root_vh = match root_mp {
                Some(mp) => mp.root_vnode,
                None => {
                    super::late_mount::note_root_failed();
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] boot: cannot get root vnode for pivot\n");
                    });
                    crate::idle();
                }
            };

            let newroot_vh = match boot_lookup(state, root_vh, b"newroot") {
                Ok(vh) if vh.is_valid() => vh,
                _ => {
                    super::late_mount::note_root_failed();
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] boot: cannot find /newroot for pivot\n");
                    });
                    crate::idle();
                }
            };

            let saltyfs_mh = match mount_ctl::covering_mount_for_vnode(state, newroot_vh) {
                Some(mh) => mh,
                None => {
                    super::late_mount::note_root_failed();
                    crate::idle();
                }
            };

            if saltyfs_mh.is_valid() {
                let saltyfs_root_vh = match state.mounts.get(saltyfs_mh) {
                    Some(mp) => mp.root_vnode,
                    None => {
                        super::late_mount::note_root_failed();
                        crate::idle();
                    }
                };
                if let Err(e) = prepare_post_pivot_scaffold(state, saltyfs_root_vh) {
                    super::late_mount::note_root_failed();
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] boot: cannot prepare post-pivot scaffold err=");
                        _lb.hex(e.discriminant() as u64);
                        _lb.str(b"\n");
                    });
                    crate::idle();
                }
                let put_old_vh = match boot_ensure_dir(
                    state,
                    saltyfs_root_vh,
                    b"initramfs",
                    S_IFDIR_L | 0o555,
                ) {
                    Ok(vh) => vh,
                    Err(_) => {
                        super::late_mount::note_root_failed();
                        trona_runtime::uerror!(|_lb| {
                            _lb.str(b"[VFS] boot: cannot ensure /initramfs in saltyfs\n");
                        });
                        crate::idle();
                    }
                };
                let pivot_result = mount_ctl::do_pivot_root(state, saltyfs_mh, put_old_vh);

                match pivot_result {
                    Ok(()) => {
                        super::late_mount::note_root_ready();
                        trona_runtime::uinfo!(|_lb| {
                            _lb.str(b"[VFS] boot: pivot_root complete, saltyfs is now /\n");
                        });
                    }
                    Err(e) => {
                        super::late_mount::note_root_failed();
                        trona_runtime::uerror!(|_lb| {
                            _lb.str(b"[VFS] boot: pivot_root failed: ");
                            _lb.hex(e.discriminant() as u64);
                            _lb.str(b"\n");
                        });
                    }
                }
            } else {
                super::late_mount::note_root_failed();
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] boot: /newroot is not covered by saltyfs for pivot\n");
                });
            }
        }
    }

    // -----------------------------------------------------------------
    // Initialize global mount namespace
    // -----------------------------------------------------------------

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: initializing global mount namespace\n");
    });

    {
        let nsh = match state.mount_ns.alloc() {
            Some(h) => h,
            None => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] FATAL: cannot allocate global mount namespace\n");
                });
                crate::idle();
            }
        };
        if let Some(ns) = state.mount_ns.get_mut(nsh) {
            *ns = crate::vfs_core::mount_ns::MountNamespace::zeroed();
            ns.refcount = 1;
            ns.root_mount = state.root_mount;
        }
        state.global_ns = nsh;
        mount_ctl::refresh_global_ns(state);
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] boot: all stages complete\n");
    });
}
