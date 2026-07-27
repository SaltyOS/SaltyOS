// SPDX-License-Identifier: GPL-2.0-only
//! sysctlfs — synchronous sysctl namespace.

use trona_kernel::core_types::TronaSysInfo;
use trona_kernel::core_types::sysinfo::TronaSysMemInfo;
use trona_posix::consts::{S_IFDIR, S_IFREG};
use uapi::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::server::sysctl_object::{SysctlLeafHandle, SysctlLeafKind, SysctlLeafState};
use crate::vfs_core::cached_ref::CachedRef;
use crate::vfs_core::identity::FsInstanceId;
use crate::vfs_core::mount::{MNT_RDONLY, MOUNT_BACKEND_SYSCTLFS, Mount, MountHandle};
use crate::vfs_core::vnode::{VNODE_BACKEND_SYSCTLFS, Vnode, VnodeHandle};
use crate::vfs_core::vops::{VfsOpResult, VfsResult, VnodeOps};

pub(crate) type SysctlfsMountHandle = Handle<SysctlfsMountData>;

const HOSTNAME_MAX: usize = 255;

#[repr(C)]
pub(crate) struct SysctlfsMountData {
    pub(crate) owner_mount: MountHandle,
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) root_vnode: VnodeHandle,
    pub(crate) hostname_len: u8,
    _pad0: [u8; 3],
    pub(crate) securelevel: i32,
    pub(crate) hostname: [u8; HOSTNAME_MAX],
}

static SYSCTLFS_VFSOPS: crate::vfs_core::vfsops::VfsOps = crate::vfs_core::vfsops::VfsOps::empty();
static SYSCTLFS_VOPS: VnodeOps = VnodeOps {
    lookup_child: None,
    build_path: None,
    ensure_symlink_target: None,
    readlink_inline: None,
    read_regular: Some(read_regular_vop),
    write_regular: Some(write_regular_vop),
    create_regular_child: None,
    mkdir_child: None,
    symlink_child: None,
    remove_child: None,
    rename_child: None,
    link_vnode_into: None,
    set_mode: None,
    set_owner: None,
    set_times: None,
    truncate: None,
    validate_open_regular: None,
    readdir_dir: None,
    supports_pager_backing: Some(deny_pager_backing_vop),
};

#[inline]
pub(crate) fn mount_is_sysctlfs(mount: &Mount) -> bool {
    mount.backend_kind == MOUNT_BACKEND_SYSCTLFS
}

#[inline]
pub(crate) fn sysctlfs_vfsops() -> *const () {
    &raw const SYSCTLFS_VFSOPS as *const crate::vfs_core::vfsops::VfsOps as *const ()
}

#[inline]
pub(crate) fn sysctlfs_vops() -> *const () {
    &raw const SYSCTLFS_VOPS as *const VnodeOps as *const ()
}

fn deny_pager_backing_vop(_state: &VfsState, _vnode: VnodeHandle) -> bool {
    false
}

fn find_mount_data_handle(
    state: &VfsState,
    owner_mount: MountHandle,
) -> Option<SysctlfsMountHandle> {
    let mut found = SysctlfsMountHandle::INVALID;
    state.sysctlfs_mounts.for_each_active(|handle, data| {
        if data.owner_mount == owner_mount {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

fn find_leaf_handle_by_vnode(state: &VfsState, vnode: VnodeHandle) -> Option<SysctlLeafHandle> {
    let vnode_ref = state.vnodes.get(vnode)?;
    let handle = vnode_ref.backend_ref::<SysctlLeafState>();
    state
        .sysctl_leaves
        .get(handle)
        .filter(|leaf| leaf.vnode == vnode)
        .map(|_| handle)
}

fn write_ascii(out: *mut u8, cap: usize, src: &[u8]) -> usize {
    let n = core::cmp::min(cap, src.len());
    if n != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(src.as_ptr(), out, n);
        }
    }
    n
}

fn write_u64_line(out: *mut u8, cap: usize, value: u64) -> usize {
    let mut buf = [0u8; 32];
    let mut idx = buf.len();
    let mut v = value;
    loop {
        idx -= 1;
        buf[idx] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let digits = &buf[idx..];
    if cap == 0 {
        return 0;
    }
    let mut len = write_ascii(out, cap, digits);
    if len < cap {
        unsafe {
            *out.add(len) = b'\n';
        }
        len += 1;
    }
    len
}

fn write_i32_line(out: *mut u8, cap: usize, value: i32) -> usize {
    if value < 0 {
        if cap == 0 {
            return 0;
        }
        unsafe {
            *out = b'-';
        }
        1 + write_u64_line(
            unsafe { out.add(1) },
            cap.saturating_sub(1),
            value.unsigned_abs() as u64,
        )
    } else {
        write_u64_line(out, cap, value as u64)
    }
}

fn sysinfo_header() -> TronaSysInfo {
    let mut hdr = TronaSysInfo::zeroed();
    let _ = trona_kernel::syscall::sys_sysinfo(&raw mut hdr, core::ptr::null_mut(), 0);
    hdr
}

fn sysmem_snapshot() -> TronaSysMemInfo {
    let mut info = TronaSysMemInfo::zeroed();
    let _ = trona_kernel::syscall::sys_sysmeminfo(&raw mut info);
    info
}

fn leaf_size_hint(state: &VfsState, mount: MountHandle, kind: SysctlLeafKind) -> u64 {
    match kind {
        SysctlLeafKind::KernOstype => b"SaltyOS\n".len() as u64,
        SysctlLeafKind::KernOsrelease => b"0.1.0\n".len() as u64,
        SysctlLeafKind::KernVersion => b"SaltyOS 0.1.0\n".len() as u64,
        SysctlLeafKind::KernMaxproc => 4,
        SysctlLeafKind::KernBoottime => 24,
        SysctlLeafKind::KernUptime => 24,
        SysctlLeafKind::KernContextSwitches => 24,
        SysctlLeafKind::HwNcpu => 4,
        SysctlLeafKind::HwPagesize => 6,
        SysctlLeafKind::HwPhysmem => 24,
        SysctlLeafKind::VmPhysmem => 24,
        SysctlLeafKind::VmPagesFree => 24,
        SysctlLeafKind::VmPageSize => 6,
        SysctlLeafKind::KernHostname => {
            match find_mount_data_handle(state, mount).and_then(|h| state.sysctlfs_mounts.get(h)) {
                Some(data) => data.hostname_len as u64 + 1,
                None => 0,
            }
        }
        SysctlLeafKind::SecuritySecurelevel => 4,
    }
}

fn parse_sysctlfs_flags(flags: u32, opts: &[u8]) -> u32 {
    let mut effective = flags;
    crate::vfs_core::mount_options::for_each_token(opts, |token| match token {
        b"ro" | b"readonly" => effective |= MNT_RDONLY,
        _ => {}
    });
    effective
}

pub(crate) fn alloc_mount(
    state: &mut VfsState,
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Option<MountHandle> {
    let effective_flags = parse_sysctlfs_flags(flags, opts);
    let root_vh = state.vnodes.alloc()?;
    let mh = state.mounts.alloc()?;
    let data_h = state.sysctlfs_mounts.alloc()?;
    let fs_id = state.alloc_fs_instance_id();

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
        vnode.backend_kind = VNODE_BACKEND_SYSCTLFS;
        vnode.id = 1;
        vnode.ops = sysctlfs_vops();
    }
    state.cache_vnode_key(root_vh);

    {
        let mount = state.mounts.get_mut(mh)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            effective_flags,
            fs_id,
            root_vh,
            b"sysctlfs",
            mount_path,
        );
        mount.backend_kind = MOUNT_BACKEND_SYSCTLFS;
        mount.vfsops = sysctlfs_vfsops();
        mount.vops = sysctlfs_vops();
    }

    let data_ptr = {
        let data = state.sysctlfs_mounts.get_mut(data_h)?;
        *data = SysctlfsMountData {
            owner_mount: mh,
            fs_instance_id: fs_id,
            root_vnode: root_vh,
            hostname_len: 7,
            _pad0: [0; 3],
            securelevel: 0,
            hostname: [0; HOSTNAME_MAX],
        };
        data.hostname[..7].copy_from_slice(b"saltyos");
        data as *mut SysctlfsMountData as *mut u8
    };

    {
        let mount = state.mounts.get_mut(mh)?;
        mount.data = data_ptr;
    }
    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        vnode.mount = CachedRef::new(fs_id, mh);
    }

    Some(mh)
}

pub(crate) fn release_mount(state: &mut VfsState, owner_mount: MountHandle) -> bool {
    let mut leaves = [SysctlLeafHandle::INVALID; 64];
    let mut count = 0usize;
    state.sysctl_leaves.for_each_active(|handle, leaf| {
        if leaf.owner_mount == owner_mount && count < leaves.len() {
            leaves[count] = handle;
            count += 1;
        }
        true
    });
    for handle in leaves.into_iter().take(count) {
        if let Some(leaf) = state.sysctl_leaves.get(handle) {
            if let Some(vnode) = state.vnodes.get_mut(leaf.vnode) {
                vnode.clear_backend_ref();
            }
        }
        if let Some(leaf) = state.sysctl_leaves.get(handle) {
            state.uncache_vnode_key(leaf.vnode);
        }
        let _ = state.sysctl_leaves.release(handle);
    }

    let Some(data_h) = find_mount_data_handle(state, owner_mount) else {
        return true;
    };
    state.sysctlfs_mounts.release(data_h)
}

pub(crate) fn release_leaf_for_vnode(state: &mut VfsState, vnode: VnodeHandle) {
    if let Some(vnode_ref) = state.vnodes.get_mut(vnode) {
        vnode_ref.clear_backend_ref();
    }
    state.uncache_vnode_key(vnode);
    if let Some(found) = find_leaf_handle_by_vnode(state, vnode) {
        let _ = state.sysctl_leaves.release(found);
    }
}

fn register_leaf(
    state: &mut VfsState,
    path: &[u8],
    mode: u32,
    kind: SysctlLeafKind,
) -> Result<(), u64> {
    let vh = state.bootstrap_create_regular_file_path(path, mode)?;
    let mount = match state.vnodes.get(vh) {
        Some(vn) => vn.mount.handle,
        None => return Err(TRONA_INVALID_OPERATION),
    };
    let leaf_h = state.sysctl_leaves.alloc().ok_or(TRONA_OUT_OF_MEMORY)?;
    {
        let leaf = state
            .sysctl_leaves
            .get_mut(leaf_h)
            .ok_or(TRONA_OUT_OF_MEMORY)?;
        *leaf = SysctlLeafState::zeroed();
        leaf.vnode = vh;
        leaf.owner_mount = mount;
        leaf.kind = kind;
    }
    let size = leaf_size_hint(state, mount, kind);
    if let Some(vn) = state.vnodes.get_mut(vh) {
        vn.set_backend_ref(leaf_h);
        vn.size = size;
    }
    state.cache_vnode_key(vh);
    Ok(())
}

pub(crate) fn populate_bootstrap_tree(state: &mut VfsState) -> bool {
    for dir in [
        b"/sys/kern".as_slice(),
        b"/sys/hw",
        b"/sys/net",
        b"/sys/vm",
        b"/sys/vfs",
        b"/sys/security",
    ] {
        if state
            .bootstrap_mkdir_path(dir, (S_IFDIR as u32) | 0o555)
            .is_err()
            && state.bootstrap_lookup_path(dir).is_none()
        {
            return false;
        }
    }

    let leaves = [
        (
            b"/sys/kern/ostype".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernOstype,
        ),
        (
            b"/sys/kern/osrelease".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernOsrelease,
        ),
        (
            b"/sys/kern/hostname".as_slice(),
            (S_IFREG as u32) | 0o644,
            SysctlLeafKind::KernHostname,
        ),
        (
            b"/sys/kern/version".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernVersion,
        ),
        (
            b"/sys/kern/maxproc".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernMaxproc,
        ),
        (
            b"/sys/kern/boottime".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernBoottime,
        ),
        (
            b"/sys/kern/uptime".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernUptime,
        ),
        (
            b"/sys/kern/context_switches".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::KernContextSwitches,
        ),
        (
            b"/sys/hw/ncpu".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::HwNcpu,
        ),
        (
            b"/sys/hw/pagesize".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::HwPagesize,
        ),
        (
            b"/sys/hw/physmem".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::HwPhysmem,
        ),
        (
            b"/sys/vm/physmem".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::VmPhysmem,
        ),
        (
            b"/sys/vm/pages_free".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::VmPagesFree,
        ),
        (
            b"/sys/vm/page_size".as_slice(),
            (S_IFREG as u32) | 0o444,
            SysctlLeafKind::VmPageSize,
        ),
        (
            b"/sys/security/securelevel".as_slice(),
            (S_IFREG as u32) | 0o644,
            SysctlLeafKind::SecuritySecurelevel,
        ),
    ];
    for (path, mode, kind) in leaves {
        if register_leaf(state, path, mode, kind).is_err() {
            return false;
        }
    }
    true
}

fn lookup_leaf<'a>(
    state: &'a VfsState,
    vnode: VnodeHandle,
) -> Option<(&'a SysctlLeafState, &'a SysctlfsMountData)> {
    let leaf_h = find_leaf_handle_by_vnode(state, vnode)?;
    let leaf = state.sysctl_leaves.get(leaf_h)?;
    let mount_h = find_mount_data_handle(state, leaf.owner_mount)?;
    let mount = state.sysctlfs_mounts.get(mount_h)?;
    Some((leaf, mount))
}

pub(crate) fn read_leaf(
    state: &VfsState,
    vnode: VnodeHandle,
    offset: u64,
    out: *mut u8,
    out_cap: usize,
) -> Option<usize> {
    let (leaf, mount) = lookup_leaf(state, vnode)?;
    let mut buf = [0u8; 160];
    let len = match leaf.kind {
        SysctlLeafKind::KernOstype => write_ascii(buf.as_mut_ptr(), buf.len(), b"SaltyOS\n"),
        SysctlLeafKind::KernOsrelease => write_ascii(buf.as_mut_ptr(), buf.len(), b"0.1.0\n"),
        SysctlLeafKind::KernHostname => {
            let n = mount.hostname_len as usize;
            let mut len = write_ascii(buf.as_mut_ptr(), buf.len(), &mount.hostname[..n]);
            if len < buf.len() {
                buf[len] = b'\n';
                len += 1;
            }
            len
        }
        SysctlLeafKind::KernVersion => write_ascii(buf.as_mut_ptr(), buf.len(), b"SaltyOS 0.1.0\n"),
        SysctlLeafKind::KernMaxproc => write_u64_line(buf.as_mut_ptr(), buf.len(), 256),
        SysctlLeafKind::KernBoottime => {
            write_u64_line(buf.as_mut_ptr(), buf.len(), sysinfo_header().boot_time_ns)
        }
        SysctlLeafKind::KernUptime => {
            write_u64_line(buf.as_mut_ptr(), buf.len(), sysinfo_header().uptime_ns)
        }
        SysctlLeafKind::KernContextSwitches => write_u64_line(
            buf.as_mut_ptr(),
            buf.len(),
            sysinfo_header().context_switches_total,
        ),
        SysctlLeafKind::HwNcpu => write_u64_line(
            buf.as_mut_ptr(),
            buf.len(),
            sysinfo_header().cpu_count as u64,
        ),
        SysctlLeafKind::HwPagesize => write_u64_line(buf.as_mut_ptr(), buf.len(), 4096),
        SysctlLeafKind::HwPhysmem => {
            let info = sysmem_snapshot();
            write_u64_line(
                buf.as_mut_ptr(),
                buf.len(),
                info.pages_total.saturating_mul(info.page_size),
            )
        }
        SysctlLeafKind::VmPhysmem => {
            let info = sysmem_snapshot();
            write_u64_line(
                buf.as_mut_ptr(),
                buf.len(),
                info.pages_total.saturating_mul(info.page_size),
            )
        }
        SysctlLeafKind::VmPagesFree => {
            let info = sysmem_snapshot();
            write_u64_line(
                buf.as_mut_ptr(),
                buf.len(),
                info.pages_free.saturating_mul(info.page_size),
            )
        }
        SysctlLeafKind::VmPageSize => {
            let info = sysmem_snapshot();
            write_u64_line(buf.as_mut_ptr(), buf.len(), info.page_size)
        }
        SysctlLeafKind::SecuritySecurelevel => {
            write_i32_line(buf.as_mut_ptr(), buf.len(), mount.securelevel)
        }
    };
    let start = core::cmp::min(offset as usize, len);
    let actual = core::cmp::min(out_cap, len.saturating_sub(start));
    if actual != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(buf.as_ptr().add(start), out, actual);
        }
    }
    Some(actual)
}

fn parse_i32(src: *const u8, len: usize) -> Option<i32> {
    if len == 0 {
        return None;
    }
    let bytes = unsafe { core::slice::from_raw_parts(src, len) };
    let mut start = 0usize;
    let mut end = bytes.len();
    while start < end && (bytes[start] == b' ' || bytes[start] == b'\n' || bytes[start] == b'\t') {
        start += 1;
    }
    while end > start
        && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\n' || bytes[end - 1] == b'\t')
    {
        end -= 1;
    }
    if start >= end {
        return None;
    }
    let mut neg = false;
    let mut idx = start;
    if bytes[idx] == b'-' {
        neg = true;
        idx += 1;
    }
    let mut value: i32 = 0;
    while idx < end {
        let b = bytes[idx];
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as i32)?;
        idx += 1;
    }
    Some(if neg { -value } else { value })
}

pub(crate) fn write_leaf(
    state: &mut VfsState,
    vnode: VnodeHandle,
    offset: u64,
    src: *const u8,
    len: usize,
) -> Result<u64, u64> {
    if offset != 0 {
        return Err(TRONA_INVALID_OPERATION);
    }

    let (leaf_kind, owner_mount) = match lookup_leaf(state, vnode) {
        Some((leaf, _)) => (leaf.kind, leaf.owner_mount),
        None => return Err(TRONA_NOT_SUPPORTED),
    };
    let mount_h = find_mount_data_handle(state, owner_mount).ok_or(TRONA_INVALID_OPERATION)?;
    let mount = state
        .sysctlfs_mounts
        .get_mut(mount_h)
        .ok_or(TRONA_INVALID_OPERATION)?;

    match leaf_kind {
        SysctlLeafKind::KernHostname => {
            let bytes = unsafe { core::slice::from_raw_parts(src, len) };
            let mut n = bytes.len();
            if n > 0 && bytes[n - 1] == b'\n' {
                n -= 1;
            }
            if n > HOSTNAME_MAX {
                n = HOSTNAME_MAX;
            }
            mount.hostname = [0; HOSTNAME_MAX];
            mount.hostname[..n].copy_from_slice(&bytes[..n]);
            mount.hostname_len = n as u8;
            if let Some(vn) = state.vnodes.get_mut(vnode) {
                vn.size = n as u64 + 1;
                vn.mtime_ns = vn.mtime_ns.saturating_add(1);
            }
            Ok(len as u64)
        }
        SysctlLeafKind::SecuritySecurelevel => {
            let value = parse_i32(src, len).ok_or(TRONA_INVALID_ARGUMENT)?;
            mount.securelevel = value;
            if let Some(vn) = state.vnodes.get_mut(vnode) {
                vn.size = if value < 0 { 3 } else { 2 };
                vn.mtime_ns = vn.mtime_ns.saturating_add(1);
            }
            Ok(len as u64)
        }
        _ => Err(TRONA_INVALID_OPERATION),
    }
}

unsafe fn read_regular_vop(
    state: &VfsState,
    _cli_handle: Option<crate::server::types::ClientHandle>,
    vnode: VnodeHandle,
    offset: u64,
    out: *mut u8,
    cap: usize,
) -> VfsResult<usize> {
    match read_leaf(state, vnode, offset, out, cap) {
        Some(n) => Ok(VfsOpResult::Complete(n)),
        None => Err(TRONA_NOT_SUPPORTED),
    }
}

unsafe fn write_regular_vop(
    state: &mut VfsState,
    vnode: VnodeHandle,
    offset: u64,
    src: *const u8,
    len: usize,
) -> VfsResult<u64> {
    let mount = state
        .vnodes
        .get(vnode)
        .map(|vn| vn.mount.handle)
        .unwrap_or(MountHandle::INVALID);
    let read_only = state
        .mounts
        .get(mount)
        .map(|m| (m.flags & MNT_RDONLY) != 0)
        .unwrap_or(false);
    if read_only {
        return Err(TRONA_READONLY);
    }
    write_leaf(state, vnode, offset, src, len).map(VfsOpResult::Complete)
}
