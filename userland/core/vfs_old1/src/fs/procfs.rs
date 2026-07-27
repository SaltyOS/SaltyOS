// SPDX-License-Identifier: GPL-2.0-only
//! procfs — synchronous generated process namespace.
//!
//! The rebuilt VFS keeps procfs deliberately small: static root files are
//! materialized in the bootstrap tree, while per-pid content is generated
//! through a lightweight vnode cache keyed by `(kind, pid)`.

use trona_kernel::core_types::kinfo::{KINFO_PROC_COMM_LEN, KinfoProc};
use trona_kernel::core_types::sysinfo::TronaProcMemSnapshot;
use trona_kernel::core_types::{TronaMsg, TronaSysInfo, TronaSysInfoCpu};
use trona_kernel::ipc;
use trona_posix::consts::{DT_DIR, DT_LNK, DT_REG, S_IFDIR, S_IFLNK, S_IFREG};
use trona_protocol::posix::init::INIT_GET_EXE_PATH;
use uapi::*;

use crate::arena::Handle;
use crate::owner::VfsState;
use crate::server::proc_object::{ProcNodeHandle, ProcNodeKind, ProcNodeState};
use crate::server::types::ClientHandle;
use crate::vfs_core::cached_ref::CachedRef;
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};
use crate::vfs_core::mount::{MOUNT_BACKEND_PROCFS, Mount, MountHandle};
use crate::vfs_core::vnode::{VNODE_BACKEND_PROCFS, VT_DIR, VT_LNK, VT_REG, Vnode, VnodeHandle};
use crate::vfs_core::vops::VnodeOps;

pub(crate) type ProcfsMountHandle = Handle<ProcfsMountData>;

#[repr(C)]
pub(crate) struct ProcfsMountData {
    pub(crate) owner_mount: MountHandle,
    pub(crate) fs_instance_id: FsInstanceId,
    pub(crate) root_vnode: VnodeHandle,
    /// `hidepid=N` mount option, mirroring Linux procfs:
    ///   0 = no restriction (default)
    ///   1 = hide pid dirs you do not own
    ///   2 = hide pid dirs you do not own and refuse access
    /// Stored at mount time; visibility logic checks it on lookup.
    pub(crate) hidepid: u8,
    pub(crate) _pad0: [u8; 7],
}

static PROCFS_VFSOPS: crate::vfs_core::vfsops::VfsOps = crate::vfs_core::vfsops::VfsOps {
    statfs: None,
    sync: None,
    remount: Some(procfs_remount),
    resolve_backing: None,
    reclaim_vnode: None,
};
static PROCFS_VOPS: VnodeOps = VnodeOps {
    lookup_child: None,
    build_path: None,
    ensure_symlink_target: None,
    readlink_inline: Some(readlink_inline_vop),
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
    validate_open_regular: Some(validate_open_regular_vop),
    readdir_dir: Some(readdir_dir_vop),
    supports_pager_backing: Some(deny_pager_backing_vop),
};

const ROOT_NAMES: &[(&[u8], ProcNodeKind, u8)] = &[
    (b"self", ProcNodeKind::SelfLink, DT_LNK),
    (b"stat", ProcNodeKind::RootStat, DT_REG),
    (b"meminfo", ProcNodeKind::RootMeminfo, DT_REG),
    (b"uptime", ProcNodeKind::RootUptime, DT_REG),
    (b"cpuinfo", ProcNodeKind::RootCpuinfo, DT_REG),
    (b"loadavg", ProcNodeKind::RootLoadavg, DT_REG),
    (b"version", ProcNodeKind::RootVersion, DT_REG),
    (b"mounts", ProcNodeKind::RootMounts, DT_REG),
    (b"filesystems", ProcNodeKind::RootFilesystems, DT_REG),
    (b"sys", ProcNodeKind::SelfLink, DT_LNK),
];

const PID_NAMES: &[(&[u8], ProcNodeKind, u8)] = &[
    (b"stat", ProcNodeKind::PidStat, DT_REG),
    (b"status", ProcNodeKind::PidStatus, DT_REG),
    (b"cmdline", ProcNodeKind::PidCmdline, DT_REG),
    (b"comm", ProcNodeKind::PidComm, DT_REG),
    (b"statm", ProcNodeKind::PidStatm, DT_REG),
    (b"exe", ProcNodeKind::PidExe, DT_LNK),
];

#[inline]
pub(crate) fn mount_is_procfs(mount: &Mount) -> bool {
    mount.backend_kind == MOUNT_BACKEND_PROCFS
}

#[inline]
pub(crate) fn procfs_vfsops() -> *const () {
    &raw const PROCFS_VFSOPS as *const crate::vfs_core::vfsops::VfsOps as *const ()
}

#[inline]
pub(crate) fn procfs_vops() -> *const () {
    &raw const PROCFS_VOPS as *const VnodeOps as *const ()
}

fn mount_data_for_vnode<'a>(
    state: &'a VfsState,
    vnode: VnodeHandle,
) -> Option<&'a ProcfsMountData> {
    let mount = state.vnodes.get(vnode)?.mount.handle;
    mount_data_for_mount(state, mount)
}

fn mount_data_for_mount<'a>(
    state: &'a VfsState,
    mount: MountHandle,
) -> Option<&'a ProcfsMountData> {
    let handle = find_mount_data_handle(state, mount)?;
    state.procfs_mounts.get(handle)
}

fn find_mount_data_handle(state: &VfsState, owner_mount: MountHandle) -> Option<ProcfsMountHandle> {
    let mut found = ProcfsMountHandle::INVALID;
    state.procfs_mounts.for_each_active(|handle, data| {
        if data.owner_mount == owner_mount {
            found = handle;
            return false;
        }
        true
    });
    if found.is_valid() { Some(found) } else { None }
}

pub(crate) fn find_node_handle_by_vnode(
    state: &VfsState,
    vnode: VnodeHandle,
) -> Option<ProcNodeHandle> {
    let vnode_ref = state.vnodes.get(vnode)?;
    let handle = vnode_ref.backend_ref::<ProcNodeState>();
    state
        .proc_nodes
        .get(handle)
        .filter(|node| node.vnode == vnode)
        .map(|_| handle)
}

fn find_node_handle_by_vnode_mut(
    state: &mut VfsState,
    vnode: VnodeHandle,
) -> Option<ProcNodeHandle> {
    let found = find_node_handle_by_vnode(state, vnode)?;
    if let Some(vnode_ref) = state.vnodes.get_mut(vnode) {
        vnode_ref.set_backend_ref(found);
    }
    Some(found)
}

fn find_node_handle_by_key(
    state: &VfsState,
    owner_mount: MountHandle,
    kind: ProcNodeKind,
    pid: u32,
) -> Option<ProcNodeHandle> {
    let fs_instance_id = state.mounts.get(owner_mount)?.fs_instance_id;
    let key = VnodeKey {
        fs_instance_id,
        backend_id: trona_protocol::BackendNodeId::new(proc_inode(kind, pid), 0),
    };
    let vnode = state.vnode_by_key(key)?;
    find_node_handle_by_vnode(state, vnode)
}

fn find_node_handle_by_key_mut(
    state: &mut VfsState,
    owner_mount: MountHandle,
    kind: ProcNodeKind,
    pid: u32,
) -> Option<ProcNodeHandle> {
    let found = find_node_handle_by_key(state, owner_mount, kind, pid)?;
    Some(found)
}

fn proc_root_vnode(state: &VfsState) -> Option<VnodeHandle> {
    state.bootstrap_lookup_path(b"/proc")
}

fn proc_root_mount(state: &VfsState) -> Option<MountHandle> {
    let root = proc_root_vnode(state)?;
    let vnode = state.vnodes.get(root)?;
    let mount = vnode.mount.handle;
    let mount_ref = state.mounts.get(mount)?;
    if mount_is_procfs(mount_ref) {
        Some(mount)
    } else {
        None
    }
}

fn proc_root_id(state: &VfsState) -> u64 {
    proc_root_vnode(state)
        .and_then(|vh| state.vnodes.get(vh).map(|vn| vn.id))
        .unwrap_or(1)
}

fn proc_inode(kind: ProcNodeKind, pid: u32) -> u64 {
    ((kind as u64) << 32) | pid as u64
}

fn current_pid(state: &VfsState, cli_handle: ClientHandle) -> u32 {
    state
        .clients
        .get(cli_handle)
        .map(|client| client.badge as u32)
        .unwrap_or(0)
}

fn proc_state_char(state: u8) -> u8 {
    match state {
        1 => b'R',
        2 => b'Z',
        3 => b'T',
        _ => b'S',
    }
}

fn proc_root_child(state: &VfsState, name: &[u8]) -> Option<VnodeHandle> {
    let root = proc_root_vnode(state)?;
    state.bootstrap_lookup_child(root, name)
}

fn proc_kinfo(pid: u32) -> Option<KinfoProc> {
    let mut kp = KinfoProc::zeroed();
    if trona_runtime::pm_get_kinfo_proc(pid, &mut kp) {
        Some(kp)
    } else {
        None
    }
}

fn proc_pid_exists(pid: u32) -> bool {
    proc_kinfo(pid).is_some()
}

fn proc_times(pid: u32) -> (u64, u64, u64, u64) {
    trona_runtime::pm_get_proc_times(pid).unwrap_or((0, 0, 0, 0))
}

fn proc_mem_snapshot(pid: u32) -> TronaProcMemSnapshot {
    let ep = trona_runtime::client::caps::init_ep();
    if ep == 0 {
        return TronaProcMemSnapshot::zeroed();
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = trona_protocol::init::INIT_GET_CLIENT_VM_STATS;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return TronaProcMemSnapshot::zeroed();
        }
        let ctx = &*crate::ipc_ctx();
        if ctx.ipc_buffer.is_null() {
            return TronaProcMemSnapshot::zeroed();
        }
        let src = (*ctx.ipc_buffer).reserved.as_ptr() as *const TronaProcMemSnapshot;
        core::ptr::read(src)
    }
}

fn proc_exe_path(pid: u32, out: &mut [u8]) -> Option<usize> {
    let ep = trona_runtime::client::caps::init_ep();
    if ep == 0 {
        return None;
    }
    unsafe {
        let mut msg = TronaMsg::zeroed();
        let mut reply = TronaMsg::zeroed();
        msg.label = INIT_GET_EXE_PATH;
        msg.length = 1;
        msg.regs[0] = pid as u64;
        let err = ipc::call_ctx(crate::ipc_ctx(), ep, &raw const msg, &raw mut reply);
        if err != 0 || reply.label != TRONA_OK {
            return None;
        }
        let path_len = core::cmp::min(reply.regs[0] as usize, out.len());
        let src = &raw const reply.regs[1] as *const u64 as *const u8;
        for idx in 0..path_len {
            out[idx] = *src.add(idx);
        }
        Some(path_len)
    }
}

fn append_bytes(dst: &mut [u8], pos: &mut usize, src: &[u8]) {
    let mut idx = 0usize;
    while idx < src.len() && *pos < dst.len() {
        dst[*pos] = src[idx];
        *pos += 1;
        idx += 1;
    }
}

fn append_u32(dst: &mut [u8], pos: &mut usize, mut v: u32) {
    if v == 0 {
        append_bytes(dst, pos, b"0");
        return;
    }
    let mut tmp = [0u8; 10];
    let mut len = 0usize;
    while v != 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
    }
    while len != 0 {
        len -= 1;
        append_bytes(dst, pos, &tmp[len..len + 1]);
    }
}

fn append_u64(dst: &mut [u8], pos: &mut usize, mut v: u64) {
    if v == 0 {
        append_bytes(dst, pos, b"0");
        return;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    while v != 0 && len < tmp.len() {
        tmp[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
    }
    while len != 0 {
        len -= 1;
        append_bytes(dst, pos, &tmp[len..len + 1]);
    }
}

fn append_line_kb(dst: &mut [u8], pos: &mut usize, label: &[u8], bytes: u64) {
    append_bytes(dst, pos, label);
    append_bytes(dst, pos, b": ");
    append_u64(dst, pos, bytes / 1024);
    append_bytes(dst, pos, b" kB\n");
}

fn append_fixed_2(dst: &mut [u8], pos: &mut usize, v: u32) {
    let tens = b'0' + ((v / 10) as u8);
    let ones = b'0' + ((v % 10) as u8);
    append_bytes(dst, pos, &[tens, ones]);
}

fn read_root_stat(dst: &mut [u8]) -> usize {
    let mut hdr = TronaSysInfo::zeroed();
    let mut cpus = [TronaSysInfoCpu::zeroed(); 64];
    let _ = trona_kernel::syscall::sys_sysinfo(&raw mut hdr, cpus.as_mut_ptr(), cpus.len() as u64);
    let (procs_total, procs_running, last_pid) =
        trona_runtime::pm_get_system_stats().unwrap_or((0, 0, 0));
    let mut agg_user = 0u64;
    let mut agg_sys = 0u64;
    let mut agg_idle = 0u64;
    let written = core::cmp::min(hdr.cpus_written as usize, cpus.len());
    for cpu in &cpus[..written] {
        agg_user = agg_user.saturating_add(cpu.user_time_ns / 10_000_000);
        agg_sys = agg_sys.saturating_add(cpu.system_time_ns / 10_000_000);
        agg_idle = agg_idle.saturating_add(cpu.idle_time_ns / 10_000_000);
    }
    let mut pos = 0usize;
    append_bytes(dst, &mut pos, b"cpu ");
    append_u64(dst, &mut pos, agg_user);
    append_bytes(dst, &mut pos, b" 0 ");
    append_u64(dst, &mut pos, agg_sys);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, agg_idle);
    append_bytes(dst, &mut pos, b" 0 0 0 0\n");
    for (idx, cpu) in cpus[..written].iter().enumerate() {
        append_bytes(dst, &mut pos, b"cpu");
        append_u32(dst, &mut pos, idx as u32);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, cpu.user_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" 0 ");
        append_u64(dst, &mut pos, cpu.system_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, cpu.idle_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" 0 0 0 0\n");
    }
    append_bytes(dst, &mut pos, b"intr 0\nctxt ");
    append_u64(dst, &mut pos, hdr.context_switches_total);
    append_bytes(dst, &mut pos, b"\nbtime ");
    append_u64(dst, &mut pos, hdr.boot_time_ns / 1_000_000_000);
    append_bytes(dst, &mut pos, b"\nprocesses ");
    append_u64(dst, &mut pos, procs_total);
    append_bytes(dst, &mut pos, b"\nprocs_running ");
    append_u64(dst, &mut pos, procs_running);
    append_bytes(dst, &mut pos, b"\nprocs_blocked 0\n");
    let _ = last_pid;
    pos
}

fn read_root_meminfo(dst: &mut [u8]) -> usize {
    let mut info = trona_kernel::core_types::sysinfo::TronaSysMemInfo::zeroed();
    let _ = trona_kernel::syscall::sys_sysmeminfo(&raw mut info);
    let page_size = info.page_size.max(1);
    let total = info.pages_total * page_size;
    let free = info.pages_free * page_size;
    let cached = info.pages_page_cache * page_size;
    let dirty = info.pages_dirty_file * page_size;
    let writeback = info.pages_writeback_file * page_size;
    let active = info.pages_active * page_size;
    let inactive = info.pages_inactive * page_size;
    let anon = info.pages_anon_private * page_size;
    let shmem = info.pages_anon_shared * page_size;
    let mapped = info.pages_file * page_size;
    let slab = info.pages_kernel_slab * page_size;
    let page_tables = info.pages_kernel_pagetable * page_size;
    let kstack = info.pages_kernel_stack * page_size;
    let available = free
        .saturating_sub(info.pages_emergency_reserve * page_size)
        .saturating_add(cached);
    let mut pos = 0usize;
    append_line_kb(dst, &mut pos, b"MemTotal", total);
    append_line_kb(dst, &mut pos, b"MemFree", free);
    append_line_kb(dst, &mut pos, b"MemAvailable", available.min(total));
    append_line_kb(dst, &mut pos, b"Cached", cached);
    append_line_kb(dst, &mut pos, b"Active", active);
    append_line_kb(dst, &mut pos, b"Inactive", inactive);
    append_line_kb(dst, &mut pos, b"AnonPages", anon);
    append_line_kb(dst, &mut pos, b"Mapped", mapped);
    append_line_kb(dst, &mut pos, b"Shmem", shmem);
    append_line_kb(dst, &mut pos, b"Dirty", dirty);
    append_line_kb(dst, &mut pos, b"Writeback", writeback);
    append_line_kb(dst, &mut pos, b"Slab", slab);
    append_line_kb(dst, &mut pos, b"KernelStack", kstack);
    append_line_kb(dst, &mut pos, b"PageTables", page_tables);
    append_line_kb(dst, &mut pos, b"SwapTotal", 0);
    append_line_kb(dst, &mut pos, b"SwapFree", 0);
    pos
}

fn read_root_uptime(dst: &mut [u8]) -> usize {
    let mut hdr = TronaSysInfo::zeroed();
    let mut cpus = [TronaSysInfoCpu::zeroed(); 64];
    let _ = trona_kernel::syscall::sys_sysinfo(&raw mut hdr, cpus.as_mut_ptr(), cpus.len() as u64);
    let up_sec = hdr.uptime_ns / 1_000_000_000;
    let up_cs = ((hdr.uptime_ns % 1_000_000_000) / 10_000_000) as u32;
    let mut idle_ns = 0u64;
    let written = core::cmp::min(hdr.cpus_written as usize, cpus.len());
    for cpu in &cpus[..written] {
        idle_ns = idle_ns.saturating_add(cpu.idle_time_ns);
    }
    let idle_sec = idle_ns / 1_000_000_000;
    let idle_cs = ((idle_ns % 1_000_000_000) / 10_000_000) as u32;
    let mut pos = 0usize;
    append_u64(dst, &mut pos, up_sec);
    append_bytes(dst, &mut pos, b".");
    append_fixed_2(dst, &mut pos, up_cs.min(99));
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, idle_sec);
    append_bytes(dst, &mut pos, b".");
    append_fixed_2(dst, &mut pos, idle_cs.min(99));
    append_bytes(dst, &mut pos, b"\n");
    pos
}

fn read_root_cpuinfo(dst: &mut [u8]) -> usize {
    let mut hdr = TronaSysInfo::zeroed();
    let _ = trona_kernel::syscall::sys_sysinfo(&raw mut hdr, core::ptr::null_mut(), 0);
    let count = hdr.cpu_count.max(1);
    let mut pos = 0usize;
    for idx in 0..count {
        append_bytes(dst, &mut pos, b"processor\t: ");
        append_u32(dst, &mut pos, idx);
        append_bytes(dst, &mut pos, b"\nvendor_id\t: SaltyOS\nmodel name\t: SaltyOS Generic CPU\ncpu MHz\t\t: 0.000\ncache size\t: 0 KB\nphysical id\t: 0\nsiblings\t: ");
        append_u32(dst, &mut pos, count);
        append_bytes(dst, &mut pos, b"\ncore id\t\t: ");
        append_u32(dst, &mut pos, idx);
        append_bytes(dst, &mut pos, b"\ncpu cores\t: ");
        append_u32(dst, &mut pos, count);
        append_bytes(dst, &mut pos, b"\nflags\t\t:\n\n");
    }
    pos
}

fn read_root_loadavg(dst: &mut [u8]) -> usize {
    let (procs_total, procs_running, last_pid) =
        trona_runtime::pm_get_system_stats().unwrap_or((0, 0, 0));
    let mut pos = 0usize;
    append_bytes(dst, &mut pos, b"0.00 0.00 0.00 ");
    append_u64(dst, &mut pos, procs_running);
    append_bytes(dst, &mut pos, b"/");
    append_u64(dst, &mut pos, procs_total);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, last_pid);
    append_bytes(dst, &mut pos, b"\n");
    pos
}

fn read_root_version(dst: &mut [u8]) -> usize {
    let mut pos = 0usize;
    append_bytes(
        dst,
        &mut pos,
        b"SaltyOS version 0.1.0 (salty@salty) #1 SMP PREEMPT\n",
    );
    pos
}

fn read_root_mounts(state: &VfsState, dst: &mut [u8]) -> usize {
    let mut pos = 0usize;
    state.mounts.for_each_active(|_, mount| {
        let path_len = mount.mount_path_len as usize;
        let type_len = mount.fs_type_name_len as usize;
        if path_len == 0 || type_len == 0 {
            return true;
        }
        let fs_name = &mount.fs_type_name[..type_len];
        let mount_path = &mount.mount_path[..path_len];
        append_bytes(dst, &mut pos, fs_name);
        append_bytes(dst, &mut pos, b" ");
        append_bytes(dst, &mut pos, mount_path);
        append_bytes(dst, &mut pos, b" ");
        append_bytes(dst, &mut pos, fs_name);
        append_bytes(dst, &mut pos, b" rw 0 0\n");
        pos < dst.len()
    });
    pos
}

fn append_filesystem_line(dst: &mut [u8], pos: &mut usize, name: &[u8]) {
    append_bytes(dst, pos, b"nodev\t");
    append_bytes(dst, pos, name);
    append_bytes(dst, pos, b"\n");
}

fn read_root_filesystems(state: &VfsState, dst: &mut [u8]) -> usize {
    let mut pos = 0usize;
    const BASE: &[&[u8]] = &[
        b"bootfs",
        b"devfs",
        b"procfs",
        b"tmpfs",
        b"sysctlfs",
        b"pipefs",
    ];
    for name in BASE {
        append_filesystem_line(dst, &mut pos, name);
    }
    state.mounts.for_each_active(|_, mount| {
        let type_len = mount.fs_type_name_len as usize;
        if type_len == 0 {
            return true;
        }
        let fs_name = &mount.fs_type_name[..type_len];
        for base in BASE {
            if fs_name == *base {
                return true;
            }
        }
        append_filesystem_line(dst, &mut pos, fs_name);
        pos < dst.len()
    });
    pos
}

fn read_pid_status(pid: u32, dst: &mut [u8]) -> usize {
    let Some(kp) = proc_kinfo(pid) else {
        return 0;
    };
    let mut pos = 0usize;
    append_bytes(dst, &mut pos, b"Name:\t");
    let mut comm_len = 0usize;
    while comm_len < kp.comm.len() && kp.comm[comm_len] != 0 {
        comm_len += 1;
    }
    append_bytes(dst, &mut pos, &kp.comm[..comm_len]);
    append_bytes(dst, &mut pos, b"\nState:\t");
    append_bytes(dst, &mut pos, &[proc_state_char(kp.state), b'\n']);
    append_bytes(dst, &mut pos, b"Pid:\t");
    append_u32(dst, &mut pos, kp.pid);
    append_bytes(dst, &mut pos, b"\nPPid:\t");
    append_u32(dst, &mut pos, kp.ppid);
    append_bytes(dst, &mut pos, b"\nPgid:\t");
    append_u32(dst, &mut pos, kp.pgid);
    append_bytes(dst, &mut pos, b"\nSid:\t");
    append_u32(dst, &mut pos, kp.sid);
    append_bytes(dst, &mut pos, b"\nThreads:\t");
    append_u32(dst, &mut pos, kp.num_threads);
    append_bytes(dst, &mut pos, b"\nVmSize:\t");
    append_u64(dst, &mut pos, kp.vm_size / 1024);
    append_bytes(dst, &mut pos, b" kB\nVmRSS:\t");
    append_u64(dst, &mut pos, kp.vm_rss / 1024);
    append_bytes(dst, &mut pos, b" kB\n");
    pos
}

fn read_pid_stat(pid: u32, dst: &mut [u8]) -> usize {
    let Some(kp) = proc_kinfo(pid) else {
        return 0;
    };
    let (utime_ns, stime_ns, num_threads, _start_ns) = proc_times(pid);
    let mut pos = 0usize;
    append_u32(dst, &mut pos, kp.pid);
    append_bytes(dst, &mut pos, b" (");
    let mut comm_len = 0usize;
    while comm_len < KINFO_PROC_COMM_LEN && kp.comm[comm_len] != 0 {
        comm_len += 1;
    }
    append_bytes(dst, &mut pos, &kp.comm[..comm_len]);
    append_bytes(dst, &mut pos, b") ");
    append_bytes(dst, &mut pos, &[proc_state_char(kp.state)]);
    append_bytes(dst, &mut pos, b" ");
    append_u32(dst, &mut pos, kp.ppid);
    append_bytes(dst, &mut pos, b" ");
    append_u32(dst, &mut pos, kp.pgid);
    append_bytes(dst, &mut pos, b" ");
    append_u32(dst, &mut pos, kp.sid);
    append_bytes(dst, &mut pos, b" ");
    append_u32(dst, &mut pos, kp.tty_dev);
    append_bytes(dst, &mut pos, b" 0 0 0 0 0 ");
    append_u64(dst, &mut pos, utime_ns / 10_000_000);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, stime_ns / 10_000_000);
    append_bytes(dst, &mut pos, b" 0 0 20 0 ");
    append_u64(dst, &mut pos, num_threads);
    append_bytes(dst, &mut pos, b" 0 0 ");
    append_u64(dst, &mut pos, kp.start_time_ns / 10_000_000);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, kp.vm_size);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, kp.vm_rss / 4096);
    append_bytes(dst, &mut pos, b"\n");
    pos
}

fn read_pid_cmdline(pid: u32, dst: &mut [u8]) -> usize {
    trona_runtime::pm_get_argv(pid, dst).unwrap_or(0)
}

fn read_pid_comm(pid: u32, dst: &mut [u8]) -> usize {
    let Some(kp) = proc_kinfo(pid) else {
        return 0;
    };
    let mut comm_len = 0usize;
    while comm_len < kp.comm.len() && kp.comm[comm_len] != 0 {
        comm_len += 1;
    }
    let copy = core::cmp::min(comm_len, dst.len().saturating_sub(1));
    if copy != 0 {
        dst[..copy].copy_from_slice(&kp.comm[..copy]);
    }
    if copy < dst.len() {
        dst[copy] = b'\n';
        copy + 1
    } else {
        copy
    }
}

fn read_pid_statm(pid: u32, dst: &mut [u8]) -> usize {
    let snap = proc_mem_snapshot(pid);
    let mut pos = 0usize;
    append_u64(dst, &mut pos, snap.vm_reserved_bytes / 4096);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_resident_pages);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.resident_file);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_exe_bytes / 4096);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_lib_bytes / 4096);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_data_bytes / 4096);
    append_bytes(dst, &mut pos, b" 0\n");
    pos
}

fn read_proc_node(
    state: &VfsState,
    cli_handle: ClientHandle,
    node: &ProcNodeState,
    dst: &mut [u8],
) -> usize {
    match node.kind {
        ProcNodeKind::RootStat => read_root_stat(dst),
        ProcNodeKind::RootMeminfo => read_root_meminfo(dst),
        ProcNodeKind::RootUptime => read_root_uptime(dst),
        ProcNodeKind::RootCpuinfo => read_root_cpuinfo(dst),
        ProcNodeKind::RootLoadavg => read_root_loadavg(dst),
        ProcNodeKind::RootVersion => read_root_version(dst),
        ProcNodeKind::RootMounts => read_root_mounts(state, dst),
        ProcNodeKind::RootFilesystems => read_root_filesystems(state, dst),
        ProcNodeKind::PidStatus => read_pid_status(node.pid, dst),
        ProcNodeKind::PidStat => read_pid_stat(node.pid, dst),
        ProcNodeKind::PidCmdline => read_pid_cmdline(node.pid, dst),
        ProcNodeKind::PidComm => read_pid_comm(node.pid, dst),
        ProcNodeKind::PidStatm => read_pid_statm(node.pid, dst),
        ProcNodeKind::SelfLink => {
            let pid = current_pid(state, cli_handle);
            let mut pos = 0usize;
            append_u32(dst, &mut pos, pid);
            pos
        }
        _ => 0,
    }
}

fn register_node(
    state: &mut VfsState,
    vnode: VnodeHandle,
    owner_mount: MountHandle,
    kind: ProcNodeKind,
    pid: u32,
    ephemeral: bool,
) -> bool {
    let Some(handle) = state.proc_nodes.alloc() else {
        return false;
    };
    let Some(node) = state.proc_nodes.get_mut(handle) else {
        return false;
    };
    *node = ProcNodeState::zeroed();
    node.vnode = vnode;
    node.owner_mount = owner_mount;
    node.kind = kind;
    node.pid = pid;
    node.ephemeral = if ephemeral { 1 } else { 0 };
    if let Some(vnode_ref) = state.vnodes.get_mut(vnode) {
        vnode_ref.set_backend_ref(handle);
    }
    true
}

fn proc_root_static_mode(kind: ProcNodeKind) -> (u8, u32, u64) {
    match kind {
        ProcNodeKind::SelfLink => (VT_LNK, (S_IFLNK as u32) | 0o777, 16),
        ProcNodeKind::RootStat => (VT_REG, (S_IFREG as u32) | 0o444, 1024),
        ProcNodeKind::RootMeminfo => (VT_REG, (S_IFREG as u32) | 0o444, 1024),
        ProcNodeKind::RootUptime => (VT_REG, (S_IFREG as u32) | 0o444, 64),
        ProcNodeKind::RootCpuinfo => (VT_REG, (S_IFREG as u32) | 0o444, 2048),
        ProcNodeKind::RootLoadavg => (VT_REG, (S_IFREG as u32) | 0o444, 64),
        ProcNodeKind::RootVersion => (VT_REG, (S_IFREG as u32) | 0o444, 128),
        ProcNodeKind::RootMounts => (VT_REG, (S_IFREG as u32) | 0o444, 1024),
        ProcNodeKind::RootFilesystems => (VT_REG, (S_IFREG as u32) | 0o444, 512),
        _ => (VT_REG, (S_IFREG as u32) | 0o444, 0),
    }
}

fn ensure_dynamic_vnode(
    state: &mut VfsState,
    owner_mount: MountHandle,
    kind: ProcNodeKind,
    pid: u32,
) -> Option<VnodeHandle> {
    if pid != 0 && !proc_pid_exists(pid) {
        return None;
    }
    if let Some(existing) = find_node_handle_by_key_mut(state, owner_mount, kind, pid) {
        let vnode = state.proc_nodes.get(existing)?.vnode;
        if pid == 0 || proc_pid_exists(pid) || matches!(kind, ProcNodeKind::PidExe) {
            return Some(vnode);
        }
        if state
            .vnodes
            .get(vnode)
            .map(|vn| vn.open_count == 0)
            .unwrap_or(false)
        {
            state.reclaim_bootstrap_vnode(vnode);
        }
    }

    let (fs_id, root_vnode) = {
        let mount = state.mounts.get(owner_mount)?;
        (mount.fs_instance_id, mount.root_vnode)
    };
    let vh = state.vnodes.alloc()?;
    let (vtype, mode, size) = match kind {
        ProcNodeKind::PidDir => (VT_DIR, (S_IFDIR as u32) | 0o555, 0),
        ProcNodeKind::PidExe => (VT_LNK, (S_IFLNK as u32) | 0o777, 64),
        ProcNodeKind::PidStatus
        | ProcNodeKind::PidStat
        | ProcNodeKind::PidCmdline
        | ProcNodeKind::PidComm
        | ProcNodeKind::PidStatm => (VT_REG, (S_IFREG as u32) | 0o444, 1024),
        _ => return None,
    };
    {
        let vnode = state.vnodes.get_mut(vh)?;
        *vnode = match vtype {
            VT_DIR => Vnode::new_bootstrap_dir(fs_id, owner_mount),
            VT_LNK => Vnode::new_bootstrap_symlink(fs_id, owner_mount, mode),
            _ => Vnode::new_bootstrap_file(fs_id, owner_mount, mode),
        };
        vnode.backend_kind = VNODE_BACKEND_PROCFS;
        vnode.mode = mode;
        vnode.id = proc_inode(kind, pid);
        vnode.size = size;
        vnode.mount = CachedRef::new(fs_id, owner_mount);
        vnode.ops = procfs_vops();
        vnode.nlink = 1;
    }
    state.cache_vnode_key(vh);
    if !register_node(state, vh, owner_mount, kind, pid, true) {
        state.uncache_vnode_key(vh);
        let _ = state.vnodes.release(vh);
        return None;
    }
    if let Some(root) = state.vnodes.get_mut(root_vnode) {
        root.nlink = root.nlink.max(1);
    }
    Some(vh)
}

fn trim_proc_prefix<'a>(path: &'a [u8]) -> Option<&'a [u8]> {
    if path == b"/proc" {
        return Some(b"");
    }
    path.strip_prefix(b"/proc/")
}

fn split_one(path: &[u8]) -> (&[u8], &[u8]) {
    for (idx, ch) in path.iter().enumerate() {
        if *ch == b'/' {
            return (&path[..idx], &path[idx + 1..]);
        }
    }
    (path, b"")
}

fn parse_pid_component(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut pid = 0u32;
    for &ch in bytes {
        if !ch.is_ascii_digit() {
            return None;
        }
        pid = pid.checked_mul(10)?.checked_add((ch - b'0') as u32)?;
    }
    Some(pid)
}

fn parse_procfs_hidepid(opts: &[u8]) -> Option<u8> {
    let mut value = None;
    crate::vfs_core::mount_options::for_each_token(opts, |token| {
        if let Some((key, val)) = crate::vfs_core::mount_options::split_kv(token) {
            if key == b"hidepid" && val.len() == 1 {
                if let b'0'..=b'2' = val[0] {
                    value = Some(val[0] - b'0');
                }
            }
        }
    });
    value
}

/// `VfsOps::remount` callback. The only mutable option procfs honors
/// today is `hidepid=`; everything else ignored to match Linux's
/// "unknown opts are silently dropped" behavior on remount.
fn procfs_remount(state: &mut VfsState, mount: MountHandle, _new_flags: u32, opts: &[u8]) -> u64 {
    let Some(handle) = find_mount_data_handle(state, mount) else {
        return TRONA_INVALID_OPERATION;
    };
    if let Some(value) = parse_procfs_hidepid(opts) {
        if let Some(data) = state.procfs_mounts.get_mut(handle) {
            data.hidepid = value;
        }
    }
    TRONA_OK
}

pub(crate) fn alloc_mount(
    state: &mut VfsState,
    mount_path: &[u8],
    flags: u32,
    opts: &[u8],
) -> Option<MountHandle> {
    let hidepid = parse_procfs_hidepid(opts).unwrap_or(0);
    let root_vh = state.vnodes.alloc()?;
    let mh = state.mounts.alloc()?;
    let data_h = state.procfs_mounts.alloc()?;
    let fs_id = state.alloc_fs_instance_id();

    {
        let vnode = state.vnodes.get_mut(root_vh)?;
        *vnode = Vnode::new_mounted_root_dir(fs_id);
        vnode.backend_kind = VNODE_BACKEND_PROCFS;
        vnode.id = 1;
        vnode.ops = procfs_vops();
    }
    state.cache_vnode_key(root_vh);

    {
        let mount = state.mounts.get_mut(mh)?;
        *mount = Mount::new_structural(
            (mh.slot().saturating_add(1)) as u16,
            flags,
            fs_id,
            root_vh,
            b"procfs",
            mount_path,
        );
        mount.backend_kind = MOUNT_BACKEND_PROCFS;
        mount.vfsops = procfs_vfsops();
        mount.vops = procfs_vops();
    }

    let data_ptr = {
        let data = state.procfs_mounts.get_mut(data_h)?;
        *data = ProcfsMountData {
            owner_mount: mh,
            fs_instance_id: fs_id,
            root_vnode: root_vh,
            hidepid,
            _pad0: [0; 7],
        };
        data as *mut ProcfsMountData as *mut u8
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
    let mut nodes = [ProcNodeHandle::INVALID; 128];
    let mut count = 0usize;
    state.proc_nodes.for_each_active(|handle, node| {
        if node.owner_mount == owner_mount && count < nodes.len() {
            nodes[count] = handle;
            count += 1;
        }
        true
    });
    for handle in nodes.into_iter().take(count) {
        if let Some(node) = state.proc_nodes.get(handle) {
            if let Some(vnode) = state.vnodes.get_mut(node.vnode) {
                vnode.clear_backend_ref();
            }
        }
        if let Some(node) = state.proc_nodes.get(handle) {
            state.uncache_vnode_key(node.vnode);
        }
        let _ = state.proc_nodes.release(handle);
    }
    let Some(data_h) = find_mount_data_handle(state, owner_mount) else {
        return true;
    };
    state.procfs_mounts.release(data_h)
}

pub(crate) fn release_node_for_vnode(state: &mut VfsState, vnode: VnodeHandle) {
    if let Some(vnode_ref) = state.vnodes.get_mut(vnode) {
        vnode_ref.clear_backend_ref();
    }
    state.uncache_vnode_key(vnode);
    if let Some(handle) = find_node_handle_by_vnode_mut(state, vnode) {
        let _ = state.proc_nodes.release(handle);
    }
}

pub(crate) fn node_is_ephemeral(state: &VfsState, vnode: VnodeHandle) -> bool {
    find_node_handle_by_vnode(state, vnode)
        .and_then(|handle| state.proc_nodes.get(handle))
        .map(|node| node.ephemeral != 0)
        .unwrap_or(false)
}

pub(crate) fn populate_bootstrap_tree(state: &mut VfsState) -> bool {
    let Some(owner_mount) = proc_root_mount(state) else {
        return false;
    };
    let static_nodes = [
        (b"/proc/self".as_slice(), ProcNodeKind::SelfLink),
        (b"/proc/stat".as_slice(), ProcNodeKind::RootStat),
        (b"/proc/meminfo".as_slice(), ProcNodeKind::RootMeminfo),
        (b"/proc/uptime".as_slice(), ProcNodeKind::RootUptime),
        (b"/proc/cpuinfo".as_slice(), ProcNodeKind::RootCpuinfo),
        (b"/proc/loadavg".as_slice(), ProcNodeKind::RootLoadavg),
        (b"/proc/version".as_slice(), ProcNodeKind::RootVersion),
        (b"/proc/mounts".as_slice(), ProcNodeKind::RootMounts),
        (
            b"/proc/filesystems".as_slice(),
            ProcNodeKind::RootFilesystems,
        ),
    ];

    for (path, kind) in static_nodes {
        let vnode = match kind {
            ProcNodeKind::SelfLink => {
                state.bootstrap_create_symlink_path(path, (S_IFLNK as u32) | 0o777, b"0")
            }
            _ => state.bootstrap_create_regular_file_path(path, (S_IFREG as u32) | 0o444),
        };
        let Ok(vh) = vnode else {
            return false;
        };
        let (_, mode, size) = proc_root_static_mode(kind);
        if let Some(vnode) = state.vnodes.get_mut(vh) {
            vnode.backend_kind = VNODE_BACKEND_PROCFS;
            vnode.id = proc_inode(kind, 0);
            vnode.mode = mode;
            vnode.size = size;
            vnode.ops = procfs_vops();
        }
        if !register_node(state, vh, owner_mount, kind, 0, false) {
            return false;
        }
    }

    state
        .bootstrap_create_symlink_path(b"/proc/sys", (S_IFLNK as u32) | 0o777, b"/sys")
        .is_ok()
}

pub(crate) fn lookup_dynamic_path(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    path: &[u8],
    no_follow: bool,
) -> Option<VnodeHandle> {
    let rest = trim_proc_prefix(path)?;
    if rest.is_empty() {
        return proc_root_vnode(state);
    }
    let Some(owner_mount) = proc_root_mount(state) else {
        return None;
    };
    let personality = state.client_personality(cli_handle);
    let hidepid = mount_data_for_mount(state, owner_mount)
        .map(|md| md.hidepid)
        .unwrap_or(0);
    let caller_pid = current_pid(state, cli_handle);
    let (head, tail) = split_one(rest);
    if head == b"self" {
        let pid = caller_pid;
        if tail.is_empty() {
            if no_follow {
                return proc_root_child(state, b"self");
            }
            return ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidDir, pid);
        }
        if tail == b"exe" && !no_follow {
            let mut exe = [0u8; 512];
            let exe_len = proc_exe_path(pid, &mut exe)?;
            return state.bootstrap_lookup_path_for_personality(
                &exe[..exe_len],
                false,
                personality,
            );
        }
        let mut rewritten = [0u8; 80];
        let mut pos = 0usize;
        append_bytes(&mut rewritten, &mut pos, b"/proc/");
        append_u32(&mut rewritten, &mut pos, pid);
        append_bytes(&mut rewritten, &mut pos, b"/");
        append_bytes(&mut rewritten, &mut pos, tail);
        return lookup_dynamic_path(state, cli_handle, &rewritten[..pos], no_follow);
    }

    let pid = parse_pid_component(head)?;
    // hidepid >= 1 hides every PID directory other than the caller's
    // own session. The full Linux model also keys off the directory's
    // owning UID; until procmgr exposes that we use "self pid only"
    // as the fail-closed approximation. /proc/self stays accessible
    // because it rewrote into /proc/<caller_pid>/... above.
    if hidepid >= 1 && pid != caller_pid {
        return None;
    }
    if tail.is_empty() {
        return ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidDir, pid);
    }
    match tail {
        b"stat" => ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidStat, pid),
        b"status" => ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidStatus, pid),
        b"cmdline" => ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidCmdline, pid),
        b"comm" => ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidComm, pid),
        b"statm" => ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidStatm, pid),
        b"exe" => {
            if !no_follow {
                let mut exe = [0u8; 512];
                let exe_len = proc_exe_path(pid, &mut exe)?;
                state.bootstrap_lookup_path_for_personality(&exe[..exe_len], false, personality)
            } else {
                ensure_dynamic_vnode(state, owner_mount, ProcNodeKind::PidExe, pid)
            }
        }
        _ => None,
    }
}

pub(crate) fn read_regular(
    state: &VfsState,
    cli_handle: ClientHandle,
    vnode: VnodeHandle,
    offset: u64,
    out: *mut u8,
    cap: usize,
) -> Option<usize> {
    let handle = find_node_handle_by_vnode(state, vnode)?;
    let node = state.proc_nodes.get(handle)?;
    let mut content = [0u8; 4096];
    let len = read_proc_node(state, cli_handle, node, &mut content);
    let start = core::cmp::min(offset as usize, len);
    let actual = core::cmp::min(cap, len.saturating_sub(start));
    if actual != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(content[start..].as_ptr(), out, actual);
        }
    }
    Some(actual)
}

unsafe fn read_regular_vop(
    state: &VfsState,
    cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    offset: u64,
    out: *mut u8,
    cap: usize,
) -> crate::vfs_core::vops::VfsResult<usize> {
    let Some(cli_handle) = cli_handle else {
        return Err(TRONA_NOT_SUPPORTED);
    };
    match read_regular(state, cli_handle, vnode, offset, out, cap) {
        Some(n) => Ok(crate::vfs_core::vops::VfsOpResult::Complete(n)),
        None => Err(TRONA_NOT_SUPPORTED),
    }
}

unsafe fn write_regular_vop(
    _state: &mut VfsState,
    _vnode: VnodeHandle,
    _offset: u64,
    _src: *const u8,
    _len: usize,
) -> crate::vfs_core::vops::VfsResult<u64> {
    Err(TRONA_INVALID_OPERATION)
}

fn validate_open_regular_vop(_state: &VfsState, _vnode: VnodeHandle, flags: u32) -> u64 {
    let accmode = flags & trona_posix::consts::O_ACCMODE;
    if accmode != trona_posix::consts::O_RDONLY
        || (flags
            & (trona_posix::consts::O_CREAT
                | trona_posix::consts::O_TRUNC
                | trona_posix::consts::O_APPEND))
            != 0
    {
        return TRONA_INVALID_OPERATION;
    }
    TRONA_OK
}

fn readlink_inline_vop(
    state: &VfsState,
    cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    out: *mut u8,
    cap: usize,
) -> crate::vfs_core::vops::VfsResult<usize> {
    let Some(cli_handle) = cli_handle else {
        return Err(TRONA_NOT_SUPPORTED);
    };
    match readlink_target(state, cli_handle, vnode, out, cap) {
        Some(n) => Ok(crate::vfs_core::vops::VfsOpResult::Complete(n)),
        None => Err(TRONA_NOT_SUPPORTED),
    }
}

fn readdir_dir_vop(
    state: &VfsState,
    cli_handle: Option<ClientHandle>,
    vnode: VnodeHandle,
    cursor: u64,
    _ignore_case: bool,
    name_out: &mut [u8; 128],
) -> crate::vfs_core::vops::ReaddirResult {
    let Some(cli_handle) = cli_handle else {
        return Err(TRONA_NOT_SUPPORTED);
    };
    match readdir_entry(state, cli_handle, vnode, cursor, name_out) {
        Some(entry) => Ok(crate::vfs_core::vops::VfsOpResult::Complete(entry)),
        None => Err(TRONA_NOT_SUPPORTED),
    }
}

fn deny_pager_backing_vop(_state: &VfsState, _vnode: VnodeHandle) -> bool {
    false
}

pub(crate) fn readlink_target(
    state: &VfsState,
    cli_handle: ClientHandle,
    vnode: VnodeHandle,
    out: *mut u8,
    cap: usize,
) -> Option<usize> {
    let handle = find_node_handle_by_vnode(state, vnode)?;
    let node = state.proc_nodes.get(handle)?;
    let mut content = [0u8; 512];
    let len = match node.kind {
        ProcNodeKind::SelfLink => {
            let mut pos = 0usize;
            append_u32(&mut content, &mut pos, current_pid(state, cli_handle));
            pos
        }
        ProcNodeKind::PidExe => proc_exe_path(node.pid, &mut content)?,
        _ => return None,
    };
    let actual = core::cmp::min(cap, len);
    if actual != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(content.as_ptr(), out, actual);
        }
    }
    Some(actual)
}

pub(crate) fn readdir_entry(
    state: &VfsState,
    _cli_handle: ClientHandle,
    dir_vh: VnodeHandle,
    cursor: u64,
    name_out: &mut [u8; 128],
) -> Option<Option<crate::vfs_core::vops::ReaddirEntry>> {
    let Some(dir_vnode) = state.vnodes.get(dir_vh) else {
        return None;
    };
    let Some(dir_mount) = state.mounts.get(dir_vnode.mount.handle) else {
        return None;
    };
    if !mount_is_procfs(dir_mount) {
        return None;
    }

    let maybe_node =
        find_node_handle_by_vnode(state, dir_vh).and_then(|handle| state.proc_nodes.get(handle));
    if cursor == 0 {
        return Some(Some(crate::vfs_core::vops::ReaddirEntry {
            next_cursor: 1,
            eof_after: false,
            name_len: 1,
            ino: dir_vnode.id,
            d_type: DT_DIR,
        }));
    }
    if cursor == 1 {
        let parent_ino = if let Some(node) = maybe_node {
            if matches!(node.kind, ProcNodeKind::PidDir) {
                proc_root_id(state)
            } else {
                dir_vnode.id
            }
        } else {
            dir_vnode.id
        };
        name_out[0] = b'.';
        name_out[1] = b'.';
        return Some(Some(crate::vfs_core::vops::ReaddirEntry {
            next_cursor: 2,
            eof_after: false,
            name_len: 2,
            ino: parent_ino,
            d_type: DT_DIR,
        }));
    }

    if maybe_node.is_none() {
        let want = (cursor - 2) as usize;
        if want < ROOT_NAMES.len() {
            let (name, kind, dtype) = ROOT_NAMES[want];
            let vnode = proc_root_child(state, name);
            let ino = vnode
                .and_then(|vh| state.vnodes.get(vh).map(|vn| vn.id))
                .unwrap_or(proc_inode(kind, 0));
            name_out[..name.len()].copy_from_slice(name);
            return Some(Some(crate::vfs_core::vops::ReaddirEntry {
                next_cursor: cursor + 1,
                eof_after: false,
                name_len: name.len() as u8,
                ino,
                d_type: dtype,
            }));
        }
        // hidepid >= 1: enumerate no PID directories in the root
        // listing. Direct `/proc/<pid>` lookups still resolve, which
        // matches Linux semantics under hidepid=1 — only enumeration
        // is suppressed. Per-uid filtering would also need procmgr to
        // expose the owning uid per pid; that wiring is not in place
        // yet.
        let hidepid = mount_data_for_vnode(state, dir_vh)
            .map(|md| md.hidepid)
            .unwrap_or(0);
        if hidepid >= 1 {
            return Some(None);
        }
        let pid_index = want.saturating_sub(ROOT_NAMES.len());
        let mut pids = [0u32; 1];
        let Some((count, _total)) = trona_runtime::pm_list_pids_buf(pid_index, &mut pids) else {
            return Some(None);
        };
        if count == 0 {
            return Some(None);
        }
        let pid = pids[0];
        let mut len = 0usize;
        append_u32(name_out, &mut len, pid);
        return Some(Some(crate::vfs_core::vops::ReaddirEntry {
            next_cursor: cursor + 1,
            eof_after: false,
            name_len: len as u8,
            ino: proc_inode(ProcNodeKind::PidDir, pid),
            d_type: DT_DIR,
        }));
    }

    let node = maybe_node?;
    if !matches!(node.kind, ProcNodeKind::PidDir) {
        return Some(None);
    }
    let want = (cursor - 2) as usize;
    if want >= PID_NAMES.len() {
        return Some(None);
    }
    let (name, kind, dtype) = PID_NAMES[want];
    name_out[..name.len()].copy_from_slice(name);
    Some(Some(crate::vfs_core::vops::ReaddirEntry {
        next_cursor: cursor + 1,
        eof_after: false,
        name_len: name.len() as u8,
        ino: proc_inode(kind, node.pid),
        d_type: dtype,
    }))
}

// =========================================================================
// Backend-RPC deferred dispatch
// =========================================================================
//
// procfs read/readlink/readdir paths that need backend RPC (init's
// KinfoProc / VmStats / argv / exe path / pid list) are routed through
// the worker pool here so the owner thread never blocks on init inside
// dispatch. The owner-side state-commit closes the loop by formatting
// the final reply text and sending it via `send_saved_reply`.

use crate::owner::backend_rpc;
use crate::owner::pending_ops::{
    self, PO_KIND_PROCFS_PID_STAT, PO_KIND_PROCFS_READ, PO_KIND_PROCFS_READDIR,
    PO_KIND_PROCFS_READLINK, PendingOpId,
};

#[inline]
fn pack_vnode_handle(h: VnodeHandle) -> u64 {
    ((h.epoch() as u64) << 32) | (h.slot() as u64)
}

#[inline]
fn unpack_vnode_handle(v: u64) -> VnodeHandle {
    Handle::<Vnode>::new(v as u32, (v >> 32) as u32)
}

/// True when this `ProcNodeKind`'s read content needs a backend RPC to
/// `init` and must be deferred to a worker. Pure-state kinds
/// (`RootMeminfo`/`RootUptime`/`RootCpuinfo`/`RootVersion`/`RootMounts`/
/// `RootFilesystems`/`SelfLink`) stay synchronous — they only call
/// `sys_sysinfo`/`sys_sysmeminfo` which are pure syscalls or read
/// `state.mounts` directly.
pub(crate) fn proc_read_needs_deferred(kind: ProcNodeKind) -> bool {
    matches!(
        kind,
        ProcNodeKind::PidStatus
            | ProcNodeKind::PidStat
            | ProcNodeKind::PidStatm
            | ProcNodeKind::PidCmdline
            | ProcNodeKind::PidComm
            | ProcNodeKind::RootStat
            | ProcNodeKind::RootLoadavg
    )
}

/// Look up `(ProcNodeKind, pid)` for a procfs-backed vnode. Returns
/// None if the vnode has been recycled or the proc node entry is gone.
pub(crate) fn proc_read_kind(state: &VfsState, vnode: VnodeHandle) -> Option<(ProcNodeKind, u32)> {
    let handle = find_node_handle_by_vnode(state, vnode)?;
    let node = state.proc_nodes.get(handle)?;
    Some((node.kind, node.pid))
}

/// Owner-side: enqueue a deferred read for a procfs node. Returns
/// false if the job ring is full so the caller can fall back to the
/// inline synchronous path. The caller must already have the `reply`
/// pointer ready — on success this writes
/// `(*reply).label = REPLY_DEFERRED_LABEL` and saves the caller's
/// reply cap into a slot tracked by the completion handler.
pub(crate) unsafe fn defer_procfs_read(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    vnode: VnodeHandle,
    offset: u64,
    want_count: u64,
    kind: ProcNodeKind,
    pid: u32,
    is_pread: bool,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let Some(reply_slot) = crate::fileops::tty_wait::save_current_caller(reply) else {
            return true;
        };

        let kinfo_size = core::mem::size_of::<KinfoProc>() as u32;
        let snap_size = core::mem::size_of::<TronaProcMemSnapshot>() as u32;

        let (op_kind, label, payload_bytes): (u32, u64, u32) = match kind {
            ProcNodeKind::PidStatus => (
                backend_rpc::BACKEND_OP_PROCFS_READ_PID_STATUS,
                trona_protocol::init::INIT_GET_KINFO_PROC,
                kinfo_size,
            ),
            ProcNodeKind::PidComm => (
                backend_rpc::BACKEND_OP_PROCFS_READ_PID_COMM,
                trona_protocol::init::INIT_GET_KINFO_PROC,
                kinfo_size,
            ),
            ProcNodeKind::PidStat => (
                backend_rpc::BACKEND_OP_PROCFS_READ_PID_STAT_STAGE0,
                trona_protocol::init::INIT_GET_KINFO_PROC,
                kinfo_size,
            ),
            ProcNodeKind::PidStatm => (
                backend_rpc::BACKEND_OP_PROCFS_READ_PID_STATM,
                trona_protocol::init::INIT_GET_CLIENT_VM_STATS,
                snap_size,
            ),
            ProcNodeKind::PidCmdline => (
                backend_rpc::BACKEND_OP_PROCFS_READ_PID_CMDLINE,
                trona_protocol::init::INIT_GET_ARGV,
                backend_rpc::BACKEND_PAYLOAD_MAX as u32,
            ),
            ProcNodeKind::RootStat => (
                backend_rpc::BACKEND_OP_PROCFS_READ_ROOT_STAT,
                trona_protocol::init::INIT_GET_SYSTEM_STATS,
                0,
            ),
            ProcNodeKind::RootLoadavg => (
                backend_rpc::BACKEND_OP_PROCFS_READ_ROOT_LOADAVG,
                trona_protocol::init::INIT_GET_SYSTEM_STATS,
                0,
            ),
            _ => {
                crate::fileops::tty_wait::release_reply_slot(reply_slot);
                return false;
            }
        };

        let mut req = TronaMsg::zeroed();
        req.label = label;
        // INIT_GET_SYSTEM_STATS takes no parameters; the per-pid
        // requests carry the pid in regs[0].
        if matches!(kind, ProcNodeKind::RootStat | ProcNodeKind::RootLoadavg) {
            req.length = 0;
        } else {
            req.length = 1;
            req.regs[0] = pid as u64;
        }

        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
        let po_kind = if matches!(kind, ProcNodeKind::PidStat) {
            PO_KIND_PROCFS_PID_STAT
        } else {
            PO_KIND_PROCFS_READ
        };
        let Some(op_id) = pending_ops::alloc(po_kind, badge, cli_handle, reply_slot) else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return false;
        };

        let mut ctx = backend_rpc::BackendOpCtx::zeroed();
        ctx.badge = badge;
        ctx.client_handle_raw = crate::owner::dispatch::pack_client_handle(cli_handle);
        ctx.stage = 0;
        ctx.data[0] = (kind as u8 as u64) | ((fd as u32 as u64) << 32);
        ctx.data[1] = pack_vnode_handle(vnode);
        ctx.data[2] = offset;
        ctx.data[3] = want_count;
        ctx.data[4] = pid as u64;
        ctx.data[5] = if is_pread { 1 } else { 0 };

        let job = backend_rpc::PendingBackendJob {
            target_ep: trona_runtime::client::caps::init_ep(),
            op_kind,
            payload_out_bytes: payload_bytes,
            op_id: op_id.raw(),
            request: req,
            ctx,
        };

        if !backend_rpc::try_enqueue_job(job) {
            let recovered = pending_ops::take_reply_slot(op_id);
            pending_ops::free(op_id);
            crate::fileops::tty_wait::release_reply_slot(recovered);
            return false;
        }
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

/// Owner-side completion handler. Returns true if the completion was
/// for a procfs read op_kind; false if the op_kind is unrelated.
pub(crate) unsafe fn complete_procfs_read(
    state: &mut VfsState,
    completion: &backend_rpc::PendingBackendCompletion,
) -> bool {
    unsafe {
        let op_id = PendingOpId::from_raw(completion.op_id);
        let Some(op) = pending_ops::get(op_id) else {
            return false;
        };
        if op.kind != PO_KIND_PROCFS_READ && op.kind != PO_KIND_PROCFS_PID_STAT {
            return false;
        }
        let cli_handle =
            crate::owner::dispatch::unpack_client_handle(completion.ctx.client_handle_raw);
        let kind_disc = completion.ctx.data[0] as u8;
        let fd = (completion.ctx.data[0] >> 32) as i32;
        let saved_vnode = unpack_vnode_handle(completion.ctx.data[1]);
        let offset = completion.ctx.data[2];
        let want_count = completion.ctx.data[3];
        let pid = completion.ctx.data[4] as u32;
        let is_pread = completion.ctx.data[5] != 0;
        let _ = kind_disc;

        // Discard the completion when the fd has been closed, the
        // client has exited, or the open file now points at a
        // different vnode (close + reopen race).
        if completion.op_kind != backend_rpc::BACKEND_OP_PROCFS_READ_PID_STAT_STAGE0
            && !validate_pending_fd_vnode(state, cli_handle, fd, saved_vnode)
        {
            // Drop the saved reply cap silently — the requesting fd is
            // gone, so there is no caller to reply to.
            let slot = pending_ops::take_reply_and_free(op_id);
            crate::fileops::tty_wait::release_reply_slot(slot);
            return true;
        }

        let mut content = [0u8; 4096];
        let content_len = match completion.op_kind {
            backend_rpc::BACKEND_OP_PROCFS_READ_PID_STATUS => {
                if !backend_ok_kinfo(completion) {
                    fail_procfs_op(op_id);
                    return true;
                }
                let kp = *(completion.payload.as_ptr() as *const KinfoProc);
                format_pid_status_from_kinfo(&kp, &mut content)
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_PID_COMM => {
                if !backend_ok_kinfo(completion) {
                    fail_procfs_op(op_id);
                    return true;
                }
                let kp = *(completion.payload.as_ptr() as *const KinfoProc);
                format_pid_comm_from_kinfo(&kp, &mut content)
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_PID_STATM => {
                if !backend_ok_snap(completion) {
                    fail_procfs_op(op_id);
                    return true;
                }
                let snap = *(completion.payload.as_ptr() as *const TronaProcMemSnapshot);
                format_pid_statm_from_snap(&snap, &mut content)
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_PID_CMDLINE => {
                if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
                    fail_procfs_op(op_id);
                    return true;
                }
                let argv_len = completion.backend_reply.regs[0] as usize;
                let copy = argv_len
                    .min(completion.payload_len as usize)
                    .min(content.len());
                content[..copy].copy_from_slice(&completion.payload[..copy]);
                copy
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_PID_STAT_STAGE0 => {
                handle_pid_stat_stage0(op_id, completion);
                return true;
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_PID_STAT_STAGE1 => {
                let _ = pid;
                handle_pid_stat_stage1(op_id, completion, &mut content)
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_ROOT_STAT => {
                if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
                    fail_procfs_op(op_id);
                    return true;
                }
                let procs_total = completion.backend_reply.regs[0];
                let procs_running = completion.backend_reply.regs[1];
                let last_pid = completion.backend_reply.regs[2];
                format_root_stat(procs_total, procs_running, last_pid, &mut content)
            }
            backend_rpc::BACKEND_OP_PROCFS_READ_ROOT_LOADAVG => {
                if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
                    fail_procfs_op(op_id);
                    return true;
                }
                let procs_total = completion.backend_reply.regs[0];
                let procs_running = completion.backend_reply.regs[1];
                let last_pid = completion.backend_reply.regs[2];
                format_root_loadavg(procs_total, procs_running, last_pid, &mut content)
            }
            _ => return false,
        };

        let reply_slot = pending_ops::take_reply_and_free(op_id);
        send_procfs_read_reply(
            state,
            cli_handle,
            fd,
            is_pread,
            offset,
            want_count,
            &content,
            content_len,
            reply_slot,
        );
        true
    }
}

unsafe fn fail_procfs_op(op_id: PendingOpId) {
    unsafe {
        let slot = pending_ops::take_reply_and_free(op_id);
        send_procfs_failure(slot);
    }
}

#[inline]
fn backend_ok_kinfo(completion: &backend_rpc::PendingBackendCompletion) -> bool {
    completion.backend_err == 0
        && completion.backend_reply.label == TRONA_OK
        && (completion.payload_len as usize) >= core::mem::size_of::<KinfoProc>()
}

#[inline]
fn backend_ok_snap(completion: &backend_rpc::PendingBackendCompletion) -> bool {
    completion.backend_err == 0
        && completion.backend_reply.label == TRONA_OK
        && (completion.payload_len as usize) >= core::mem::size_of::<TronaProcMemSnapshot>()
}

unsafe fn send_procfs_failure(reply_slot: u64) {
    unsafe {
        let mut reply = TronaMsg::zeroed();
        reply.label = TRONA_INVALID_OPERATION;
        crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
    }
}

unsafe fn send_procfs_read_reply(
    state: &mut VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    is_pread: bool,
    offset: u64,
    want_count: u64,
    content: &[u8],
    content_len: usize,
    reply_slot: u64,
) {
    unsafe {
        const INLINE_READ_MAX: usize = 152;
        let start = (offset as usize).min(content_len);
        let actual = (want_count as usize)
            .min(INLINE_READ_MAX)
            .min(content_len.saturating_sub(start));

        let mut reply = TronaMsg::zeroed();
        reply.label = TRONA_OK;
        reply.regs[0] = actual as u64;
        if actual != 0 {
            let dst = &raw mut reply.regs[1] as *mut u8;
            core::ptr::copy_nonoverlapping(content[start..].as_ptr(), dst, actual);
        }
        reply.length = 1 + ((actual as u64 + 7) / 8);

        if !is_pread {
            if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
                of.offset = of.offset.saturating_add(actual as u64);
            }
        }
        crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
    }
}

fn format_pid_status_from_kinfo(kp: &KinfoProc, dst: &mut [u8]) -> usize {
    let mut pos = 0usize;
    append_bytes(dst, &mut pos, b"Name:\t");
    let mut comm_len = 0usize;
    while comm_len < kp.comm.len() && kp.comm[comm_len] != 0 {
        comm_len += 1;
    }
    append_bytes(dst, &mut pos, &kp.comm[..comm_len]);
    append_bytes(dst, &mut pos, b"\nState:\t");
    append_bytes(dst, &mut pos, &[proc_state_char(kp.state), b'\n']);
    append_bytes(dst, &mut pos, b"Pid:\t");
    append_u32(dst, &mut pos, kp.pid);
    append_bytes(dst, &mut pos, b"\nPPid:\t");
    append_u32(dst, &mut pos, kp.ppid);
    append_bytes(dst, &mut pos, b"\nPgid:\t");
    append_u32(dst, &mut pos, kp.pgid);
    append_bytes(dst, &mut pos, b"\nSid:\t");
    append_u32(dst, &mut pos, kp.sid);
    append_bytes(dst, &mut pos, b"\nThreads:\t");
    append_u32(dst, &mut pos, kp.num_threads);
    append_bytes(dst, &mut pos, b"\nVmSize:\t");
    append_u64(dst, &mut pos, kp.vm_size / 1024);
    append_bytes(dst, &mut pos, b" kB\nVmRSS:\t");
    append_u64(dst, &mut pos, kp.vm_rss / 1024);
    append_bytes(dst, &mut pos, b" kB\n");
    pos
}

fn format_pid_comm_from_kinfo(kp: &KinfoProc, dst: &mut [u8]) -> usize {
    let mut comm_len = 0usize;
    while comm_len < kp.comm.len() && kp.comm[comm_len] != 0 {
        comm_len += 1;
    }
    let copy = core::cmp::min(comm_len, dst.len().saturating_sub(1));
    if copy != 0 {
        dst[..copy].copy_from_slice(&kp.comm[..copy]);
    }
    if copy < dst.len() {
        dst[copy] = b'\n';
        copy + 1
    } else {
        copy
    }
}

fn format_pid_statm_from_snap(snap: &TronaProcMemSnapshot, dst: &mut [u8]) -> usize {
    let mut pos = 0usize;
    append_u64(dst, &mut pos, snap.vm_reserved_bytes / 4096);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_resident_pages);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.resident_file);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_exe_bytes / 4096);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_lib_bytes / 4096);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, snap.vm_data_bytes / 4096);
    append_bytes(dst, &mut pos, b" 0\n");
    pos
}

/// PidStat stage 0 completion: KinfoProc returned. Park it in the
/// pending-op's payload buffer and enqueue stage 1
/// (`INIT_GET_PROC_TIMES`). `pending_ops::free` releases the payload
/// when the op terminates, so success and failure paths converge on
/// `take_reply_and_free`.
unsafe fn handle_pid_stat_stage0(
    op_id: PendingOpId,
    completion: &backend_rpc::PendingBackendCompletion,
) {
    unsafe {
        if !backend_ok_kinfo(completion) {
            fail_procfs_op(op_id);
            return;
        }
        let pid = completion.ctx.data[4] as u32;

        let Some(payload_ref) = pending_ops::alloc_payload() else {
            fail_procfs_op(op_id);
            return;
        };
        let kinfo_size = core::mem::size_of::<KinfoProc>();
        if let Some(buf) = pending_ops::payload_bytes_mut(payload_ref) {
            buf[..kinfo_size].copy_from_slice(&completion.payload[..kinfo_size]);
        } else {
            pending_ops::release_payload(payload_ref);
            fail_procfs_op(op_id);
            return;
        }
        if let Some(op) = pending_ops::get_mut(op_id) {
            op.payload_ref = payload_ref;
            op.stage = 1;
        } else {
            pending_ops::release_payload(payload_ref);
            fail_procfs_op(op_id);
            return;
        }

        let mut req = TronaMsg::zeroed();
        req.label = trona_protocol::init::INIT_GET_PROC_TIMES;
        req.length = 1;
        req.regs[0] = pid as u64;

        let mut ctx = completion.ctx;
        ctx.stage = 1;

        // The previous stage left this op in COMPLETING; requeue back
        // to QUEUED so the worker's mark_running can succeed.
        if !pending_ops::requeue(op_id) {
            return;
        }
        let job = backend_rpc::PendingBackendJob {
            target_ep: trona_runtime::client::caps::init_ep(),
            op_kind: backend_rpc::BACKEND_OP_PROCFS_READ_PID_STAT_STAGE1,
            payload_out_bytes: 0,
            op_id: op_id.raw(),
            request: req,
            ctx,
        };
        if !backend_rpc::try_enqueue_job(job) {
            fail_procfs_op(op_id);
            return;
        }
    }
}

/// PidStat stage 1: proc_times has returned in `backend_reply.regs[0..4]`.
/// Combine with the KinfoProc parked in the pending-op's payload and
/// format the final stat line. The caller takes the reply slot and
/// frees the op (which also releases the payload buffer).
unsafe fn handle_pid_stat_stage1(
    op_id: PendingOpId,
    completion: &backend_rpc::PendingBackendCompletion,
    dst: &mut [u8],
) -> usize {
    unsafe {
        if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
            fail_procfs_op(op_id);
            return 0;
        }
        let Some(op) = pending_ops::get(op_id) else {
            fail_procfs_op(op_id);
            return 0;
        };
        let payload_ref = op.payload_ref;
        let Some(buf) = pending_ops::payload_bytes(payload_ref) else {
            fail_procfs_op(op_id);
            return 0;
        };
        let kp = *(buf.as_ptr() as *const KinfoProc);
        let utime_ns = completion.backend_reply.regs[0];
        let stime_ns = completion.backend_reply.regs[1];
        let num_threads = completion.backend_reply.regs[2];
        let _start_ns = completion.backend_reply.regs[3];

        let mut pos = 0usize;
        append_u32(dst, &mut pos, kp.pid);
        append_bytes(dst, &mut pos, b" (");
        let mut comm_len = 0usize;
        while comm_len < KINFO_PROC_COMM_LEN && kp.comm[comm_len] != 0 {
            comm_len += 1;
        }
        append_bytes(dst, &mut pos, &kp.comm[..comm_len]);
        append_bytes(dst, &mut pos, b") ");
        append_bytes(dst, &mut pos, &[proc_state_char(kp.state)]);
        append_bytes(dst, &mut pos, b" ");
        append_u32(dst, &mut pos, kp.ppid);
        append_bytes(dst, &mut pos, b" ");
        append_u32(dst, &mut pos, kp.pgid);
        append_bytes(dst, &mut pos, b" ");
        append_u32(dst, &mut pos, kp.sid);
        append_bytes(dst, &mut pos, b" ");
        append_u32(dst, &mut pos, kp.tty_dev);
        append_bytes(dst, &mut pos, b" 0 0 0 0 0 ");
        append_u64(dst, &mut pos, utime_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, stime_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" 0 0 20 0 ");
        append_u64(dst, &mut pos, num_threads);
        append_bytes(dst, &mut pos, b" 0 0 ");
        append_u64(dst, &mut pos, kp.start_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, kp.vm_size);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, kp.vm_rss / 4096);
        append_bytes(dst, &mut pos, b"\n");
        pos
    }
}

/// True when a procfs readlink target requires a backend RPC to init.
/// `PidExe` is the only such kind; `SelfLink` is resolved entirely
/// from owner state.
pub(crate) fn proc_readlink_needs_deferred(kind: ProcNodeKind) -> bool {
    matches!(kind, ProcNodeKind::PidExe)
}

/// Owner-side: enqueue a deferred readlink for a procfs node. Returns
/// false if the job ring is full.
pub(crate) unsafe fn defer_procfs_readlink(
    state: &VfsState,
    cli_handle: ClientHandle,
    vnode: VnodeHandle,
    pid: u32,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let Some(reply_slot) = crate::fileops::tty_wait::save_current_caller(reply) else {
            return true;
        };
        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
        let Some(op_id) =
            pending_ops::alloc(PO_KIND_PROCFS_READLINK, badge, cli_handle, reply_slot)
        else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return false;
        };

        let mut req = TronaMsg::zeroed();
        req.label = INIT_GET_EXE_PATH;
        req.length = 1;
        req.regs[0] = pid as u64;

        let mut ctx = backend_rpc::BackendOpCtx::zeroed();
        ctx.badge = badge;
        ctx.client_handle_raw = crate::owner::dispatch::pack_client_handle(cli_handle);
        ctx.stage = 0;
        ctx.data[1] = pack_vnode_handle(vnode);
        ctx.data[4] = pid as u64;

        let job = backend_rpc::PendingBackendJob {
            target_ep: trona_runtime::client::caps::init_ep(),
            op_kind: backend_rpc::BACKEND_OP_PROCFS_READLINK_PID_EXE,
            payload_out_bytes: 0,
            op_id: op_id.raw(),
            request: req,
            ctx,
        };
        if !backend_rpc::try_enqueue_job(job) {
            let recovered = pending_ops::take_reply_slot(op_id);
            pending_ops::free(op_id);
            crate::fileops::tty_wait::release_reply_slot(recovered);
            return false;
        }
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

/// Owner-side completion handler for procfs readlink (PidExe).
pub(crate) unsafe fn complete_procfs_readlink(
    completion: &backend_rpc::PendingBackendCompletion,
) -> bool {
    if completion.op_kind != backend_rpc::BACKEND_OP_PROCFS_READLINK_PID_EXE {
        return false;
    }
    unsafe {
        let op_id = PendingOpId::from_raw(completion.op_id);
        let Some(op) = pending_ops::get(op_id) else {
            return false;
        };
        if op.kind != PO_KIND_PROCFS_READLINK {
            return false;
        }
        let mut reply = TronaMsg::zeroed();
        let reply_slot = pending_ops::take_reply_and_free(op_id);
        if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
            reply.label = TRONA_INVALID_OPERATION;
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
            return true;
        }
        const INLINE_READLINK_MAX: usize = 152;
        let path_len = completion.backend_reply.regs[0] as usize;
        let actual = path_len.min(INLINE_READLINK_MAX);
        reply.label = TRONA_OK;
        reply.regs[0] = actual as u64;
        if actual != 0 {
            let src = &raw const completion.backend_reply.regs[1] as *const u8;
            let dst = &raw mut reply.regs[1] as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, actual);
        }
        reply.length = 1 + ((actual as u64 + 7) / 8);
        crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
    }
    true
}

/// Owner-side: returns Some(pid_index) when a procfs root readdir
/// cursor falls in the pid-enumeration range and therefore needs the
/// `INIT_LIST_PIDS_BUF` RPC. Returns None for cursors that map to
/// static root entries (`.`/`..`/ROOT_NAMES) or for non-procfs / PidDir
/// directories where readdir is purely state-driven.
pub(crate) fn procfs_readdir_pid_index(
    state: &VfsState,
    dir_vh: VnodeHandle,
    cursor: u64,
) -> Option<u64> {
    let dir_vnode = state.vnodes.get(dir_vh)?;
    let dir_mount = state.mounts.get(dir_vnode.mount.handle)?;
    if !mount_is_procfs(dir_mount) {
        return None;
    }
    let maybe_node = find_node_handle_by_vnode(state, dir_vh).and_then(|h| state.proc_nodes.get(h));
    if let Some(node) = maybe_node {
        if matches!(node.kind, ProcNodeKind::PidDir) {
            return None;
        }
    }
    if cursor < 2 {
        return None;
    }
    let want = (cursor - 2) as usize;
    if want < ROOT_NAMES.len() {
        return None;
    }
    Some(want.saturating_sub(ROOT_NAMES.len()) as u64)
}

/// Owner-side: enqueue a deferred procfs root readdir for one pid
/// entry. Returns false if the job ring is full.
pub(crate) unsafe fn defer_procfs_readdir(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    dir_vh: VnodeHandle,
    cursor: u64,
    pid_index: u64,
    reply: *mut TronaMsg,
) -> bool {
    unsafe {
        let Some(reply_slot) = crate::fileops::tty_wait::save_current_caller(reply) else {
            return true;
        };
        let badge = state.clients.get(cli_handle).map(|c| c.badge).unwrap_or(0);
        let Some(op_id) = pending_ops::alloc(PO_KIND_PROCFS_READDIR, badge, cli_handle, reply_slot)
        else {
            crate::fileops::tty_wait::release_reply_slot(reply_slot);
            return false;
        };

        let mut req = TronaMsg::zeroed();
        req.label = trona_protocol::init::INIT_LIST_PIDS_BUF;
        req.length = 2;
        req.regs[0] = pid_index;
        req.regs[1] = 1;

        let mut ctx = backend_rpc::BackendOpCtx::zeroed();
        ctx.badge = badge;
        ctx.client_handle_raw = crate::owner::dispatch::pack_client_handle(cli_handle);
        ctx.stage = 0;
        ctx.data[0] = fd as u32 as u64;
        ctx.data[1] = pack_vnode_handle(dir_vh);
        ctx.data[2] = cursor;

        let job = backend_rpc::PendingBackendJob {
            target_ep: trona_runtime::client::caps::init_ep(),
            op_kind: backend_rpc::BACKEND_OP_PROCFS_READDIR_PIDS,
            payload_out_bytes: 4,
            op_id: op_id.raw(),
            request: req,
            ctx,
        };
        if !backend_rpc::try_enqueue_job(job) {
            let recovered = pending_ops::take_reply_slot(op_id);
            pending_ops::free(op_id);
            crate::fileops::tty_wait::release_reply_slot(recovered);
            return false;
        }
        (*reply).label = crate::fileops::tty_wait::REPLY_DEFERRED_LABEL;
        (*reply).length = 0;
        true
    }
}

/// Owner-side completion handler for procfs root readdir pid entries.
pub(crate) unsafe fn complete_procfs_readdir(
    state: &mut VfsState,
    completion: &backend_rpc::PendingBackendCompletion,
) -> bool {
    use crate::server::open_file::{DIR_CURSOR_BACKEND, DIR_CURSOR_EOF};
    use crate::server::types::OBJ_DIRECTORY;
    use trona_posix::consts::DT_DIR;

    if completion.op_kind != backend_rpc::BACKEND_OP_PROCFS_READDIR_PIDS {
        return false;
    }
    unsafe {
        let op_id = PendingOpId::from_raw(completion.op_id);
        let Some(op) = pending_ops::get(op_id) else {
            return false;
        };
        if op.kind != PO_KIND_PROCFS_READDIR {
            return false;
        }
        let cli_handle =
            crate::owner::dispatch::unpack_client_handle(completion.ctx.client_handle_raw);
        let fd = completion.ctx.data[0] as i32;
        let saved_vnode = unpack_vnode_handle(completion.ctx.data[1]);
        let cursor = completion.ctx.data[2];

        // Drop silently if the dirfd is gone or now points elsewhere.
        if !validate_pending_fd_vnode(state, cli_handle, fd, saved_vnode) {
            let slot = pending_ops::take_reply_and_free(op_id);
            crate::fileops::tty_wait::release_reply_slot(slot);
            return true;
        }

        let reply_slot = pending_ops::take_reply_and_free(op_id);
        let mut reply = TronaMsg::zeroed();
        if completion.backend_err != 0 || completion.backend_reply.label != TRONA_OK {
            reply.label = TRONA_INVALID_OPERATION;
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
            return true;
        }

        let count = completion.backend_reply.regs[0];
        if count == 0 {
            if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
                if of.kind == OBJ_DIRECTORY {
                    of.dir_cursor_state = DIR_CURSOR_EOF;
                    of.dir_cursor = 0;
                }
            }
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = 0;
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
            return true;
        }

        let pid = *(completion.payload.as_ptr() as *const u32);
        let mut name = [0u8; 128];
        let mut name_len = 0usize;
        append_u32(&mut name, &mut name_len, pid);

        let next_cursor = cursor + 1;
        if let Some(of) = state.client_open_file_mut(cli_handle, fd as usize) {
            if of.kind != OBJ_DIRECTORY {
                reply.label = TRONA_INVALID_ARGUMENT;
                crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
                return true;
            }
            of.dir_cursor_state = DIR_CURSOR_BACKEND;
            of.dir_cursor = next_cursor;
        } else {
            reply.label = TRONA_INVALID_ARGUMENT;
            crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
            return true;
        }

        let ino = proc_inode(ProcNodeKind::PidDir, pid);
        reply.label = TRONA_OK;
        reply.length = 5 + ((name_len as u64 + 7) / 8);
        reply.regs[0] = name_len as u64;
        reply.regs[1] = 0;
        reply.regs[2] = ino;
        reply.regs[3] = DT_DIR as u64;
        let dst = &raw mut reply.regs[4] as *mut u8;
        core::ptr::copy_nonoverlapping(name.as_ptr(), dst, name_len);
        crate::fileops::tty_wait::send_saved_reply(reply_slot, &raw const reply);
        true
    }
}

/// Format `/proc/stat` content using `pm_get_system_stats` reply data
/// (`procs_total`, `procs_running`, `last_pid`) plus an owner-side
/// `sys_sysinfo` syscall (which is a pure kernel call, never blocking).
fn format_root_stat(procs_total: u64, procs_running: u64, last_pid: u64, dst: &mut [u8]) -> usize {
    let mut hdr = TronaSysInfo::zeroed();
    let mut cpus = [TronaSysInfoCpu::zeroed(); 64];
    let _ = trona_kernel::syscall::sys_sysinfo(&raw mut hdr, cpus.as_mut_ptr(), cpus.len() as u64);
    let mut agg_user = 0u64;
    let mut agg_sys = 0u64;
    let mut agg_idle = 0u64;
    let written = core::cmp::min(hdr.cpus_written as usize, cpus.len());
    for cpu in &cpus[..written] {
        agg_user = agg_user.saturating_add(cpu.user_time_ns / 10_000_000);
        agg_sys = agg_sys.saturating_add(cpu.system_time_ns / 10_000_000);
        agg_idle = agg_idle.saturating_add(cpu.idle_time_ns / 10_000_000);
    }
    let mut pos = 0usize;
    append_bytes(dst, &mut pos, b"cpu ");
    append_u64(dst, &mut pos, agg_user);
    append_bytes(dst, &mut pos, b" 0 ");
    append_u64(dst, &mut pos, agg_sys);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, agg_idle);
    append_bytes(dst, &mut pos, b" 0 0 0 0\n");
    for (idx, cpu) in cpus[..written].iter().enumerate() {
        append_bytes(dst, &mut pos, b"cpu");
        append_u32(dst, &mut pos, idx as u32);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, cpu.user_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" 0 ");
        append_u64(dst, &mut pos, cpu.system_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" ");
        append_u64(dst, &mut pos, cpu.idle_time_ns / 10_000_000);
        append_bytes(dst, &mut pos, b" 0 0 0 0\n");
    }
    append_bytes(dst, &mut pos, b"intr 0\nctxt ");
    append_u64(dst, &mut pos, hdr.context_switches_total);
    append_bytes(dst, &mut pos, b"\nbtime ");
    append_u64(dst, &mut pos, hdr.boot_time_ns / 1_000_000_000);
    append_bytes(dst, &mut pos, b"\nprocesses ");
    append_u64(dst, &mut pos, procs_total);
    append_bytes(dst, &mut pos, b"\nprocs_running ");
    append_u64(dst, &mut pos, procs_running);
    append_bytes(dst, &mut pos, b"\nprocs_blocked 0\n");
    let _ = last_pid;
    pos
}

fn format_root_loadavg(
    procs_total: u64,
    procs_running: u64,
    last_pid: u64,
    dst: &mut [u8],
) -> usize {
    let mut pos = 0usize;
    append_bytes(dst, &mut pos, b"0.00 0.00 0.00 ");
    append_u64(dst, &mut pos, procs_running);
    append_bytes(dst, &mut pos, b"/");
    append_u64(dst, &mut pos, procs_total);
    append_bytes(dst, &mut pos, b" ");
    append_u64(dst, &mut pos, last_pid);
    append_bytes(dst, &mut pos, b"\n");
    pos
}

/// Verify that `fd` in `cli_handle`'s open-file table still points at
/// the same vnode that was saved when the deferred backend RPC was
/// enqueued. Returns false when the fd was closed/recycled or the
/// client has gone away — in which case the completion should drop
/// rather than mutate unrelated state.
fn validate_pending_fd_vnode(
    state: &VfsState,
    cli_handle: ClientHandle,
    fd: i32,
    saved_vnode: VnodeHandle,
) -> bool {
    if state.clients.get(cli_handle).is_none() {
        return false;
    }
    if fd < 0 {
        return false;
    }
    state
        .client_open_file(cli_handle, fd as usize)
        .map(|of| of.vnode == saved_vnode)
        .unwrap_or(false)
}
