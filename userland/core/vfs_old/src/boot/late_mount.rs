// SPDX-License-Identifier: GPL-2.0-only
//! Late-mount retry controller for service-backed filesystems.
//!
//! When a fstab mount fails at boot (e.g. saltyfs isn't up yet), the entry
//! is queued here for async retry via the timer wheel.

use crate::ipc::timer_wheel::{self, TimerKind};
use crate::owner::VfsState;
use crate::owner::pending::PendingOpHandle;
use crate::owner::resume::{
    Resume,
    fs::{FsResume, LatePivotOp},
};
use crate::personality::posix::{consts::S_IFDIR_L, poll};
use crate::vfs_core::error::{VfsError, VfsResult};
use crate::vfs_core::mount::MountHandle;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::outcome::{Parked, Ready};
use crate::vfs_core::vnode::{VT_DIR, VnodeHandle};

use super::fstab::FstabEntry;

const MAX_PENDING: usize = 8;
const INITIAL_RETRY_NS: u64 = 500_000_000;
const MAX_RETRY_NS: u64 = 5_000_000_000;
const MAX_RETRIES: u8 = 20;
const LATE_PIVOT_RETRY_NS: u64 = 10_000_000;
const ROOTFS_READY_BITS: u64 = 1;
const ROOTFS_FAILED_BITS: u64 = 1 << 1;
const LATE_PIVOT_CHILD_DIR_COUNT: usize = 5;
const LATE_PIVOT_DIR_COUNT: usize = 6;
const LATE_PIVOT_DIRS: [(&[u8], u32); LATE_PIVOT_DIR_COUNT] = [
    (b"dev", S_IFDIR_L | 0o755),
    (b"proc", S_IFDIR_L | 0o555),
    (b"tmp", S_IFDIR_L | 0o1777),
    (b"sys", S_IFDIR_L | 0o555),
    (b"pipe", S_IFDIR_L | 0o755),
    (b"initramfs", S_IFDIR_L | 0o555),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum RootfsState {
    BootRoot,
    RootMountPending,
    RootMountedPendingPivot,
    RootReady,
    RootFailed,
}

struct PendingMount {
    active: u8,
    is_root: u8,
    fstype: [u8; 16],
    fstype_len: u8,
    target: [u8; 128],
    target_len: u8,
    source: u64,
    flags: u32,
    retry_count: u8,
    next_retry_ns: u64,
}

impl PendingMount {
    const fn zeroed() -> Self {
        PendingMount {
            active: 0,
            is_root: 0,
            fstype: [0; 16],
            fstype_len: 0,
            target: [0; 128],
            target_len: 0,
            source: 0,
            flags: 0,
            retry_count: 0,
            next_retry_ns: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct LatePivotState {
    pub(crate) active: bool,
    pub(crate) next_dir_index: u8,
    pub(crate) pinned_mask: u8,
    pub(crate) new_root_mh: MountHandle,
    pub(crate) saltyfs_root_vh: VnodeHandle,
    pub(crate) prepared: [VnodeHandle; LATE_PIVOT_DIR_COUNT],
}

impl LatePivotState {
    pub(crate) const fn zeroed() -> Self {
        Self {
            active: false,
            next_dir_index: 0,
            pinned_mask: 0,
            new_root_mh: MountHandle::INVALID,
            saltyfs_root_vh: VnodeHandle::INVALID,
            prepared: [VnodeHandle::INVALID; LATE_PIVOT_DIR_COUNT],
        }
    }
}

enum PivotDrive {
    Continue,
    Parked,
    Fail(VfsError),
}

static mut PENDING: [PendingMount; MAX_PENDING] = [const { PendingMount::zeroed() }; MAX_PENDING];
static mut ROOTFS_STATE: RootfsState = RootfsState::BootRoot;

fn signal_rootfs_event(bits: u64) {
    let slot = trona_runtime::client::caps::rootfs_ready_ntfn();
    if slot != 0 {
        let _ = trona_kernel::syscall::syscall(uapi::KERNITE_SYS_SIGNAL, slot, bits, 0, 0, 0, 0);
    }
}

fn late_pivot_dir_name(dir_index: usize) -> &'static [u8] {
    LATE_PIVOT_DIRS[dir_index].0
}

fn log_late_pivot_dir_error(name: &[u8], e: VfsError) {
    trona_runtime::uerror!(|_lb| {
        _lb.str(b"[VFS] late_mount: cannot prepare rootfs mountpoint /");
        _lb.bytes(name);
        _lb.str(b" err=");
        _lb.hex(e.discriminant() as u64);
        _lb.str(b"\n");
    });
}

pub(crate) fn note_root_mount_pending() {
    unsafe {
        if ROOTFS_STATE == RootfsState::BootRoot {
            ROOTFS_STATE = RootfsState::RootMountPending;
        }
    }
}

pub(crate) fn note_root_mounted_pending_pivot() {
    unsafe {
        if ROOTFS_STATE != RootfsState::RootReady {
            ROOTFS_STATE = RootfsState::RootMountedPendingPivot;
        }
    }
}

pub(crate) fn note_root_ready() {
    unsafe {
        if ROOTFS_STATE == RootfsState::RootReady {
            return;
        }
        ROOTFS_STATE = RootfsState::RootReady;
        signal_rootfs_event(ROOTFS_READY_BITS);
    }
}

pub(crate) fn note_root_failed() {
    unsafe {
        if ROOTFS_STATE == RootfsState::RootReady || ROOTFS_STATE == RootfsState::RootFailed {
            return;
        }
        ROOTFS_STATE = RootfsState::RootFailed;
        signal_rootfs_event(ROOTFS_FAILED_BITS);
    }
}

unsafe fn reset_late_pivot(state: &mut VfsState) {
    unsafe {
        let snapshot = state.late_pivot;
        for idx in 0..LATE_PIVOT_DIR_COUNT {
            if (snapshot.pinned_mask & (1u8 << idx)) == 0 {
                continue;
            }
            let vh = snapshot.prepared[idx];
            if let Some(vn) = state.vnodes.get_mut(vh) {
                vn.unpin();
            }
        }
        state.late_pivot = LatePivotState::zeroed();
    }
}

unsafe fn fail_deferred_pivot(state: &mut VfsState, e: VfsError) {
    unsafe {
        note_root_failed();
        reset_late_pivot(state);
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] late_mount: deferred pivot_root failed err=");
            _lb.hex(e.discriminant() as u64);
            _lb.str(b"\n");
        });
    }
}

unsafe fn fail_deferred_pivot_message(state: &mut VfsState, msg: &[u8]) {
    unsafe {
        note_root_failed();
        reset_late_pivot(state);
        trona_runtime::uerror!(|_lb| {
            _lb.bytes(msg);
            _lb.str(b"\n");
        });
    }
}

unsafe fn stamp_late_pivot_resume(
    state: &mut VfsState,
    handle: PendingOpHandle,
    dir_index: u8,
    op: LatePivotOp,
) -> bool {
    unsafe {
        if state.stamp_resume_ctx(
            handle,
            0,
            0,
            Resume::Fs(FsResume::LatePivot { dir_index, op }),
        ) {
            true
        } else {
            state.cancel_pending_op(handle);
            false
        }
    }
}

unsafe fn store_late_pivot_dir(
    state: &mut VfsState,
    dir_index: usize,
    vh: VnodeHandle,
) -> VfsResult<()> {
    unsafe {
        let vnode = state.vnodes.get(vh).ok_or(VfsError::Io)?;
        if vnode.vtype != VT_DIR {
            return Err(VfsError::NotDir);
        }

        let old_vh = state.late_pivot.prepared[dir_index];
        let old_pinned = (state.late_pivot.pinned_mask & (1u8 << dir_index)) != 0;
        if old_pinned && old_vh.is_valid() && old_vh != vh {
            if let Some(old_vn) = state.vnodes.get_mut(old_vh) {
                old_vn.unpin();
            }
            state.late_pivot.pinned_mask &= !(1u8 << dir_index);
        }
        if (state.late_pivot.pinned_mask & (1u8 << dir_index)) == 0 {
            let vnode = state.vnodes.get_mut(vh).ok_or(VfsError::Io)?;
            vnode.pin();
            state.late_pivot.pinned_mask |= 1u8 << dir_index;
        }
        state.late_pivot.prepared[dir_index] = vh;
        state.late_pivot.next_dir_index = (dir_index + 1) as u8;
        Ok(())
    }
}

fn schedule_deferred_pivot_retry() {
    let deadline = poll::monotonic_now_ns().saturating_add(LATE_PIVOT_RETRY_NS);
    timer_wheel::register_timer(deadline, TimerKind::MountRetry, 0);
}

unsafe fn issue_late_pivot_lookup(state: &mut VfsState, dir_index: usize) -> PivotDrive {
    unsafe {
        let parent_vh = state.late_pivot.saltyfs_root_vh;
        let name = late_pivot_dir_name(dir_index);
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, parent_vh)
        {
            Some(ctx) => ctx,
            None => return PivotDrive::Fail(VfsError::Io),
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.lookup)(&mut ctx, name.as_ptr(), name.len() as u8) {
            Ok(Ready(vh)) if vh.is_valid() => match store_late_pivot_dir(state, dir_index, vh) {
                Ok(()) => PivotDrive::Continue,
                Err(e) => PivotDrive::Fail(e),
            },
            Ok(Ready(_)) | Err(VfsError::NotFound) => issue_late_pivot_mkdir(state, dir_index),
            Ok(Parked(handle)) => {
                if stamp_late_pivot_resume(state, handle, dir_index as u8, LatePivotOp::Lookup) {
                    PivotDrive::Parked
                } else {
                    PivotDrive::Fail(VfsError::Io)
                }
            }
            Err(VfsError::WouldBlock) => {
                schedule_deferred_pivot_retry();
                PivotDrive::Parked
            }
            Err(e) => PivotDrive::Fail(e),
        }
    }
}

unsafe fn issue_late_pivot_mkdir(state: &mut VfsState, dir_index: usize) -> PivotDrive {
    unsafe {
        let parent_vh = state.late_pivot.saltyfs_root_vh;
        let (name, mode) = LATE_PIVOT_DIRS[dir_index];
        let mut ctx = match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, parent_vh)
        {
            Some(ctx) => ctx,
            None => return PivotDrive::Fail(VfsError::Io),
        };
        let ops = &*(*ctx.vnode).ops;
        match (ops.meta.mkdir)(
            &mut ctx,
            name.as_ptr(),
            name.len() as u8,
            mode,
            &raw const super::BOOT_CRED,
        ) {
            Ok(Ready(vh)) => match store_late_pivot_dir(state, dir_index, vh) {
                Ok(()) => PivotDrive::Continue,
                Err(e) => PivotDrive::Fail(e),
            },
            Ok(Parked(handle)) => {
                if stamp_late_pivot_resume(state, handle, dir_index as u8, LatePivotOp::Mkdir) {
                    PivotDrive::Parked
                } else {
                    PivotDrive::Fail(VfsError::Io)
                }
            }
            Err(VfsError::WouldBlock) => {
                schedule_deferred_pivot_retry();
                PivotDrive::Parked
            }
            Err(VfsError::Exists) => issue_late_pivot_lookup(state, dir_index),
            Err(e) => PivotDrive::Fail(e),
        }
    }
}

unsafe fn drive_deferred_pivot(state: &mut VfsState) {
    unsafe {
        while state.late_pivot.active {
            let dir_index = state.late_pivot.next_dir_index as usize;
            if dir_index >= LATE_PIVOT_DIR_COUNT {
                let snapshot = state.late_pivot;
                let child_targets: [VnodeHandle; LATE_PIVOT_CHILD_DIR_COUNT] = [
                    snapshot.prepared[0],
                    snapshot.prepared[1],
                    snapshot.prepared[2],
                    snapshot.prepared[3],
                    snapshot.prepared[4],
                ];
                let put_old_vh = snapshot.prepared[LATE_PIVOT_DIR_COUNT - 1];
                match super::pivot_root::vfs_pivot_root_prepared(
                    state,
                    snapshot.new_root_mh,
                    put_old_vh,
                    &child_targets,
                ) {
                    Ok(()) => {
                        mount_ctl::refresh_global_ns(state);
                        reset_late_pivot(state);
                        note_root_ready();
                        trona_runtime::uinfo!(|_lb| {
                            _lb.str(b"[VFS] late_mount: deferred pivot_root complete\n");
                        });
                    }
                    Err(e) => fail_deferred_pivot(state, e),
                }
                return;
            }

            match issue_late_pivot_lookup(state, dir_index) {
                PivotDrive::Continue => continue,
                PivotDrive::Parked => return,
                PivotDrive::Fail(e) => {
                    log_late_pivot_dir_error(late_pivot_dir_name(dir_index), e);
                    fail_deferred_pivot(state, e);
                    return;
                }
            }
        }
    }
}

pub(crate) unsafe fn resume_deferred_pivot_lookup(
    state: &mut VfsState,
    dir_index: u8,
    result: VfsResult<Option<VnodeHandle>>,
) {
    unsafe {
        if !state.late_pivot.active {
            return;
        }
        if state.late_pivot.next_dir_index != dir_index {
            fail_deferred_pivot_message(
                state,
                b"[VFS] late_mount: late-pivot lookup completion out of order",
            );
            return;
        }
        match result {
            Ok(Some(vh)) => match store_late_pivot_dir(state, dir_index as usize, vh) {
                Ok(()) => drive_deferred_pivot(state),
                Err(e) => {
                    log_late_pivot_dir_error(late_pivot_dir_name(dir_index as usize), e);
                    fail_deferred_pivot(state, e);
                }
            },
            Ok(None) => match issue_late_pivot_mkdir(state, dir_index as usize) {
                PivotDrive::Continue => drive_deferred_pivot(state),
                PivotDrive::Parked => {}
                PivotDrive::Fail(e) => {
                    log_late_pivot_dir_error(late_pivot_dir_name(dir_index as usize), e);
                    fail_deferred_pivot(state, e);
                }
            },
            Err(e) => {
                log_late_pivot_dir_error(late_pivot_dir_name(dir_index as usize), e);
                fail_deferred_pivot(state, e);
            }
        }
    }
}

pub(crate) unsafe fn resume_deferred_pivot_mkdir(
    state: &mut VfsState,
    dir_index: u8,
    result: VfsResult<VnodeHandle>,
) {
    unsafe {
        if !state.late_pivot.active {
            return;
        }
        if state.late_pivot.next_dir_index != dir_index {
            fail_deferred_pivot_message(
                state,
                b"[VFS] late_mount: late-pivot mkdir completion out of order",
            );
            return;
        }
        match result {
            Ok(vh) => match store_late_pivot_dir(state, dir_index as usize, vh) {
                Ok(()) => drive_deferred_pivot(state),
                Err(e) => {
                    log_late_pivot_dir_error(late_pivot_dir_name(dir_index as usize), e);
                    fail_deferred_pivot(state, e);
                }
            },
            Err(VfsError::Exists) => match issue_late_pivot_lookup(state, dir_index as usize) {
                PivotDrive::Continue => drive_deferred_pivot(state),
                PivotDrive::Parked => {}
                PivotDrive::Fail(e) => {
                    log_late_pivot_dir_error(late_pivot_dir_name(dir_index as usize), e);
                    fail_deferred_pivot(state, e);
                }
            },
            Err(e) => {
                log_late_pivot_dir_error(late_pivot_dir_name(dir_index as usize), e);
                fail_deferred_pivot(state, e);
            }
        }
    }
}

/// Queue a failed fstab mount for async retry.
pub(crate) fn queue_pending(entry: &FstabEntry, is_root: bool) {
    let now = poll::monotonic_now_ns();
    let deadline = now + INITIAL_RETRY_NS;

    if is_root {
        note_root_mount_pending();
    }

    unsafe {
        for i in 0..MAX_PENDING {
            let p = &mut PENDING[i];
            if p.active != 0 {
                continue;
            }

            p.active = 1;
            p.is_root = if is_root { 1 } else { 0 };

            let ft_len = entry.fstype_len as usize;
            p.fstype[..ft_len].copy_from_slice(&entry.fstype[..ft_len]);
            p.fstype_len = entry.fstype_len;

            let tgt_len = entry.target_len as usize;
            p.target[..tgt_len].copy_from_slice(&entry.target[..tgt_len]);
            p.target_len = entry.target_len;

            p.source = 0;
            p.flags = entry.flags;
            p.retry_count = 0;
            p.next_retry_ns = deadline;

            timer_wheel::register_timer(deadline, TimerKind::MountRetry, 0);
            return;
        }
    }

    trona_runtime::uwarn!(|_lb| {
        _lb.str(b"[VFS] late_mount: pending queue full, mount will not be retried\n");
    });
}

/// Process expired mount retries. Called from timer wheel expiry.
///
/// # Safety
///
/// Must be called from the VFS event loop context with `state` available.
pub(crate) unsafe fn retry_pending_mounts(state: &mut VfsState) {
    unsafe {
        if state.late_pivot.active {
            drive_deferred_pivot(state);
        }

        let now = poll::monotonic_now_ns();

        for i in 0..MAX_PENDING {
            let p = &mut PENDING[i];
            if p.active == 0 || p.next_retry_ns > now {
                continue;
            }

            let fstype = &p.fstype[..p.fstype_len as usize];
            let target = &p.target[..p.target_len as usize];
            let is_root = p.is_root != 0;

            trona_runtime::uinfo!(|_lb| {
                _lb.str(b"[VFS] late_mount: retry ");
                _lb.bytes(target);
                _lb.str(b" (attempt ");
                _lb.dec(p.retry_count as u64 + 1);
                _lb.str(b")\n");
            });

            let mount_result = if is_root {
                attempt_root_mount(state, fstype, p.flags)
            } else {
                attempt_overlay_mount(state, target, fstype, p.flags)
            };

            if mount_result {
                p.active = 0;
                mount_ctl::refresh_global_ns(state);

                if is_root {
                    perform_deferred_pivot(state);
                }
            } else {
                p.retry_count += 1;
                if p.retry_count >= MAX_RETRIES {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] late_mount: giving up on ");
                        _lb.bytes(target);
                        _lb.str(b" after ");
                        _lb.dec(MAX_RETRIES as u64);
                        _lb.str(b" retries\n");
                    });
                    if is_root {
                        note_root_failed();
                    }
                    p.active = 0;
                } else {
                    let backoff =
                        core::cmp::min(INITIAL_RETRY_NS << (p.retry_count as u64), MAX_RETRY_NS);
                    p.next_retry_ns = now + backoff;
                    timer_wheel::register_timer(p.next_retry_ns, TimerKind::MountRetry, 0);
                }
            }
        }
    }
}

/// Check if any pending mounts remain.
pub(crate) fn has_pending() -> bool {
    unsafe {
        for i in 0..MAX_PENDING {
            if PENDING[i].active != 0 {
                return true;
            }
        }
        false
    }
}

unsafe fn attempt_root_mount(state: &mut VfsState, fstype: &[u8], flags: u32) -> bool {
    unsafe {
        let root_mh = state.root_mount;
        let root_mp = match state.mounts.get(root_mh) {
            Some(m) => m,
            None => return false,
        };
        let root_vh = root_mp.root_vnode;
        if !root_vh.is_valid() {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] late_mount: root retry aborted, root mount has no root vnode\n");
            });
            return false;
        }

        let newroot_vh = match super::bootstrap::boot_ensure_dir(
            state,
            root_vh,
            b"newroot",
            crate::personality::posix::consts::S_IFDIR_L | 0o755,
        ) {
            Ok(vh) => vh,
            Err(e) => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] late_mount: cannot ensure /newroot err=");
                    _lb.hex(e.discriminant() as u64);
                    _lb.str(b"\n");
                });
                return false;
            }
        };

        let result = mount_ctl::do_mount_sync(
            state,
            newroot_vh,
            fstype,
            b"/newroot",
            0,
            flags,
            core::ptr::null(),
            0,
        );

        match result {
            Ok(_) => {
                note_root_mounted_pending_pivot();
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[VFS] late_mount: root filesystem mounted on /newroot\n");
                });
                true
            }
            Err(e) => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] late_mount: root mount retry failed err=");
                    _lb.hex(e.discriminant() as u64);
                    _lb.str(b"\n");
                });
                false
            }
        }
    }
}

unsafe fn attempt_overlay_mount(
    state: &mut VfsState,
    target: &[u8],
    fstype: &[u8],
    flags: u32,
) -> bool {
    unsafe {
        let target_vh = match mount_ctl::resolve_mount_path(state, target) {
            Ok(vh) => vh,
            Err(_) => return false,
        };

        mount_ctl::do_mount_sync(
            state,
            target_vh,
            fstype,
            target,
            0,
            flags,
            core::ptr::null(),
            0,
        )
        .is_ok()
    }
}

unsafe fn perform_deferred_pivot(state: &mut VfsState) {
    unsafe {
        if state.late_pivot.active {
            return;
        }

        let root_mh = state.root_mount;
        let root_mp = match state.mounts.get(root_mh) {
            Some(m) => m,
            None => {
                note_root_failed();
                return;
            }
        };
        let root_vh = root_mp.root_vnode;
        if !root_vh.is_valid() {
            note_root_failed();
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] late_mount: deferred pivot aborted, missing current root vnode\n");
            });
            return;
        }

        let newroot_vh = {
            let mut ctx =
                match crate::vfs_core::vop_context::OwnerVopCtx::from_state(state, root_vh) {
                    Some(c) => c,
                    None => {
                        note_root_failed();
                        return;
                    }
                };
            let ops = &*(*ctx.vnode).ops;
            let result = (ops.meta.lookup)(&mut ctx, b"newroot".as_ptr(), 7);
            match result {
                Ok(Ready(vh)) if vh.is_valid() => vh,
                _ => {
                    note_root_failed();
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[VFS] late_mount: cannot find /newroot for deferred pivot\n");
                    });
                    return;
                }
            }
        };

        let saltyfs_mh = match mount_ctl::covering_mount_for_vnode(state, newroot_vh) {
            Some(mh) => mh,
            None => {
                note_root_failed();
                return;
            }
        };

        if !saltyfs_mh.is_valid() {
            note_root_failed();
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] late_mount: /newroot is not covered by a mounted filesystem\n");
            });
            return;
        }

        let saltyfs_root_vh = match state.mounts.get(saltyfs_mh) {
            Some(mp) => mp.root_vnode,
            None => {
                note_root_failed();
                return;
            }
        };

        if !saltyfs_root_vh.is_valid() {
            note_root_failed();
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] late_mount: deferred pivot aborted, saltyfs root vnode missing\n");
            });
            return;
        }

        state.late_pivot = LatePivotState {
            active: true,
            next_dir_index: 0,
            pinned_mask: 0,
            new_root_mh: saltyfs_mh,
            saltyfs_root_vh,
            prepared: [VnodeHandle::INVALID; LATE_PIVOT_DIR_COUNT],
        };
        drive_deferred_pivot(state);
    }
}
