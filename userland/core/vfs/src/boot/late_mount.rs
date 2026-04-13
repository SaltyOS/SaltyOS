// SPDX-License-Identifier: GPL-2.0-only
//! Late-mount retry controller for service-backed filesystems.
//!
//! When a fstab mount fails at boot (e.g. saltyfs isn't up yet), the entry
//! is queued here for async retry via the timer wheel.

use crate::ipc::timer_wheel::{self, TimerKind};
use crate::owner::VfsState;
use crate::personality::posix::poll;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vnode::VnodeHandle;

use super::fstab::FstabEntry;

const MAX_PENDING: usize = 8;
const INITIAL_RETRY_NS: u64 = 500_000_000;
const MAX_RETRY_NS: u64 = 5_000_000_000;
const MAX_RETRIES: u8 = 20;
const ROOTFS_READY_BITS: u64 = 1;
const ROOTFS_FAILED_BITS: u64 = 1 << 1;

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

static mut PENDING: [PendingMount; MAX_PENDING] = [const { PendingMount::zeroed() }; MAX_PENDING];
static mut ROOTFS_STATE: RootfsState = RootfsState::BootRoot;

fn signal_rootfs_event(bits: u64) {
    if crate::server::consts::VFS_CAP_ROOTFS_READY_NTFN != 0 {
        let _ = trona::syscall::syscall(
            trona::SYS_SIGNAL,
            crate::server::consts::VFS_CAP_ROOTFS_READY_NTFN,
            bits,
            0,
            0,
            0,
            0,
        );
    }
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

    trona::uwarn!(|_lb| {
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
        let now = poll::monotonic_now_ns();

        for i in 0..MAX_PENDING {
            let p = &mut PENDING[i];
            if p.active == 0 || p.next_retry_ns > now {
                continue;
            }

            let fstype = &p.fstype[..p.fstype_len as usize];
            let target = &p.target[..p.target_len as usize];
            let is_root = p.is_root != 0;

            trona::uinfo!(|_lb| {
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
                    trona::uerror!(|_lb| {
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
            trona::uwarn!(|_lb| {
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
                trona::uwarn!(|_lb| {
                    _lb.str(b"[VFS] late_mount: cannot ensure /newroot err=");
                    _lb.hex(e as u32 as u64);
                    _lb.str(b"\n");
                });
                return false;
            }
        };

        let result = mount_ctl::do_mount(
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
                trona::uinfo!(|_lb| {
                    _lb.str(b"[VFS] late_mount: root filesystem mounted on /newroot\n");
                });
                true
            }
            Err(e) => {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[VFS] late_mount: root mount retry failed err=");
                    _lb.hex(e as u32 as u64);
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

        mount_ctl::do_mount(
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
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] late_mount: deferred pivot aborted, missing current root vnode\n");
            });
            return;
        }

        // Lookup /newroot via VopContext
        let newroot_vh = {
            let ctx = match mount_ctl::build_vop_context(state, root_vh) {
                Some(c) => c,
                None => {
                    note_root_failed();
                    return;
                }
            };
            let ops = &*(*ctx.vnode).ops;
            let result = (ops.meta.lookup)(&ctx, b"newroot".as_ptr(), 7);
            mount_ctl::clear_trampolines();
            match result {
                Ok(vh) if vh.is_valid() => vh,
                _ => {
                    note_root_failed();
                    trona::uerror!(|_lb| {
                        _lb.str(b"[VFS] late_mount: cannot find /newroot for deferred pivot\n");
                    });
                    return;
                }
            }
        };

        // Find the mount covering /newroot
        let saltyfs_mh = match mount_ctl::covering_mount_for_vnode(state, newroot_vh) {
            Some(mh) => mh,
            None => {
                note_root_failed();
                return;
            }
        };

        if !saltyfs_mh.is_valid() {
            note_root_failed();
            trona::uerror!(|_lb| {
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
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] late_mount: deferred pivot aborted, saltyfs root vnode missing\n");
            });
            return;
        }

        if let Err(e) = super::bootstrap::prepare_post_pivot_scaffold(state, saltyfs_root_vh) {
            note_root_failed();
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] late_mount: cannot prepare post-pivot scaffold err=");
                _lb.hex(e as u32 as u64);
                _lb.str(b"\n");
            });
            return;
        }

        let put_old_vh = match super::bootstrap::boot_ensure_dir(
            state,
            saltyfs_root_vh,
            b"initramfs",
            crate::personality::posix::consts::S_IFDIR_L | 0o555,
        ) {
            Ok(vh) => vh,
            Err(e) => {
                note_root_failed();
                trona::uerror!(|_lb| {
                    _lb.str(b"[VFS] late_mount: cannot ensure /initramfs in saltyfs err=");
                    _lb.hex(e as u32 as u64);
                    _lb.str(b"\n");
                });
                return;
            }
        };

        match mount_ctl::do_pivot_root(state, saltyfs_mh, put_old_vh) {
            Ok(()) => {
                note_root_ready();
                trona::uinfo!(|_lb| {
                    _lb.str(b"[VFS] late_mount: deferred pivot_root complete\n");
                });
            }
            Err(e) => {
                note_root_failed();
                trona::uerror!(|_lb| {
                    _lb.str(b"[VFS] late_mount: deferred pivot_root failed err=");
                    _lb.hex(e as u32 as u64);
                    _lb.str(b"\n");
                });
            }
        }
    }
}
