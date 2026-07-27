// SPDX-License-Identifier: GPL-2.0-only
//! Real-root mount and pivot retry controller.
//!
//! The rebuilt VFS keeps bootstrap simple: `/dev`, `/proc`, `/sys`, `/tmp`,
//! and `/pipe` come up immediately on the initramfs-style boot root. The
//! service then polls `/etc/fstab` for a real root entry and retries the
//! `/newroot` graft plus `pivot_root` until the backend filesystem is ready.

use trona_kernel::syscall;
use uapi::*;

use crate::owner::VfsState;
use crate::vfs_core::mount_ctl;
use crate::vfs_core::vnode::VT_REG;

use super::fstab::{self, FstabEntry};

const ROOTFS_READY_BITS: u64 = 1;
const ROOTFS_FAILED_BITS: u64 = 1 << 1;
const ROOTFS_RETRY_NS: u64 = 500_000_000;
const ROOTFS_MAX_RETRIES: u8 = 20;

const ROOTFS_STATE_PENDING: u8 = 0;
const ROOTFS_STATE_READY: u8 = 1;
const ROOTFS_STATE_FAILED: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RootfsState {
    pub(crate) status: u8,
    pub(crate) retry_count: u8,
    _pad0: [u8; 6],
    pub(crate) next_retry_ns: u64,
}

impl RootfsState {
    pub(crate) const fn zeroed() -> Self {
        Self {
            status: ROOTFS_STATE_PENDING,
            retry_count: 0,
            _pad0: [0; 6],
            next_retry_ns: 0,
        }
    }

    #[inline]
    fn ready(&self) -> bool {
        self.status == ROOTFS_STATE_READY
    }

    #[inline]
    fn failed(&self) -> bool {
        self.status == ROOTFS_STATE_FAILED
    }
}

fn monotonic_now_ns() -> u64 {
    syscall::syscall(SYS_CLOCK_GETTIME, CLOCK_MONOTONIC as u64, 0, 0, 0, 0, 0).value
}

fn signal_rootfs_event(bits: u64) {
    let slot = trona_runtime::client::caps::rootfs_ready_ntfn();
    if slot == 0 {
        return;
    }
    let _ = syscall::syscall(SYS_SIGNAL, slot, bits, 0, 0, 0, 0);
}

fn note_root_ready(state: &mut VfsState) {
    if state.rootfs.ready() {
        return;
    }
    state.rootfs.status = ROOTFS_STATE_READY;
    state.rootfs.next_retry_ns = 0;
    signal_rootfs_event(ROOTFS_READY_BITS);
}

fn note_root_failed(state: &mut VfsState) {
    if state.rootfs.failed() || state.rootfs.ready() {
        return;
    }
    state.rootfs.status = ROOTFS_STATE_FAILED;
    state.rootfs.next_retry_ns = 0;
    signal_rootfs_event(ROOTFS_FAILED_BITS);
}

fn schedule_retry(state: &mut VfsState, now_ns: u64) {
    state.rootfs.retry_count = state.rootfs.retry_count.saturating_add(1);
    if state.rootfs.retry_count >= ROOTFS_MAX_RETRIES {
        note_root_failed(state);
    } else {
        state.rootfs.next_retry_ns = now_ns.saturating_add(ROOTFS_RETRY_NS);
    }
}

fn root_fstab_entry(state: &VfsState) -> Option<FstabEntry> {
    let fstab_vh = state.bootstrap_lookup_path(b"/etc/fstab")?;
    let vnode = state.vnodes.get(fstab_vh)?;
    if vnode.vtype != VT_REG {
        return None;
    }
    let entries = unsafe { fstab::parse(vnode.data as *const u8, vnode.size as usize) };
    for entry in entries {
        if entry.active != 0 && entry.is_root() {
            return Some(entry);
        }
    }
    None
}

fn try_pivot_root(state: &mut VfsState, now_ns: u64) {
    let err = mount_ctl::do_pivot_root(state, b"/newroot", b"/initramfs");
    if err == TRONA_OK {
        note_root_ready(state);
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] root handoff complete, real root is now /\n");
        });
        return;
    }

    trona_runtime::uwarn!(|_lb| {
        _lb.str(b"[VFS] root pivot retry failed err=");
        _lb.hex(err);
        _lb.str(b"\n");
    });
    schedule_retry(state, now_ns);
}

/// Drive the `/newroot` mount + `pivot_root` state machine.
pub(crate) fn maybe_drive(state: &mut VfsState) {
    if state.rootfs.ready() || state.rootfs.failed() {
        return;
    }

    let now_ns = monotonic_now_ns();
    if state.rootfs.next_retry_ns != 0 && now_ns < state.rootfs.next_retry_ns {
        return;
    }

    if state.bootstrap.real_root_mount.is_valid()
        && state.bootstrap.real_root_mount != state.root_mount
    {
        try_pivot_root(state, now_ns);
        return;
    }

    let Some(entry) = root_fstab_entry(state) else {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] root handoff aborted: /etc/fstab has no root entry\n");
        });
        note_root_failed(state);
        return;
    };

    if entry.fstype_slice() != b"saltyfs" {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] root handoff aborted: unsupported root fstype ");
            _lb.bytes(entry.fstype_slice());
            _lb.str(b"\n");
        });
        note_root_failed(state);
        return;
    }

    let err = mount_ctl::do_bootstrap_mount(
        state,
        b"/newroot",
        entry.fstype_slice(),
        entry.flags,
        entry.opts_slice(),
    );
    if err == TRONA_OK {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] real root mounted on /newroot\n");
        });
        try_pivot_root(state, now_ns);
        return;
    }

    if err == TRONA_ALREADY_EXISTS
        && state.bootstrap.real_root_mount.is_valid()
        && state.bootstrap.real_root_mount != state.root_mount
    {
        try_pivot_root(state, now_ns);
        return;
    }

    trona_runtime::uwarn!(|_lb| {
        _lb.str(b"[VFS] root mount retry failed err=");
        _lb.hex(err);
        _lb.str(b" retry=");
        _lb.dec(state.rootfs.retry_count as u64);
        _lb.str(b"\n");
    });
    schedule_retry(state, now_ns);
}
