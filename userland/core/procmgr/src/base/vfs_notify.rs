//! Asynchronous VFS notification queue.
//!
//! `send_timed` is retired, but procmgr still needs best-effort
//! fire-and-forget `VFS_CLIENT_EXIT` / `VFS_CLIENT_EXEC` delivery
//! without stalling the main server loop. A tiny helper thread owns the
//! blocking `send_ctx` and drains a bounded in-process queue.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, Ordering};

use trona_kernel::core_types::TronaMsg;
use trona_kernel::ipc;
use trona_runtime::thread::sync::{Mutex, Semaphore};
use trona_runtime::thread::thread;

const VFS_NOTIFY_RING_CAP: usize = 32;

#[derive(Clone, Copy)]
struct VfsNotifyJob {
    label: u64,
    badge: u64,
}

impl VfsNotifyJob {
    const fn empty() -> Self {
        Self { label: 0, badge: 0 }
    }
}

static VFS_NOTIFY_LOCK: Mutex = Mutex::new();
static VFS_NOTIFY_READY: Semaphore = Semaphore::new(0);
static VFS_NOTIFY_STARTED: AtomicBool = AtomicBool::new(false);
static mut VFS_NOTIFY_RING: [VfsNotifyJob; VFS_NOTIFY_RING_CAP] =
    [VfsNotifyJob::empty(); VFS_NOTIFY_RING_CAP];
static mut VFS_NOTIFY_HEAD: usize = 0;
static mut VFS_NOTIFY_TAIL: usize = 0;
static mut VFS_NOTIFY_COUNT: usize = 0;

pub(crate) unsafe fn initialize() {
    if VFS_NOTIFY_STARTED.load(Ordering::Acquire) {
        return;
    }

    let cfg = match thread::SpawnConfig::for_runtime_bootstrap_untyped() {
        Ok(cfg) => cfg,
        Err(err) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS notify worker config failed err=");
                _lb.dec(err.as_i32() as u64);
                _lb.str(b"\n");
            });
            return;
        }
    };

    match unsafe { thread::spawn_fn(vfs_notify_worker_entry, core::ptr::null_mut(), &cfg) } {
        Ok(_) => {
            VFS_NOTIFY_STARTED.store(true, Ordering::Release);
        }
        Err(err) => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] VFS notify worker spawn failed err=");
                _lb.dec(err.as_i32() as u64);
                _lb.str(b"\n");
            });
        }
    }
}

pub(crate) fn enqueue_client_exit(badge: u64) -> bool {
    enqueue_job(trona_protocol::vfs::public::VFS_CLIENT_EXIT, badge)
}

pub(crate) fn enqueue_client_exec(badge: u64) -> bool {
    enqueue_job(trona_protocol::vfs::public::VFS_CLIENT_EXEC, badge)
}

fn enqueue_job(label: u64, badge: u64) -> bool {
    if !VFS_NOTIFY_STARTED.load(Ordering::Acquire) {
        return false;
    }

    VFS_NOTIFY_LOCK.lock();
    let pushed = unsafe {
        if VFS_NOTIFY_COUNT == VFS_NOTIFY_RING_CAP {
            false
        } else {
            VFS_NOTIFY_RING[VFS_NOTIFY_TAIL] = VfsNotifyJob { label, badge };
            VFS_NOTIFY_TAIL = (VFS_NOTIFY_TAIL + 1) % VFS_NOTIFY_RING_CAP;
            VFS_NOTIFY_COUNT += 1;
            true
        }
    };
    VFS_NOTIFY_LOCK.unlock();

    if pushed {
        let _ = VFS_NOTIFY_READY.post();
    }
    pushed
}

fn pop_job() -> Option<VfsNotifyJob> {
    VFS_NOTIFY_LOCK.lock();
    let job = unsafe {
        if VFS_NOTIFY_COUNT == 0 {
            None
        } else {
            let job = VFS_NOTIFY_RING[VFS_NOTIFY_HEAD];
            VFS_NOTIFY_RING[VFS_NOTIFY_HEAD] = VfsNotifyJob::empty();
            VFS_NOTIFY_HEAD = (VFS_NOTIFY_HEAD + 1) % VFS_NOTIFY_RING_CAP;
            VFS_NOTIFY_COUNT -= 1;
            Some(job)
        }
    };
    VFS_NOTIFY_LOCK.unlock();
    job
}

unsafe extern "C" fn vfs_notify_worker_entry(_arg: *mut u8) {
    loop {
        VFS_NOTIFY_READY.wait();
        let Some(job) = pop_job() else {
            continue;
        };

        let ep = crate::base::cap_helpers::vfs_provider_ep();
        if ep == 0 {
            continue;
        }

        let mut msg = TronaMsg::zeroed();
        msg.label = job.label;
        msg.length = 1;
        msg.regs[0] = job.badge;
        let err = unsafe { ipc::send_ctx(crate::ipc_ctx(), ep, &raw const msg) };
        if err != 0 {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] VFS notify send failed label=");
                _lb.hex(job.label);
                _lb.str(b" badge=");
                _lb.hex(job.badge);
                _lb.str(b" err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
        }
    }
}
