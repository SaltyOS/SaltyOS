//! SaltyOS VFS Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Filesystem namespace service.
//!
//! The owner thread is the sole mutator of namespace state: vnodes,
//! mounts, mount namespaces, and client-visible root transitions all
//! live behind one `VfsState`. Worker threads exist to carry blocking
//! work without taking ownership of namespace metadata.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_loader;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;

trona_runtime::local_cap!(pub(crate) netsrv_ep = "vfs:netsrv_ep");
trona_runtime::local_cap!(pub(crate) posix_ttysrv_ep = "vfs:posix_ttysrv");

mod arena;
mod boot;
mod fileops;
mod fs;
mod ipc;
mod owner;
mod personality;
mod server;
mod vfs_core;

use trona_kernel::core_types::*;
use trona_kernel::ipc as trona_ipc;
use trona_kernel::syscall;
use trona_protocol::posix::*;
use trona_runtime::thread::thread;
use uapi::*;

// ======================================================================
// Helpers
// ======================================================================

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona_runtime::current_ipc_ctx()
}

fn register_with_namesrv() {
    if trona_runtime::client::caps::namesrv_ep() == 0 {
        return;
    }

    let mut reg_msg = TronaMsg::zeroed();
    let mut reg_reply = TronaMsg::zeroed();
    let svc_name = b"vfs";

    // Mirror `userland/core/namesrv/src/wire.rs` —
    // `ENTRY_FLAG_BADGE_AS_CALLER` makes namesrv mint a per-caller
    // badged copy of vfs's master service-EP send on every LOOKUP so
    // vfs's request dispatcher can demultiplex callers by `client_id`.
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    reg_msg.label = NAMESRV_REGISTER;
    reg_msg.regs[0] = svc_name.len() as u64;

    unsafe {
        let dst = &raw mut reg_msg.regs[1] as *mut u8;
        for i in 0..svc_name.len() {
            *dst.add(i) = svc_name[i];
        }
    }
    reg_msg.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    reg_msg.length = (REGISTER_FLAGS_REG + 1) as u64;

    let publish_ep = trona_runtime::client::caps::service_client_ep_for_transfer();
    unsafe {
        trona_ipc::set_send_cap_ctx(ipc_ctx(), 0, publish_ep);
    }
    let err = unsafe {
        trona_ipc::call_ctx(
            ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep(),
            &raw const reg_msg,
            &raw mut reg_reply,
        )
    };
    trona_runtime::client::caps::finish_service_client_ep_transfer(publish_ep, err);
    if err == 0 && reg_reply.label == TRONA_OK {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] registered with namesrv\n");
        });
    } else {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: namesrv registration failed err=");
            _lb.hex(err as u64);
            _lb.str(b" label=");
            _lb.hex(reg_reply.label);
            _lb.str(b"\n");
        });
    }
}

fn allocate_netsrv_callback_ep(state: &mut owner::VfsState) {
    if crate::netsrv_ep() == 0 {
        return;
    }
    let Some(slot) = trona_runtime::core::slot_alloc::slot_alloc() else {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: callback EP slot alloc failed\n");
        });
        return;
    };
    let Some(ut) = trona_runtime::runtime_get_bootstrap_untyped() else {
        let _ = trona_runtime::core::slot_alloc::slot_free(slot);
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: bootstrap untyped unavailable for callback EP\n");
        });
        return;
    };
    let err = trona_kernel::invoke::untyped_retype(ut, OBJ_ENDPOINT, 0, slot);
    if err != 0 {
        let _ = trona_runtime::core::slot_alloc::slot_free(slot);
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: callback EP retype failed err=");
            _lb.dec(err as u64);
            _lb.str(b"\n");
        });
        return;
    }
    state.netsrv_callback_ep = slot;
}

fn bind_boot_notifications() {
    if trona_runtime::client::caps::pty_ntfn() == 0 {
        return;
    }

    let err = trona_kernel::invoke::tcb_bind_notification(
        CAP_SELF_TCB,
        trona_runtime::client::caps::pty_ntfn(),
    );
    if err == 0 {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] PTY notification bound to TCB\n");
        });
        // The owner can bind only one notification object. Reuse
        // pty_ntfn as the physical fan-in object, but give worker
        // completions their own bit namespace so they cannot be
        // mistaken for PTY 0.
        let worker_bit = owner::backend_rpc::WORKER_COMPLETION_NTFN_BIT;
        let (worker_ntfn, worker_signal_bits) = match trona_runtime::core::slot_alloc::slot_alloc()
        {
            Some(slot) => {
                let mint_err = trona_kernel::invoke::cnode_mint(
                    CAP_SELF_CSPACE,
                    trona_runtime::client::caps::pty_ntfn(),
                    CAP_SELF_CSPACE,
                    slot,
                    worker_bit,
                );
                if mint_err == 0 {
                    trona_runtime::uinfo!(|_lb| {
                        _lb.str(b"[VFS] worker completion notification alias minted bit=");
                        _lb.hex(worker_bit);
                        _lb.str(b"\n");
                    });
                    (slot, 0)
                } else {
                    let _ = trona_runtime::core::slot_alloc::slot_free(slot);
                    trona_runtime::uwarn!(|_lb| {
                        _lb.str(b"[VFS] WARN: worker notification alias mint failed err=");
                        _lb.hex(mint_err as u64);
                        _lb.str(b"; using raw PTY notification with explicit worker bit\n");
                    });
                    (trona_runtime::client::caps::pty_ntfn(), worker_bit)
                }
            }
            None => {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] WARN: worker notification alias slot alloc failed; ");
                    _lb.str(b"using raw PTY notification with explicit worker bit\n");
                });
                (trona_runtime::client::caps::pty_ntfn(), worker_bit)
            }
        };
        owner::backend_rpc::set_worker_completion_ntfn(worker_ntfn, worker_signal_bits);
    } else {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: PTY notification bind failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
    }
}

fn signal_ready() -> u64 {
    syscall::syscall(
        SYS_SIGNAL,
        trona_runtime::client::caps::readiness_ntfn(),
        1,
        0,
        0,
        0,
        0,
    )
    .error
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[VFS] SaltyOS VFS server starting\n");
    });

    let mut state = match owner::VfsState::new() {
        Some(state) => state,
        None => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] FATAL: failed to allocate namespace state\n");
            });
            idle();
        }
    };

    if !state.initialize_bootstrap_namespace() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] FATAL: failed to initialize bootstrap namespace\n");
        });
        idle();
    }
    if !boot::extract_initrd(&mut state) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] FATAL: failed to extract initrd\n");
        });
        idle();
    }

    // The owner owns the service endpoint's receive slot. Keeping it
    // explicit in `VfsState` prevents worker-side IPC from aliasing the
    // same slot and keeps cap-delivery paths honest.
    state.owner_recv_slot = match trona_runtime::core::slot_alloc::slot_alloc() {
        Some(slot) => slot,
        None => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] FATAL: no owner receive slot\n");
            });
            idle();
        }
    };
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx(),
            CAP_SELF_CSPACE,
            state.owner_recv_slot,
            0,
        );
    }

    // Each worker receives its own receive slot. Owner and worker IPC
    // streams must never alias, especially once mount backends begin to
    // issue blocking RPC on behalf of the namespace layer.
    for idx in 0..owner::worker::MAX_WORKERS {
        if let Some(slot) = trona_runtime::core::slot_alloc::slot_alloc() {
            state.worker_recv_slots[idx] = slot;
            owner::worker::set_worker_recv_slot(idx, slot);
        } else {
            break;
        }
    }

    register_with_namesrv();
    bind_boot_notifications();
    allocate_netsrv_callback_ep(&mut state);
    // NET_REGISTER_VFS is fired lazily — netsrv depends on vfs and
    // therefore comes up *after* us. The owner loop's idle timer
    // re-tries registration until netsrv answers.

    let spawn_config = match thread::SpawnConfig::for_runtime_bootstrap_untyped() {
        Ok(config) => config,
        Err(err) => {
            trona_runtime::uwarn!(|_lb| {
                _lb.str(b"[VFS] WARN: worker bootstrap unavailable err=");
                _lb.dec(err.as_i32() as u64);
                _lb.str(b"\n");
            });
            let ready_err = signal_ready();
            if ready_err == 0 {
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[VFS] owner loop ready (no workers)\n");
                });
            } else {
                trona_runtime::uwarn!(|_lb| {
                    _lb.str(b"[VFS] WARN: readiness signal failed err=");
                    _lb.hex(ready_err);
                    _lb.str(b"\n");
                });
            }
            unsafe { owner::loop_::run_owner_loop(&mut state) }
        }
    };

    state.workers_spawned = unsafe { owner::worker::spawn_workers(spawn_config) };

    let ready_err = signal_ready();
    if ready_err == 0 {
        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[VFS] owner loop ready\n");
        });
    } else {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: readiness signal failed err=");
            _lb.hex(ready_err);
            _lb.str(b"\n");
        });
    }

    unsafe { owner::loop_::run_owner_loop(&mut state) }
}

pub(crate) fn idle() -> ! {
    loop {
        trona_kernel::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
