// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS namesrv — capability broker.
//!
//! Single-threaded reactor: one TCB blocks on the master EQ_WAIT;
//! every event (master MP readable, park Timer fired, registered cap
//! peer-closed) drains through `main_loop::run_loop`. Authorization is
//! by 64-bit badge bit layout (see `authz`); blocking LOOKUP /
//! SUBSCRIBE callers park their reply MessagePipe endpoint in
//! `PendingSubs` until a publisher REGISTER or Timer expiry resolves
//! the wait with `reply-marked MP_WRITE`.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;
extern crate uapi;

mod authz;
mod boot;
mod dispatch;
mod entry;
mod eviction;
mod main_loop;
mod owner;
mod policy;
mod registry;
mod segment_alloc;
mod slots;
mod subs;
mod watch;
mod wire;

use main_loop::ServerState;
use trona_kernel::syscall;

static mut STATE: ServerState = ServerState::new();

fn idle() -> ! {
    loop {
        syscall::invoke(
            uapi::KERNITE_CAP_SELF_TCB as u64,
            uapi::KERNITE_INV_TCB_YIELD as u64,
            0,
            0,
            0,
            0,
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[NAMESERV] starting\n");
    });

    let state = unsafe { &mut *(&raw mut STATE) };

    if !boot::read_startup_caps(state) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[NAMESERV] startup cap_table missing required namesrv-private roles\n");
        });
        idle();
    }
    state.clock_cap = trona_runtime::client::caps::clock_cap().addr();

    if !boot::reserve_internal_slots() {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[NAMESERV] failed to reserve recv-scratch / cap-stash slots\n");
        });
        idle();
    }

    if !boot::arm_baseline_watches(state) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[NAMESERV] failed to arm master MP Watch\n");
        });
        idle();
    }

    let ready_err = boot::signal_core_ready(state);
    if ready_err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[NAMESERV] failed to signal core ready err=");
            _lb.hex(ready_err as u64);
            _lb.str(b"\n");
        });
        idle();
    }

    main_loop::run_loop(state);
}
