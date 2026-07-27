// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS init — PID 1 supervisor.
//!
//! Boot starts here when the kernel jumps into the init image with the
//! standard system-cap quintet, the boot untyped seed, and the initrd
//! frame. We split untyped, spawn namesrv → rsrcsrv → mmsrv with
//! direct retypes (no rsrcsrv yet), retroactively bind every
//! pre-mmsrv TCB's fault MP, then walk the manifest's topo-sort
//! to spawn each remaining service. Steady-state work runs on the
//! owner reactor in `supervisor::owner_loop::run`.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_loader;
extern crate trona_posix;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;
extern crate uapi;

mod internal_slots;
mod supervisor;
mod wire;

use supervisor::SupervisorState;

static mut STATE: SupervisorState = SupervisorState::new();

fn idle() -> ! {
    loop {
        trona_kernel::syscall::yield_now();
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[INIT] PID 1 starting\n");
    });

    let state = unsafe { &mut *(&raw mut STATE) };

    // `run_full_sequence` reads bootinfo / initrd in Stage A, then
    // parses `.service` manifests *before* spawning any core service
    // so Stage G has a populated topo-sort to walk.
    if let Err(err) = supervisor::boot::run_full_sequence(state) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[INIT] boot failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        idle();
    }

    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[INIT] entering owner loop, services=");
        _lb.dec(state.manifest.count as u64);
        _lb.str(b"\n");
    });

    supervisor::owner_loop::run(state);
}
