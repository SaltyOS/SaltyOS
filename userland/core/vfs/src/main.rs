//! SaltyOS VFS Server
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! VFS server with ramfs, devfs, procfs, tmpfs, saltyfs. FHS-compliant layout.

#![no_std]
#![no_main]

extern crate trona;
extern crate trona_loader;

mod arena;
mod backend;
mod boot;
mod fileops;
mod fs;
mod ipc;
mod owner;
mod personality;
mod server;
mod vfs_core;

pub use server::state::*;

use trona::consts::kernel::*;
use trona::consts::server::*;
use trona::protocol::namesrv::*;
use trona::serial;
use trona::types::core::*;

use server::consts::*;

// ======================================================================
// Helper functions
// ======================================================================

pub(crate) fn puts(s: &[u8]) {
    serial::serial_puts(s);
}

fn signal_ready() {
    let _ = trona::syscall::syscall(SYS_SIGNAL, trona::caps::readiness_ntfn(), 1, 0, 0, 0, 0);
}

pub(crate) fn ipc_ctx() -> *mut IpcContext {
    trona::current_ipc_ctx()
}

// ======================================================================
// ChaCha20-based CSPRNG for /dev/urandom
// ======================================================================

const CHACHA20_SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

#[inline(always)]
fn chacha_qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

/// Generate one 64-byte ChaCha20 keystream block into `out`.
unsafe fn chacha20_block(key: *const u8, counter: u64, out: *mut u8) {
    let mut state = [0u32; 16];

    state[0] = CHACHA20_SIGMA[0];
    state[1] = CHACHA20_SIGMA[1];
    state[2] = CHACHA20_SIGMA[2];
    state[3] = CHACHA20_SIGMA[3];

    unsafe {
        let mut i = 0;
        while i < 8 {
            let off = i * 4;
            state[4 + i] = u32::from_le_bytes([
                *key.add(off),
                *key.add(off + 1),
                *key.add(off + 2),
                *key.add(off + 3),
            ]);
            i += 1;
        }
    }

    state[12] = counter as u32;
    state[13] = (counter >> 32) as u32;
    state[14] = 0;
    state[15] = 0;

    let initial = state;

    let mut r = 0;
    while r < 10 {
        chacha_qr(&mut state, 0, 4, 8, 12);
        chacha_qr(&mut state, 1, 5, 9, 13);
        chacha_qr(&mut state, 2, 6, 10, 14);
        chacha_qr(&mut state, 3, 7, 11, 15);
        chacha_qr(&mut state, 0, 5, 10, 15);
        chacha_qr(&mut state, 1, 6, 11, 12);
        chacha_qr(&mut state, 2, 7, 8, 13);
        chacha_qr(&mut state, 3, 4, 9, 14);
        r += 1;
    }

    unsafe {
        let mut i = 0;
        while i < 16 {
            let val = state[i].wrapping_add(initial[i]);
            let bytes = val.to_le_bytes();
            *out.add(i * 4) = bytes[0];
            *out.add(i * 4 + 1) = bytes[1];
            *out.add(i * 4 + 2) = bytes[2];
            *out.add(i * 4 + 3) = bytes[3];
            i += 1;
        }
    }
}

pub(crate) unsafe fn urandom_init() {
    unsafe {
        let key = &raw mut URANDOM_KEY as *mut u8;
        let mut filled = 0usize;

        // Primary: seed from hardware RDRAND/RNDR via kernel syscall
        while filled < 32 {
            match trona::syscall::sys_getrandom() {
                Some(val) => {
                    let bytes = val.to_le_bytes();
                    let remain = 32 - filled;
                    let n = if remain < 8 { remain } else { 8 };
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), key.add(filled), n);
                    filled += n;
                }
                None => {
                    // Fallback: TSC + clock mixing
                    let mut ts = Timespec::zeroed();
                    trona::syscall::syscall(
                        SYS_CLOCK_GETTIME,
                        0,
                        &raw mut ts as u64,
                        0,
                        0,
                        0,
                        0,
                    );
                    let tsc: u64;
                    #[cfg(target_arch = "x86_64")]
                    {
                        let tsc_lo: u32;
                        let tsc_hi: u32;
                        core::arch::asm!("rdtsc", out("eax") tsc_lo, out("edx") tsc_hi);
                        tsc = (tsc_hi as u64) << 32 | tsc_lo as u64;
                    }
                    #[cfg(target_arch = "aarch64")]
                    {
                        core::arch::asm!("mrs {}, CNTVCT_EL0", out(reg) tsc);
                    }
                    let v = ts
                        .tv_nsec
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(tsc);
                    let bytes = v.to_le_bytes();
                    let remain = 32 - filled;
                    let n = if remain < 8 { remain } else { 8 };
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), key.add(filled), n);
                    filled += n;
                }
            }
        }

        URANDOM_COUNTER = 0;
        URANDOM_CTR = 0;
        URANDOM_BUF_POS = 64; // Force refill on first read
    }
}

pub(crate) unsafe fn urandom_next() -> u64 {
    unsafe {
        URANDOM_COUNTER += 1;
        if URANDOM_COUNTER >= URANDOM_RESEED_INTERVAL {
            URANDOM_COUNTER = 0;
            // Reseed: XOR fresh RDRAND bytes into the key
            if let Some(fresh) = trona::syscall::sys_getrandom() {
                let key = &raw mut URANDOM_KEY as *mut u8;
                let bytes = fresh.to_le_bytes();
                let mut i = 0;
                while i < 8 {
                    *key.add(i) ^= bytes[i];
                    i += 1;
                }
            }
        }

        // Refill buffer if exhausted
        let pos = URANDOM_BUF_POS;
        if pos + 8 > 64 {
            chacha20_block(
                &raw const URANDOM_KEY as *const u8,
                URANDOM_CTR,
                &raw mut URANDOM_BUF as *mut u8,
            );
            URANDOM_CTR = URANDOM_CTR.wrapping_add(1);
            URANDOM_BUF_POS = 0;
            let buf = &raw const URANDOM_BUF as *const u8;
            let result = u64::from_le_bytes([
                *buf, *buf.add(1), *buf.add(2), *buf.add(3),
                *buf.add(4), *buf.add(5), *buf.add(6), *buf.add(7),
            ]);
            URANDOM_BUF_POS = 8;
            return result;
        }

        let buf = (&raw const URANDOM_BUF as *const u8).add(pos);
        let result = u64::from_le_bytes([
            *buf, *buf.add(1), *buf.add(2), *buf.add(3),
            *buf.add(4), *buf.add(5), *buf.add(6), *buf.add(7),
        ]);
        URANDOM_BUF_POS = pos + 8;
        result
    }
}

pub(crate) fn str_equal_raw(a: *const u8, alen: usize, b: *const u8, blen: usize) -> bool {
    if alen != blen {
        return false;
    }
    for i in 0..alen {
        unsafe {
            if *a.add(i) != *b.add(i) {
                return false;
            }
        }
    }
    true
}

// ======================================================================
// Initialization
// ======================================================================

unsafe fn init_fb_info() {
    unsafe {
        let bootinfo = BOOTINFO_VADDR as *const u8;
        let magic = (bootinfo as *const u64).read();
        if magic != BOOTINFO_MAGIC {
            return;
        }
        let p32 = bootinfo.add(32) as *const u32;
        FB_WIDTH = p32.read();
        FB_HEIGHT = p32.add(1).read();
        FB_PITCH = p32.add(2).read();
        FB_BPP = *bootinfo.add(44);
        FB_RED_POS = *bootinfo.add(45);
        FB_RED_SIZE = *bootinfo.add(46);
        FB_GREEN_POS = *bootinfo.add(47);
        FB_GREEN_SIZE = *bootinfo.add(48);
        FB_BLUE_POS = *bootinfo.add(49);
        FB_BLUE_SIZE = *bootinfo.add(50);
    }
}

// ======================================================================
// Entry point
// ======================================================================

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    trona::uinfo!(|_lb| {
        _lb.str(b"[VFS] SaltyOS VFS server starting\n");
    });

    let mut state = match owner::VfsState::new() {
        Some(state) => state,
        None => {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] FATAL: failed to allocate VfsState\n");
            });
            idle();
        }
    };

    unsafe {
        let derr = init_dynamic_state_storage();
        if derr != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[VFS] FAIL: state storage init err=");
                _lb.hex(derr as u64);
                _lb.str(b"\n");
            });
            idle();
        }
    }

    unsafe {
        urandom_init();
        boot::init_boot_env(&mut state);
        init_fb_info();
    }

    trona::uinfo!(|_lb| {
        _lb.str(b"[VFS] Filesystem ready\n");
    });

    if trona::caps::namesrv_ep() != 0 {
        let mut reg_msg = TronaMsg::zeroed();
        let mut reg_reply = TronaMsg::zeroed();
        let svc_name = b"vfs";
        reg_msg.label = NS_REGISTER;
        reg_msg.regs[0] = svc_name.len() as u64;
        reg_msg.length = 1 + (svc_name.len() as u64 + 7) / 8;
        let ns_dst = &raw mut reg_msg.regs[1] as *mut u8;
        unsafe {
            for i in 0..svc_name.len() {
                *ns_dst.add(i) = svc_name[i];
            }
        }

        unsafe {
            trona::ipc::set_send_cap_ctx(ipc_ctx(), 0, trona::caps::service_ep());
            let err = trona::ipc::call_ctx(
                ipc_ctx(),
                trona::caps::namesrv_ep(),
                &raw const reg_msg,
                &raw mut reg_reply,
            );
            if err == 0 && reg_reply.label == TRONA_OK {
                trona::uinfo!(|_lb| {
                    _lb.str(b"[VFS] registered with namesrv\n");
                });
            } else {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[VFS] WARN: namesrv registration failed\n");
                });
            }
        }
    }

    {
        let err = trona::invoke::tcb_bind_notification(CAP_SELF_TCB, VFS_CAP_PTY_NTFN);
        if err == 0 {
            trona::uinfo!(|_lb| {
                _lb.str(b"[VFS] PTY notification bound to TCB\n");
            });
        } else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[VFS] WARN: PTY notification bind failed\n");
            });
        }
    }

    signal_ready();

    if unsafe { !backend::prepare_backend_callback_endpoint() } {
        trona::uerror!(|_lb| {
            _lb.str(b"[VFS] failed to prepare backend callback endpoint\n");
        });
        idle();
    }

    if unsafe { !backend::ensure_mmsrv_pager_callback_registered() } {
        trona::uwarn!(|_lb| {
            _lb.str(b"[VFS] WARN: mmsrv pager callback EP registration failed; using service fallback\n");
        });
    }

    #[cfg(not(vfs_worker_pool))]
    {
        // Allocate receive slot.
        unsafe {
            let slot = match trona::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[VFS] FATAL: no receive slot\n");
                    });
                    idle();
                }
            };
            state.current_recv_slot = slot;
            state.worker_recv_slots[0] = slot;

            // Receive-slot statics are still consumed by the IPC loop helpers.
            CURRENT_RECV_SLOT = slot;
            set_worker_recv_slot(0, slot);
            trona::ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);
        }

        let recv_endpoints = [trona::caps::service_ep(), VFS_CAP_BACKEND_CALLBACK_EP];

        // Enter the owner loop — never returns.
        unsafe { owner::loop_::run_owner_loop(&mut state, &recv_endpoints) }
    }

    #[cfg(vfs_worker_pool)]
    {
        let (workers, overridden) = ipc::loop_::compute_vfs_worker_count();
        trona::uinfo!(|_lb| {
            _lb.str(b"[VFS] worker pool mode: ");
            _lb.dec(workers as u64);
            if overridden {
                _lb.str(b" workers (override)\n");
            } else {
                _lb.str(b" workers (auto)\n");
            }
        });

        unsafe {
            WORKER_RECV_SLOT_COUNT = workers;
            for worker_idx in 0..workers {
                let slot = match trona::slot_alloc::slot_alloc() {
                    Some(s) => s,
                    None => {
                        trona::uerror!(|_lb| {
                            _lb.str(b"[VFS] FATAL: no worker receive slot for pager IPC\n");
                        });
                        idle();
                    }
                };
                set_worker_recv_slot(worker_idx, slot);
                if worker_idx == 0 {
                    CURRENT_RECV_SLOT = slot;
                    trona::ipc::set_receive_slot_ctx(ipc_ctx(), CAP_SELF_CSPACE, slot, 0);
                }
            }
        }

        let sc_cap = trona::caps::sc_cap();
        let recv_endpoints = [trona::caps::service_ep(), VFS_CAP_BACKEND_CALLBACK_EP];
        let config = trona::worker::WorkerConfig {
            worker_count: workers,
            endpoints: recv_endpoints.as_ptr(),
            endpoint_count: recv_endpoints.len(),
            untyped: CAP_UNTYPED_START,
            self_tcb: CAP_SELF_TCB,
            self_sc: sc_cap,
            stack_pages: 32,
            pool_budget_us: 0,
            pool_period_us: 0,
            cspace_depth: 0,
            on_enter: Some(ipc::loop_::vfs_worker_on_enter),
            next_timeout_ns: Some(ipc::loop_::vfs_worker_next_timeout_ns),
            on_timeout: Some(ipc::loop_::vfs_worker_on_timeout),
        };
        unsafe { trona::worker::run_workers(&config, ipc::loop_::vfs_worker_handler) }
    }
}

pub(crate) fn idle() -> ! {
    loop {
        trona::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}
