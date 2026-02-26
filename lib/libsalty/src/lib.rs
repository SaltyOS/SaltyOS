//! libsalty -- SaltyOS userspace system library (Rust)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! This crate has a dual personality:
//!
//! 1. **Rust modules** -- `syscall`, `ipc`, `invoke`, `posix`, etc. provide
//!    typed Rust APIs for kernel syscalls, IPC, capability invocations, POSIX
//!    compatibility, ELF loading, and CPIO parsing.
//!
//! 2. **C ABI exports** -- Every `salty_*` function in this file is
//!    `#[unsafe(no_mangle)] pub extern "C"` so that the runtime dynamic linker
//!    (`rtld`) can resolve them from `libsalty.so`. C programs link against
//!    these symbols via `saltyc`.
//!
//! # Global state
//!
//! - [`__salty_ipc_ctx`] -- Per-process IPC context (IPC buffer pointer +
//!   send-cap counter). Initialized by `rtld` or the CRT before `main`.
//! - `__sig_*` -- Signal handler table, blocked mask, and `sa_flags` / `sa_mask`
//!   arrays for POSIX signal delivery.
//! - `__salty_next_frame_slot` / `__salty_slot_base` / `__salty_slot_count` --
//!   Weak symbols overridden by `rtld` with per-process slot allocator state
//!   from auxv entries.
//!
//! See `docs/design/overview.md` for the overall SaltyOS architecture.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(linkage)]

pub mod consts;
pub mod cpio;
pub mod dns;
pub mod elf_dynamic;
pub mod elf_loader;
pub mod framebuffer;
pub mod invoke;
pub mod ipc;
pub mod layout;
pub mod posix;
pub mod posix_mm;
pub mod pthread;
pub mod serial;
pub mod signals;
pub mod slot_alloc;
pub mod sync;
pub mod syscall;
pub mod tls;
pub mod types;

// Re-export for convenience
pub use consts::*;
pub use types::*;

// Standard child CSpace layout
const CAP_PROCMGR_EP: u64 = 3;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

/// Per-process IPC context holding the IPC buffer pointer and send-cap count.
/// Initialized by `rtld` (dynamic) or the CRT (static) before `main`.
#[unsafe(no_mangle)]
pub static mut __salty_ipc_ctx: IpcContext = IpcContext::new();

/// Per-signal handler function pointers (indexed by signal number).
/// `SIG_DFL` (0) and `SIG_IGN` (1) are special sentinel values.
#[unsafe(no_mangle)]
pub static __sig_handlers: [core::sync::atomic::AtomicUsize; NSIG] =
    [const { core::sync::atomic::AtomicUsize::new(0) }; NSIG];

/// Atomic flag: 1 once signal infrastructure has been initialized.
#[unsafe(no_mangle)]
pub static __sig_initialized: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(0);

/// Bitmask of currently blocked signals (bit N = signal N blocked).
#[unsafe(no_mangle)]
pub static mut __sig_blocked_mask: u32 = 0;

/// Per-signal sa_mask: additional signals to block during handler execution.
#[unsafe(no_mangle)]
pub static mut __sig_sa_mask: [u32; NSIG] = [0; NSIG];

/// Per-signal sa_flags (e.g. `SA_RESETHAND`).
#[unsafe(no_mangle)]
pub static mut __sig_sa_flags: [i32; NSIG] = [0; NSIG];

/// Next available CNode slot for frame allocation. Weak symbol overridden
/// by `rtld` with the value from the process's slot pool.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __salty_next_frame_slot: u64 = 64;

/// Base of the per-process CNode slot pool (from `AT_SALTY_SLOT_BASE` auxv).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __salty_slot_base: u64 = 0;

/// Number of slots in the per-process pool (from `AT_SALTY_SLOT_COUNT` auxv).
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __salty_slot_count: u64 = 0;

/// Notification cap for CSpace expansion signaling
/// (from `AT_SALTY_CSPACE_NTFN` auxv). 0 if not available.
#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __salty_cspace_ntfn: u64 = 0;

// ---------------------------------------------------------------------------
// Panic handler (for libsalty.so and statically-linked binaries)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    serial::serial_puts(b"[PANIC] userspace\n");
    loop {
        syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

// ---------------------------------------------------------------------------
// C ABI exports: IPC operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_invoke(
    cap: Cap,
    label: u64,
    arg0: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
) -> SaltyResult {
    invoke::invoke(cap, label, arg0, arg1, arg2, arg3)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_send(ep: Cap, msg: *const SaltyMsg) -> i32 {
    unsafe { ipc::send_ctx(tls::current_ipc_ctx(), ep, msg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_recv(ep: Cap, msg: *mut SaltyMsg, badge: *mut u64) -> i32 {
    unsafe { ipc::recv_ctx(tls::current_ipc_ctx(), ep, msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_call(ep: Cap, msg: *const SaltyMsg, reply: *mut SaltyMsg) -> i32 {
    unsafe { ipc::call_ctx(tls::current_ipc_ctx(), ep, msg, reply) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_reply_recv(
    ep: Cap,
    reply: *const SaltyMsg,
    out_msg: *mut SaltyMsg,
    badge: *mut u64,
) -> i32 {
    unsafe { ipc::reply_recv_ctx(tls::current_ipc_ctx(), ep, reply, out_msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_nbsend(ep: Cap, msg: *const SaltyMsg) -> i32 {
    unsafe { ipc::nbsend_ctx(tls::current_ipc_ctx(), ep, msg) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Notification operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_signal(ntfn: Cap, bits: u64) -> i32 {
    syscall::syscall(SYS_SIGNAL, ntfn, bits, 0, 0, 0, 0).error as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_wait(ntfn: Cap) -> u64 {
    syscall::syscall(SYS_WAIT, ntfn, 0, 0, 0, 0, 0).value
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_poll(ntfn: Cap, bits: *mut u64) -> i32 {
    let r = syscall::syscall(SYS_POLL, ntfn, 0, 0, 0, 0, 0);
    if r.error == 0 && !bits.is_null() {
        unsafe {
            *bits = r.value;
        }
    }
    r.error as i32
}

// ---------------------------------------------------------------------------
// C ABI exports: Misc syscalls
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_yield() {
    syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_debug_putchar(c: u8) {
    syscall::syscall(SYS_DEBUG_PUTCHAR, c as u64, 0, 0, 0, 0, 0);
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_debug_dump_state() {
    syscall::syscall(SYS_DEBUG_DUMP_STATE, 0, 0, 0, 0, 0, 0);
}

// ---------------------------------------------------------------------------
// C ABI exports: Capability invocations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_untyped_retype(
    untyped: Cap,
    new_type: u64,
    size_bits: u64,
    dest_slot: u64,
) -> i32 {
    invoke::untyped_retype(untyped, new_type, size_bits, dest_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_configure(tcb: Cap, rip: u64, rsp: u64, ipc_buf: u64) -> i32 {
    invoke::tcb_configure(tcb, rip, rsp, ipc_buf)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_resume(tcb: Cap) -> i32 {
    invoke::tcb_resume(tcb)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_set_space(tcb: Cap, cspace: Cap, vspace: Cap) -> i32 {
    invoke::tcb_set_space(tcb, cspace, vspace)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_set_fault_handler(tcb: Cap, fault_ep: Cap) -> i32 {
    invoke::tcb_set_fault_handler(tcb, fault_ep)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_set_ipc_buffer(tcb: Cap, addr: u64) -> i32 {
    invoke::tcb_set_ipc_buffer(tcb, addr)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_write_registers(tcb: Cap, flags: u64, rip: u64, rsp: u64) -> i32 {
    invoke::tcb_write_registers(tcb, flags, rip, rsp)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_suspend(tcb: Cap) -> i32 {
    invoke::tcb_suspend(tcb)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_sc_configure(sc: Cap, budget_us: u64, period_us: u64) -> i32 {
    invoke::sc_configure(sc, budget_us, period_us)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_sc_bind(sc: Cap, tcb: Cap) -> i32 {
    invoke::sc_bind(sc, tcb)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_vspace_map(vspace: Cap, frame: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke::vspace_map(vspace, frame, vaddr, flags)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_vspace_unmap(vspace: Cap, vaddr: u64) -> i32 {
    invoke::vspace_unmap(vspace, vaddr)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_vspace_map_pt(vspace: Cap, frame: Cap, vaddr: u64, level: u64) -> i32 {
    invoke::vspace_map_pt(vspace, frame, vaddr, level)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_vspace_walk(vspace: Cap, start_vaddr: u64, max_entries: u64) -> i32 {
    invoke::vspace_walk(vspace, start_vaddr, max_entries)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_vspace_copy_page(src_vspace: Cap, src_vaddr: u64, dst_frame: Cap) -> i32 {
    invoke::vspace_copy_page(src_vspace, src_vaddr, dst_frame)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_vspace_clone_cow_page(
    src_vspace: Cap,
    src_vaddr: u64,
    dst_vspace: Cap,
    dst_vaddr: u64,
) -> i32 {
    invoke::vspace_clone_cow_page(src_vspace, src_vaddr, dst_vspace, dst_vaddr)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_copy(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    rights: u64,
) -> i32 {
    invoke::cnode_copy(src_cnode, src_slot, dest_cnode, dest_slot, rights)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_mint(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    badge: u64,
) -> i32 {
    invoke::cnode_mint(src_cnode, src_slot, dest_cnode, dest_slot, badge)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_move(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
) -> i32 {
    invoke::cnode_move(dest_cnode, dest_slot, src_cnode, src_slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_mutate(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
    badge: u64,
) -> i32 {
    invoke::cnode_mutate(dest_cnode, dest_slot, src_cnode, src_slot, badge)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_save_caller(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_save_caller(cnode, slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_delete(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_delete(cnode, slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_cnode_revoke(cnode: Cap, slot: u64) -> i32 {
    invoke::cnode_revoke(cnode, slot)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_irq_handler_ack(irq_handler: Cap) -> i32 {
    invoke::irq_handler_ack(irq_handler)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_irq_handler_set_notification(irq_handler: Cap, ntfn: Cap) -> i32 {
    invoke::irq_handler_set_notification(irq_handler, ntfn)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcb_set_tls_base(tcb: Cap, tls_base: u64) -> i32 {
    invoke::tcb_set_tls_base(tcb, tls_base)
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_futex_wait(addr: *const u32, expected: u32) -> i32 {
    syscall::syscall(SYS_FUTEX, addr as u64, FUTEX_WAIT, expected as u64, 0, 0, 0).error as i32
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_futex_wake(addr: *const u32, count: u32) -> i32 {
    syscall::syscall(SYS_FUTEX, addr as u64, FUTEX_WAKE, count as u64, 0, 0, 0).value as i32
}

// ---------------------------------------------------------------------------
// C ABI exports: Fork helper (called from fork.S)
// ---------------------------------------------------------------------------

static mut FORK_STACK_CHECK_BUDGET: u32 = 8;

/// Fork implementation called from the `fork.S` assembly trampoline.
///
/// `saved_rsp` points to a stack frame containing callee-saved registers
/// (r15, r14, r13, r12, rbx, rbp, return RIP) saved by the assembly stub.
/// When userland SSE2 is enabled, a 256-byte XMM0-15 save block lives below
/// `saved_rsp` and is restored by the parent return path and `fork_child_entry`.
/// These are packed into an IPC message to procmgr so it can configure the
/// child thread's register state. Returns the child PID (>0) in the parent,
/// or -1 on failure. The child resumes at `child_entry` (never returns here).
#[unsafe(no_mangle)]
pub extern "C" fn _posix_fork_impl(saved_rsp: u64, child_entry: u64) -> i32 {
    if saved_rsp == 0 || child_entry == 0 {
        return -1;
    }

    unsafe {
        let saved = saved_rsp as *const u64;
        let mut before = [0u64; 7];
        for (i, slot) in before.iter_mut().enumerate() {
            *slot = *saved.add(i);
        }

        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_FORK;
        msg.length = 9;
        msg.regs[0] = saved_rsp;
        msg.regs[1] = child_entry;
        msg.regs[2] = *saved.add(5); // rbp
        msg.regs[3] = *saved.add(4); // rbx
        msg.regs[4] = *saved.add(3); // r12
        msg.regs[5] = *saved.add(2); // r13
        msg.regs[6] = *saved.add(1); // r14
        msg.regs[7] = *saved.add(0); // r15
        msg.regs[8] = *saved.add(6); // return RIP

        // Pass parent's TLS base so procmgr can set FS_BASE on the child TCB.
        // The child has a COW copy of the parent's TLS block at the same virtual
        // address, so it needs the same FS_BASE to avoid faulting on fs:[0].
        let tls_base: u64 = match tls::current_tls() {
            Some(ptr) => ptr as u64,
            None => 0,
        };
        msg.regs[9] = tls_base;
        msg.length = 10;

        let err = ipc::call_ctx(
            tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
        }

        if FORK_STACK_CHECK_BUDGET > 0 {
            for (i, was) in before.iter().enumerate() {
                let now = *saved.add(i);
                if now != *was {
                    let mut lb = serial::LineBuf::new();
                    lb.str(b"[FORKCHK] parent stack changed idx=");
                    lb.hex(i as u64);
                    lb.str(b" was=");
                    lb.hex(*was);
                    lb.str(b" now=");
                    lb.hex(now);
                    lb.str(b" rsp=");
                    lb.hex(saved_rsp);
                    lb.str(b"\n");
                    lb.flush();
                    break;
                }
            }
            FORK_STACK_CHECK_BUDGET -= 1;
        }

        reply.regs[0] as i32
    }
}

// ---------------------------------------------------------------------------
// Helper: serial_puts as C ABI for use from assembly or mixed code
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_serial_puts(s: *const u8) {
    if s.is_null() {
        return;
    }
    unsafe {
        let mut i = 0;
        while *s.add(i) != 0 {
            serial::serial_putc(*s.add(i));
            i += 1;
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_serial_hex(val: u64) {
    serial::serial_hex(val);
}

// ---------------------------------------------------------------------------
// C ABI exports: Socket operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_socket(domain: i32, sock_type: i32) -> i32 {
    unsafe { posix::posix_socket(domain, sock_type) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_bind(fd: i32, path: *const u8, addr_len: u32) -> i32 {
    unsafe { posix::posix_bind(fd, path, addr_len) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_listen(fd: i32, backlog: i32) -> i32 {
    unsafe { posix::posix_listen(fd, backlog) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_accept(fd: i32) -> i32 {
    unsafe { posix::posix_accept(fd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_connect(fd: i32, path: *const u8, addr_len: u32) -> i32 {
    unsafe { posix::posix_connect(fd, path, addr_len) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_shutdown(fd: i32, how: i32) -> i32 {
    unsafe { posix::posix_shutdown(fd, how) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_socketpair(fds: *mut i32) -> i32 {
    unsafe { posix::posix_socketpair(fds) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_posix_poll(fds: *mut PollFd, nfds: u32, timeout: i32) -> i32 {
    unsafe { posix::posix_poll(fds, nfds, timeout) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_shm_open(name: *const u8, flags: i32) -> i32 {
    unsafe { posix::posix_shm_open(name, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_shm_unlink(name: *const u8) -> i32 {
    unsafe { posix::posix_shm_unlink(name) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_ftruncate(fd: i32, length: u64) -> i32 {
    unsafe { posix::posix_ftruncate(fd, length) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Pipe / dup
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_pipe(fds: *mut i32) -> i32 {
    unsafe { posix::posix_pipe(fds) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_pipe2(fds: *mut i32, flags: i32) -> i32 {
    unsafe { posix::posix_pipe2(fds, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_dup(oldfd: i32) -> i32 {
    unsafe { posix::posix_dup(oldfd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_dup2(oldfd: i32, newfd: i32) -> i32 {
    unsafe { posix::posix_dup2(oldfd, newfd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_dup3(oldfd: i32, newfd: i32, flags: i32) -> i32 {
    unsafe { posix::posix_dup3(oldfd, newfd, flags) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_mkfifo(path: *const u8, mode: u32) -> i32 {
    unsafe { posix::posix_mkfifo(path, mode) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Process groups and UID/GID
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe { posix::posix_setpgid(pid, pgid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getpgid(pid: i32) -> i32 {
    unsafe { posix::posix_getpgid(pid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_setsid() -> i32 {
    unsafe { posix::posix_setsid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getsid(pid: i32) -> i32 {
    unsafe { posix::posix_getsid(pid) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getuid() -> i32 {
    unsafe { posix::posix_getuid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_geteuid() -> i32 {
    unsafe { posix::posix_geteuid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getgid() -> i32 {
    unsafe { posix::posix_getgid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getegid() -> i32 {
    unsafe { posix::posix_getegid() }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getgroups(size: i32, list: *mut i32) -> i32 {
    unsafe { posix::posix_getgroups(size, list) }
}

// ---------------------------------------------------------------------------
// C ABI exports: Time API
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_clock_gettime(clock_id: i32, ts: *mut types::Timespec) -> i32 {
    unsafe { posix::posix_clock_gettime(clock_id, ts) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_gettimeofday(tv: *mut types::Timeval) -> i32 {
    unsafe { posix::posix_gettimeofday(tv) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_nanosleep(req: *const types::Timespec, rem: *mut types::Timespec) -> i32 {
    unsafe { posix::posix_nanosleep(req, rem) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_usleep(usec: u64) -> i32 {
    unsafe { posix::posix_usleep(usec) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_sleep(seconds: u64) -> u64 {
    unsafe { posix::posix_sleep(seconds) }
}

// ---------------------------------------------------------------------------
// C ABI exports: fcntl / isatty / chdir / getcwd / ioctl
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// C ABI exports: Terminal I/O
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcgetattr(fd: i32, termios_p: *mut types::Termios) -> i32 {
    unsafe { posix::posix_tcgetattr(fd, termios_p) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_tcsetattr(fd: i32, action: i32, termios_p: *const types::Termios) -> i32 {
    unsafe { posix::posix_tcsetattr(fd, action, termios_p) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_epoll_create1(flags: i32) -> i32 {
    let _ = flags;
    unsafe { posix::posix_epoll_create() }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_epoll_ctl(
    epfd: i32,
    op: i32,
    fd: i32,
    event: *const types::EpollEvent,
) -> i32 {
    unsafe {
        let (events, data) = if !event.is_null() {
            ((*event).events, (*event).data)
        } else {
            (0, 0)
        };
        posix::posix_epoll_ctl(epfd, op, fd, events, data)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_epoll_wait(
    epfd: i32,
    events: *mut types::EpollEvent,
    maxevents: i32,
    timeout: i32,
) -> i32 {
    unsafe { posix::posix_epoll_wait(epfd, events, maxevents, timeout) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_fcntl(fd: i32, cmd: i32, arg: i64) -> i32 {
    unsafe { posix::posix_fcntl(fd, cmd, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_isatty(fd: i32) -> i32 {
    unsafe { posix::posix_isatty(fd) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_ioctl(fd: i32, request: u64, arg: u64) -> i32 {
    unsafe { posix::posix_ioctl(fd, request, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_chdir(path: *const u8) -> i32 {
    unsafe { posix::posix_chdir(path) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getcwd(buf: *mut u8, size: u64) -> i32 {
    unsafe { posix::posix_getcwd(buf, size) }
}

// ---------------------------------------------------------------------------
// C ABI exports: pthread operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_pthread_create(
    thread_out: *mut pthread::PthreadT,
    start_fn: unsafe extern "C" fn(*mut u8) -> *mut u8,
    arg: *mut u8,
) -> i32 {
    unsafe { pthread::pthread_create(thread_out, core::ptr::null(), start_fn, arg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_pthread_join(thread: pthread::PthreadT, retval: *mut *mut u8) -> i32 {
    unsafe { pthread::pthread_join(thread, retval) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_pthread_exit(retval: *mut u8) -> ! {
    unsafe { pthread::pthread_exit(retval) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_pthread_self() -> pthread::PthreadT {
    pthread::pthread_self()
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_pthread_detach(thread: pthread::PthreadT) -> i32 {
    unsafe { pthread::pthread_detach(thread) }
}

// ---------------------------------------------------------------------------
// C ABI exports: TLS initialization
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_init_tls() {
    unsafe { tls::init_main_thread_tls() }
}

// ---------------------------------------------------------------------------
// C ABI exports: DNS operations
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn salty_dns_resolve(hostname: *const u8, hostname_len: usize) -> u32 {
    if hostname.is_null() || hostname_len == 0 || hostname_len > 120 {
        return 0;
    }
    // SAFETY: Caller guarantees hostname points to hostname_len valid bytes.
    let slice = unsafe { core::slice::from_raw_parts(hostname, hostname_len) };
    unsafe { dns::dns_resolve(slice) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_getaddrinfo(node: *const u8, result: *mut types::DnsAddrInfo) -> i32 {
    unsafe { dns::posix_getaddrinfo(node, result) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_gethostbyname(name: *const u8) -> u32 {
    unsafe { dns::posix_gethostbyname(name) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_dns_reverse_lookup(
    ip: u32,
    hostname_out: *mut u8,
    hostname_max: usize,
) -> usize {
    unsafe { dns::dns_reverse_lookup(ip, hostname_out, hostname_max) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_dns_cache_flush() {
    unsafe { dns::dns_cache_flush() }
}
