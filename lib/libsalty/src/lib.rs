//! libsalty - SaltyOS System Library (Rust)
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Provides system call wrappers and IPC helpers for userland.
//! All public functions are `#[unsafe(no_mangle)] pub extern "C"` for
//! dynamic linking compatibility with rtld.

#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(linkage)]

pub mod consts;
pub mod cpio;
pub mod elf_dynamic;
pub mod elf_loader;
pub mod invoke;
pub mod ipc;
pub mod posix;
pub mod posix_mm;
pub mod serial;
pub mod signals;
pub mod syscall;
pub mod types;

// Re-export for convenience
pub use consts::*;
pub use types::*;

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub static mut __salty_ipc_ctx: IpcContext = IpcContext::new();

#[unsafe(no_mangle)]
pub static mut __sig_handlers: [usize; NSIG] = [0; NSIG];

#[unsafe(no_mangle)]
pub static mut __sig_initialized: i32 = 0;

#[unsafe(no_mangle)]
#[linkage = "weak"]
pub static mut __salty_next_frame_slot: u64 = 64;

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
    unsafe { ipc::send_ctx(&raw mut __salty_ipc_ctx, ep, msg) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_recv(ep: Cap, msg: *mut SaltyMsg, badge: *mut u64) -> i32 {
    unsafe { ipc::recv_ctx(&raw mut __salty_ipc_ctx, ep, msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_call(ep: Cap, msg: *const SaltyMsg, reply: *mut SaltyMsg) -> i32 {
    unsafe { ipc::call_ctx(&raw mut __salty_ipc_ctx, ep, msg, reply) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_reply_recv(
    ep: Cap,
    reply: *const SaltyMsg,
    out_msg: *mut SaltyMsg,
    badge: *mut u64,
) -> i32 {
    unsafe { ipc::reply_recv_ctx(&raw mut __salty_ipc_ctx, ep, reply, out_msg, badge) }
}

#[unsafe(no_mangle)]
pub extern "C" fn salty_nbsend(ep: Cap, msg: *const SaltyMsg) -> i32 {
    unsafe { ipc::nbsend_ctx(&raw mut __salty_ipc_ctx, ep, msg) }
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
pub extern "C" fn salty_vspace_copy_page(
    src_vspace: Cap,
    src_vaddr: u64,
    dst_frame: Cap,
) -> i32 {
    invoke::vspace_copy_page(src_vspace, src_vaddr, dst_frame)
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

// ---------------------------------------------------------------------------
// C ABI exports: Fork helper (called from fork.S)
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _posix_fork_impl(saved_rsp: u64, child_entry: u64) -> i32 {
    if saved_rsp == 0 || child_entry == 0 {
        return -1;
    }

    unsafe {
        let saved = saved_rsp as *const u64;

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

        let err = ipc::call_ctx(
            &raw mut __salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            return -1;
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
pub extern "C" fn salty_bind(fd: i32, path: *const u8) -> i32 {
    unsafe { posix::posix_bind(fd, path) }
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
pub extern "C" fn salty_connect(fd: i32, path: *const u8) -> i32 {
    unsafe { posix::posix_connect(fd, path) }
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
