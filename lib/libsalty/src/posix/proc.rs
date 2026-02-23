// SPDX-License-Identifier: GPL-2.0-only
//! POSIX process operations (exit, getpid, waitpid, execve, kill, clock_gettime).

use crate::consts::*;
use crate::types::*;
use super::CAP_PROCMGR_EP;

/// Terminate the current process with `status`.
///
/// Sends `PM_EXIT` to the process manager via blocking Call. The procmgr
/// never replies -- the child stays in ReplyWait until TCB_SUSPEND moves
/// it to Inactive. This avoids the yield-loop that starves SCHED_IPC_LOCK
/// on SMP.
pub unsafe fn posix_exit(status: i32) -> ! {
    unsafe {
        // Final userspace-side cleanup of exited pthread slots before process teardown.
        crate::pthread::process_exit_reap();

        let mut msg = SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXIT;
        msg.length = 1;
        msg.regs[0] = status as u64;

        // Call blocks waiting for reply; procmgr never replies for PM_EXIT,
        // so the child stays in ReplyWait until TCB_SUSPEND moves it to Inactive.
        // This avoids the yield-loop that starves SCHED_IPC_LOCK on SMP.
        let mut reply = SaltyMsg::zeroed();
        crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
    }
    // Unreachable: call never returns since procmgr never replies
    loop {
        crate::syscall::syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

/// Return the process ID of the calling process.
pub unsafe fn posix_getpid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETPID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the parent process ID of the calling process.
pub unsafe fn posix_getppid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETPPID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Wait for a child process to change state.
///
/// `pid` selects which child (-1 = any). `options` may include WNOHANG.
/// On success, writes the wait status to `*status` and returns the child PID.
/// Returns -1 on error.
pub unsafe fn posix_waitpid3(pid: i32, status: *mut i32, options: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_WAIT;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = options as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }

        if !status.is_null() {
            *status = reply.regs[0] as i32;
        }
        reply.regs[1] as i32
    }
}

/// Convenience wrapper for `posix_waitpid3` with `options=0` (blocking).
pub unsafe fn posix_waitpid(pid: i32, status: *mut i32) -> i32 {
    unsafe { posix_waitpid3(pid, status, 0) }
}

/// Replace the current process image with a new program.
///
/// Packs the executable path, argv, and envp into a single IPC message to
/// the process manager. Arguments and environment strings are packed
/// contiguously (null-terminated) into the remaining message registers.
/// Returns 0 on success (caller is replaced), -1 on error.
pub unsafe fn posix_execve(
    path: *const u8,
    argv: *const *const u8,
    envp: *const *const u8,
) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXEC;

        let mut path_len: u8 = 0;
        while *path.add(path_len as usize) != 0 && path_len < 64 {
            path_len += 1;
        }

        // regs[0] = path_len
        msg.regs[0] = path_len as u64;
        let dst = &mut msg.regs[1] as *mut u64 as *mut u8;
        for i in 0..path_len as usize {
            *dst.add(i) = *path.add(i);
        }
        let path_regs = 1 + ((path_len as u64 + 7) / 8) as usize;

        // Count argc and envc, and total string data length
        let mut argc: u32 = 0;
        let mut envc: u32 = 0;
        let mut total_str_len: usize = 0;

        if !argv.is_null() {
            let mut i = 0;
            while !(*argv.add(i)).is_null() {
                let mut slen = 0usize;
                while *(*argv.add(i)).add(slen) != 0 {
                    slen += 1;
                }
                total_str_len += slen + 1; // include null terminator
                argc += 1;
                i += 1;
            }
        }
        if !envp.is_null() {
            let mut i = 0;
            while !(*envp.add(i)).is_null() {
                let mut slen = 0usize;
                while *(*envp.add(i)).add(slen) != 0 {
                    slen += 1;
                }
                total_str_len += slen + 1;
                envc += 1;
                i += 1;
            }
        }

        // regs[path_regs] = (argc << 32) | envc
        let next = path_regs;
        msg.regs[next] = ((argc as u64) << 32) | (envc as u64);

        // Pack null-terminated strings contiguously into regs[next+1..]
        let str_start = next + 1;
        let avail_bytes = (20 - str_start) * 8;
        let copy_len = if total_str_len > avail_bytes { avail_bytes } else { total_str_len };

        let str_dst = &mut msg.regs[str_start] as *mut u64 as *mut u8;
        let mut pos = 0usize;

        if !argv.is_null() {
            let mut i = 0;
            while !(*argv.add(i)).is_null() && pos < copy_len {
                let arg = *argv.add(i);
                let mut j = 0usize;
                while *arg.add(j) != 0 && pos < copy_len {
                    *str_dst.add(pos) = *arg.add(j);
                    pos += 1;
                    j += 1;
                }
                if pos < copy_len {
                    *str_dst.add(pos) = 0;
                    pos += 1;
                }
                i += 1;
            }
        }
        if !envp.is_null() {
            let mut i = 0;
            while !(*envp.add(i)).is_null() && pos < copy_len {
                let env = *envp.add(i);
                let mut j = 0usize;
                while *env.add(j) != 0 && pos < copy_len {
                    *str_dst.add(pos) = *env.add(j);
                    pos += 1;
                    j += 1;
                }
                if pos < copy_len {
                    *str_dst.add(pos) = 0;
                    pos += 1;
                }
                i += 1;
            }
        }

        let str_regs = (pos + 7) / 8;
        msg.length = (str_start + str_regs) as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Send signal `sig` to process `pid`. Returns 0 on success, -1 on error.
pub unsafe fn posix_kill(pid: i32, sig: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_KILL;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = sig as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Fork the current process, returning the child PID to the parent and 0
/// to the child. Defined in `fork.S` (assembly trampoline that issues the
/// PM_FORK IPC and re-initializes the child's IPC context).
unsafe extern "C" {
    pub safe fn posix_fork() -> i32;
}

/// Set the process group ID of process `pid` to `pgid`.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_setpgid(pid: i32, pgid: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_SETPGID;
        msg.length = 2;
        msg.regs[0] = pid as u32 as u64;
        msg.regs[1] = pgid as u32 as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        0
    }
}

/// Get the process group ID of process `pid`. Returns pgid or -1 on error.
pub unsafe fn posix_getpgid(pid: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETPGID;
        msg.length = 1;
        msg.regs[0] = pid as u32 as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Create a new session and set the process as session leader.
/// Returns the new session ID, or -1 on error.
pub unsafe fn posix_setsid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_SETSID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Get the session ID of process `pid` (or caller when `pid==0`).
/// Returns sid on success, -1 on error.
pub unsafe fn posix_getsid(pid: i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETSID;
        msg.length = 1;
        msg.regs[0] = pid as u32 as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the real user ID of the calling process.
pub unsafe fn posix_getuid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETUID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the effective user ID of the calling process.
pub unsafe fn posix_geteuid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETEUID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the real group ID of the calling process.
pub unsafe fn posix_getgid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETGID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Return the effective group ID of the calling process.
pub unsafe fn posix_getegid() -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETEGID;
        msg.length = 0;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Get supplementary group IDs. Returns the number of groups, or -1 on error.
pub unsafe fn posix_getgroups(size: i32, _list: *mut i32) -> i32 {
    unsafe {
        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_GETGROUPS;
        msg.length = 1;
        msg.regs[0] = size as u64;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 {
            return -5; // EIO
        }
        if reply.label != SALTY_OK {
            return super::salty_err_to_posix(reply.label);
        }
        reply.regs[0] as i32
    }
}

/// Read the monotonic clock, writing seconds and nanoseconds into `*ts`.
/// Uses the kernel `SYS_CLOCK_GETTIME` syscall directly (no IPC).
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_clock_gettime(clock_id: i32, ts: *mut crate::types::Timespec) -> i32 {
    unsafe {
        let res = crate::syscall::syscall(SYS_CLOCK_GETTIME, clock_id as u64, 0, 0, 0, 0, 0);
        if res.error != 0 {
            return -1;
        }
        let ns = res.value;
        (*ts).tv_sec = ns / 1_000_000_000;
        (*ts).tv_nsec = ns % 1_000_000_000;
        0
    }
}

/// Get the current time as seconds + microseconds into `*tv`.
/// Uses the kernel clock syscall, converting nanoseconds to microseconds.
/// Returns 0 on success, -1 on error.
pub unsafe fn posix_gettimeofday(tv: *mut crate::types::Timeval) -> i32 {
    unsafe {
        let res = crate::syscall::syscall(SYS_CLOCK_GETTIME, 0, 0, 0, 0, 0, 0);
        if res.error != 0 {
            return -1;
        }
        let ns = res.value;
        (*tv).tv_sec = ns / 1_000_000_000;
        (*tv).tv_usec = (ns % 1_000_000_000) / 1_000;
        0
    }
}

/// Sleep for the duration specified in `*req`.
/// If `rem` is non-null, any remaining time after interruption is written
/// there (always zero in current implementation). Returns 0 on success.
pub unsafe fn posix_nanosleep(req: *const crate::types::Timespec, rem: *mut crate::types::Timespec) -> i32 {
    unsafe {
        let seconds = (*req).tv_sec;
        let nanos = (*req).tv_nsec;
        let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
        if !rem.is_null() {
            (*rem).tv_sec = 0;
            (*rem).tv_nsec = 0;
        }
        if res.error != 0 {
            return -1;
        }
        0
    }
}

/// Sleep for `usec` microseconds. Returns 0 on success, -1 on error.
pub unsafe fn posix_usleep(usec: u64) -> i32 {
    let seconds = usec / 1_000_000;
    let nanos = (usec % 1_000_000) * 1_000;
    let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, nanos, 0, 0, 0, 0);
    if res.error != 0 { -1 } else { 0 }
}

/// Sleep for `seconds`. Returns 0 on success, or remaining seconds on error.
pub unsafe fn posix_sleep(seconds: u64) -> u64 {
    let res = crate::syscall::syscall(SYS_NANOSLEEP, seconds, 0, 0, 0, 0, 0);
    if res.error != 0 { seconds } else { 0 }
}
