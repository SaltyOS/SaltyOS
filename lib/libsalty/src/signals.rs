//! POSIX signal handling via notification-based delivery
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Signals are delivered through a kernel notification object
//! (`CAP_SIGNAL_NTFN`). Each signal number corresponds to a bit in the
//! notification word. The process manager sets bits via `SYS_SIGNAL` when
//! `kill()` is called. `posix_sigcheck()` polls the notification and
//! dispatches handlers registered via `posix_signal()`.
//!
//! Signal disposition is tracked both locally (handler function pointers in
//! `__sig_handlers`) and in the process manager (SIG_DFL/SIG_IGN/SIG_CATCH).
//! Blocked signals are re-raised so they remain pending.

use crate::consts::*;
use crate::types::*;
use core::sync::atomic::Ordering;

// Standard child CSpace layout
const CAP_PROCMGR_EP: u64 = 3;
const CAP_SIGNAL_NTFN: u64 = 6;

/// Returns `true` if the default action for `sig` is to terminate the process.
fn sig_default_action(sig: i32) -> bool {
    // Returns true if default action is terminate
    match sig {
        SIGCHLD | SIGCONT | SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => false,
        _ => true,
    }
}

/// One-shot initialization of signal state (idempotent via compare_exchange).
unsafe fn sig_init() {
    let _ = crate::__sig_initialized.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst);
}

/// Install a signal handler for signal `sig`.
///
/// `handler` is one of: `SIG_DFL` (default), `SIG_IGN` (ignore), or a
/// function pointer cast to `usize`. Returns the previous handler, or
/// `SIG_ERR` (usize::MAX) on error.
///
/// Notifies the process manager of the new disposition category so it
/// can decide whether to deliver or suppress signals.
pub unsafe fn posix_signal(sig: i32, handler: usize) -> usize {
    unsafe {
        sig_init();

        if sig <= 0 || sig >= NSIG as i32 || sig == SIGKILL || sig == SIGSTOP {
            return usize::MAX; // SIG_ERR
        }
        if handler == usize::MAX {
            return usize::MAX; // SIG_ERR
        }

        let old = crate::__sig_handlers[sig as usize].load(Ordering::SeqCst);
        crate::__sig_handlers[sig as usize].store(handler, Ordering::SeqCst);

        // Notify procmgr of disposition category
        let disp: u64 = if handler == SIG_DFL {
            SIG_DISP_DFL
        } else if handler == SIG_IGN {
            SIG_DISP_IGN
        } else {
            SIG_DISP_CATCH
        };

        let mut msg = SaltyMsg::zeroed();
        let mut reply = SaltyMsg::zeroed();
        msg.label = POSIX_PM_SIGACTION;
        msg.length = 2;
        msg.regs[0] = sig as u64;
        msg.regs[1] = disp;

        let err = crate::ipc::call_ctx(
            crate::tls::current_ipc_ctx(),
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            // Revert on failure
            crate::__sig_handlers[sig as usize].store(old, Ordering::SeqCst);
            return usize::MAX; // SIG_ERR
        }

        old
    }
}

/// Poll for pending signals and dispatch handlers.
///
/// Polls `CAP_SIGNAL_NTFN` for signal bits. For each pending signal:
/// - If blocked: re-raises it via `SYS_SIGNAL` so it stays pending.
/// - If SIG_IGN: silently consumed.
/// - If SIG_DFL with terminate action: calls `posix_exit(128 + sig)`.
/// - Otherwise: saves/restores the blocked mask, handles SA_RESETHAND,
///   and calls the user handler function.
///
/// Note: SA_RESTART has no effect in SaltyOS. Signals are delivered
/// cooperatively — system calls (IPC) are never interrupted, so there
/// is no syscall to restart. SA_RESTART is stored but intentionally
/// not checked here.
///
/// Returns the number of signals dispatched (0 if none pending).
pub unsafe fn posix_sigcheck() -> i32 {
    unsafe {
        sig_init();

        let mut bits: u64 = 0;
        let err = crate::salty_poll(CAP_SIGNAL_NTFN, &raw mut bits);
        if err != 0 || bits == 0 {
            return 0;
        }

        let blocked = *(&raw const crate::__sig_blocked_mask);
        let mut repost: u64 = 0;
        let mut dispatched: i32 = 0;

        for sig in 1..NSIG as i32 {
            if bits & (1u64 << sig) == 0 {
                continue;
            }

            // Check blocked mask — if blocked, re-raise later
            if blocked & (1u32 << sig) != 0 {
                repost |= 1u64 << sig;
                continue;
            }

            let handler = crate::__sig_handlers[sig as usize].load(Ordering::SeqCst);
            if handler == SIG_IGN {
                // Ignore
            } else if handler == SIG_DFL {
                if sig_default_action(sig) {
                    crate::posix::posix_exit(128 + sig);
                }
            } else {
                // Save blocked mask, apply sa_mask | self
                let saved_mask = *(&raw const crate::__sig_blocked_mask);
                let sa_mask = (*(&raw const crate::__sig_sa_mask))[sig as usize];
                (*(&raw mut crate::__sig_blocked_mask)) = saved_mask | sa_mask | (1u32 << sig);

                // SA_RESETHAND: reset to SIG_DFL after first delivery
                let sa_flags = (*(&raw const crate::__sig_sa_flags))[sig as usize];
                if sa_flags & SA_RESETHAND != 0 {
                    crate::__sig_handlers[sig as usize].store(SIG_DFL, Ordering::SeqCst);
                    // Notify procmgr of disposition change
                    let mut msg = SaltyMsg::zeroed();
                    let mut reply = SaltyMsg::zeroed();
                    msg.label = POSIX_PM_SIGACTION;
                    msg.length = 2;
                    msg.regs[0] = sig as u64;
                    msg.regs[1] = SIG_DISP_DFL;
                    let _ = crate::ipc::call_ctx(
                        crate::tls::current_ipc_ctx(),
                        CAP_PROCMGR_EP,
                        &raw const msg,
                        &raw mut reply,
                    );
                }

                // Call the handler function
                let func: unsafe extern "C" fn(i32) = core::mem::transmute(handler);
                func(sig);

                // Restore blocked mask
                (*(&raw mut crate::__sig_blocked_mask)) = saved_mask;
            }
            dispatched += 1;
        }

        // Re-raise blocked signals so they remain pending
        if repost != 0 {
            crate::syscall::syscall(SYS_SIGNAL, CAP_SIGNAL_NTFN, repost, 0, 0, 0, 0);
        }

        dispatched
    }
}
