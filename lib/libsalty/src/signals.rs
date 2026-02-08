//! POSIX signal handling
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::types::*;

fn sig_default_action(sig: i32) -> bool {
    // Returns true if default action is terminate
    match sig {
        SIGCHLD | SIGCONT | SIGSTOP => false,
        _ => true,
    }
}

unsafe fn sig_init() {
    unsafe {
        if crate::__sig_initialized != 0 {
            return;
        }
        for i in 0..NSIG {
            crate::__sig_handlers[i] = SIG_DFL;
        }
        crate::__sig_initialized = 1;
    }
}

pub unsafe fn posix_signal(sig: i32, handler: usize) -> usize {
    unsafe {
        sig_init();

        if sig <= 0 || sig >= NSIG as i32 || sig == SIGKILL || sig == SIGSTOP {
            return usize::MAX; // SIG_ERR
        }
        if handler == usize::MAX {
            return usize::MAX; // SIG_ERR
        }

        let old = crate::__sig_handlers[sig as usize];
        crate::__sig_handlers[sig as usize] = handler;

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
            &raw mut crate::__salty_ipc_ctx,
            CAP_PROCMGR_EP,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK {
            // Revert on failure
            crate::__sig_handlers[sig as usize] = old;
            return usize::MAX; // SIG_ERR
        }

        old
    }
}

pub unsafe fn posix_sigcheck() -> i32 {
    unsafe {
        sig_init();

        let mut bits: u64 = 0;
        let err = crate::salty_poll(CAP_SIGNAL_NTFN, &raw mut bits);
        if err != 0 || bits == 0 {
            return 0;
        }

        let mut dispatched: i32 = 0;
        for sig in 1..NSIG as i32 {
            if bits & (1u64 << sig) == 0 {
                continue;
            }

            let handler = crate::__sig_handlers[sig as usize];
            if handler == SIG_IGN {
                // Ignore
            } else if handler == SIG_DFL {
                if sig_default_action(sig) {
                    crate::posix::posix_exit(128 + sig);
                }
            } else {
                // Call the handler function
                let func: unsafe extern "C" fn(i32) = core::mem::transmute(handler);
                func(sig);
            }
            dispatched += 1;
        }
        dispatched
    }
}
