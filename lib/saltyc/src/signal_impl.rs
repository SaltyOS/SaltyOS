//! POSIX signal handling
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Single-threaded signal implementation backed by libsalty's notification
//! mechanism. Signal handlers are registered via `salty::signals::posix_signal`,
//! which sets up a kernel notification object to deliver signals asynchronously.
//!
//! The `sigaction` interface stores `sa_mask` and `sa_flags` in shared libsalty
//! globals (`__sig_sa_mask`, `__sig_sa_flags`) so the signal delivery trampoline
//! can apply the correct mask before invoking the handler. Up to 32 signals
//! are supported (`NSIG = 32`).

use crate::errno;

pub type SighandlerT = usize;
pub const SIG_DFL: SighandlerT = 0;
pub const SIG_IGN: SighandlerT = 1;
pub const SIG_ERR: SighandlerT = usize::MAX;

pub const SA_RESTART: i32 = 0x10000000;
pub const SA_NOCLDSTOP: i32 = 0x00000001;
pub const SA_NOCLDWAIT: i32 = 0x00000002;
pub const SA_SIGINFO: i32 = 0x00000004;
pub const SA_RESETHAND: i32 = 0x80000000u32 as i32;

pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

const NSIG: usize = 32;

#[repr(C)]
pub struct Sigaction {
    pub sa_handler: SighandlerT,
    pub sa_mask: Sigset,
    pub sa_flags: i32,
    pub sa_restorer: usize,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Sigset {
    pub bits: u32,
}

// SAFETY: single-threaded process; HANDLERS and BLOCKED_MASK are only
// accessed from the main thread.
static mut HANDLERS: [SighandlerT; NSIG] = [SIG_DFL; NSIG];
static mut BLOCKED_MASK: Sigset = Sigset { bits: 0 };

/// Install a signal handler for signal `sig`.
///
/// Registers the handler with libsalty's notification-based signal delivery
/// via `salty::signals::posix_signal`. Both `SIG_DFL` and `SIG_IGN` are
/// forwarded to libsalty so it can update the kernel notification mask.
///
/// Returns the previous handler on success, or `SIG_ERR` on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(sig: i32, handler: SighandlerT) -> SighandlerT {
    unsafe {
        if sig <= 0 || sig >= NSIG as i32 {
            errno::set_errno(errno::EINVAL);
            return SIG_ERR;
        }

        let old = *(&raw const HANDLERS).cast::<[SighandlerT; NSIG]>().as_ref().unwrap_unchecked().get_unchecked(sig as usize);
        (*(&raw mut HANDLERS))[sig as usize] = handler;

        // If handler is a catch function (not SIG_DFL or SIG_IGN), register with libsalty
        if handler != SIG_DFL && handler != SIG_IGN {
            let result = salty::signals::posix_signal(sig, handler);
            if result == usize::MAX {
                // Registration failed, revert
                (*(&raw mut HANDLERS))[sig as usize] = old;
                errno::set_errno(errno::EINVAL);
                return SIG_ERR;
            }
        } else {
            // Still notify libsalty of disposition change
            let result = salty::signals::posix_signal(sig, handler);
            if result == usize::MAX {
                (*(&raw mut HANDLERS))[sig as usize] = old;
                errno::set_errno(errno::EINVAL);
                return SIG_ERR;
            }
        }

        old
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigaction(
    sig: i32,
    act: *const Sigaction,
    oact: *mut Sigaction,
) -> i32 {
    unsafe {
        if sig <= 0 || sig >= NSIG as i32 {
            errno::set_errno(errno::EINVAL);
            return -1;
        }

        // Fill old action if requested
        if !oact.is_null() {
            (*oact).sa_handler = (*(&raw const HANDLERS))[sig as usize];
            (*oact).sa_mask = Sigset { bits: (*(&raw const salty::__sig_sa_mask))[sig as usize] };
            (*oact).sa_flags = (*(&raw const salty::__sig_sa_flags))[sig as usize];
            (*oact).sa_restorer = 0;
        }

        // Install new action if provided
        if !act.is_null() {
            let new_handler = (*act).sa_handler;
            let old = (*(&raw const HANDLERS))[sig as usize];

            (*(&raw mut HANDLERS))[sig as usize] = new_handler;

            let result = salty::signals::posix_signal(sig, new_handler);
            if result == usize::MAX {
                // Revert on failure
                (*(&raw mut HANDLERS))[sig as usize] = old;
                errno::set_errno(errno::EINVAL);
                return -1;
            }

            // Store sa_mask and sa_flags in shared libsalty globals
            (*(&raw mut salty::__sig_sa_mask))[sig as usize] = (*act).sa_mask.bits;
            (*(&raw mut salty::__sig_sa_flags))[sig as usize] = (*act).sa_flags;
        }

        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigprocmask(
    how: i32,
    set: *const Sigset,
    oldset: *mut Sigset,
) -> i32 {
    unsafe {
        let current = *(&raw const salty::__sig_blocked_mask);
        if !oldset.is_null() {
            (*oldset).bits = current;
        }

        if !set.is_null() {
            let new_bits = (*set).bits;
            let updated = match how {
                SIG_BLOCK => current | new_bits,
                SIG_UNBLOCK => current & !new_bits,
                SIG_SETMASK => new_bits,
                _ => {
                    errno::set_errno(errno::EINVAL);
                    return -1;
                }
            };
            (*(&raw mut salty::__sig_blocked_mask)) = updated;
            (*(&raw mut BLOCKED_MASK)).bits = updated;
        }

        0
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigsuspend(_mask: *const Sigset) -> i32 {
    errno::set_errno(errno::EINTR);
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sigpending(set: *mut Sigset) -> i32 {
    if !set.is_null() {
        unsafe {
            (*set).bits = 0;
        }
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sigemptyset(set: *mut Sigset) -> i32 {
    if set.is_null() {
        return -1;
    }
    unsafe {
        (*set).bits = 0;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sigfillset(set: *mut Sigset) -> i32 {
    if set.is_null() {
        return -1;
    }
    unsafe {
        (*set).bits = 0xFFFFFFFF;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sigaddset(set: *mut Sigset, sig: i32) -> i32 {
    if set.is_null() || sig <= 0 || sig >= NSIG as i32 {
        return -1;
    }
    unsafe {
        (*set).bits |= 1u32 << sig;
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sigdelset(set: *mut Sigset, sig: i32) -> i32 {
    if set.is_null() || sig <= 0 || sig >= NSIG as i32 {
        return -1;
    }
    unsafe {
        (*set).bits &= !(1u32 << sig);
    }
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn sigismember(set: *const Sigset, sig: i32) -> i32 {
    if set.is_null() || sig <= 0 || sig >= NSIG as i32 {
        return -1;
    }
    unsafe { (((*set).bits >> sig) & 1) as i32 }
}

#[unsafe(no_mangle)]
pub extern "C" fn siginterrupt(_sig: i32, _flag: i32) -> i32 {
    0
}
