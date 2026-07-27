// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX signal personality bits.
//!
//! `SIG*` numeric assignments + the personality-neutral
//! [`FaultKind`] → [`Signo`] projection that init's fault-forward
//! handler consults when translating an mmsrv-reported user
//! exception into a POSIX SIGSEGV / SIGBUS / SIGILL / SIGFPE.
//!
//! `sigaction` wire encoding lives in [`super::types::Sigset`]
//! (the mask) plus the [`SigAction`] struct defined here. Win32
//! has no signal-equivalent on the same wire — the personality
//! split keeps signal types out of the neutral surface.
#![allow(dead_code)]

use super::types::Sigset;

/// POSIX signal number — 1-based.
pub(crate) type Signo = i32;

pub(crate) const SIGHUP: Signo = 1;
pub(crate) const SIGINT: Signo = 2;
pub(crate) const SIGQUIT: Signo = 3;
pub(crate) const SIGILL: Signo = 4;
pub(crate) const SIGTRAP: Signo = 5;
pub(crate) const SIGABRT: Signo = 6;
pub(crate) const SIGBUS: Signo = 7;
pub(crate) const SIGFPE: Signo = 8;
pub(crate) const SIGKILL: Signo = 9;
pub(crate) const SIGUSR1: Signo = 10;
pub(crate) const SIGSEGV: Signo = 11;
pub(crate) const SIGUSR2: Signo = 12;
pub(crate) const SIGPIPE: Signo = 13;
pub(crate) const SIGALRM: Signo = 14;
pub(crate) const SIGTERM: Signo = 15;
pub(crate) const SIGCHLD: Signo = 17;
pub(crate) const SIGCONT: Signo = 18;
pub(crate) const SIGSTOP: Signo = 19;
pub(crate) const SIGTSTP: Signo = 20;
pub(crate) const SIGTTIN: Signo = 21;
pub(crate) const SIGTTOU: Signo = 22;
pub(crate) const SIGURG: Signo = 23;
pub(crate) const SIGXCPU: Signo = 24;
pub(crate) const SIGXFSZ: Signo = 25;
pub(crate) const SIGVTALRM: Signo = 26;
pub(crate) const SIGPROF: Signo = 27;
pub(crate) const SIGWINCH: Signo = 28;
pub(crate) const SIGIO: Signo = 29;
pub(crate) const SIGPWR: Signo = 30;
pub(crate) const SIGSYS: Signo = 31;

/// First real-time signal. `SIGRTMAX = SIGRTMIN + 32` on Linux.
pub(crate) const SIGRTMIN: Signo = 32;

/// Standard `sigaction.sa_flags` bits.
pub(crate) const SA_NOCLDSTOP: u32 = 0x0000_0001;
pub(crate) const SA_NOCLDWAIT: u32 = 0x0000_0002;
pub(crate) const SA_SIGINFO: u32 = 0x0000_0004;
pub(crate) const SA_ONSTACK: u32 = 0x0800_0000;
pub(crate) const SA_RESTART: u32 = 0x1000_0000;
pub(crate) const SA_NODEFER: u32 = 0x4000_0000;
pub(crate) const SA_RESETHAND: u32 = 0x8000_0000;

/// Sentinel `sa_handler` values (cast as integer).
pub(crate) const SIG_DFL: u64 = 0;
pub(crate) const SIG_IGN: u64 = 1;

/// `struct sigaction` — Linux x86_64 layout. The handler /
/// sigaction union collapses to a single `u64` here; callers
/// that need `sa_sigaction` reinterpret the field according to
/// `SA_SIGINFO`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SigAction {
    /// Either `sa_handler: void (*)(int)` or `sa_sigaction:
    /// void (*)(int, siginfo_t *, void *)` depending on
    /// `sa_flags & SA_SIGINFO`. Stored as `u64` so the wire
    /// shape is union-agnostic.
    pub sa_handler: u64,
    pub sa_flags: u32,
    /// Optional restorer trampoline — set by libc when the
    /// kernel returns from a signal frame. vfs does not invoke
    /// it; carried opaquely so the wire round-trip is bit-exact.
    pub sa_restorer: u64,
    pub sa_mask: Sigset,
}

impl Default for SigAction {
    fn default() -> Self {
        Self {
            sa_handler: SIG_DFL,
            sa_flags: 0,
            sa_restorer: 0,
            sa_mask: Sigset::default(),
        }
    }
}

/// Personality-neutral fault kinds reported by mmsrv. The
/// dispatcher in init forwards a fault record carrying one of
/// these; vfs's personality::posix::signals layer projects them
/// onto the corresponding POSIX signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultKind {
    /// Page fault — unbacked / unrecoverable. Maps to SIGSEGV.
    PageFault,
    /// Misaligned access / unaligned cache / RAS bus error. Maps
    /// to SIGBUS.
    BusError,
    /// Illegal instruction or undecodable opcode. Maps to SIGILL.
    IllegalInstruction,
    /// Single-step / breakpoint / ptrace trap. Maps to SIGTRAP.
    Breakpoint,
    /// Division by zero / floating-point exception. Maps to
    /// SIGFPE.
    Arithmetic,
    /// Bad capability invocation / kernel-side malformed cap. Maps
    /// to SIGSYS so the caller sees a system-call-class fault, not
    /// a memory-class one.
    BadCapability,
    /// OOM that mmsrv could not recover. Uncatchable — maps to
    /// SIGKILL so init's fault-forward path delivers it as a hard
    /// kill regardless of the caller's `sigaction`.
    OutOfMemory,
    /// User-defined exception (debugger trap / explicit hardware
    /// trap). Maps to SIGSEGV by convention; the trona-level
    /// detail lands in `siginfo`.
    UserException,
}

/// Translate a fault kind to its POSIX signal number.
#[inline]
pub(crate) const fn fault_to_signo(kind: FaultKind) -> Signo {
    match kind {
        FaultKind::PageFault => SIGSEGV,
        FaultKind::BusError => SIGBUS,
        FaultKind::IllegalInstruction => SIGILL,
        FaultKind::Breakpoint => SIGTRAP,
        FaultKind::Arithmetic => SIGFPE,
        FaultKind::BadCapability => SIGSYS,
        FaultKind::OutOfMemory => SIGKILL,
        FaultKind::UserException => SIGSEGV,
    }
}

/// Returns `true` for signals that POSIX explicitly forbids
/// from being caught, blocked, or ignored. `sigaction(SIGKILL,
/// …)` and `sigaction(SIGSTOP, …)` return EINVAL.
#[inline]
pub(crate) const fn is_uncatchable(signo: Signo) -> bool {
    signo == SIGKILL || signo == SIGSTOP
}

/// Default action for a signal that has no installed handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DefaultAction {
    /// Terminate the process.
    Terminate,
    /// Terminate + dump core.
    CoreDump,
    /// Stop the process.
    Stop,
    /// Continue the process.
    Continue,
    /// Ignore.
    Ignore,
}

/// Lookup the default action POSIX assigns to `signo`. This is
/// what init runs when the caller's sigaction is `SIG_DFL`.
#[inline]
pub(crate) const fn default_action(signo: Signo) -> DefaultAction {
    match signo {
        SIGCHLD | SIGURG | SIGWINCH => DefaultAction::Ignore,
        SIGCONT => DefaultAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultAction::Stop,
        SIGABRT | SIGBUS | SIGFPE | SIGILL | SIGQUIT | SIGSEGV | SIGSYS | SIGTRAP | SIGXCPU
        | SIGXFSZ => DefaultAction::CoreDump,
        _ => DefaultAction::Terminate,
    }
}
