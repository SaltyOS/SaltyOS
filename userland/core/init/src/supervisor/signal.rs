// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX signal subsystem state. init owns:
//!   * the per-process signal MP send side (best-effort wake nudges;
//!     durable signal state is the coalesced pending mask below),
//!   * a per-process signal disposition table (`SIG_DFL` / `SIG_IGN` /
//!     installed handlers),
//!   * a per-process pending-signal mask (signals queued but not yet
//!     delivered because the process has them blocked).

use trona_kernel::core_types::{IpcContext, TronaMsg};
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::supervisor::SupervisorState;
use crate::supervisor::proc_table::{ProcessRecord, ProcessState};

pub const SIGHUP: u8 = 1;
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGILL: u8 = 4;
pub const SIGTRAP: u8 = 5;
pub const SIGABRT: u8 = 6;
pub const SIGFPE: u8 = 8;
pub const SIGKILL: u8 = 9;
pub const SIGUSR1: u8 = 10;
pub const SIGSEGV: u8 = 11;
pub const SIGUSR2: u8 = 12;
pub const SIGPIPE: u8 = 13;
pub const SIGALRM: u8 = 14;
pub const SIGTERM: u8 = 15;
pub const SIGCHLD: u8 = 17;
pub const SIGCONT: u8 = 18;
pub const SIGSTOP: u8 = 19;
pub const SIGTSTP: u8 = 20;
pub const SIGTTIN: u8 = 21;
pub const SIGTTOU: u8 = 22;
pub const SIGSYS: u8 = 31;

pub const SIGNAL_COUNT: usize = 64;

pub fn is_known_signal(sig: u8) -> bool {
    matches!(
        sig,
        SIGHUP
            | SIGINT
            | SIGQUIT
            | SIGILL
            | SIGTRAP
            | SIGABRT
            | SIGFPE
            | SIGKILL
            | SIGUSR1
            | SIGSEGV
            | SIGUSR2
            | SIGPIPE
            | SIGALRM
            | SIGTERM
            | SIGCHLD
            | SIGCONT
            | SIGSTOP
            | SIGTSTP
            | SIGTTIN
            | SIGTTOU
            | SIGSYS
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignalDefaultAction {
    Ignore,
    Terminate,
    Stop,
    Continue,
}

pub const fn default_action_for(sig: u8) -> SignalDefaultAction {
    match sig {
        SIGCHLD => SignalDefaultAction::Ignore,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => SignalDefaultAction::Stop,
        SIGCONT => SignalDefaultAction::Continue,
        _ => SignalDefaultAction::Terminate,
    }
}

/// Disposition of a single signal. Mirrors POSIX `sigaction.sa_handler`
/// semantics — the actual user-side handler entry-point lives in the
/// process; init only tracks "is this signal default / ignored /
/// caught" so we can shortcut delivery for ignored signals.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignalDisposition {
    Default,
    Ignored,
    /// Process installed a handler. Init does not need the handler
    /// pointer — it just notifies the process that signal `n` is
    /// pending and the process's signal worker reads its own table.
    Handled,
}

impl SignalDisposition {
    pub const fn default_for(sig: u8) -> Self {
        match default_action_for(sig) {
            SignalDefaultAction::Ignore => Self::Ignored,
            _ => Self::Default,
        }
    }

    pub const fn is_ignored_for(self, sig: u8) -> bool {
        match self {
            Self::Ignored => true,
            Self::Default => match default_action_for(sig) {
                SignalDefaultAction::Ignore => true,
                _ => false,
            },
            Self::Handled => false,
        }
    }
}

#[derive(Clone, Copy)]
pub struct SignalState {
    pub dispositions: [SignalDisposition; SIGNAL_COUNT],
    /// Bitset of signals queued but not yet delivered (process has
    /// them blocked).
    pub pending_mask: u64,
    /// Bitset of signals the process currently has blocked.
    pub block_mask: u64,
}

impl SignalState {
    pub const fn new() -> Self {
        Self {
            dispositions: [SignalDisposition::Default; SIGNAL_COUNT],
            pending_mask: 0,
            block_mask: 0,
        }
    }

    /// Initialise default dispositions per POSIX. Called for every
    /// `ProcessRecord` at spawn time.
    pub fn install_defaults(&mut self) {
        for s in 0..SIGNAL_COUNT {
            self.dispositions[s] = SignalDisposition::default_for(s as u8);
        }
        self.pending_mask = 0;
        self.block_mask = 0;
    }
}

/// Wire layout for one signal record written into a process's signal
/// MP. Mirrors `siginfo_t` essentials.
///
/// ```text
///   regs[0] = signum
///   regs[1] = sender_pid
///   regs[2] = sender_uid
///   regs[3] = code (SI_USER / SI_KERNEL / SI_QUEUE / etc.)
///   regs[4] = sigval (signed integer payload)
/// ```
pub fn signal_record(
    msg: &mut TronaMsg,
    signum: u8,
    sender_pid: u32,
    sender_uid: u32,
    code: u32,
    sigval: i64,
) {
    msg.label = 0;
    msg.length = 5;
    msg.regs[0] = signum as u64;
    msg.regs[1] = sender_pid as u64;
    msg.regs[2] = sender_uid as u64;
    msg.regs[3] = code as u64;
    msg.regs[4] = sigval as u64;
}

/// Map a fault-kind code (from mmsrv's `INIT_REPORT_FAULT.regs[2]`)
/// into the POSIX signal that should kill the process.
pub fn fault_kind_to_signal(fault_kind: u64) -> u8 {
    use crate::wire::{
        FAULT_KIND_BREAKPOINT, FAULT_KIND_CAPABILITY, FAULT_KIND_ILLEGAL_INSTRUCTION,
        FAULT_KIND_OOM, FAULT_KIND_PAGE_FAULT, FAULT_KIND_USER_EXCEPTION,
    };
    match fault_kind {
        FAULT_KIND_PAGE_FAULT => SIGSEGV,
        FAULT_KIND_OOM => SIGKILL,
        FAULT_KIND_ILLEGAL_INSTRUCTION => SIGILL,
        FAULT_KIND_BREAKPOINT => SIGTRAP,
        FAULT_KIND_USER_EXCEPTION => SIGSEGV,
        FAULT_KIND_CAPABILITY => SIGSYS,
        _ => SIGKILL,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignalDelivery {
    Invalid,
    Ignored,
    Pending,
    Notified,
    Terminate,
    Stop,
    Continue,
}

fn signal_mask(sig: u8) -> Option<u64> {
    let sig_idx = (sig as usize).min(SIGNAL_COUNT - 1);
    if !is_known_signal(sig) || sig_idx >= SIGNAL_COUNT {
        return None;
    }
    Some(1u64 << (sig as u64).min(63))
}

fn mark_pending(proc: &mut ProcessRecord, sig: u8) {
    let Some(mask) = signal_mask(sig) else {
        return;
    };
    proc.signal_state.pending_mask |= mask;
}

/// Record SIGCHLD as durable pending state only.
///
/// Child-exit notification must not depend on the signal MP wake
/// path: `finalize_exit` may also be holding a parked `waitpid` reply
/// token, and parent progress must be driven by the reliable wait
/// reply. The parent folds this pending bit in on the next
/// `posix_sigcheck`.
pub fn queue_sigchld_pending(proc: &mut ProcessRecord) -> SignalDelivery {
    let sig = SIGCHLD;
    let Some(mask) = signal_mask(sig) else {
        return SignalDelivery::Invalid;
    };
    let sig_idx = (sig as usize).min(SIGNAL_COUNT - 1);
    let state = &mut proc.signal_state;
    if state.dispositions[sig_idx].is_ignored_for(sig) {
        return SignalDelivery::Ignored;
    }
    state.pending_mask |= mask;
    SignalDelivery::Pending
}

/// Deliver a semantic POSIX signal. The per-process signal pipe is
/// used only as a wake nudge; the durable signal state is the
/// coalesced pending bit in init.
pub fn queue_signal(
    proc: &mut ProcessRecord,
    sig: u8,
    sender_pid: u32,
    sender_uid: u32,
    code: u32,
    sigval: i64,
) -> SignalDelivery {
    let Some(mask) = signal_mask(sig) else {
        return SignalDelivery::Invalid;
    };
    if sig == SIGKILL {
        return SignalDelivery::Terminate;
    }
    if sig == SIGSTOP {
        return SignalDelivery::Stop;
    }
    if sig == SIGCONT {
        return SignalDelivery::Continue;
    }
    let sig_idx = (sig as usize).min(SIGNAL_COUNT - 1);
    let signal_mp_send_slot = proc
        .signal_mp_send
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default()
        .addr();
    {
        let state = &mut proc.signal_state;
        if state.dispositions[sig_idx].is_ignored_for(sig) {
            return SignalDelivery::Ignored;
        }
        if (state.block_mask & mask) != 0 {
            state.pending_mask |= mask;
            return SignalDelivery::Pending;
        }
        if state.dispositions[sig_idx] == SignalDisposition::Default {
            return match default_action_for(sig) {
                SignalDefaultAction::Ignore => SignalDelivery::Ignored,
                SignalDefaultAction::Terminate => SignalDelivery::Terminate,
                SignalDefaultAction::Stop => SignalDelivery::Stop,
                SignalDefaultAction::Continue => SignalDelivery::Continue,
            };
        }
    }

    let mut msg = TronaMsg::zeroed();
    signal_record(&mut msg, sig, sender_pid, sender_uid, code, sigval);
    let err = unsafe {
        mp_write_nonblocking(
            trona_runtime::current_ipc_ctx(),
            signal_mp_send_slot,
            &raw const msg,
        )
    };
    if err == 0 {
        SignalDelivery::Notified
    } else {
        mark_pending(proc, sig);
        SignalDelivery::Pending
    }
}

pub fn deliver_signal(
    state: &mut SupervisorState,
    target_pid: u32,
    sig: u8,
    sender_pid: u32,
    sender_uid: u32,
    code: u32,
    sigval: i64,
) -> SignalDelivery {
    let delivery = {
        let Some(proc) = state.procs.get_mut(target_pid) else {
            return SignalDelivery::Invalid;
        };
        queue_signal(proc, sig, sender_pid, sender_uid, code, sigval)
    };

    match delivery {
        SignalDelivery::Terminate => {
            crate::supervisor::lifecycle::finalize_exit(state, target_pid, -(sig as i32));
        }
        SignalDelivery::Stop => stop_process(state, target_pid, sig),
        SignalDelivery::Continue => continue_process(state, target_pid),
        _ => {}
    }
    delivery
}

fn stop_process(state: &mut SupervisorState, pid: u32, sig: u8) {
    match state.procs.get(pid) {
        Some(p) if p.state == ProcessState::Active => {}
        _ => return,
    }
    state.procs.for_each_thread(pid, |thread| {
        let tcb = thread
            .tcb
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default();
        if !tcb.is_null() {
            let _ = invoke::tcb_stop(tcb);
        }
    });
    if let Some(proc) = state.procs.get_mut(pid) {
        proc.state = ProcessState::Stopped;
        proc.stop_status = ((sig as i32) << 8) | 0x7f;
        proc.stop_reported = false;
    }
}

fn continue_process(state: &mut SupervisorState, pid: u32) {
    match state.procs.get(pid) {
        Some(p) if p.state == ProcessState::Stopped => {}
        _ => return,
    }
    state.procs.for_each_thread(pid, |thread| {
        let tcb = thread
            .tcb
            .as_ref()
            .map(OwnedCap::borrow)
            .unwrap_or_default();
        if !tcb.is_null() {
            let _ = invoke::tcb_start(tcb);
        }
    });
    if let Some(proc) = state.procs.get_mut(pid) {
        proc.state = ProcessState::Active;
        proc.stop_status = 0;
        proc.stop_reported = false;
    }
}

pub fn take_pending(proc: &mut ProcessRecord) -> (u64, u64) {
    let pending = proc.signal_state.pending_mask;
    proc.signal_state.pending_mask = 0;
    (pending, proc.signal_state.block_mask)
}

unsafe fn mp_write_nonblocking(ipc_ctx: *mut IpcContext, mp: u64, msg: *const TronaMsg) -> i32 {
    unsafe {
        if mp == 0 {
            return uapi::KERNITE_ERR_INVALID_ARGUMENT as i32;
        }
        ipc::mp_write_ctx(ipc_ctx, mp, msg)
    }
}
