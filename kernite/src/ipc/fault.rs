// SPDX-License-Identifier: GPL-2.0-only
//! Per-task fault delivery into a bound `MessagePipe` —
//! **reply-to-resume** semantics.
//!
//! A thread installs a fault `MessagePipe` via `TCB_SET_FAULT_PIPE`.
//! When the thread takes an unhandled fault (page fault without a
//! mapped MO, illegal instruction, breakpoint trap, OOM during
//! commit, user-issued fault intent) the arch fault handler builds
//! a fault `MpRecord` and calls `deliver_fault`. The kernel then
//! writes a kernel-marked call record into the bound fault pipe,
//! parks the faulter reading the same endpoint, and resumes only when
//! the handler answers with `reply-marked MP_WRITE`.
//!
//! Resumption decision lives with the handler:
//!
//! * `reply-marked MP_WRITE` with label `KERNITE_OK` on the fault pipe → faulter
//!   wakes and the arch return path resumes userspace at the original
//!   faulting RIP/ELR (instruction retry — handler was responsible
//!   for making retry safe before replying).
//! * Close the fault pipe, send a malformed/non-OK reply, or kill the
//!   faulter → `deliver_fault` returns `false`, and the arch handler
//!   escalates to `task::quiesce::begin_destroy`.
//!
//! Delivery itself is best-effort: if the fault pipe is full or
//! peer-closed we cannot park the faulter (the handler can never
//! drain the record) so we tear the binding down and return `false`
//! immediately. The arch handler treats `false` as "no recovery
//! possible — destroy".

use crate::ipc::message_pipe::{CarrierSlots, MpRecord, ReadOutcome, TryWriteErr};
use crate::sched::thread::Tcb;

const MP_FLAG_CALL: u64 = uapi::KERNITE_MP_FLAG_CALL as u64;
const MP_FLAG_REPLY: u64 = uapi::KERNITE_MP_FLAG_REPLY as u64;
const MP_FLAG_FAULT: u64 = uapi::KERNITE_MP_FLAG_FAULT as u64;

/// Fault label values placed into the `label` field of the delivered
/// fault `MpRecord`.
#[repr(u64)]
pub enum FaultLabel {
    NullFault = 0,
    PageFault = 1,
    IllegalInstruction = 2,
    Breakpoint = 3,
    UserException = 4,
    OomFault = 5,
    Cap = 6,
}

/// Build a page-fault record. `address` is the faulting VA, `flags`
/// carries arch-specific cause bits, `rip` / `elr` is the faulting
/// instruction pointer, `is_instruction_fetch` indicates an instruction
/// vs data access.
pub fn page_fault_record(
    address: u64,
    flags: u64,
    rip: u64,
    is_instruction_fetch: bool,
) -> MpRecord {
    let mut record = MpRecord::empty();
    record.label = FaultLabel::PageFault as u64;
    record.length = 4;
    record.words[0] = address;
    record.words[1] = flags;
    record.words[2] = rip;
    record.words[3] = is_instruction_fetch as u64;
    record
}

/// Build an OOM record for a faulting page-allocation.
pub fn oom_record(far: u64, rip: u64, reason: u64) -> MpRecord {
    let mut record = MpRecord::empty();
    record.label = FaultLabel::OomFault as u64;
    record.length = 3;
    record.words[0] = far;
    record.words[1] = rip;
    record.words[2] = reason;
    record
}

/// Build a generic user-exception record (illegal instruction, GPF,
/// breakpoint).
pub fn user_exception_record(vector: u64, error_code: u64, rip: u64, rsp: u64) -> MpRecord {
    let mut record = MpRecord::empty();
    record.label = FaultLabel::UserException as u64;
    record.length = 4;
    record.words[0] = vector;
    record.words[1] = error_code;
    record.words[2] = rip;
    record.words[3] = rsp;
    record
}

/// Deliver a fault record into the thread's bound fault MessagePipe
/// using `MP_CALL`-shaped reply-to-resume semantics.
///
/// Returns `true` when the handler replied with `reply-marked MP_WRITE` and
/// `KERNITE_OK` (resumption requested — caller's arch fault handler
/// should return to user mode at the faulting instruction). Returns
/// `false` when:
///
/// * No fault pipe is bound.
/// * The bound fault pipe is `STATE_PEER_CLOSED` or
///   `STATE_CLOSED` (no live handler).
/// * The fault pipe's outbound ring is full at this instant — we
///   cannot park the faulter on a producer-side queue from the
///   exception entry path safely (nested fault risk during the
///   subsequent `MP_WRITE` retry), so we cancel the binding.
/// * The handler sends a malformed/non-OK reply or kills us while
///   the faulter is waiting.
///
/// In every `false` branch the arch fault handler escalates to
/// `task::quiesce::begin_destroy`. The `true` branch returns
/// directly to user mode — userspace re-executes the faulting
/// instruction with whatever state the handler set up.
///
/// # Safety
/// `tcb` must point at the currently-running `Tcb`. Caller is the
/// arch fault entry path, so interrupts are arch-disabled and the
/// scheduler is in a consistent state for `reschedule`.
pub unsafe fn deliver_fault(tcb: *mut Tcb, mut record: MpRecord) -> bool {
    // Snapshot the per-thread fault binding under `tcb_lock` so a
    // concurrent `TCB_SET_FAULT_PIPE` cannot tear the bound endpoint
    // while the exception path snapshots it.
    let irq_lock = unsafe { crate::mm::save_irq_disable() };
    unsafe { (*tcb).tcb_lock() };
    let pipe = unsafe { (*tcb).fault_pipe };
    unsafe { (*tcb).tcb_unlock() };
    unsafe { crate::mm::restore_irq(irq_lock) };

    if pipe.is_null() {
        return false;
    }

    record.flags |= MP_FLAG_CALL | MP_FLAG_FAULT;
    record.cap_count = 0;
    let carriers = CarrierSlots::empty();

    // Single try_write_record. PeerClosed / WouldBlock both mean
    // "no recoverable handler right now".
    match unsafe { (*pipe).try_write_record(record, carriers) } {
        Ok(()) => {}
        Err(TryWriteErr::PeerClosed) | Err(TryWriteErr::WouldBlock) => return false,
    }

    unsafe { wait_for_fault_reply(tcb, pipe) }
}

unsafe fn drop_carriers(carriers: &mut CarrierSlots) {
    let irq = unsafe { crate::mm::save_irq_disable() };
    crate::mm::CAP_LOCK.lock();
    for entry in carriers.0.iter_mut() {
        let cur = *entry;
        *entry = crate::ipc::message_pipe::CarrierEntry::null();
        // Release the transit pin and tear the slot down. The pin froze
        // the slot's generation, so no epoch re-check is needed.
        unsafe { cur.unpin_and_delete() };
    }
    crate::mm::CAP_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
}

unsafe fn wait_for_fault_reply(
    tcb: *mut Tcb,
    pipe: *mut crate::ipc::message_pipe::MessagePipe,
) -> bool {
    let scheduler = crate::sched::scheduler::scheduler();
    loop {
        let mut malformed = false;
        let outcome = unsafe {
            (*pipe).try_read_with_install(|carriers, reply| -> Result<u64, ()> {
                if reply.cap_count != 0 {
                    malformed = true;
                    drop_carriers(carriers);
                    reply.cap_count = 0;
                }
                if (reply.flags & MP_FLAG_REPLY) == 0 {
                    malformed = true;
                }
                Ok(reply.label)
            })
        };
        match outcome {
            ReadOutcome::Read(label) => {
                return !malformed && label == uapi::KERNITE_OK as u64;
            }
            ReadOutcome::PeerClosed | ReadOutcome::ConsumeFailed => return false,
            ReadOutcome::WouldBlock => unsafe {
                (*tcb).futex_wakeup_result = 0;
                let _ = (*pipe).enqueue_reader_waiter(tcb);
                scheduler.reschedule();
            },
        }
    }
}
