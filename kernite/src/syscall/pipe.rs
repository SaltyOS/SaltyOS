// SPDX-License-Identifier: GPL-2.0-only
//! Pipe-related syscall handlers for the new ABI.
//!
//! Covers `MessagePipe` and `DataPipe` operations. Call/reply semantics
//! ride on top of `MP_CALL` / `MP_WRITE`: the caller writes a request
//! with a kernel transaction id, and the server answers by writing a
//! reply record that carries the same txid in the IPC buffer metadata.

const EVENT_TYPE_USER: u32 = uapi::KERNITE_EVENT_TYPE_USER;
const STATE_READABLE: u64 = uapi::KERNITE_STATE_READABLE as u64;
const STATE_WRITABLE: u64 = uapi::KERNITE_STATE_WRITABLE as u64;
const MP_FLAG_CALL: u64 = uapi::KERNITE_MP_FLAG_CALL as u64;
const MP_FLAG_REPLY: u64 = uapi::KERNITE_MP_FLAG_REPLY as u64;

static NEXT_MP_CALL_TXID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

/// Kernel-reserved high bit for sync MP_CALL transaction ids. Userspace
/// async request/reply writes must keep txids below this bit so they can
/// never collide with a kernel-generated sync-call txid on a shared pipe.
/// Derived from the bindgen-bridged bit *position* — see the
/// `KERNITE_MP_TXID_KERNEL_BIT` ABI note (bindgen cannot carry the mask).
const KERNEL_TXID_BIT: u64 = 1u64 << uapi::KERNITE_MP_TXID_KERNEL_BIT_SHIFT;

use super::support::{
    IPC_BADGE_WORD, IPC_CAPS_BASE_WORD, IPC_FLAGS_WORD, IPC_MP_TXID_WORD, IPC_MSG_REGS_BASE_WORD,
    IPC_RECEIVE_CNODE_WORD, IPC_RECEIVE_DEPTH_WORD, IPC_RECEIVE_INDEX_WORD,
    syscall_error_from_cap_error,
};
use super::{
    CAP_LOCK, CapRights, Capability, ObjectType, SyscallError, SyscallResult,
    copy_to_current_ipc_words, msg_info, read_current_ipc_word, validate_capability,
};
use crate::cap::INVALID_SLOT;
use crate::ipc::data_pipe::{DATA_PIPE_MAX_DATAGRAM, DataPipe, TryConsumeErr, TryProduceErr};
use crate::ipc::message_pipe::{
    CarrierSlots, MP_MSG_CAPS, MP_MSG_WORDS, MessagePipe, MpRecord, ReadOutcome, TryWriteErr,
};
use crate::ipc::transfer::{InstalledCap, rollback_installed_locked};

fn next_mp_call_txid() -> u64 {
    // Sync MP_CALL txids occupy the kernel-reserved high range so they
    // never collide with userspace async-write txids (held to the low
    // range by `apply_mp_write_metadata`). The monotonic counter supplies
    // the low 63 bits; OR-ing in `KERNEL_TXID_BIT` also guarantees the
    // result is never the zero sentinel.
    let n = NEXT_MP_CALL_TXID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    (n & !KERNEL_TXID_BIT) | KERNEL_TXID_BIT
}

/// Build an `MpRecord` from invoke args + the IPC buffer overflow.
/// Args carry the msg_info-style label/length plus three register
/// words; words 4..length come from the current thread's IPC buffer.
fn build_mp_record(msg_info: u64, mr0: u64, mr1: u64, mr2: u64) -> Result<MpRecord, SyscallError> {
    let raw_length = msg_info::get_length(msg_info);
    let raw_caps = msg_info::get_extra_caps(msg_info);
    if raw_length > MP_MSG_WORDS || raw_caps > MP_MSG_CAPS {
        // Surface oversize requests explicitly rather than silently
        // truncating the tail. Userland gets a deterministic
        // `TooLarge` error and can resize / split before retry.
        return Err(SyscallError::TooLarge);
    }
    let mut record = MpRecord::empty();
    record.label = msg_info::get_label(msg_info);
    let length = raw_length;
    record.length = length as u64;
    if length > 0 {
        record.words[0] = mr0;
    }
    if length > 1 {
        record.words[1] = mr1;
    }
    if length > 2 {
        record.words[2] = mr2;
    }
    if length > 3 {
        // `record.words[k]` is the logical `regs[k]` payload mirror
        // — `mr0..mr2` already populated `record.words[0..3]` from the
        // invoke arg registers. The remaining slots live in the
        // sender's IPC buffer at the UAPI overlay position
        // `msg[IPC_MSG_REGS_BASE_WORD + k]`, NOT at the raw word
        // offset `k`. Reading `read_current_ipc_word(k)` here would
        // pull `regs[k - 2]` instead — an off-by-2 that shifts
        // payload words 3..length by two slots on the wire.
        for i in 3..length {
            unsafe {
                record.words[i] = read_current_ipc_word(IPC_MSG_REGS_BASE_WORD + i)?;
            }
        }
    }
    record.cap_count = raw_caps as u64;
    Ok(record)
}

/// Build an `MpRecord` reading the ENTIRE message body from the current
/// thread's IPC buffer (words `0..length` at `IPC_MSG_REGS_BASE_WORD +
/// i`). Used by `MP_CALL`, whose request payload lives in the buffer so
/// its `deadline` can ride an invoke register — unlike `build_mp_record`,
/// no payload word arrives in registers.
fn build_mp_record_from_buffer(msg_info: u64) -> Result<MpRecord, SyscallError> {
    let raw_length = msg_info::get_length(msg_info);
    let raw_caps = msg_info::get_extra_caps(msg_info);
    if raw_length > MP_MSG_WORDS || raw_caps > MP_MSG_CAPS {
        return Err(SyscallError::TooLarge);
    }
    let mut record = MpRecord::empty();
    record.label = msg_info::get_label(msg_info);
    record.length = raw_length as u64;
    for i in 0..raw_length {
        record.words[i] = unsafe { read_current_ipc_word(IPC_MSG_REGS_BASE_WORD + i)? };
    }
    record.cap_count = raw_caps as u64;
    Ok(record)
}

/// Apply sender-controlled MessagePipe metadata for `MP_WRITE`.
///
/// The write ABI carries the actual payload in invoke args plus the
/// IPC-buffer overflow area. Reply routing metadata lives in the typed
/// IPC buffer header so a reply is just a write record with
/// `KERNITE_MP_FLAG_REPLY` and the txid copied from the inbound call.
fn apply_mp_write_metadata(record: &mut MpRecord) -> Result<(), SyscallError> {
    let flags = unsafe { read_current_ipc_word(IPC_FLAGS_WORD)? };
    if (flags & !MP_FLAG_REPLY) != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    record.flags = flags;
    let txid = unsafe { read_current_ipc_word(IPC_MP_TXID_WORD)? };
    // A reply echoes whatever txid its request carried (high for a sync
    // MP_CALL, low for an async request), so its range is unrestricted. A
    // non-reply (async request) write may carry its own low-range
    // correlation txid, but never the kernel-reserved high range — that
    // would let a user write forge a reply completing a parked sync caller.
    // txid == 0 stays the "no correlation" sentinel.
    if (flags & MP_FLAG_REPLY) == 0 && (txid & KERNEL_TXID_BIT) != 0 {
        return Err(SyscallError::InvalidArgument);
    }
    record.txid = txid;
    Ok(())
}

/// Capture sidecar — the carriers themselves carry only `CapRef`s
/// (so the message-pipe ring stays a uniform `[CarrierSlots; depth]`),
/// but the syscall layer keeps a parallel record of where each
/// `CapRef` came from. `rollback_carriers` uses this sidecar to put
/// the `CapRef`s back into the sender's CNode if the message is
/// rejected before it reaches the ring.
///
/// Once the message has been queued (or installed at the receiver),
/// the sidecar is dropped — at that point the carrier's lifetime is
/// owned by the ring (or by the receiver CNode), and rollback is no
/// longer meaningful.
pub(super) struct CaptureContext {
    pub carriers: CarrierSlots,
    /// Sender cap addresses (root-CSpace relative) the carriers were moved
    /// out of. Rollback RE-RESOLVES these against the sender's current
    /// root CSpace rather than caching a raw leaf-`CNode` pointer: a
    /// sibling thread can destroy a nested leaf CNode during the
    /// lock-released in-flight window, so a cached pointer would dangle.
    /// An address that no longer resolves means the cap can't go home and
    /// is torn down instead.
    pub sender_addrs: [u64; MP_MSG_CAPS],
    pub cap_count: usize,
}

impl CaptureContext {
    pub(super) const fn empty() -> Self {
        Self {
            carriers: CarrierSlots::empty(),
            sender_addrs: [crate::cap::INVALID_SLOT as u64; MP_MSG_CAPS],
            cap_count: 0,
        }
    }
}

/// Resolve the caller-supplied carrier source slots from the
/// current thread's IPC buffer caps[] area, validate that each cap
/// carries `TRANSFER` rights, and **move** each `CapRef` out of the
/// sender's CNode into the carrier array.
///
/// CapRef move semantics: the underlying global capability slot's
/// CDT linkage and object refcount stay intact — only the binding
/// from sender CNode → global slot is detached. The carrier holds
/// the moved `CapRef` until the receiver's `install` reattaches it
/// to the receiver's CNode (or `rollback_carriers` puts it back).
///
/// IPC-buffer reads happen BEFORE `CAP_LOCK` is taken so a uaccess
/// page-fault path cannot recurse into the cap subsystem under the
/// global lock.
unsafe fn capture_caps_into_carriers(
    record: &mut MpRecord,
    msg_info_word: u64,
) -> Result<CaptureContext, SyscallError> {
    let cap_count = msg_info::get_extra_caps(msg_info_word).min(MP_MSG_CAPS);
    record.cap_count = cap_count as u64;
    let mut ctx = CaptureContext::empty();
    ctx.cap_count = cap_count;
    if cap_count == 0 {
        return Ok(ctx);
    }

    // Stage 1 (no lock): read every source slot address out of the
    // IPC buffer up-front. uaccess can take page faults; doing this
    // before grabbing CAP_LOCK keeps the lock ordering clean.
    let mut slot_addrs = [INVALID_SLOT as u64; MP_MSG_CAPS];
    for i in 0..cap_count {
        slot_addrs[i] = unsafe { read_current_ipc_word(IPC_CAPS_BASE_WORD + i)? };
    }

    // Stage 2 (CAP_LOCK): resolve each address against the sender's
    // root CSpace and move the `CapRef` out of the sender CNode.
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return Err(SyscallError::InvalidOperation);
    }
    let root = unsafe { (*current).cspace_root };
    if root.is_null() {
        return Err(SyscallError::InvalidOperation);
    }

    let irq = unsafe { crate::mm::save_irq_disable() };
    CAP_LOCK.lock();
    for i in 0..cap_count {
        let addr = slot_addrs[i];
        if addr == INVALID_SLOT as u64 {
            unsafe { undo_partial_capture_locked(&ctx, i) };
            CAP_LOCK.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(SyscallError::InvalidCapability);
        }
        let resolved = unsafe { crate::cap::cnode::resolve_root_cspace_for_slot(&*root, addr) };
        let (sender_cnode, sender_idx) = match resolved {
            Ok(p) => p,
            Err(_) => {
                unsafe { undo_partial_capture_locked(&ctx, i) };
                CAP_LOCK.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return Err(SyscallError::InvalidCapability);
            }
        };
        let peek = match unsafe { (&*sender_cnode).get_ref(sender_idx) } {
            Some(r) => r,
            None => {
                unsafe { undo_partial_capture_locked(&ctx, i) };
                CAP_LOCK.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return Err(SyscallError::InvalidCapability);
            }
        };
        let cap = peek.get();
        if cap.is_null() {
            unsafe { undo_partial_capture_locked(&ctx, i) };
            CAP_LOCK.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(SyscallError::InvalidCapability);
        }
        if !cap.has_right(CapRights::TRANSFER) {
            unsafe { undo_partial_capture_locked(&ctx, i) };
            CAP_LOCK.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(SyscallError::InsufficientRights);
        }
        let moved = match unsafe { (&mut *sender_cnode).take_ref(sender_idx) } {
            Some(r) => r,
            None => {
                unsafe { undo_partial_capture_locked(&ctx, i) };
                CAP_LOCK.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return Err(SyscallError::InvalidCapability);
            }
        };
        // Snapshot the slot's reuse epoch under CAP_LOCK. Any later
        // free + reuse during the in-flight window bumps it, which
        // install / rollback / cancel paths catch via
        // `get_generation(slot) == entry.epoch`.
        let epoch = crate::cap::get_generation(moved.slot);
        ctx.carriers.0[i] = crate::ipc::message_pipe::CarrierEntry {
            slot: moved.slot,
            epoch,
        };
        // The cap is now in transit — moved out of the sender CNode, not
        // yet installed into the receiver. Pin its global slot so a
        // concurrent CSpace teardown cannot free + reuse it during the
        // deferred-install window. The pin is released when the cap
        // leaves transit (installed, rolled back, or dropped).
        crate::cap::pin_transit(moved.slot);
        ctx.sender_addrs[i] = addr;
    }
    CAP_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
    Ok(ctx)
}

/// CAP_LOCK-held helper: put a partial capture back into the sender's
/// CNode entries when a later step fails. Each carrier's epoch is
/// re-checked against the slot's current reuse counter before
/// `insert_ref` — a free + reuse during the brief partial-capture
/// window would otherwise let us bind the sender's CNode entry to
/// an unrelated cap.
unsafe fn undo_partial_capture_locked(ctx: &CaptureContext, captured: usize) {
    // Re-resolve each sender address against the live root CSpace rather
    // than a cached leaf-CNode pointer. This runs under the same CAP_LOCK
    // the capture held, so the leaf is still alive and resolution
    // succeeds; the current thread is the sender, so its root is the right
    // CSpace.
    let root = {
        let cur = crate::sched::scheduler::scheduler().current();
        if cur.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { (*cur).cspace_root }
        }
    };
    for i in 0..captured {
        let entry = ctx.carriers.0[i];
        if entry.is_null() {
            continue;
        }
        // The cap returns to the sender CNode — it leaves transit, so
        // release the pin taken at capture.
        crate::cap::unpin_transit(entry.slot);
        let addr = ctx.sender_addrs[i];
        let reinserted = if !root.is_null() {
            match unsafe { crate::cap::cnode::resolve_root_cspace_for_slot(&*root, addr) } {
                Ok((cnode, idx)) => unsafe {
                    (&mut *cnode)
                        .insert_ref(
                            idx,
                            crate::cap::CapRef::from_slot_generation(
                                entry.slot,
                                entry.epoch as u32,
                            ),
                        )
                        .is_ok()
                },
                Err(_) => false,
            }
        } else {
            false
        };
        if !reinserted {
            // The sender address no longer resolves (nested CNode gone) or
            // the slot was refilled — the cap can't go home, so tear it
            // down rather than leaking the global slot.
            crate::cap::CDT::delete_capability(entry.slot);
        }
    }
}

/// Roll back already-captured carriers back into the sender's CNode
/// when the kernel decided not to deliver them after all (e.g. the
/// pipe rejected the write with `STATE_PEER_CLOSED`). The capture
/// sidecar gives us each `CapRef`'s original `(sender_cnode,
/// sender_idx)`; we attempt to put the `CapRef` back at that
/// position. If the sender's slot is no longer empty (a sibling
/// thread sharing the same CNode raced in and filled it), we tear
/// the binding down via the canonical `CDT::delete_capability` path
/// (cdt-remove → release_object → nullify_capability → free_slot)
/// rather than silently overwriting whatever the sender's peer
/// thread put there.
///
/// Called WITHOUT `CAP_LOCK` held; this helper takes the lock
/// internally.
/// Free every still-non-null `CapRef` in `carriers` via the canonical
/// `CDT::delete_capability` path. Used after a mailbox claim has
/// transferred ownership to the caller's stack but the receive-side
/// install or IPC-buffer write has failed — the sender CSpace is no
/// longer reachable (its slots may have been reused), so the carriers
/// cannot be rolled back, only freed. Each entry's slot epoch is
/// re-checked to skip ABA-reused slots that no longer hold our cap.
///
/// # Safety
/// `carriers` must be uniquely owned by the caller — already moved
/// out of the sender CSpace and not yet installed into the receiver
/// CSpace. Caller must NOT hold `CAP_LOCK` — this fn takes it
/// internally.
pub(super) unsafe fn drop_uninstalled_carriers(carriers: &mut CarrierSlots) {
    let irq = unsafe { crate::mm::save_irq_disable() };
    CAP_LOCK.lock();
    for i in 0..MP_MSG_CAPS {
        let entry = carriers.0[i];
        carriers.0[i] = crate::ipc::message_pipe::CarrierEntry::null();
        // The cap is dropped — never delivered, never rolled back into a
        // CNode. Release its transit pin, then tear the global slot down
        // via the canonical CDT path. No-op for a null entry.
        unsafe { entry.unpin_and_delete() };
    }
    CAP_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
}

unsafe fn rollback_carriers(ctx: &mut CaptureContext) {
    // Re-fetch the sender's root CSpace BEFORE taking CAP_LOCK (mirrors
    // capture). The capture-time leaf-CNode pointers are deliberately not
    // cached: a sibling can destroy a nested leaf CNode during the
    // lock-released in-flight window, so reinsertion re-resolves each
    // sender address against the live CSpace. The current thread is the
    // sender (same syscall), so its root is the right CSpace.
    let root = {
        let cur = crate::sched::scheduler::scheduler().current();
        if cur.is_null() {
            core::ptr::null_mut()
        } else {
            unsafe { (*cur).cspace_root }
        }
    };
    let irq = unsafe { crate::mm::save_irq_disable() };
    CAP_LOCK.lock();
    for i in 0..ctx.cap_count.min(MP_MSG_CAPS) {
        let entry = ctx.carriers.0[i];
        let addr = ctx.sender_addrs[i];
        ctx.carriers.0[i] = crate::ipc::message_pipe::CarrierEntry::null();
        ctx.sender_addrs[i] = crate::cap::INVALID_SLOT as u64;
        if entry.is_null() {
            continue;
        }
        // The cap leaves transit — it returns to the sender CNode or, if
        // its address no longer resolves (nested CNode gone) or the slot
        // was refilled, is torn down. Release the pin first.
        crate::cap::unpin_transit(entry.slot);
        let capref = crate::cap::CapRef::from_slot_generation(entry.slot, entry.epoch as u32);
        // Best-effort reinsertion at the original sender address, re-resolved
        // against the live CSpace so a destroyed nested leaf CNode is observed
        // as a resolve failure instead of a dangling-pointer write.
        let reinserted = if !root.is_null() {
            match unsafe { crate::cap::cnode::resolve_root_cspace_for_slot(&*root, addr) } {
                Ok((cnode, idx)) => unsafe { (&mut *cnode).insert_ref(idx, capref) }.is_ok(),
                Err(_) => false,
            }
        } else {
            false
        };
        if reinserted {
            continue;
        }
        // Reinsertion impossible — walk the full teardown path so the CDT
        // linkage detaches before the global slot is recycled (release +
        // free alone would leave a stale CDT child pointer behind).
        crate::cap::CDT::delete_capability(entry.slot);
    }
    ctx.cap_count = 0;
    CAP_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
}

/// Resolve the receiver-side install destination from the current
/// thread's IPC buffer (`receive_cnode` / `receive_index` /
/// `receive_depth`) and install each carrier into the receiver's
/// CSpace as a sequential `Capability`.
///
/// Returns the receive-side install records in the order they were
/// installed. Returns `Err(SyscallError)` if any install step
/// fails — the caller treats this as `ReadOutcome::ConsumeFailed`
/// so the message stays at the head of the ring and no carrier is
/// consumed. On failure the function rolls back every install it
/// has already performed so the receiver's CSpace is left
/// untouched.
pub(super) unsafe fn install_carriers_into_receiver(
    carriers: &mut CarrierSlots,
    cap_count: usize,
) -> Result<[InstalledCap; MP_MSG_CAPS], SyscallError> {
    let mut installed = [InstalledCap::null(); MP_MSG_CAPS];
    if cap_count == 0 {
        return Ok(installed);
    }
    // IPC-buffer reads can fault — propagate the precise SyscallError
    // (BadAddress for fault, not OutOfMemory) so the consume closure
    // surfaces the right diagnostic at the syscall boundary.
    let receive_index = unsafe { read_current_ipc_word(IPC_RECEIVE_INDEX_WORD)? };
    // `receive_cnode` / `receive_depth` are reserved for nested
    // cap-resolution chains; the current install path resolves each
    // receive slot via the root CSpace addressing of the receiver's
    // TCB. Read them so a future nested model can drop straight into
    // this position.
    let _cn = unsafe { read_current_ipc_word(IPC_RECEIVE_CNODE_WORD)? };
    let _depth = unsafe { read_current_ipc_word(IPC_RECEIVE_DEPTH_WORD)? };

    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return Err(SyscallError::InvalidOperation);
    }
    let root = unsafe { (*current).cspace_root };
    if root.is_null() {
        return Err(SyscallError::InvalidOperation);
    }

    let irq = unsafe { crate::mm::save_irq_disable() };
    CAP_LOCK.lock();
    // Track each install so partial failure can move the `CapRef`s
    // back into `carriers` for the caller to dispose of.
    let mut install_sites: [(usize, *mut crate::cap::CNode); MP_MSG_CAPS] =
        [(0, core::ptr::null_mut()); MP_MSG_CAPS];

    for i in 0..cap_count {
        let entry = carriers.0[i];
        if entry.is_null() {
            unsafe { rollback_installed_locked(carriers, &install_sites, i) };
            CAP_LOCK.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(SyscallError::InvalidCapability);
        }
        // Invariant: the transit pin taken at capture froze this slot's
        // generation for the entire in-flight window, so the carrier's
        // captured epoch must still match here. A mismatch would mean a
        // transit pin was released early — a bug in the carrier pin
        // accounting, not a benign ABA race — so assert rather than
        // silently dropping the cap. The silent drop is exactly the
        // fork-breaking failure this pin design eliminates.
        crate::kernel::bug::kassert_eq!(
            crate::cap::get_generation(entry.slot),
            entry.epoch,
            "in-transit carrier slot generation advanced under a held transit pin"
        );
        let capref = crate::cap::CapRef::from_slot_generation(entry.slot, entry.epoch as u32);
        let dest_addr = receive_index + i as u64;
        let resolved =
            unsafe { crate::cap::cnode::resolve_root_cspace_for_slot(&*root, dest_addr) };
        let (recv_cnode, recv_idx) = match resolved {
            Ok(p) => p,
            Err(_) => {
                unsafe { rollback_installed_locked(carriers, &install_sites, i) };
                CAP_LOCK.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                return Err(SyscallError::InvalidCapability);
            }
        };
        if let Err(e) = unsafe { (&mut *recv_cnode).insert_ref(recv_idx, capref) } {
            unsafe { rollback_installed_locked(carriers, &install_sites, i) };
            CAP_LOCK.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(syscall_error_from_cap_error(e));
        }
        // Capture per-install identity BEFORE clearing the carrier.
        // `slot` is the global cap slot the sender pushed across;
        // `generation` is the slot's reuse counter at install time
        // (`entry.epoch` would also do — we just re-read for clarity).
        // Together they let the rollback path detect whether the
        // receive slot still holds *this* install or has been
        // overwritten by a sibling CSpace mutation.
        let install_slot = capref.slot;
        let install_gen = entry.epoch;
        // From this point forward the receiver CNode owns the CapRef.
        // Clear the carrier so the syscall layer cannot rollback it
        // back into the sender (the message has been delivered).
        carriers.0[i] = crate::ipc::message_pipe::CarrierEntry::null();
        install_sites[i] = (recv_idx, recv_cnode);
        // Report the install position in the **receiver's address
        // space** (user-relative cap_ptr) — what userland needs to
        // invoke the cap. The underlying global slot is a kernel-
        // internal handle and must NOT cross the syscall boundary.
        installed[i] = InstalledCap {
            dest_addr,
            slot: install_slot,
            generation: install_gen,
        };
    }
    // Full commit: every carrier was installed into the receiver CNode.
    // The caps have left transit (the receiver owns them now), so drop
    // the transit pins taken at capture. Done after the whole loop —
    // never per-entry — so a partial-install failure (which take_refs the
    // installed caps back into `carriers` via `rollback_installed_locked`)
    // leaves every pin intact and never has to re-pin.
    for inst in installed.iter().take(cap_count) {
        if inst.slot != INVALID_SLOT {
            crate::cap::unpin_transit(inst.slot);
        }
    }
    CAP_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
    Ok(installed)
}

// `rollback_installed_locked` lives in `crate::ipc::transfer`;
// `install_carriers_into_receiver` calls it through the imported
// alias above.

/// Surface an `MpRecord` to userspace via the IPC buffer.
///
/// Writes label / length / message words and the sender's badge +
/// flags into their typed slots in the IPC buffer. The `installed`
/// slots are the receive-side CSpace indices the kernel minted from
/// the message's hidden carriers — userland reads them out of the
/// caps[] area.
pub(super) fn write_mp_record_to_ipc(
    record: &MpRecord,
    installed: &[InstalledCap; MP_MSG_CAPS],
) -> Result<(), SyscallError> {
    unsafe {
        let mut words: [u64; MP_MSG_WORDS + 2] = [0; MP_MSG_WORDS + 2];
        words[0] = record.label;
        words[1] = record.length;
        let n = (record.length as usize).min(MP_MSG_WORDS);
        for i in 0..n {
            words[i + 2] = record.words[i];
        }
        copy_to_current_ipc_words(0, &words[..n + 2])?;

        super::write_current_ipc_word(IPC_BADGE_WORD, record.badge)?;
        super::write_current_ipc_word(IPC_FLAGS_WORD, record.flags)?;
        super::write_current_ipc_word(IPC_MP_TXID_WORD, record.txid)?;
        let cap_count = (record.cap_count as usize).min(MP_MSG_CAPS);
        for i in 0..cap_count {
            super::write_current_ipc_word(IPC_CAPS_BASE_WORD + i, installed[i].dest_addr)?;
        }
        for i in cap_count..MP_MSG_CAPS {
            super::write_current_ipc_word(IPC_CAPS_BASE_WORD + i, INVALID_SLOT as u64)?;
        }
        // Surface cap_count in the reserved area so receivers can
        // locate user-supplied caps without scanning sentinels.
        super::write_current_ipc_word(
            super::support::IPC_RECEIVED_CAP_COUNT_WORD,
            cap_count as u64,
        )?;
    }
    Ok(())
}

pub(super) fn syscall_mp_write(
    cap: &Capability,
    msg_info_word: u64,
    mr0: u64,
    mr1: u64,
    mr2: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MessagePipe, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let mut record = match build_mp_record(msg_info_word, mr0, mr1, mr2) {
        Ok(r) => r,
        Err(e) => return SyscallResult::err(e),
    };
    record.badge = cap.badge;
    if let Err(e) = apply_mp_write_metadata(&mut record) {
        return SyscallResult::err(e);
    }
    let mut ctx = match unsafe { capture_caps_into_carriers(&mut record, msg_info_word) } {
        Ok(c) => c,
        Err(err) => return SyscallResult::err(err),
    };

    let mp = cap.object as *mut MessagePipe;
    loop {
        match unsafe { (*mp).try_write_record(record, ctx.carriers) } {
            Ok(()) => return SyscallResult::ok(0),
            Err(crate::ipc::message_pipe::TryWriteErr::PeerClosed) => {
                unsafe { rollback_carriers(&mut ctx) };
                return SyscallResult::err(SyscallError::PeerClosed);
            }
            Err(crate::ipc::message_pipe::TryWriteErr::WouldBlock) => {
                // Non-blocking by contract (zx_channel_write parity): a full
                // ring surfaces `WouldBlock`. Block-until-writable is an
                // `object_watch(WRITABLE | PEER_CLOSED)` + `EQ_WAIT`.
                unsafe { rollback_carriers(&mut ctx) };
                return SyscallResult::err(SyscallError::WouldBlock);
            }
        }
    }
}

/// Park the current TCB on `mp`'s writer waiter queue until the ring
/// has space, arming an absolute `IpcTimeout` deadline (skipped when
/// `deadline == u64::MAX`). Returns `None` on a normal wake (the caller
/// should retry the try-op), `Some(TimedOut)` when the deadline fired.
///
/// **`sched_ref` ownership**: `enqueue_writer_waiter` (pipe queue
/// `push`) and `arm_thread_ipc_timeout` (deadline queue `arm_thread`)
/// each take their own pin internally. The wake path that fires
/// (producer-driven `pop` → `wake_thread`, or deadline dispatch's
/// `sched_ref_release_may_destroy`) drops its own pin, and
/// `cancel_thread` here drops the deadline pin if the producer-driven
/// wake won the race. This fn must NOT take an extra pin — it would
/// leak on every block.
///
/// **Timeout-time waiter unlink**: deadline dispatch only runs the
/// pipe wake plan; per `WakeTransition::PipeWait`'s contract the
/// caller is responsible for removing itself from the pipe waiter
/// queue. On a timeout return below we call `detach_waiter` so the
/// pipe queue does not carry a stale node into the next producer's
/// pop.
unsafe fn block_writer_for_deadline(mp: *mut MessagePipe, deadline: u64) -> Option<SyscallError> {
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return Some(SyscallError::InvalidOperation);
    }
    // Absolute deadline; `u64::MAX` blocks forever. An already-expired
    // deadline returns `TimedOut` without parking.
    if deadline != u64::MAX && crate::arch::now_ns() >= deadline {
        return Some(SyscallError::TimedOut);
    }
    unsafe {
        (*current).futex_wakeup_result = 0;
        let _ = (*mp).enqueue_writer_waiter(current);
        if deadline != u64::MAX {
            crate::sched::deadline_queue::arm_thread_ipc_timeout(current, deadline);
        }
        scheduler.reschedule();
        // Drop any unfired deadline pin (no-op if it already fired).
        let _ = crate::sched::deadline_queue::cancel_thread(current);
        let result = (*current).futex_wakeup_result;
        (*current).futex_wakeup_result = 0;
        if result == SyscallError::TimedOut as u64 {
            // Deadline fired — pipe waiter queue may still hold us.
            // `detach_waiter` removes us if present and drops the
            // queue's `sched_ref` pin.
            let core = (*mp).core;
            let me = (*mp).which_side;
            crate::ipc::message_pipe::MessagePipeCore::detach_waiter(
                core,
                current,
                me,
                crate::sched::thread::BlockedReason::PipeWrite,
            );
            // Also drop any in-flight publish in our mailbox that
            // won the wake race against the deadline. The producer
            // (cross-CPU `try_write_fast` against this thread) may
            // have deposited a `MailboxKind::Message` between
            // the deadline fire and this code path; consuming it
            // here would mean we lose nothing but the producer
            // observes its publish completed normally.
            //
            // CAP_LOCK contract: `cancel_pending` walks any
            // mailbox-resident carrier slots via
            // `CDT::delete_capability`, which assumes CAP_LOCK
            // held. Acquire here so the destroy path's CAP_LOCK
            // assumption stays uniform.
            let irq2 = crate::mm::save_irq_disable();
            CAP_LOCK.lock();
            (*current).mp_fast_mailbox.cancel_pending();
            CAP_LOCK.unlock();
            crate::mm::restore_irq(irq2);
            return Some(SyscallError::TimedOut);
        }
    }
    None
}

/// Park the current TCB after a successful `MP_CALL` request enqueue.
/// The call waiter was registered atomically with the request write;
/// this routine only flips the already-queued waiter into the blocked
/// scheduler state and handles timeout cleanup.
unsafe fn block_call_for_deadline(mp: *mut MessagePipe, deadline: u64) -> Option<SyscallError> {
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return Some(SyscallError::InvalidOperation);
    }
    // Absolute deadline; `u64::MAX` blocks forever for the reply. An
    // already-expired deadline unregisters the call waiter and returns
    // `TimedOut` rather than parking.
    if deadline != u64::MAX && crate::arch::now_ns() >= deadline {
        unsafe {
            (*mp).unregister_call_waiter(current);
            drop_current_call_reply(current);
        }
        return Some(SyscallError::TimedOut);
    }
    unsafe {
        if (*current)
            .message_waiter
            .ready
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        if !(*mp).prepare_call_waiter_block(current) {
            if (*current)
                .message_waiter
                .ready
                .load(core::sync::atomic::Ordering::Acquire)
            {
                return None;
            }
            return Some(SyscallError::PeerClosed);
        }

        (*current).futex_wakeup_result = 0;
        if deadline != u64::MAX {
            crate::sched::deadline_queue::arm_thread_ipc_timeout(current, deadline);
        }
        scheduler.reschedule();
        let _ = crate::sched::deadline_queue::cancel_thread(current);
        let result = (*current).futex_wakeup_result;
        (*current).futex_wakeup_result = 0;
        if result == SyscallError::TimedOut as u64 {
            (*mp).unregister_call_waiter(current);
            drop_current_call_reply(current);
            return Some(SyscallError::TimedOut);
        }
        if (*current)
            .message_waiter
            .ready
            .load(core::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        if !(*mp).call_waiter_registered(current) {
            return Some(SyscallError::PeerClosed);
        }
    }
    None
}

pub(super) fn syscall_mp_read(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MessagePipe, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let mp = cap.object as *mut MessagePipe;
    // Peek-then-commit: the consume closure runs install + IPC-buffer
    // write inside `try_read_with_install`'s fail-safe window. On
    // closure failure (cap install failure, IPC-buffer fault, or
    // sibling CSpace race) the head ring slot is restored from the
    // surviving-CapRef snapshot AND the record's `cap_count` is
    // shrunk to match — the record is NOT lost, and a subsequent
    // reader sees a self-consistent (record, carriers) pair.
    // `consume_err` carries the precise `SyscallError` back across
    // the closure boundary so we surface `BadAddress` for IPC-buffer
    // faults, `SlotOccupied` for stale receive slots, and
    // `InvalidCapability` for resolve / sibling-delete races.
    loop {
        let mut consume_err: Option<SyscallError> = None;
        let outcome = unsafe {
            (*mp).try_read_with_install(|carriers, record| -> Result<u64, ()> {
                let cap_count = (record.cap_count as usize).min(MP_MSG_CAPS);
                let installed = match install_carriers_into_receiver(carriers, cap_count) {
                    Ok(slots) => slots,
                    Err(err) => {
                        // `carriers` already carries the surviving
                        // `CapRef`s thanks to `rollback_installed_locked`
                        // inside `install_carriers_into_receiver`.
                        consume_err = Some(err);
                        return Err(());
                    }
                };
                if let Err(err) = write_mp_record_to_ipc(record, &installed) {
                    // IPC-buffer write faulted. Pull the just-installed
                    // `CapRef`s back out of the receiver's CNode into
                    // the local `carriers` snapshot so
                    // `release_claim_with_carriers` can restore them
                    // into the ring head. A sibling thread sharing the
                    // CSpace may have deleted some receive slots in
                    // between install and rollback — those carriers
                    // cannot be recovered, so the closure shrinks
                    // `record.cap_count` to the surviving count and
                    // compacts the surviving `CapRef`s to the front
                    // of `carriers`. The next read sees a coherent
                    // (record, carriers) pair.
                    let surviving = rollback_install_to_carriers(carriers, &installed, cap_count);
                    record.cap_count = surviving as u64;
                    consume_err = Some(err);
                    return Err(());
                }
                Ok(record.label)
            })
        };
        match outcome {
            ReadOutcome::Read(label) => return SyscallResult::ok(label),
            ReadOutcome::PeerClosed => return SyscallResult::err(SyscallError::PeerClosed),
            // Non-blocking by contract (zx_channel_read parity): an empty
            // pipe surfaces `WouldBlock`. Block-until-readable is an
            // `object_watch(READABLE | PEER_CLOSED)` + `EQ_WAIT`.
            ReadOutcome::WouldBlock => return SyscallResult::err(SyscallError::WouldBlock),
            ReadOutcome::ConsumeFailed => {
                return SyscallResult::err(consume_err.unwrap_or(SyscallError::OutOfMemory));
            }
        }
    }
}

unsafe fn drop_current_call_reply(current: *mut crate::sched::thread::Tcb) {
    if current.is_null() {
        return;
    }
    unsafe {
        if (*current)
            .message_waiter
            .ready
            .swap(false, core::sync::atomic::Ordering::AcqRel)
        {
            let irq = crate::mm::save_irq_disable();
            CAP_LOCK.lock();
            (*current)
                .message_waiter
                .reply_carriers
                .drop_via_cdt_locked();
            CAP_LOCK.unlock();
            crate::mm::restore_irq(irq);
            (*current)
                .message_waiter
                .txid
                .store(0, core::sync::atomic::Ordering::Release);
        }
    }
}

unsafe fn consume_call_reply(
    current: *mut crate::sched::thread::Tcb,
) -> Result<Option<u64>, SyscallError> {
    if current.is_null()
        || !unsafe {
            (*current)
                .message_waiter
                .ready
                .load(core::sync::atomic::Ordering::Acquire)
        }
    {
        return Ok(None);
    }

    unsafe {
        (*current)
            .message_waiter
            .ready
            .store(false, core::sync::atomic::Ordering::Release);
        let record = (*current).message_waiter.reply;
        let mut carriers = (*current).message_waiter.reply_carriers;
        (*current).message_waiter.reply = MpRecord::empty();
        (*current).message_waiter.reply_carriers = CarrierSlots::empty();
        (*current)
            .message_waiter
            .txid
            .store(0, core::sync::atomic::Ordering::Release);

        let cap_count = (record.cap_count as usize).min(MP_MSG_CAPS);
        let installed = match install_carriers_into_receiver(&mut carriers, cap_count) {
            Ok(slots) => slots,
            Err(err) => {
                drop_uninstalled_carriers(&mut carriers);
                return Err(err);
            }
        };
        if let Err(err) = write_mp_record_to_ipc(&record, &installed) {
            let _ = rollback_install_to_carriers(&mut carriers, &installed, cap_count);
            drop_uninstalled_carriers(&mut carriers);
            return Err(err);
        }
        Ok(Some(record.label))
    }
}

/// Pull `count` already-installed `CapRef`s back out of the receiver's
/// CNode (at slot addresses given by `installed[..count]`) and write
/// them, COMPACTED, into the local `carriers` snapshot. Returns the
/// number of carriers actually recovered — when a sibling thread
/// sharing the CSpace has deleted / moved one of the install
/// destinations between the install and this rollback, that carrier
/// is lost (the side-effect of the user's CSpace mutation; we cannot
/// invent a CapRef for a slot that no longer holds the cap we just
/// installed). Surviving `CapRef`s are packed into
/// `carriers.0[..returned_count]`; the rest are nulled.
///
/// The caller is responsible for shrinking `record.cap_count` to the
/// returned count so the (record, carriers) pair the ring sees after
/// `release_claim_with_carriers` is self-consistent.
///
/// # Safety
/// `installed[i]` (for `i < count`) must be the receive-CSpace slot
/// address that `install_carriers_into_receiver` returned. Caller
/// must NOT hold `CAP_LOCK` — this fn takes it internally.
pub(super) unsafe fn rollback_install_to_carriers(
    carriers: &mut CarrierSlots,
    installed: &[InstalledCap; MP_MSG_CAPS],
    count: usize,
) -> usize {
    if count == 0 {
        return 0;
    }
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        return 0;
    }
    let root = unsafe { (*current).cspace_root };
    if root.is_null() {
        return 0;
    }

    let irq = unsafe { crate::mm::save_irq_disable() };
    CAP_LOCK.lock();
    let mut surviving = 0usize;
    for i in 0..count.min(MP_MSG_CAPS) {
        let inst = installed[i];
        if inst.dest_addr == INVALID_SLOT as u64 || inst.slot == INVALID_SLOT {
            continue;
        }
        let resolved =
            unsafe { crate::cap::cnode::resolve_root_cspace_for_slot(&*root, inst.dest_addr) };
        if let Ok((cnode, idx)) = resolved {
            // Identity gate: the receive slot must still hold the
            // exact `(global_slot, generation)` pair we installed
            // — not just any cap that happens to occupy this dest
            // address. A sibling thread sharing the CSpace might
            // have moved / deleted / reused our slot between
            // install and rollback; in that case the cap there now
            // belongs to that sibling and we MUST NOT take_ref it.
            let cur = unsafe { (&*cnode).get_ref(idx) };
            let cur_capref = match cur {
                Some(r) => r,
                None => continue,
            };
            if cur_capref.slot != inst.slot {
                // Different global slot occupies the dest now —
                // someone else's cap. Skip; this carrier is lost.
                continue;
            }
            // Same global slot index — but verify the slot itself
            // hasn't been freed and re-allocated to another cap
            // (which would inherit the slot index but bump the
            // generation counter).
            let cur_gen = crate::cap::get_generation(inst.slot);
            if cur_gen != inst.generation {
                continue;
            }
            if let Some(capref) = unsafe { (&mut *cnode).take_ref(idx) } {
                // The cap is taken back out of the receiver and re-homed
                // into the carrier array — it re-enters transit for the
                // next read, so re-pin its global slot. The matching
                // unpin happened when `install_carriers_into_receiver`
                // full-committed this delivery. Compact the survivors
                // into the front of the carrier array so the next
                // reader's install path sees a contiguous range
                // `[0, surviving)` matching the shrunk `record.cap_count`.
                // Snapshot a fresh epoch — `inst.generation` would also
                // do, but re-reading keeps the carrier-creation invariant
                // ("epoch sampled while holding CAP_LOCK after the
                // take_ref") symmetric with the original capture path.
                let epoch = crate::cap::get_generation(capref.slot);
                crate::cap::pin_transit(capref.slot);
                carriers.0[surviving] = crate::ipc::message_pipe::CarrierEntry {
                    slot: capref.slot,
                    epoch,
                };
                surviving += 1;
            }
        }
    }
    // Null any trailing slots that originally held carriers but have
    // now been compacted away. install_carriers_into_receiver already
    // nulled the slots on successful install; this loop nulls any
    // gap left between `surviving` and `count` so the ring's
    // post-rollback carrier array has well-defined contents.
    for j in surviving..count.min(MP_MSG_CAPS) {
        carriers.0[j] = crate::ipc::message_pipe::CarrierEntry::null();
    }
    CAP_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
    surviving
}

pub(super) fn syscall_mp_close(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MessagePipe, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    unsafe {
        let mp = &mut *(cap.object as *mut MessagePipe);
        mp.close();
    }
    SyscallResult::ok(0)
}

/// Bind a freshly retyped `MessagePipeCore` to two freshly retyped
/// `MessagePipe` side handles. The invocation target is the core;
/// `side_a_cap_ptr` and `side_b_cap_ptr` are the sides. Each side
/// takes a refcount on the core so destruction is well-ordered.
pub(super) fn syscall_mp_pair(
    cap: &Capability,
    side_a_cap_ptr: u64,
    side_b_cap_ptr: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::MessagePipeCore, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let a = match super::cspace::lookup_capability(side_a_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&a, ObjectType::MessagePipe, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let b = match super::cspace::lookup_capability(side_b_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&b, ObjectType::MessagePipe, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    unsafe {
        match MessagePipe::pair(
            cap.object as *mut crate::ipc::message_pipe::MessagePipeCore,
            a.object as *mut MessagePipe,
            b.object as *mut MessagePipe,
        ) {
            Ok(()) => SyscallResult::ok(0),
            Err(()) => SyscallResult::err(SyscallError::AlreadyExists),
        }
    }
}

/// Bidirectional request/reply on a single `MessagePipe`.
///
/// The client writes a request record annotated with a kernel txid,
/// then waits only for an `MP_WRITE` reply record echoing that txid.
/// Ordinary `MP_READ` no longer races with concurrent callers on the
/// same endpoint.
pub(super) fn syscall_mp_call(
    cap: &Capability,
    msg_info_word: u64,
    deadline: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(
        cap,
        ObjectType::MessagePipe,
        CapRights::READ | CapRights::WRITE,
    ) {
        return SyscallResult::err(e);
    }

    // The request body travels in the IPC buffer (like `zx_channel_call`'s
    // args struct) so the `deadline` can ride an invoke register.
    let mut request = match build_mp_record_from_buffer(msg_info_word) {
        Ok(r) => r,
        Err(e) => return SyscallResult::err(e),
    };
    request.flags |= MP_FLAG_CALL;
    request.badge = cap.badge;
    request.txid = next_mp_call_txid();
    let mut ctx = match unsafe { capture_caps_into_carriers(&mut request, msg_info_word) } {
        Ok(c) => c,
        Err(err) => return SyscallResult::err(err),
    };

    let mp = cap.object as *mut MessagePipe;
    let scheduler = crate::sched::scheduler::scheduler();
    let current = scheduler.current();
    if current.is_null() {
        unsafe { rollback_carriers(&mut ctx) };
        return SyscallResult::err(SyscallError::InvalidOperation);
    }
    loop {
        match unsafe { (*mp).try_call_write_record(current, request.txid, request, ctx.carriers) } {
            Ok(()) => break,
            Err(TryWriteErr::PeerClosed) => {
                unsafe { rollback_carriers(&mut ctx) };
                return SyscallResult::err(SyscallError::PeerClosed);
            }
            Err(TryWriteErr::WouldBlock) => {
                match unsafe { block_writer_for_deadline(mp, deadline) } {
                    None => continue,
                    Some(err) => {
                        unsafe { rollback_carriers(&mut ctx) };
                        return SyscallResult::err(err);
                    }
                }
            }
        }
    }

    loop {
        match unsafe { consume_call_reply(current) } {
            Ok(Some(label)) => return SyscallResult::ok(label),
            Ok(None) => {}
            Err(err) => return SyscallResult::err(err),
        }
        match unsafe { block_call_for_deadline(mp, deadline) } {
            None => continue,
            Some(err) => {
                unsafe {
                    (*mp).unregister_call_waiter(current);
                    drop_current_call_reply(current);
                }
                return SyscallResult::err(err);
            }
        }
    }
}

pub(super) fn syscall_dp_produce(cap: &Capability, user_buf: u64, user_len: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let dp = cap.object as *mut DataPipe;
    if unsafe { (*dp).is_datagram() } {
        // Datagram mode: the whole buffer becomes one atomic framed record.
        if user_len as usize > DATA_PIPE_MAX_DATAGRAM {
            return SyscallResult::err(SyscallError::TooLarge);
        }
        let len = user_len as usize;
        let mut staging = [0u8; DATA_PIPE_MAX_DATAGRAM];
        if len > 0 {
            if user_buf == 0 {
                return SyscallResult::err(SyscallError::BadAddress);
            }
            unsafe {
                if !crate::arch::uaccess::copy_from_user_bytes(user_buf, staging.as_mut_ptr(), len)
                {
                    return SyscallResult::err(SyscallError::BadAddress);
                }
            }
        }
        return match unsafe { (*dp).try_produce_datagram(&staging[..len]) } {
            Ok(()) => SyscallResult::ok(user_len),
            Err(TryProduceErr::PeerClosed) => SyscallResult::err(SyscallError::PeerClosed),
            Err(TryProduceErr::WouldBlock) => SyscallResult::err(SyscallError::WouldBlock),
        };
    }
    if user_buf == 0 || user_len == 0 {
        return SyscallResult::ok(0);
    }
    let mut staging = [0u8; 256];
    let mut produced: u64 = 0;
    while produced < user_len {
        let want = ((user_len - produced) as usize).min(staging.len());
        let src = user_buf + produced;
        unsafe {
            if !crate::arch::uaccess::copy_from_user_bytes(src, staging.as_mut_ptr(), want) {
                return SyscallResult::err(SyscallError::BadAddress);
            }
        }
        // Push the staging chunk through `try_produce_chunk` until it is
        // fully drained or the pipe fills (non-blocking: surface the
        // bytes produced so far). Partial-progress accounting lives here
        // (not inside the object) so the syscall layer can report
        // `Ok(produced)` even when the second-or-later iteration hits a
        // closed peer.
        let mut chunk_written = 0usize;
        while chunk_written < want {
            match unsafe { (*dp).try_produce_chunk(&staging[chunk_written..want]) } {
                Ok(n) => {
                    chunk_written += n;
                    produced += n as u64;
                }
                Err(TryProduceErr::PeerClosed) => {
                    if produced > 0 {
                        return SyscallResult::ok(produced);
                    }
                    return SyscallResult::err(SyscallError::PeerClosed);
                }
                Err(TryProduceErr::WouldBlock) => {
                    // Non-blocking by contract: a full pipe surfaces the
                    // bytes produced so far, or `WouldBlock` if none.
                    // Block-until-writable is a `WRITABLE` watch + `EQ_WAIT`.
                    if produced > 0 {
                        return SyscallResult::ok(produced);
                    }
                    return SyscallResult::err(SyscallError::WouldBlock);
                }
            }
        }
    }
    SyscallResult::ok(produced)
}

pub(super) fn syscall_dp_consume(cap: &Capability, user_buf: u64, user_len: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let dp = cap.object as *mut DataPipe;
    if unsafe { (*dp).is_datagram() } {
        // Datagram mode: read exactly one framed record. The reservation
        // tracks the whole frame so `commit_consume` drops it even when the
        // caller's buffer truncates the payload (POSIX SOCK_DGRAM semantics).
        let want = (user_len as usize).min(DATA_PIPE_MAX_DATAGRAM);
        let mut staging = [0u8; DATA_PIPE_MAX_DATAGRAM];
        let chunk = match unsafe { (*dp).try_consume_chunk(&mut staging[..want]) } {
            Ok(n) => n,
            Err(TryConsumeErr::PeerClosed) => return SyscallResult::err(SyscallError::PeerClosed),
            Err(TryConsumeErr::WouldBlock) => return SyscallResult::err(SyscallError::WouldBlock),
        };
        if chunk > 0 {
            if user_buf == 0 {
                unsafe { (*dp).abort_peek() };
                return SyscallResult::err(SyscallError::BadAddress);
            }
            unsafe {
                if !crate::arch::uaccess::copy_to_user_bytes(user_buf, staging.as_ptr(), chunk) {
                    (*dp).abort_peek();
                    return SyscallResult::err(SyscallError::BadAddress);
                }
            }
        }
        unsafe { (*dp).commit_consume(chunk) };
        return SyscallResult::ok(chunk as u64);
    }
    if user_buf == 0 || user_len == 0 {
        return SyscallResult::ok(0);
    }
    let mut staging = [0u8; 256];
    let mut consumed: u64 = 0;
    while consumed < user_len {
        let want = ((user_len - consumed) as usize).min(staging.len());
        // Non-blocking read: any `WouldBlock` surfaces as a short-read
        // (bytes consumed so far) or `WouldBlock` on a virgin call.
        // PeerClosed mid-read returns a short-read; PeerClosed on a
        // virgin call returns the error.
        // Peek-then-commit. The peek copies bytes into staging
        // without advancing the ring head; if the user-space copy
        // below faults, we skip `commit_consume` and the data
        // stays in the ring for the next read attempt — no
        // EFAULT-time data loss.
        let chunk = match unsafe { (*dp).try_consume_chunk(&mut staging[..want]) } {
            Ok(n) => n,
            Err(TryConsumeErr::PeerClosed) => {
                if consumed > 0 {
                    return SyscallResult::ok(consumed);
                }
                return SyscallResult::err(SyscallError::PeerClosed);
            }
            Err(TryConsumeErr::WouldBlock) => {
                // Non-blocking by contract: surface the bytes consumed so
                // far, or `WouldBlock` if none. Block-until-readable is a
                // `READABLE` watch + `EQ_WAIT`.
                if consumed > 0 {
                    return SyscallResult::ok(consumed);
                }
                return SyscallResult::err(SyscallError::WouldBlock);
            }
        };
        let dst = user_buf + consumed;
        unsafe {
            if !crate::arch::uaccess::copy_to_user_bytes(dst, staging.as_ptr(), chunk) {
                // user copy faulted — DON'T commit. Release the
                // single-reader reservation that try_consume_chunk
                // took out so the ring isn't permanently locked.
                // The bytes stay in the ring; next reader re-peeks.
                (*dp).abort_peek();
                if consumed > 0 {
                    return SyscallResult::ok(consumed);
                }
                return SyscallResult::err(SyscallError::BadAddress);
            }
        }
        // user copy succeeded — commit the peek.
        unsafe { (*dp).commit_consume(chunk) };
        consumed += chunk as u64;
    }
    SyscallResult::ok(consumed)
}

pub(super) fn syscall_dp_query(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let dp = cap.object as *const DataPipe;
    match unsafe { (*dp).query() } {
        Some((used, state)) => SyscallResult::ok(used | (state << 32)),
        None => SyscallResult::err(SyscallError::PeerClosed),
    }
}

pub(super) fn syscall_dp_close(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    unsafe {
        let dp = &mut *(cap.object as *mut DataPipe);
        dp.close();
    }
    SyscallResult::ok(0)
}

/// Bind a freshly retyped `DataPipeCore` to two `DataPipe` side
/// handles (mirror of `syscall_mp_pair`).
pub(super) fn syscall_dp_pair(
    cap: &Capability,
    side_a_cap_ptr: u64,
    side_b_cap_ptr: u64,
    datagram_flag: u64,
) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipeCore, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let a = match super::cspace::lookup_capability(side_a_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&a, ObjectType::DataPipe, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    let b = match super::cspace::lookup_capability(side_b_cap_ptr) {
        Ok(c) => c,
        Err(e) => return SyscallResult::err(e),
    };
    if let Err(e) = validate_capability(&b, ObjectType::DataPipe, CapRights::CONFIGURE) {
        return SyscallResult::err(e);
    }
    unsafe {
        match DataPipe::pair(
            cap.object as *mut crate::ipc::data_pipe::DataPipeCore,
            a.object as *mut DataPipe,
            b.object as *mut DataPipe,
            datagram_flag != 0,
        ) {
            Ok(()) => SyscallResult::ok(0),
            Err(()) => SyscallResult::err(SyscallError::AlreadyExists),
        }
    }
}

/// Set this side's RX byte threshold (`STATE_READ_THRESHOLD` asserts when
/// inbound `used >= threshold`; `0` disables).
pub(super) fn syscall_dp_set_rx_threshold(cap: &Capability, threshold: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::READ) {
        return SyscallResult::err(e);
    }
    let dp = cap.object as *mut DataPipe;
    unsafe { (*dp).set_rx_threshold(threshold as u32) };
    SyscallResult::ok(0)
}

/// Set this side's TX free-space threshold (`STATE_WRITE_THRESHOLD` asserts
/// when outbound `free >= threshold`; `0` disables).
pub(super) fn syscall_dp_set_tx_threshold(cap: &Capability, threshold: u64) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let dp = cap.object as *mut DataPipe;
    unsafe { (*dp).set_tx_threshold(threshold as u32) };
    SyscallResult::ok(0)
}

/// Half-close this side's write direction: further produce returns
/// `PeerClosed` and the peer reader sees EOF after draining.
pub(super) fn syscall_dp_shutdown(cap: &Capability) -> SyscallResult {
    if let Err(e) = validate_capability(cap, ObjectType::DataPipe, CapRights::WRITE) {
        return SyscallResult::err(e);
    }
    let dp = cap.object as *mut DataPipe;
    unsafe { (*dp).shutdown_write() };
    SyscallResult::ok(0)
}

// Reference unused-but-imported items so the compile gate (when
// resumed) doesn't flag them while the surrounding planes are still
// being wired up.
const _: u64 = STATE_READABLE;
const _: u64 = STATE_WRITABLE;
const _: u32 = EVENT_TYPE_USER;
const _: crate::cap::CapSlot = INVALID_SLOT;
