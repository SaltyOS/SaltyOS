// SPDX-License-Identifier: GPL-2.0-only
//! `MessagePipe` — bidirectional message channel with capability transfer.
//!
//! Storage layout follows the Zircon channel model: a shared
//! `MessagePipeCore` carries the cross-side state (rings, locks,
//! waiter queues, watcher lists), while two lightweight `MessagePipe`
//! handles each reference the same core and tag themselves "side A"
//! or "side B". The user receives caps to the two sides; cap drops on
//! one side are independent of the other.
//!
//! Lifecycle:
//!
//! * Userland retypes one `MessagePipeCore` and two `MessagePipe`s
//!   from untyped memory.
//! * `MP_PAIR(core_cap, side_a_cap, side_b_cap)` wires the three
//!   together: each side stores `core` and bumps the core's
//!   refcount. After pair, the user normally drops their cap to the
//!   core (its lifetime is held by the two sides).
//! * Closing or destroying a side asserts `STATE_CLOSED` on its half
//!   of the core and `STATE_PEER_CLOSED` on the other half, then
//!   drops one core refcount. When both sides have done this, the
//!   core's refcount reaches zero and the reaper finalizes it.
//!
//! There is no peer pointer between sides — every cross-side
//! interaction goes through the core under its own lock, so there is
//! never a window where one side dereferences a peer that has been
//! reaped.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU8, AtomicU32, AtomicU64, Ordering};

const STATE_CLOSED: u64 = uapi::KERNITE_STATE_CLOSED as u64;
const STATE_PEER_CLOSED: u64 = uapi::KERNITE_STATE_PEER_CLOSED as u64;
const STATE_READABLE: u64 = uapi::KERNITE_STATE_READABLE as u64;
const STATE_WRITABLE: u64 = uapi::KERNITE_STATE_WRITABLE as u64;
const MP_FLAG_REPLY: u64 = uapi::KERNITE_MP_FLAG_REPLY as u64;

use crate::cap::ObjectType;
use crate::cap::object::KernelObject;
use crate::event::watcher_list::WatcherList;
use crate::mm::SpinLock;
use crate::sched::thread::Tcb;

/// Maximum inline message words (label + length + 30 register words).
pub const MP_MSG_WORDS: usize = uapi::KERNITE_MP_RECORD_WORDS as usize;
/// Maximum capability handles transferred per message.
pub const MP_MSG_CAPS: usize = uapi::KERNITE_MP_RECORD_CAPS as usize;
/// Bounded queue depth.
pub const MP_QUEUE_DEPTH: usize = 16;

/// Side identity stored on each `MessagePipe` handle.
pub const SIDE_A: u8 = 0;
pub const SIDE_B: u8 = 1;

/// Per-message envelope. Wire layout matches `kernite_mp_record` in
/// `kernite/include/uapi/ipc.h` field-for-field — any drift breaks
/// the userland ABI.
///
/// `flags` carries `KERNITE_MP_FLAG_*` wire bits (call / reply /
/// fault hint); `badge` is the sender-supplied opaque tag. Cap
/// transfer is out-of-band — the kernel pairs each enqueued record
/// with a `[Capability; MP_MSG_CAPS]` carrier array stored alongside
/// the ring slot.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MpRecord {
    pub label: u64,
    pub length: u64,
    pub cap_count: u64,
    pub flags: u64,
    pub badge: u64,
    pub txid: u64,
    pub words: [u64; MP_MSG_WORDS],
}

impl MpRecord {
    pub const fn empty() -> Self {
        Self {
            label: 0,
            length: 0,
            cap_count: 0,
            flags: 0,
            badge: 0,
            txid: 0,
            words: [0; MP_MSG_WORDS],
        }
    }
}

/// Per-thread `MP_CALL` reply slot — the kernel analog of Zircon's
/// `MessageWaiter`. A parked caller registers itself (`try_call_write_record`
/// → `waiters_call`) and a matching reply-marked `MP_WRITE` (the
/// `try_write_record` reply arm, matched by `txid`) delivers the reply *here*,
/// out-of-band, flipping `ready` to direct-wake the caller. The reply payload
/// lives in this per-TCB slot, never in the recv ring.
#[repr(C)]
pub struct MessageWaiter {
    /// Active transaction id while the owning thread is parked in `MP_CALL`;
    /// `0` when idle.
    pub txid: core::sync::atomic::AtomicU64,
    /// Set by the reply arm once the reply is delivered into this slot; polled
    /// by `block_call_for_deadline` / the caller's consume path.
    pub ready: core::sync::atomic::AtomicBool,
    /// The delivered reply record.
    pub reply: MpRecord,
    /// The delivered reply's MOVE cap carriers (installed into the caller's
    /// CSpace on consume; dropped via the CDT on timeout / thread teardown).
    pub reply_carriers: CarrierSlots,
}

impl MessageWaiter {
    pub const fn new() -> Self {
        Self {
            txid: core::sync::atomic::AtomicU64::new(0),
            ready: core::sync::atomic::AtomicBool::new(false),
            reply: MpRecord::empty(),
            reply_carriers: CarrierSlots::empty(),
        }
    }
}

/// Tagged fast-deposit mailbox embedded in every TCB.
///
/// Producer sites (`MessagePipe::try_write_fast` for cross-thread
/// fast-write) deposit a `MpRecord` directly into the receiver's
/// mailbox instead of pushing through a `PipeRing`. The receiver
/// claims message deposits at its next `MP_READ` fast-drain check.
///
/// State machine (`AtomicU8` over `MailboxKind`):
///
/// ```text
///     Empty ──producer.start──▶ Writing
///                                  │
///                                  ▼ producer.finalize
///     Empty ◀──consumer.finish── Reading ◀──consumer.claim── Message
/// ```
///
/// `source_obj` is refcount-pinned for the entire `Writing..Reading`
/// window — producer bumps it before the `Empty→Writing` CAS,
/// consumer releases it after the payload copy and before the
/// `Reading→Empty` finalize. This pin is what makes the raw pointer
/// safe to dereference even though the source may be reaped between
/// publish and claim.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MailboxKind {
    Empty = 0,
    Writing = 1,
    Message = 2,
    Reading = 4,
}

impl MailboxKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Empty),
            1 => Some(Self::Writing),
            2 => Some(Self::Message),
            4 => Some(Self::Reading),
            _ => None,
        }
    }
}

#[repr(C)]
pub struct MpFastMailbox {
    pub kind: AtomicU8,
    /// Mirror of `kind` at publish time, kept across the
    /// `Reading` window so `cancel_pending` (and other observers
    /// that see the mailbox in `Reading` state with a still-set
    /// `source_obj`) can identify the source object's type. The
    /// `kind` field itself transitions `Message → Reading`
    /// during a peek, losing the type information needed to
    /// `release_object` correctly. `source_kind` is set to the
    /// publish kind on `try_publish`, never changed during the
    /// peek window, and cleared (to `Empty`) when the source pin
    /// is released — by `commit_peek` (success path), by
    /// `try_claim` (peek + commit shorthand), or by
    /// `cancel_pending` (forcible drop).
    pub source_kind: AtomicU8,
    pub source_side: AtomicU32,
    pub source_seq: AtomicU64,
    /// `MessagePipeCore*` when `source_kind == Message`. Pinned via
    /// refcount inside the `Writing..commit/abort/cancel` window.
    pub source_obj: AtomicPtr<KernelObject>,
    pub payload: UnsafeCell<MpRecord>,
    /// Cap carriers transferred along with the record. Each
    /// non-null `CapRef` represents ownership the producer moved
    /// out of its CSpace via `take_ref` (or, for fault delivery,
    /// a moved sender cap). The consumer re-binds these into its own
    /// CSpace inside `consume_fn` and
    /// the mailbox storage is reset to `CarrierSlots::empty` on
    /// `commit_peek`. `abort_peek` writes the (possibly-mutated)
    /// snapshot back so the next reader still observes a coherent
    /// `(record, carriers)` pair. `cancel_pending` walks any
    /// still-live entries and runs `CDT::delete_capability` —
    /// once `try_peek` has CAS'd the mailbox into `Reading`, the
    /// carrier ownership has moved to the consumer's stack and
    /// `cancel_pending` no longer touches it.
    pub carriers: UnsafeCell<CarrierSlots>,
}

// SAFETY: cross-thread access serialised by the `kind` state machine.
unsafe impl Sync for MpFastMailbox {}

impl MpFastMailbox {
    pub const fn new() -> Self {
        Self {
            kind: AtomicU8::new(MailboxKind::Empty as u8),
            source_kind: AtomicU8::new(MailboxKind::Empty as u8),
            source_side: AtomicU32::new(0),
            source_seq: AtomicU64::new(0),
            source_obj: AtomicPtr::new(core::ptr::null_mut()),
            payload: UnsafeCell::new(MpRecord::empty()),
            carriers: UnsafeCell::new(CarrierSlots::empty()),
        }
    }

    /// Producer entry: try to publish `payload` (+ `carriers`) into
    /// this mailbox.
    ///
    /// `kind` MUST be `Message`. `source_obj` is the
    /// `KernelObject*` of the deposit's source — a
    /// `MessagePipeCore`. `source_obj`'s refcount MUST already have
    /// been incremented by the caller; on success
    /// the consumer takes ownership of that pin and releases it during
    /// `try_claim`. On failure (mailbox busy) the caller MUST release
    /// the pin themselves and retain ownership of `carriers` (so the
    /// fastpath publish failure path can fall back to ring enqueue
    /// or rollback into the sender CSpace without losing caps).
    ///
    /// `carriers` is moved into the mailbox on success: the consumer
    /// reads it inside `try_peek` and re-binds the carriers into its
    /// own CSpace via `consume_fn`. On a peek that aborts (consume
    /// failed mid-install), the consumer re-publishes the snapshot
    /// via `abort_peek` so the deposit stays observable.
    ///
    /// # Safety
    /// `source_obj` must be a valid `KernelObject*` of the type implied
    /// by `kind` whose refcount has been bumped exactly once for this
    /// publish. Each non-null `CapRef` in `carriers` must be uniquely
    /// owned by the caller (taken out of the sender CSpace, or freshly
    /// minted as a kernel-private cap) so the mailbox can hand
    /// ownership to the consumer without a sibling claim race.
    pub unsafe fn try_publish(
        &self,
        kind: MailboxKind,
        source_obj: *mut KernelObject,
        source_side: u32,
        source_seq: u64,
        payload: MpRecord,
        carriers: CarrierSlots,
    ) -> bool {
        crate::kernel::bug::kassert!(matches!(kind, MailboxKind::Message));
        if self
            .kind
            .compare_exchange(
                MailboxKind::Empty as u8,
                MailboxKind::Writing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return false;
        }
        self.source_obj.store(source_obj, Ordering::Relaxed);
        self.source_side.store(source_side, Ordering::Relaxed);
        self.source_seq.store(source_seq, Ordering::Relaxed);
        // source_kind mirrors kind across the entire Writing → ...
        // → final-release window so any observer that sees a
        // `Reading` state with a still-set `source_obj` (e.g.
        // `cancel_pending` racing a `try_peek`) can determine the
        // source object's type tag for `release_object`. Stored
        // BEFORE the terminal `kind` Release so `cancel_pending`'s
        // post-spin Acquire load on `source_kind` cannot read a
        // stale `Empty` from a prior cycle.
        self.source_kind.store(kind as u8, Ordering::Relaxed);
        unsafe { *self.payload.get() = payload };
        unsafe { *self.carriers.get() = carriers };
        self.kind.store(kind as u8, Ordering::Release);
        true
    }

    /// Consumer claim: if the mailbox carries a payload from
    /// `expected_obj` with matching `expected_seq`, transition to
    /// `Reading`, copy the payload + carriers, release the source
    /// pin, and clear. Returns `None` when the mailbox is empty,
    /// when source/seq mismatch, or when another consumer wins the
    /// `Reading` CAS.
    ///
    /// This is the atomic "peek + commit" combo for callers that
    /// don't need a fallible install step. The carriers come back
    /// in the `CarrierSlots` payload; ownership has fully moved to
    /// the caller — they MUST install them into a CSpace or
    /// `CDT::delete_capability` each non-null entry, otherwise the
    /// minted slots leak.
    ///
    /// Use `try_peek` followed by `commit_peek` / `abort_peek` when
    /// the consumer needs a fallible install / copy step between
    /// the peek and the commit (e.g. user-buffer IPC write that
    /// may take a `BadAddress` fault, or partial cap install that
    /// rolls back into a mutated `(record, carriers)` snapshot).
    ///
    /// # Safety
    /// Caller must own the right to consume from `expected_obj` and
    /// must be operating with `expected_seq` matching the producer's
    /// publish-time stamp.
    pub unsafe fn try_claim(
        &self,
        expected_obj: *mut KernelObject,
        expected_seq: u64,
    ) -> Option<(MailboxKind, MpRecord, CarrierSlots)> {
        let (kind, record, carriers) = unsafe { self.try_peek(expected_obj, expected_seq) }?;
        unsafe { self.commit_peek(kind) };
        Some((kind, record, carriers))
    }

    /// Snapshot the mailbox payload + transition `Message →
    /// Reading` WITHOUT releasing the source pin or clearing
    /// source_obj/seq. Pairs with `commit_peek` (success → release
    /// source pin and Empty) or `abort_peek` (failure → restore the
    /// snapshot so the deposit survives for the next reader).
    ///
    /// The source pin from `try_publish` stays held across the
    /// peek window — callers MUST resolve the peek with exactly one
    /// of `commit_peek` / `abort_peek`. Carrier ownership moves to
    /// the caller's stack on the winning `Reading` CAS; if the
    /// caller commits, the carriers must be installed into a CSpace
    /// (or CDT-deleted), if it aborts, the carriers go back into
    /// the mailbox via `abort_peek`.
    ///
    /// # Safety
    /// Same preconditions as `try_claim`. Multiple concurrent
    /// `try_peek` callers are safe — the `Reading` CAS funnels them
    /// through; only the winner gets `Some`.
    pub unsafe fn try_peek(
        &self,
        expected_obj: *mut KernelObject,
        expected_seq: u64,
    ) -> Option<(MailboxKind, MpRecord, CarrierSlots)> {
        let snapshot = self.kind.load(Ordering::Acquire);
        let mk = match snapshot {
            x if x == MailboxKind::Message as u8 => MailboxKind::Message,
            _ => return None,
        };
        if self.source_obj.load(Ordering::Acquire) != expected_obj {
            return None;
        }
        if self.source_seq.load(Ordering::Acquire) != expected_seq {
            return None;
        }
        if self
            .kind
            .compare_exchange(
                mk as u8,
                MailboxKind::Reading as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        let payload = unsafe { *self.payload.get() };
        let carriers = unsafe { *self.carriers.get() };
        // Stamp the mailbox slot with empty carriers so the storage
        // invariant ("Reading" mailbox has no live carrier
        // ownership) is observable to `cancel_pending`.
        unsafe { *self.carriers.get() = CarrierSlots::empty() };
        Some((mk, payload, carriers))
    }

    /// Finalize a `try_peek` that succeeded: release the source pin
    /// + clear source/seq + transition `Reading → Empty`.
    /// `kind` is the value returned by `try_peek` and tells us which
    /// kernel-object type tag to use when releasing the source pin.
    ///
    /// # Safety
    /// MUST be paired exactly once with the matching `try_peek` that
    /// returned `Some`. `kind` must be that returned value
    /// (`Message` → source is a `MessagePipeCore`).
    pub unsafe fn commit_peek(&self, kind: MailboxKind) {
        crate::kernel::bug::kassert!(matches!(kind, MailboxKind::Message));
        let source = self
            .source_obj
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        let source_side = self.source_side.load(Ordering::Relaxed);
        self.source_side.store(0, Ordering::Relaxed);
        self.source_seq.store(0, Ordering::Relaxed);

        // For a Message commit, mirror the slowpath ring-drain
        // readability gating in `try_read_with_install` phase 3:
        // clear `STATE_READABLE` on the reader side if the
        // corresponding ring is empty. Without this the peer's
        // `STATE_READABLE` stays set forever after a fastpath drain,
        // leaking into Watch / poll readiness. The publisher set
        // the bit unconditionally in `try_write_fast`; commit must
        // be the matching side. Reply commits don't touch pipe
        // readability.
        if !source.is_null() && matches!(kind, MailboxKind::Message) {
            let core_ptr = source as *mut MessagePipeCore;
            let reader_side = MessagePipeCore::other_side(source_side as u8);
            let irq = unsafe { crate::mm::save_irq_disable() };
            unsafe { (*core_ptr).lock.lock() };
            let core = unsafe { &mut *core_ptr };
            if core.ring_for_reader(reader_side).used == 0 {
                core.state_for(reader_side)
                    .fetch_and(!STATE_READABLE, Ordering::Release);
            }
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
        }
        if !source.is_null() {
            unsafe { crate::cap::release_object(source, ObjectType::MessagePipeCore) };
        }
        // Clear the source_kind mirror AFTER the source pin has
        // been released so a concurrent `cancel_pending` either
        // sees `(Reading, source_obj=non-null, source_kind=kind)`
        // (and idempotently re-tries the release on a now-null
        // `source_obj`) or `(Empty, source_obj=null,
        // source_kind=Empty)` — never the dangerous middle state
        // where `source_kind` is already cleared but `source_obj`
        // still points at a live object.
        self.source_kind
            .store(MailboxKind::Empty as u8, Ordering::Relaxed);
        self.kind.store(MailboxKind::Empty as u8, Ordering::Release);
    }

    /// Roll back a `try_peek` whose follow-up consume failed (e.g.
    /// user-buffer copy faulted, partial cap install rolled back).
    /// The mailbox transitions `Reading → kind` so the deposit is
    /// observable again to the next reader. The source pin from
    /// the original `try_publish` is NOT released — the deposit is
    /// still live, the consumer just couldn't take it on this
    /// attempt.
    ///
    /// `record` and `carriers` are written back as the new mailbox
    /// snapshot. They are typically the (possibly-mutated) versions
    /// the consume closure handled — partial cap install can
    /// shrink `record.cap_count` and shuffle survivors back into
    /// `carriers`, and that adjusted shape is what the next reader
    /// must see.
    ///
    /// # Safety
    /// MUST be paired exactly once with a `try_peek` that returned
    /// `Some`. `kind` must be that returned value. `carriers` must
    /// represent the still-live cap ownership (entries the
    /// consumer was unable to install) — entries the consumer DID
    /// install must already be cleared to `CarrierEntry::null()`
    /// before the abort, otherwise mailbox + receiver CSpace would
    /// both claim the same slot.
    pub unsafe fn abort_peek(&self, kind: MailboxKind, record: MpRecord, carriers: CarrierSlots) {
        crate::kernel::bug::kassert!(matches!(kind, MailboxKind::Message));
        // Write the (possibly-mutated) snapshot back BEFORE
        // restoring the terminal kind so an Acquire reader cannot
        // observe `Message` with stale carriers.
        unsafe { *self.payload.get() = record };
        unsafe { *self.carriers.get() = carriers };
        // source_obj / source_seq are untouched — they still match
        // the live deposit. Just restore the kind so subsequent
        // try_peek / try_claim observe the mailbox as full again.
        self.kind.store(kind as u8, Ordering::Release);
    }

    /// Drop any in-flight publish. Used by `detach_thread_wait_queues`
    /// when a TCB is destroyed mid-call. Forces `kind` to `Empty` and
    /// releases the source pin if one was held.
    ///
    /// **Writing-state race**: a producer between
    /// `try_publish`'s `Empty→Writing` CAS and the terminal
    /// `kind.store(Message)` has already set `source_obj` but
    /// the kind still says `Writing`, so a naive `swap` would either
    /// drop the source pin without knowing its type (the source can
    /// be a valid `MessagePipeCore`) or fail to drop it entirely. We
    /// spin until the producer's finalize completes
    /// — the producer path between `Writing` and the finalize store
    /// is a fixed number of atomic ops, so the spin is bounded.
    ///
    /// **Reading-state race**: a peek-style consumer
    /// (`try_peek` / `try_read_with_install` consume closure) has
    /// CAS'd kind to `Reading` BUT has NOT released `source_obj`
    /// yet — that release happens later in `commit_peek`. We must
    /// not assume `Reading` means "consumer already released
    /// source"; instead we read the publish-time `source_kind`
    /// mirror to recover the source object's type tag and release
    /// the pin ourselves. The consumer's eventual `commit_peek`
    /// observes a now-null `source_obj` and idempotently skips its
    /// own release.
    ///
    /// # Safety
    /// Caller must hold an exclusive reference to the owning TCB
    /// (the destroy path) so no other code on this CPU is mutating
    /// the mailbox in parallel; cross-CPU producers are still
    /// permitted and are handled by the spin-then-swap protocol.
    pub unsafe fn cancel_pending(&self) {
        // 1. Wait out any producer mid-publish.
        loop {
            let cur = self.kind.load(Ordering::Acquire);
            if cur != MailboxKind::Writing as u8 {
                break;
            }
            core::hint::spin_loop();
        }

        // 2. Swap kind → Empty atomically. The original kind tells
        //    us what mailbox storage held.
        let snapshot = self.kind.swap(MailboxKind::Empty as u8, Ordering::AcqRel);
        let mirror = self.source_kind.load(Ordering::Acquire);
        let mailbox_kind = match MailboxKind::from_u8(mirror) {
            Some(MailboxKind::Message) => MailboxKind::Message,
            _ => {
                // `Empty` mirror — either nothing was ever published
                // in this cycle, or `commit_peek` raced ahead and
                // cleared the mirror. No source pin to release.
                let _ = snapshot;
                return;
            }
        };
        let stype = ObjectType::MessagePipeCore;

        // 3. Capture source info BEFORE clearing — `source_side`
        //    is needed below to find the right ring side for the
        //    Message ring-fallback.
        let source = self.source_obj.load(Ordering::Acquire);
        let source_side = self.source_side.load(Ordering::Relaxed);

        // 4. For a `Message`-kind snapshot whose CAS finalized
        //    (`Message`, not `Reading`/`Empty`), the writer believes
        //    its publish succeeded — losing the record here would
        //    create a "writer success + receiver miss" tear. Try to
        //    push the (record, carriers) into the same pipe core's
        //    reader-side ring so the message stays observable to
        //    a re-arming reader. On ring-full / non-Message we
        //    fall through to the old delete-and-drop path.
        //
        //    Carrier ownership rule: a `Reading` snapshot means a
        //    consumer's `try_peek` already took carriers onto its
        //    stack — we must NOT touch them here.
        let mut ring_consumed = false;
        if !source.is_null() && matches!(mailbox_kind, MailboxKind::Message) {
            let core_ptr = source as *mut MessagePipeCore;
            let reader_side = MessagePipeCore::other_side(source_side as u8);
            let pushed_meta;
            unsafe {
                let irq = crate::mm::save_irq_disable();
                (*core_ptr).lock.lock();
                let core = &mut *core_ptr;
                if core.ring_for_reader(reader_side).is_full() {
                    pushed_meta = None;
                } else {
                    let record_snapshot = *self.payload.get();
                    let carriers_snapshot = *self.carriers.get();
                    core.ring_for_reader(reader_side)
                        .push(record_snapshot, carriers_snapshot);
                    // 0→1 STATE_READABLE transition is the only
                    // edge that should fan out to watchers; a
                    // sibling reader that already drained the ring
                    // and cleared READABLE will re-set it here.
                    let prev = core
                        .state_for(reader_side)
                        .fetch_or(STATE_READABLE, Ordering::Release);
                    let publish_edge = (prev & STATE_READABLE) == 0;
                    let waiter = core.waiters_read(reader_side).pop();
                    pushed_meta = Some((publish_edge, waiter));
                }
                (*core_ptr).lock.unlock();
                crate::mm::restore_irq(irq);
            }
            if let Some((publish_edge, waiter)) = pushed_meta {
                if publish_edge {
                    let watchers =
                        unsafe { (*core_ptr).watchers_for(reader_side) as *mut WatcherList };
                    unsafe { (*watchers).publish(STATE_READABLE) };
                }
                if !waiter.is_null() {
                    unsafe { wake_thread(waiter) };
                }
                // Carriers moved into the ring; clear mailbox
                // storage so the post-clear delete branch below
                // doesn't double-free them.
                unsafe { *self.carriers.get() = CarrierSlots::empty() };
                ring_consumed = true;
            }
        }

        // 5. Clear mailbox source info regardless.
        self.source_obj
            .store(core::ptr::null_mut(), Ordering::Release);
        self.source_side.store(0, Ordering::Relaxed);
        self.source_seq.store(0, Ordering::Relaxed);
        self.source_kind
            .store(MailboxKind::Empty as u8, Ordering::Relaxed);

        // 6. Release the source pin the producer's `try_publish`
        //    bumped. The ring-fallback path doesn't keep a separate
        //    pipe-core pin — ring records live as part of the core
        //    they belong to.
        if !source.is_null() {
            unsafe { crate::cap::release_object(source, stype) };
        }

        // 7. If the message wasn't ring-rehomed, delete its
        //    carriers via CDT. CAP_LOCK contract: caller MUST hold
        //    `CAP_LOCK` across this call. The TCB destroy path
        //    (`Tcb::cleanup` → `detach_thread_wait_queues`)
        //    already does — see the SAFETY note at
        //    `kernite/src/sched/thread.rs:1257`. Syscall-context
        //    callers (`MP_CALL` rollback / timeout) acquire
        //    CAP_LOCK around their `cancel_pending` invocation
        //    themselves.
        if !ring_consumed {
            match snapshot {
                x if x == MailboxKind::Message as u8 => {
                    let stored = unsafe { &mut *self.carriers.get() };
                    for entry in stored.0.iter_mut() {
                        // The cap was in transit on this mailbox and will
                        // never be delivered: release its transit pin and
                        // tear the slot down. The pin froze the slot's
                        // generation, so no epoch re-check is needed.
                        let cur = *entry;
                        *entry = CarrierEntry::null();
                        unsafe { cur.unpin_and_delete() };
                    }
                }
                _ => {
                    // Reading / Empty / Writing — carrier ownership
                    // is not on the mailbox.
                }
            }
        }
    }
}

/// One carrier slot — a `CapRef`-style binding that has been moved
/// out of a sender's CNode (or freshly minted as a kernel-private
/// cap) plus a snapshot of the global slot's reuse counter at the
/// time the move completed. `epoch` mirrors `InstalledCap`'s
/// ABA defence so carrier-side rollback / install / delete paths
/// can detect a slot that was freed and reused for an unrelated
/// cap during the in-flight window. The counter source is
/// `crate::cap::get_generation` (`free_slot` bumps it once per
/// release). `null` carries
/// `(INVALID_SLOT, 0)`.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct CarrierEntry {
    pub slot: crate::cap::CapSlot,
    pub epoch: u64,
}

impl CarrierEntry {
    pub const fn null() -> Self {
        Self {
            slot: crate::cap::INVALID_SLOT,
            epoch: 0,
        }
    }
    pub const fn is_null(&self) -> bool {
        self.slot == crate::cap::INVALID_SLOT
    }

    /// Drop this in-transit carrier cap: release its transit pin and tear
    /// the global slot down via the canonical CDT path. The pin taken at
    /// capture froze the slot's generation, so this always targets the
    /// cap that was captured (no epoch re-check needed). No-op for a null
    /// entry.
    ///
    /// # Safety
    /// Caller must hold `CAP_LOCK` and must own the transit pin this
    /// releases (this entry was captured / re-homed and not already
    /// delivered or dropped).
    pub unsafe fn unpin_and_delete(self) {
        if self.is_null() {
            return;
        }
        crate::cap::unpin_transit(self.slot);
        crate::cap::CDT::delete_capability(self.slot);
    }
}

/// Hidden carrier slots paired 1:1 with each ring record.
///
/// Carriers carry **`CapRef` move semantics** — at `MP_WRITE` the
/// kernel validates each sender source slot's `TRANSFER` right,
/// `take_ref` it out of the sender's CNode (sender slot becomes
/// empty), and stores the moved `CapRef` here. The underlying
/// global capability slot keeps its CDT linkage and object refcount
/// untouched — only the *CNode-to-slot* binding moves. At `MP_READ`
/// the kernel `insert_ref`s each carrier into the receiver's CNode
/// under the receive-cnode/index tuple. On install failure the
/// message is left at the head of the ring and the carriers are
/// rolled back into the sender's CNode so the syscall is observably
/// atomic.
///
/// `epoch` snapshots are taken at `take_ref` / mint time and
/// re-validated at install / rollback / delete time. A slot whose
/// epoch has advanced was freed and possibly reused for an
/// unrelated cap; mismatched entries are compacted out of the
/// carrier set rather than installed (which would attach the
/// unrelated cap to the receiver's CNode) or deleted (which would
/// destroy the unrelated cap).
///
/// On pipe close (`MessagePipe::close`) any in-flight carriers are
/// destroyed — the underlying global slot's `Capability` is released
/// (object refcount--, CDT detach, slot freelist return) because the
/// sender already dropped its CNode binding and no receiver took it.
#[derive(Clone, Copy)]
pub struct CarrierSlots(pub [CarrierEntry; MP_MSG_CAPS]);

impl CarrierSlots {
    pub const fn empty() -> Self {
        Self([CarrierEntry::null(); MP_MSG_CAPS])
    }

    /// Drop every still-owned carrier slot via the CDT path.
    ///
    /// # Safety
    /// Caller must hold `CAP_LOCK`. Each non-null entry must be
    /// uniquely owned by this carrier array.
    pub unsafe fn drop_via_cdt_locked(&mut self) {
        for entry in self.0.iter_mut() {
            let cur = *entry;
            *entry = CarrierEntry::null();
            // Release the transit pin and tear the slot down. The pin
            // froze the slot's generation, so no epoch re-check is needed.
            unsafe { cur.unpin_and_delete() };
        }
    }
}

/// Error from `MessagePipe::try_write_record` — non-blocking
/// enqueue cannot synthesise a kernel-managed wait, so the caller
/// surfaces `PeerClosed` immediately on a dead peer and decides
/// whether `WouldBlock` should turn into a deadline-armed park.
pub enum TryWriteErr {
    PeerClosed,
    WouldBlock,
}

/// Outcome of `MessagePipe::try_read_with_install`. Splits the
/// failure modes so the syscall layer can map each case to a distinct
/// error (peer-closed vs would-block vs consume-failed).
pub enum ReadOutcome {
    /// Successfully read; the consume closure ran to completion. The
    /// `u64` payload is whatever the closure returned in its `Ok`
    /// case — by convention `MpRecord::label` so the syscall layer
    /// can surface it without a second round-trip through the record.
    Read(u64),
    /// Peer closed and no record left to drain.
    PeerClosed,
    /// Non-blocking read found the ring empty.
    WouldBlock,
    /// The consume closure rejected the message (typical reasons:
    /// receive-CSpace install failure, IPC-buffer write fault). The
    /// closure is contractually required to leave `carriers` populated
    /// with the surviving `CapRef`s so the head ring slot's
    /// `release_claim_with_carriers` can restore them — the message
    /// stays at the head of the ring and the caller may retry after
    /// fixing the underlying condition (free a destination slot, fix
    /// the IPC-buffer mapping, etc).
    ConsumeFailed,
}

/// Single-direction bounded ring of `MpRecord`s with paired carrier
/// arrays for cap transfer.
///
/// `claimers[i]` reserves the head slot for a single reader during
/// the peek-then-install window. `peek_and_claim` CAS-claims the
/// current head; `pop_claimed` advances head only if the caller's
/// claim is still valid; `release_claim` aborts the claim without
/// advancing. This protects the install path when it must run
/// outside the core lock.
#[repr(C)]
struct PipeRing {
    head: u32,
    tail: u32,
    used: u32,
    _pad: u32,
    records: [MpRecord; MP_QUEUE_DEPTH],
    carriers: [CarrierSlots; MP_QUEUE_DEPTH],
    claimers: [AtomicPtr<Tcb>; MP_QUEUE_DEPTH],
}

impl PipeRing {
    const fn new() -> Self {
        Self {
            head: 0,
            tail: 0,
            used: 0,
            _pad: 0,
            records: [MpRecord::empty(); MP_QUEUE_DEPTH],
            carriers: [CarrierSlots::empty(); MP_QUEUE_DEPTH],
            claimers: [const { AtomicPtr::new(core::ptr::null_mut()) }; MP_QUEUE_DEPTH],
        }
    }

    fn is_full(&self) -> bool {
        self.used as usize == MP_QUEUE_DEPTH
    }

    fn push(&mut self, record: MpRecord, carriers: CarrierSlots) {
        let slot = self.tail as usize;
        self.records[slot] = record;
        self.carriers[slot] = carriers;
        self.tail = ((self.tail as usize + 1) % MP_QUEUE_DEPTH) as u32;
        self.used += 1;
    }

    fn peek_head(&self) -> Option<(MpRecord, CarrierSlots)> {
        if self.used == 0 {
            return None;
        }
        let slot = self.head as usize;
        Some((self.records[slot], self.carriers[slot]))
    }

    /// Reserve the head slot for `reader` and return its contents.
    /// Returns `None` if the ring is empty or another reader has
    /// already claimed the head.
    fn peek_and_claim(&self, reader: *mut Tcb) -> Option<(MpRecord, CarrierSlots)> {
        if self.used == 0 {
            return None;
        }
        let slot = self.head as usize;
        if self.claimers[slot]
            .compare_exchange(
                core::ptr::null_mut(),
                reader,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_err()
        {
            return None;
        }
        Some((self.records[slot], self.carriers[slot]))
    }

    /// Abort a claim taken by `peek_and_claim` without advancing
    /// the head, writing the (possibly partially-rolled-back)
    /// `record` and `carriers` back into the ring slot. The install
    /// path runs outside the core lock and may rollback partial
    /// installs into its stack-local snapshot — the snapshot then
    /// has to replace the ring slot's record + carriers so the next
    /// reader sees the surviving `CapRef`s (and a matching
    /// `record.cap_count`, post-rollback) instead of the pre-install
    /// original (which would re-fire the same partial install or
    /// observe a `cap_count` that no longer matches the surviving
    /// carrier set).
    fn release_claim_with_carriers(
        &mut self,
        reader: *mut Tcb,
        record: MpRecord,
        carriers: CarrierSlots,
    ) {
        let slot = self.head as usize;
        if self.claimers[slot].load(Ordering::Acquire) != reader {
            return;
        }
        self.records[slot] = record;
        self.carriers[slot] = carriers;
        self.claimers[slot].store(core::ptr::null_mut(), Ordering::Release);
    }

    /// Pop the head only if our claim is still valid. Caller must
    /// have previously called `peek_and_claim` with the same `reader`.
    fn pop_claimed(&mut self, reader: *mut Tcb) -> Option<(MpRecord, CarrierSlots)> {
        let slot = self.head as usize;
        if self.claimers[slot].load(Ordering::Acquire) != reader {
            return None;
        }
        self.claimers[slot].store(core::ptr::null_mut(), Ordering::Release);
        let record = self.records[slot];
        let carriers = self.carriers[slot];
        self.carriers[slot] = CarrierSlots::empty();
        self.head = ((self.head as usize + 1) % MP_QUEUE_DEPTH) as u32;
        self.used -= 1;
        Some((record, carriers))
    }

    fn pop(&mut self) -> (MpRecord, CarrierSlots) {
        let slot = self.head as usize;
        let record = self.records[slot];
        let carriers = self.carriers[slot];
        self.carriers[slot] = CarrierSlots::empty();
        self.head = ((self.head as usize + 1) % MP_QUEUE_DEPTH) as u32;
        self.used -= 1;
        (record, carriers)
    }

    /// Pop every in-flight record + carrier slot, calling
    /// `CDT::delete_capability` on each slot — the canonical cap
    /// teardown that detaches the CDT entry, releases the object
    /// refcount, nullifies the slot capability, and returns the
    /// global slot to the freelist.
    ///
    /// # Safety
    /// Caller must hold CAP_LOCK so the CDT mutation + slot bitmap
    /// updates are serialised, and must hold the owning
    /// `MessagePipeCore` lock so concurrent producers / consumers
    /// can't observe a half-drained ring.
    unsafe fn drain_carriers_via_cdt(&mut self) {
        while self.used > 0 {
            let (_, carriers) = self.pop();
            for entry in carriers.0.iter() {
                // close-drain semantics: an in-flight carrier whose
                // sender has long-since returned from the syscall and
                // whose receiver will never read cannot be put back into
                // either CNode. Release its transit pin and tear the
                // global slot down via the canonical CDT path —
                // `CDT::delete_capability` performs cdt-remove →
                // release_object → nullify_capability → free_slot
                // atomically under CAP_LOCK so no stale CDT child pointer
                // lingers after the slot is recycled. The pin froze the
                // slot's generation, so no epoch re-check is needed.
                unsafe { entry.unpin_and_delete() };
            }
        }
    }
}

/// Singly-linked waiter queue (intrusive on `Tcb.eq_wait_next`).
#[repr(C)]
struct WaiterQueue {
    head: *mut Tcb,
    tail: *mut Tcb,
}

impl WaiterQueue {
    const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }

    /// Append `tcb` to the queue. Caller must hold the owning core's
    /// lock. Bumps the TCB's `sched_ref` so the scheduler holds a
    /// strong reference to the TCB while it sits on the list — paired
    /// with `sched_ref_release_may_destroy` after the wake.
    fn push(&mut self, tcb: *mut Tcb) {
        unsafe { (*tcb).eq_wait_next = core::ptr::null_mut() };
        unsafe { (*tcb).sched_ref_inc() };
        if self.tail.is_null() {
            self.head = tcb;
        } else {
            unsafe { (*self.tail).eq_wait_next = tcb };
        }
        self.tail = tcb;
    }

    /// Remove the first waiter and return its TCB. The waiter slot's
    /// `sched_ref` is dropped by `wake_thread` (the wake helper that
    /// retires the popped TCB), not here — so caller must ensure the
    /// returned TCB is funneled through `wake_thread` exactly once.
    fn pop(&mut self) -> *mut Tcb {
        let head = self.head;
        if head.is_null() {
            return core::ptr::null_mut();
        }
        let next = unsafe { (*head).eq_wait_next };
        self.head = next;
        if next.is_null() {
            self.tail = core::ptr::null_mut();
        }
        unsafe { (*head).eq_wait_next = core::ptr::null_mut() };
        head
    }

    /// Remove a specific TCB from the queue. Returns `true` when the
    /// TCB was found (and unlinked). Caller must hold the owning
    /// core's lock and is responsible for releasing the TCB's
    /// `sched_ref` after the queue's lock has been dropped.
    fn remove(&mut self, tcb: *mut Tcb) -> bool {
        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let next = unsafe { (*cur).eq_wait_next };
            if cur == tcb {
                if prev.is_null() {
                    self.head = next;
                } else {
                    unsafe { (*prev).eq_wait_next = next };
                }
                if self.tail == cur {
                    self.tail = prev;
                }
                unsafe { (*cur).eq_wait_next = core::ptr::null_mut() };
                return true;
            }
            prev = cur;
            cur = next;
        }
        false
    }

    fn contains(&self, tcb: *mut Tcb) -> bool {
        let mut cur = self.head;
        while !cur.is_null() {
            if cur == tcb {
                return true;
            }
            cur = unsafe { (*cur).eq_wait_next };
        }
        false
    }

    /// Remove the first MP_CALL waiter whose transaction id matches
    /// `txid`. The caller owns the returned waiter's queue
    /// `sched_ref` and must pass it to `wake_thread` or release it.
    fn remove_call_txid(&mut self, txid: u64) -> *mut Tcb {
        let mut prev: *mut Tcb = core::ptr::null_mut();
        let mut cur = self.head;
        while !cur.is_null() {
            let next = unsafe { (*cur).eq_wait_next };
            let cur_txid = unsafe {
                (*cur)
                    .message_waiter
                    .txid
                    .load(core::sync::atomic::Ordering::Acquire)
            };
            if cur_txid == txid {
                if prev.is_null() {
                    self.head = next;
                } else {
                    unsafe { (*prev).eq_wait_next = next };
                }
                if self.tail == cur {
                    self.tail = prev;
                }
                unsafe { (*cur).eq_wait_next = core::ptr::null_mut() };
                return cur;
            }
            prev = cur;
            cur = next;
        }
        core::ptr::null_mut()
    }
}

/// Shared MessagePipe core: cross-side state for a paired channel.
#[repr(C)]
pub struct MessagePipeCore {
    pub header: KernelObject,
    pub lock: SpinLock,
    pub state_a: AtomicU64,
    pub state_b: AtomicU64,
    pub watchers_a: WatcherList,
    pub watchers_b: WatcherList,
    /// Records produced by side A, consumed by side B.
    a_to_b: PipeRing,
    /// Records produced by side B, consumed by side A.
    b_to_a: PipeRing,
    waiters_a_read: WaiterQueue,
    waiters_a_write: WaiterQueue,
    waiters_a_call: WaiterQueue,
    waiters_b_read: WaiterQueue,
    waiters_b_write: WaiterQueue,
    waiters_b_call: WaiterQueue,
    side_a_alive: AtomicBool,
    side_b_alive: AtomicBool,
    /// `true` once `MP_PAIR` has wired both sides into this core.
    paired: AtomicBool,
}

unsafe impl Sync for MessagePipeCore {}

impl MessagePipeCore {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::MessagePipeCore, 0),
            lock: SpinLock::new(),
            state_a: AtomicU64::new(STATE_WRITABLE),
            state_b: AtomicU64::new(STATE_WRITABLE),
            watchers_a: WatcherList::new(),
            watchers_b: WatcherList::new(),
            a_to_b: PipeRing::new(),
            b_to_a: PipeRing::new(),
            waiters_a_read: WaiterQueue::new(),
            waiters_a_write: WaiterQueue::new(),
            waiters_a_call: WaiterQueue::new(),
            waiters_b_read: WaiterQueue::new(),
            waiters_b_write: WaiterQueue::new(),
            waiters_b_call: WaiterQueue::new(),
            side_a_alive: AtomicBool::new(false),
            side_b_alive: AtomicBool::new(false),
            paired: AtomicBool::new(false),
        }
    }

    fn ring_for_writer(&mut self, writer_side: u8) -> &mut PipeRing {
        if writer_side == SIDE_A {
            &mut self.a_to_b
        } else {
            &mut self.b_to_a
        }
    }

    fn ring_for_reader(&mut self, reader_side: u8) -> &mut PipeRing {
        if reader_side == SIDE_A {
            &mut self.b_to_a
        } else {
            &mut self.a_to_b
        }
    }

    fn state_for(&self, side: u8) -> &AtomicU64 {
        if side == SIDE_A {
            &self.state_a
        } else {
            &self.state_b
        }
    }

    fn watchers_for(&mut self, side: u8) -> &mut WatcherList {
        if side == SIDE_A {
            &mut self.watchers_a
        } else {
            &mut self.watchers_b
        }
    }

    fn waiters_read(&mut self, side: u8) -> &mut WaiterQueue {
        if side == SIDE_A {
            &mut self.waiters_a_read
        } else {
            &mut self.waiters_b_read
        }
    }

    fn waiters_write(&mut self, side: u8) -> &mut WaiterQueue {
        if side == SIDE_A {
            &mut self.waiters_a_write
        } else {
            &mut self.waiters_b_write
        }
    }

    fn waiters_call(&mut self, side: u8) -> &mut WaiterQueue {
        if side == SIDE_A {
            &mut self.waiters_a_call
        } else {
            &mut self.waiters_b_call
        }
    }

    fn side_alive(&self, side: u8) -> &AtomicBool {
        if side == SIDE_A {
            &self.side_a_alive
        } else {
            &self.side_b_alive
        }
    }

    fn other_side(side: u8) -> u8 {
        if side == SIDE_A { SIDE_B } else { SIDE_A }
    }

    /// Cross-CPU-capable v1 fastpath for `MP_WRITE`.
    ///
    /// Bypasses the bounded ring entirely: when the peer side already
    /// has a thread parked on `PipeRead`, the kernel publishes the
    /// inbound record into that thread's `mp_fast_mailbox` (5-state
    /// CAS protocol pinning the source `MessagePipeCore` via
    /// refcount) and dispatches a `pipe_wait_wake_plan` wake — which
    /// handles same-CPU and cross-CPU wake equally (the wake plan's
    /// internal `wake_blocked_thread` path takes care of IPI).
    /// Returns `false` to signal a slowpath bail; on `false` the
    /// caller's record is untouched.
    ///
    /// Bailout conditions:
    ///
    /// * `record.length > 4` — the IPC buffer overflow path is
    ///   reserved for the slowpath.
    /// * Pipe is unpaired or our side is closed or the peer side is
    ///   dead — the slowpath surfaces the precise error.
    /// * No waiter parked on the peer's read queue — fall back to
    ///   the slowpath's ring-enqueue.
    ///
    /// # Safety
    /// `self` must be a live `MessagePipeCore` and `me` must be a
    /// valid side identity (`SIDE_A` or `SIDE_B`). Each non-null
    /// `CapRef` in `carriers` must be uniquely owned by the caller —
    /// either taken out of the sender's CSpace via `take_ref`, or
    /// freshly minted as a kernel-private cap whose new global slot
    /// has not yet been published anywhere else.
    pub unsafe fn try_write_fast(
        &mut self,
        me: u8,
        record: MpRecord,
        carriers: CarrierSlots,
    ) -> bool {
        if record.length > 4 {
            return false;
        }
        if (record.cap_count as usize) > MP_MSG_CAPS {
            return false;
        }
        let other = Self::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();

        if !self.paired.load(Ordering::Acquire)
            || (self.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0
            || !self.side_alive(other).load(Ordering::Acquire)
        {
            self.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return false;
        }

        let waiter = self.waiters_read(other).pop();
        if waiter.is_null() {
            self.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return false;
        }

        // Pin the source core via refcount for the mailbox publish
        // window — the consumer's `try_claim` releases this pin once
        // the payload has been copied out. Pairs with the
        // `release_object` inside `MpFastMailbox::try_claim`.
        let core_obj = self as *mut MessagePipeCore as *mut KernelObject;
        unsafe {
            (*core_obj).ref_count.fetch_add(1, Ordering::AcqRel);
        }
        let waiter_seq = unsafe { (*waiter).wait_seq };
        let published = unsafe {
            (*waiter).mp_fast_mailbox.try_publish(
                MailboxKind::Message,
                core_obj,
                me as u32,
                waiter_seq,
                record,
                carriers,
            )
        };
        if !published {
            // The popped waiter's mailbox should always be Empty —
            // a parked `PipeRead` thread cannot legitimately carry
            // a pending publish. Defensive: drop the pin we took,
            // unpark the waiter so it retries via the slowpath, and
            // bail. Sched_ref ownership is funnelled through
            // `wake_thread` exactly once. The caller retains
            // `carriers` ownership for slowpath retry / rollback.
            unsafe {
                crate::cap::release_object(core_obj, ObjectType::MessagePipeCore);
            }
            self.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            unsafe { wake_thread(waiter) };
            return false;
        }

        // Publish READABLE→peer for any external watchers, then drop
        // the lock. The watcher publish itself runs outside the lock
        // (see `WatcherList::publish`), but flipping the bit under
        // the core lock keeps the producer/consumer ordering tight.
        let prev_other = self
            .state_for(other)
            .fetch_or(STATE_READABLE, Ordering::Release);
        let publish_to_other = if (prev_other & STATE_READABLE) == 0 {
            STATE_READABLE
        } else {
            0
        };
        let watchers = self.watchers_for(other) as *mut WatcherList;

        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_to_other != 0 {
            unsafe { (*watchers).publish(publish_to_other) };
        }
        unsafe { wake_thread(waiter) };
        true
    }

    /// Drain every in-flight carrier slot from BOTH rings, releasing
    /// each one through the canonical `CDT::delete_capability` path.
    /// Called from `MessagePipeCore`'s finalizer (refcount → 0) once
    /// both side handles have been cleaned up — no producer or
    /// consumer can be racing this drain at that point.
    ///
    /// # Safety
    /// Caller must hold CAP_LOCK (the finalizer is invoked under
    /// CAP_LOCK by the reaper); this fn does NOT take CAP_LOCK
    /// itself. The caller must NOT hold the core lock — that lock
    /// is irrelevant by the time refcount has reached zero, and
    /// nesting it under CAP_LOCK would invert the documented
    /// hierarchy.
    pub unsafe fn drain_all_carriers(&mut self) {
        unsafe {
            self.a_to_b.drain_carriers_via_cdt();
            self.b_to_a.drain_carriers_via_cdt();
        }
    }

    /// Detach `tcb` from the waiter queue matching
    /// `reason` and release its waiter-slot `sched_ref`. Called from
    /// `detach_thread_wait_queues` when the owning thread is being
    /// destroyed mid-wait.
    ///
    /// # Safety
    /// `core` must be a live `MessagePipeCore`. `tcb` must be the
    /// thread whose `wait_object` points at this core.
    pub unsafe fn detach_waiter(
        core: *mut MessagePipeCore,
        tcb: *mut Tcb,
        side: u8,
        reason: crate::sched::thread::BlockedReason,
    ) {
        if core.is_null() || tcb.is_null() {
            return;
        }
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core).lock.lock() };
        let removed = match reason {
            crate::sched::thread::BlockedReason::PipeWrite => unsafe {
                (*core).waiters_write(side).remove(tcb)
            },
            crate::sched::thread::BlockedReason::PipeRead => unsafe {
                (*core).waiters_read(side).remove(tcb)
            },
            crate::sched::thread::BlockedReason::PipeCall => unsafe {
                (*core).waiters_call(side).remove(tcb)
            },
            _ => false,
        };
        unsafe { (*core).lock.unlock() };
        unsafe { crate::mm::restore_irq(irq) };

        if removed {
            unsafe {
                crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
            }
        }
    }
}

/// Lightweight side handle: a cap-bearing front to a shared core.
///
/// All watcher state lives on the shared `MessagePipeCore` — the
/// side handle keeps only a strong pointer to the core plus its own
/// side identity. Watch lookups for a `MessagePipe` cap dereference
/// `core.watchers_a` / `core.watchers_b` directly (see
/// `cap::refcount::watcher_list_for_obj_type` and
/// `syscall::event::watcher_list_for`).
#[repr(C)]
pub struct MessagePipe {
    pub header: KernelObject,
    /// Strong pointer to the shared core. Refcount on the core
    /// includes our side's contribution; dropped in `cleanup()`.
    pub core: *mut MessagePipeCore,
    /// `SIDE_A` or `SIDE_B`.
    pub which_side: u8,
    /// Padding to keep the struct's size predictable across
    /// architectures.
    pub _pad: [u8; 7],
}

unsafe impl Sync for MessagePipe {}

impl MessagePipe {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::MessagePipe, 0),
            core: core::ptr::null_mut(),
            which_side: 0xFF,
            _pad: [0; 7],
        }
    }

    /// Bind two newly retyped sides + a core into a paired channel.
    ///
    /// Each side increments the core's refcount by one. The caller
    /// releases its own core cap normally; the channel stays alive as
    /// long as either side is reachable.
    ///
    /// Returns `Err(())` if any of the inputs is already paired or
    /// the two sides reference different cores.
    ///
    /// # Safety
    /// `core`, `a`, and `b` must be live, kernel-allocated objects
    /// the caller currently holds caps for.
    pub unsafe fn pair(
        core: *mut MessagePipeCore,
        a: *mut MessagePipe,
        b: *mut MessagePipe,
    ) -> Result<(), ()> {
        if core.is_null() || a.is_null() || b.is_null() || a == b {
            return Err(());
        }
        unsafe {
            if (*core).paired.swap(true, Ordering::AcqRel) {
                return Err(());
            }
            if !(*a).core.is_null() || !(*b).core.is_null() {
                (*core).paired.store(false, Ordering::Release);
                return Err(());
            }
            (*a).core = core;
            (*a).which_side = SIDE_A;
            (*b).core = core;
            (*b).which_side = SIDE_B;
            (*core).side_a_alive.store(true, Ordering::Release);
            (*core).side_b_alive.store(true, Ordering::Release);
            crate::cap::increment_refcount(core as *mut KernelObject);
            crate::cap::increment_refcount(core as *mut KernelObject);
        }
        Ok(())
    }

    /// Outcome of a single `try_write_record` attempt — non-blocking
    /// enqueue. The caller (syscall layer) decides whether to block,
    /// surface `WouldBlock`, or surface `PeerClosed` based on its own
    /// `timeout_ns` policy.
    ///
    /// `WouldBlock` means the peer's incoming ring is full at this
    /// instant; the message has not been queued and the carriers are
    /// untouched.
    ///
    /// Non-blocking enqueue. If the peer side is reachable and the
    /// ring has room, push the record and wake any reader parked on
    /// `PipeRead`. Otherwise return without touching the ring.
    ///
    /// # Safety
    /// `self` must be a live `MessagePipe` whose `core` was set by
    /// `pair`.
    pub unsafe fn try_write_record(
        &self,
        record: MpRecord,
        carriers: CarrierSlots,
    ) -> Result<(), TryWriteErr> {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return Err(TryWriteErr::PeerClosed);
        }
        let me = self.which_side;
        let other = MessagePipeCore::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };

        if (core.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0
            || !core.side_alive(other).load(Ordering::Acquire)
        {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryWriteErr::PeerClosed);
        }

        if (record.flags & MP_FLAG_REPLY) != 0 && record.txid != 0 {
            let waiter = core.waiters_call(other).remove_call_txid(record.txid);
            if !waiter.is_null() {
                unsafe {
                    (*waiter).message_waiter.reply = record;
                    (*waiter).message_waiter.reply_carriers = carriers;
                    (*waiter).message_waiter.txid.store(0, Ordering::Release);
                    (*waiter)
                        .message_waiter
                        .ready
                        .store(true, Ordering::Release);
                }
                core.lock.unlock();
                unsafe { crate::mm::restore_irq(irq) };
                unsafe { wake_thread(waiter) };
                return Ok(());
            }
            // No parked call-waiter — this reply targets an async caller
            // that services its EventQueue instead of parking on the txid.
            // Fall through to the ordinary ring enqueue + STATE_READABLE
            // publish below; the caller reads the reply off its recv ring
            // and correlates it by txid (Zircon late/unmatched-reply shape).
        }

        if core.ring_for_writer(me).is_full() {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryWriteErr::WouldBlock);
        }

        core.ring_for_writer(me).push(record, carriers);

        let prev_other = core
            .state_for(other)
            .fetch_or(STATE_READABLE, Ordering::Release);
        let publish_to_other = if (prev_other & STATE_READABLE) == 0 {
            STATE_READABLE
        } else {
            0
        };
        if core.ring_for_writer(me).is_full() {
            core.state_for(me)
                .fetch_and(!STATE_WRITABLE, Ordering::Release);
        }

        let waiter = core.waiters_read(other).pop();
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_to_other != 0 {
            let watchers = core.watchers_for(other) as *mut WatcherList;
            unsafe { (*watchers).publish(publish_to_other) };
        }
        if !waiter.is_null() {
            unsafe { wake_thread(waiter) };
        }
        Ok(())
    }

    /// Atomically enqueue an `MP_CALL` request and register the caller
    /// as the sole waiter for `txid`. This closes the race where a
    /// fast server reply could arrive between request enqueue and
    /// caller wait registration.
    ///
    /// # Safety
    /// `tcb` must be the current TCB. `record.txid` must equal
    /// `txid`, and `carriers` must be uniquely owned by the caller.
    pub unsafe fn try_call_write_record(
        &self,
        tcb: *mut Tcb,
        txid: u64,
        record: MpRecord,
        carriers: CarrierSlots,
    ) -> Result<(), TryWriteErr> {
        if tcb.is_null() || txid == 0 {
            return Err(TryWriteErr::PeerClosed);
        }
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return Err(TryWriteErr::PeerClosed);
        }
        let me = self.which_side;
        let other = MessagePipeCore::other_side(me);

        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };

        if (core.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0
            || !core.side_alive(other).load(Ordering::Acquire)
        {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryWriteErr::PeerClosed);
        }

        if core.ring_for_writer(me).is_full() {
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return Err(TryWriteErr::WouldBlock);
        }

        unsafe {
            (*tcb).message_waiter.ready.store(false, Ordering::Release);
            (*tcb).message_waiter.reply_carriers = CarrierSlots::empty();
            (*tcb).message_waiter.reply = MpRecord::empty();
            (*tcb).message_waiter.txid.store(txid, Ordering::Release);
            core.waiters_call(me).push(tcb);
            (*tcb).wait_object = core_ptr as *mut core::ffi::c_void;
            (*tcb).wait_side = me;
            (*tcb).wait_seq = (*tcb).wait_seq.wrapping_add(1);
        }

        core.ring_for_writer(me).push(record, carriers);

        let prev_other = core
            .state_for(other)
            .fetch_or(STATE_READABLE, Ordering::Release);
        let publish_to_other = if (prev_other & STATE_READABLE) == 0 {
            STATE_READABLE
        } else {
            0
        };
        if core.ring_for_writer(me).is_full() {
            core.state_for(me)
                .fetch_and(!STATE_WRITABLE, Ordering::Release);
        }

        let waiter = core.waiters_read(other).pop();
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };

        if publish_to_other != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(other) as *mut WatcherList };
            unsafe { (*watchers).publish(publish_to_other) };
        }
        if !waiter.is_null() {
            unsafe { wake_thread(waiter) };
        }
        Ok(())
    }

    /// Transition a registered MP_CALL waiter into the blocked state.
    /// Returns `false` when a reply or close already removed the
    /// waiter before the caller parked.
    ///
    /// # Safety
    /// `tcb` must be the current TCB and must have been registered by
    /// `try_call_write_record` on this pipe side.
    pub unsafe fn prepare_call_waiter_block(&self, tcb: *mut Tcb) -> bool {
        if tcb.is_null() || unsafe { (*tcb).message_waiter.ready.load(Ordering::Acquire) } {
            return false;
        }
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return false;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        let queued = core.waiters_call(me).contains(tcb);
        if queued && !unsafe { (*tcb).message_waiter.ready.load(Ordering::Acquire) } {
            unsafe {
                let t = &mut *tcb;
                t.wait_object = core_ptr as *mut core::ffi::c_void;
                t.wait_side = me;
                t.tcb_lock();
                crate::task::wait::prepare_blocked_reason_locked(
                    t,
                    crate::sched::thread::BlockedReason::PipeCall,
                );
                t.tcb_unlock();
            }
            core.lock.unlock();
            unsafe { crate::mm::restore_irq(irq) };
            return true;
        }
        core.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        false
    }

    /// Return whether this TCB is still registered as a call waiter on
    /// this side.
    ///
    /// # Safety
    /// `tcb` must be a live TCB pointer.
    pub unsafe fn call_waiter_registered(&self, tcb: *mut Tcb) -> bool {
        let core_ptr = self.core;
        if core_ptr.is_null() || tcb.is_null() {
            return false;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let queued = unsafe { (&mut *core_ptr).waiters_call(me).contains(tcb) };
        unsafe { (*core_ptr).lock.unlock() };
        unsafe { crate::mm::restore_irq(irq) };
        queued
    }

    /// Remove this TCB from the call waiter queue if it is still
    /// present, releasing the queue's scheduler reference.
    ///
    /// # Safety
    /// `tcb` must be a live TCB pointer.
    pub unsafe fn unregister_call_waiter(&self, tcb: *mut Tcb) -> bool {
        let core_ptr = self.core;
        if core_ptr.is_null() || tcb.is_null() {
            return false;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let removed = unsafe { (&mut *core_ptr).waiters_call(me).remove(tcb) };
        unsafe { (*core_ptr).lock.unlock() };
        unsafe { crate::mm::restore_irq(irq) };
        if removed {
            unsafe {
                (*tcb).message_waiter.txid.store(0, Ordering::Release);
                crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
            }
        }
        removed
    }

    /// Park `tcb` on this side's writer-wait queue. Caller is the
    /// syscall layer; it has already bumped `tcb.sched_ref_inc()` for
    /// the waiter slot. Returns the new `wait_seq` so the caller can
    /// stamp deadline-queue arm-points consistently.
    ///
    /// # Safety
    /// `tcb` must be the current TCB. Caller must `reschedule()`
    /// after this returns.
    pub unsafe fn enqueue_writer_waiter(&self, tcb: *mut Tcb) -> u64 {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return 0;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        unsafe {
            core.waiters_write(me).push(tcb);
            let t = &mut *tcb;
            t.wait_object = core_ptr as *mut core::ffi::c_void;
            t.wait_side = me;
            t.wait_seq = t.wait_seq.wrapping_add(1);
            let new_seq = t.wait_seq;
            t.tcb_lock();
            crate::task::wait::prepare_blocked_reason_locked(
                t,
                crate::sched::thread::BlockedReason::PipeWrite,
            );
            t.tcb_unlock();
            core.lock.unlock();
            crate::mm::restore_irq(irq);
            new_seq
        }
    }

    /// Read a record from this side's incoming ring with a closure
    /// that **consumes** it: install hidden carriers into the
    /// receiver's CSpace AND copy the record into userspace, both
    /// under the same fail-safe peek-then-commit window.
    ///
    /// The previous design had three distinct phases — claim →
    /// install → pop_claimed (advance head) — and let the syscall
    /// layer copy the record into the IPC buffer AFTER the head was
    /// already advanced. A `BadAddress` fault in the IPC-buffer copy
    /// then lost the record AND left carriers permanently install in
    /// the receiver CNode. Folding the IPC copy into the closure puts
    /// the entire user-observable side effect inside the fail-safe
    /// window: closure failure → `release_claim_with_carriers` writes
    /// the surviving `CapRef`s back into the ring → next read attempt
    /// sees the same record at head.
    ///
    /// Sequencing:
    /// 1. Fastpath: claim from `mp_fast_mailbox` (no carriers, no
    ///    ring touch); closure runs against an empty carrier array.
    ///    On fastpath consume failure the deposit is already gone
    ///    from the mailbox — there is no ring slot to restore. The
    ///    closure is responsible for any cap-rollback in that case;
    ///    the record itself is lost (matching the old fastpath
    ///    behaviour, since fast deposits never sat in a ring).
    /// 2. Phase 1 (core lock): `peek_and_claim` to reserve head;
    ///    snapshot record + carriers onto stack.
    /// 3. Phase 2 (no core lock): run closure, which may take
    ///    CAP_LOCK to walk the receiver CNode and may take a
    ///    user-mode page fault while writing the IPC buffer.
    /// 4. Phase 3 (core lock): on `Ok(label)`, `pop_claimed` advances
    ///    head + republishes WRITABLE to peer; on `Err(())`,
    ///    `release_claim_with_carriers(snapshot)` puts the surviving
    ///    `CapRef`s back into the ring slot so the next read sees
    ///    them.
    ///
    /// Returns `WouldBlock` when the ring is empty AND the side is
    /// not closed; the caller (syscall layer) decides whether to
    /// park as a `PipeRead` waiter under its own `timeout_ns` policy.
    ///
    /// The closure receives `(&mut CarrierSlots, &MpRecord)`. On `Err`
    /// it MUST leave `carriers` carrying every surviving `CapRef`
    /// (anything that didn't make it into the receiver CNode and any
    /// `take_ref` rollback from a partially-installed group). The
    /// closure's `Ok(u64)` payload is propagated back to the caller
    /// via `ReadOutcome::Read(_)` — by convention the record's label.
    ///
    /// # Safety
    /// `self` must be a live `MessagePipe` whose `core` was set by
    /// `pair`. `consume` must be safe to invoke without holding the
    /// core lock — it WILL hold CAP_LOCK during cap installation and
    /// MAY take user-mode page faults during IPC-buffer copy.
    pub unsafe fn try_read_with_install(
        &self,
        consume: impl FnOnce(&mut CarrierSlots, &mut MpRecord) -> Result<u64, ()>,
    ) -> ReadOutcome {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return ReadOutcome::PeerClosed;
        }
        let me = self.which_side;
        let other = MessagePipeCore::other_side(me);
        let mut consume_opt = Some(consume);

        // Fastpath drain — peek the mailbox, run consume, then commit
        // (success) or abort (failure). Aborting puts the deposit
        // back so a retry / next read still sees it; without that,
        // a closure failure (BadAddress on IPC-buffer write, etc.)
        // would lose the message.
        unsafe {
            let scheduler = crate::sched::scheduler::scheduler();
            let current = scheduler.current();
            if !current.is_null() {
                let core_obj = core_ptr as *mut KernelObject;
                let wait_seq = (*current).wait_seq;
                if let Some((kind, mut record, mut carriers)) =
                    (*current).mp_fast_mailbox.try_peek(core_obj, wait_seq)
                {
                    crate::kernel::bug::kassert_eq!(kind, MailboxKind::Message);
                    let consume_fn = match consume_opt.take() {
                        Some(f) => f,
                        None => {
                            (*current)
                                .mp_fast_mailbox
                                .abort_peek(kind, record, carriers);
                            return ReadOutcome::ConsumeFailed;
                        }
                    };
                    return match consume_fn(&mut carriers, &mut record) {
                        Ok(label) => {
                            (*current).mp_fast_mailbox.commit_peek(kind);
                            ReadOutcome::Read(label)
                        }
                        Err(()) => {
                            // Restore the mailbox deposit so the
                            // next read attempt re-observes it. The
                            // source pin (set by the producer's
                            // `try_publish`) stays held since
                            // `abort_peek` does not touch it — the
                            // deposit is still live, just deferred.
                            // The (record, carriers) pair we hand
                            // back may have been mutated by the
                            // consume closure's partial-install
                            // rollback (`record.cap_count` shrunk,
                            // installed entries cleared in
                            // `carriers`); the next reader observes
                            // the surviving snapshot.
                            (*current)
                                .mp_fast_mailbox
                                .abort_peek(kind, record, carriers);
                            ReadOutcome::ConsumeFailed
                        }
                    };
                }
            }
        }

        // Phase 1 — reserve head under core lock, snapshot record +
        // carriers to stack, drop lock.
        let scheduler = crate::sched::scheduler::scheduler();
        let reader = scheduler.current();
        if reader.is_null() {
            return ReadOutcome::PeerClosed;
        }

        let (claimed, my_state_at_peek) = unsafe {
            let irq = crate::mm::save_irq_disable();
            (*core_ptr).lock.lock();
            let core = &mut *core_ptr;
            let claim = core.ring_for_reader(me).peek_and_claim(reader);
            let state = core.state_for(me).load(Ordering::Acquire);
            core.lock.unlock();
            crate::mm::restore_irq(irq);
            (claim, state)
        };

        let (mut record, mut carriers) = match claimed {
            Some(rc) => rc,
            None => {
                if (my_state_at_peek & (STATE_CLOSED | STATE_PEER_CLOSED)) != 0 {
                    return ReadOutcome::PeerClosed;
                }
                return ReadOutcome::WouldBlock;
            }
        };

        // Phase 2 — consume runs OUTSIDE the core lock. It will take
        // CAP_LOCK to walk the receiver CNode (lock order:
        // CAP_LOCK → mp_core.lock) and may take a page fault while
        // copying the record into the receiver's IPC buffer. Partial
        // install + rollback (and any IPC-write fault recovery) may
        // mutate `carriers` in place AND adjust `record.cap_count`
        // when a sibling CSpace race makes carrier rollback
        // impossible — the closure puts surviving `CapRef`s back
        // into the snapshot and shrinks `cap_count` to match so we
        // can write a self-consistent (record, carriers) pair back
        // into the ring on failure.
        let consume_fn = match consume_opt.take() {
            Some(f) => f,
            None => {
                unsafe {
                    let irq = crate::mm::save_irq_disable();
                    (*core_ptr).lock.lock();
                    (*core_ptr)
                        .ring_for_reader(me)
                        .release_claim_with_carriers(reader, record, carriers);
                    (*core_ptr).lock.unlock();
                    crate::mm::restore_irq(irq);
                }
                return ReadOutcome::ConsumeFailed;
            }
        };
        let label = match consume_fn(&mut carriers, &mut record) {
            Ok(label) => label,
            Err(()) => {
                unsafe {
                    let irq = crate::mm::save_irq_disable();
                    (*core_ptr).lock.lock();
                    (*core_ptr)
                        .ring_for_reader(me)
                        .release_claim_with_carriers(reader, record, carriers);
                    (*core_ptr).lock.unlock();
                    crate::mm::restore_irq(irq);
                }
                return ReadOutcome::ConsumeFailed;
            }
        };

        // Phase 3 — consume committed, advance head + republish state
        // under core lock + collect waiter / watcher publish.
        let (waiter, publish_to_other) = unsafe {
            let irq = crate::mm::save_irq_disable();
            (*core_ptr).lock.lock();
            let core = &mut *core_ptr;
            let _ = core.ring_for_reader(me).pop_claimed(reader);
            if core.ring_for_reader(me).used == 0 {
                core.state_for(me)
                    .fetch_and(!STATE_READABLE, Ordering::Release);
            }
            let prev_other = core
                .state_for(other)
                .fetch_or(STATE_WRITABLE, Ordering::Release);
            let publish = if (prev_other & STATE_WRITABLE) == 0 {
                STATE_WRITABLE
            } else {
                0
            };
            let w = core.waiters_write(other).pop();
            core.lock.unlock();
            crate::mm::restore_irq(irq);
            (w, publish)
        };

        if publish_to_other != 0 {
            let watchers = unsafe { (*core_ptr).watchers_for(other) as *mut WatcherList };
            unsafe { (*watchers).publish(publish_to_other) };
        }
        if !waiter.is_null() {
            unsafe { wake_thread(waiter) };
        }
        ReadOutcome::Read(label)
    }

    /// Park `tcb` on this side's reader-wait queue. Caller has
    /// already bumped `tcb.sched_ref_inc()`. Returns the new
    /// `wait_seq` so the caller can stamp deadline-queue arms /
    /// fastpath-mailbox sources consistently.
    ///
    /// # Safety
    /// `tcb` must be the current TCB. Caller must `reschedule()`
    /// after this returns.
    pub unsafe fn enqueue_reader_waiter(&self, tcb: *mut Tcb) -> u64 {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return 0;
        }
        let me = self.which_side;
        let irq = unsafe { crate::mm::save_irq_disable() };
        unsafe { (*core_ptr).lock.lock() };
        let core = unsafe { &mut *core_ptr };
        unsafe {
            core.waiters_read(me).push(tcb);
            let t = &mut *tcb;
            t.wait_object = core_ptr as *mut core::ffi::c_void;
            t.wait_side = me;
            t.wait_seq = t.wait_seq.wrapping_add(1);
            let new_seq = t.wait_seq;
            t.tcb_lock();
            crate::task::wait::prepare_blocked_reason_locked(
                t,
                crate::sched::thread::BlockedReason::PipeRead,
            );
            t.tcb_unlock();
            core.lock.unlock();
            crate::mm::restore_irq(irq);
            new_seq
        }
    }

    /// Close this side. Marks `STATE_CLOSED` on this side, propagates
    /// `STATE_PEER_CLOSED` to the other side, wakes every blocked
    /// waiter on this channel.
    pub fn close(&mut self) {
        let core_ptr = self.core;
        if core_ptr.is_null() {
            return;
        }
        let me = self.which_side;
        let other = MessagePipeCore::other_side(me);

        unsafe {
            let irq = crate::mm::save_irq_disable();
            (*core_ptr).lock.lock();
            let core = &mut *core_ptr;

            let already_closed = (core.state_for(me).load(Ordering::Acquire) & STATE_CLOSED) != 0;
            if already_closed {
                core.lock.unlock();
                crate::mm::restore_irq(irq);
                return;
            }

            core.state_for(me).fetch_or(STATE_CLOSED, Ordering::Release);
            core.state_for(other)
                .fetch_or(STATE_PEER_CLOSED, Ordering::Release);
            core.side_alive(me).store(false, Ordering::Release);

            // Carriers stay queued in the rings — `close` runs under
            // the core lock without holding CAP_LOCK, so it cannot
            // safely reach into the CDT / slot freelist. The
            // `MessagePipeCore` finalizer (`destroy_object_final`,
            // CAP_LOCK held) drains both rings via
            // `drain_carriers_via_cdt` once both side caps have
            // dropped — by then no producer or consumer can race
            // the drain, and the canonical `CDT::delete_capability`
            // path is safe to walk.

            // Drain waiters on both sides so no thread is left blocked
            // on a half-closed channel.
            let mut readers_a = core::ptr::null_mut();
            let mut writers_a = core::ptr::null_mut();
            let mut callers_a = core::ptr::null_mut();
            let mut readers_b = core::ptr::null_mut();
            let mut writers_b = core::ptr::null_mut();
            let mut callers_b = core::ptr::null_mut();
            collect_queue(&mut core.waiters_a_read, &mut readers_a);
            collect_queue(&mut core.waiters_a_write, &mut writers_a);
            collect_queue(&mut core.waiters_a_call, &mut callers_a);
            collect_queue(&mut core.waiters_b_read, &mut readers_b);
            collect_queue(&mut core.waiters_b_write, &mut writers_b);
            collect_queue(&mut core.waiters_b_call, &mut callers_b);

            core.lock.unlock();
            crate::mm::restore_irq(irq);

            // Wake every drained waiter outside the core lock so the
            // scheduler can take its own locks without nesting.
            wake_chain(readers_a);
            wake_chain(writers_a);
            wake_chain(callers_a);
            wake_chain(readers_b);
            wake_chain(writers_b);
            wake_chain(callers_b);

            // Republish state changes to any registered watches.
            let other_watchers = core.watchers_for(other) as *mut WatcherList;
            (*other_watchers).publish(STATE_PEER_CLOSED);
            let me_watchers = core.watchers_for(me) as *mut WatcherList;
            (*me_watchers).publish(STATE_CLOSED);
        }
    }

    /// Drop the core's refcount contributed by this side. Called from
    /// the side's destructor after `close()`. Drains the per-side
    /// watcher list inside the core so any `Watch` pointing at this
    /// side handle has its `watched_object` cleared before the side
    /// is reaped.
    ///
    /// # Safety
    /// Must be called exactly once per side, after `close()`.
    pub unsafe fn cleanup(&mut self) {
        let core_ptr = self.core;
        let me = self.which_side;
        self.close();
        self.core = core::ptr::null_mut();
        unsafe {
            if !core_ptr.is_null() {
                let watchers = (*core_ptr).watchers_for(me) as *mut WatcherList;
                (*watchers).drain_closed();
                crate::cap::release_object(
                    core_ptr as *mut KernelObject,
                    ObjectType::MessagePipeCore,
                );
            }
        }
    }
}

unsafe fn wake_thread(tcb: *mut Tcb) {
    unsafe {
        let _ = crate::sched::control::execute_wake_plan(
            crate::sched::control::pipe_wait_wake_plan(tcb),
        );
        // Drop the per-side waiter slot's `sched_ref_inc` taken at
        // `WaiterQueue::push`. `sched_ref_release_may_destroy` is
        // null-safe and acquires CAP_LOCK on the destroy path, so it
        // must run *after* every per-object lock has been released.
        crate::sched::scheduler::scheduler().sched_ref_release_may_destroy(tcb);
    }
}

#[inline]
fn collect_queue(q: &mut WaiterQueue, out: &mut *mut Tcb) {
    *out = q.head;
    q.head = core::ptr::null_mut();
    q.tail = core::ptr::null_mut();
}

#[inline]
unsafe fn wake_chain(mut head: *mut Tcb) {
    while !head.is_null() {
        unsafe {
            let next = (*head).eq_wait_next;
            (*head).eq_wait_next = core::ptr::null_mut();
            wake_thread(head);
            head = next;
        }
    }
}
