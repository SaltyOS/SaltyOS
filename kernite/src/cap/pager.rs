// SPDX-License-Identifier: GPL-2.0-only
//! Pager — file-backed `MemoryObject` supplier.
//!
//! A `Pager` is a userland-held capability bound to an `EventQueue`. mmsrv
//! attaches it to a file-backed MO via `MO_ATTACH_PAGER`; the kernel routes
//! every absent-page fault on that MO into the pager's bound EQ as a
//! `KERNITE_EVENT_TYPE_PAGER_REQUEST` record. The faulting TCB blocks on a
//! `PendingPagerRequest` keyed by `(mo_id, page_idx)` until vfs replies
//! with `PAGER_SUPPLY_PAGE` (frame ownership transitions into the MO via
//! `FrameOwner::MoData`) or `PAGER_FAIL` (the fault re-surfaces to userspace
//! through the existing fault delivery path).
//!
//! Lock order:
//!   `VSpace.lock → MemoryObject.commit_lock → Pager.lock → Tcb.tcb_lock`.
//! `EventQueue::enqueue` runs with `Pager.lock` released — pin the bound
//! EQ refcount, snapshot the record under the lock, drop, then enqueue.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::cap::memory_object::MemoryObject;
use crate::cap::object::{KernelObject, ObjectType};
use crate::event::event_queue::EventQueue;
use crate::mm::SpinLock;
use crate::sched::thread::Tcb;

/// Maximum number of in-flight `(mo_id, page_idx)` pending requests
/// system-wide. Each request coalesces N concurrent fault waiters into
/// one entry so this is the total set of distinct unfilled pages, not
/// the total of blocked threads.
pub const MAX_PENDING_PAGER_REQUESTS: usize = 1024;

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum PendingState {
    Pending = 0,
    Supplied = 1,
    Failed = 2,
    Reclaimed = 3,
}

/// One in-flight `(mo_id, page_idx)` fault. Multiple TCBs faulting the
/// same page coalesce onto a single request via `waiter_head`. Slot is
/// allocated from `PENDING_POOL` under `PENDING_POOL.lock` and lives
/// until the supply / fail / cancel terminator releases it.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingPagerRequest {
    pub pager: *mut Pager,
    pub mo: *mut MemoryObject,
    pub mo_id: u64,
    pub page_idx: u32,
    pub access_flags: u8,
    pub state: u8,
    pub _pad0: u16,
    pub request_epoch: u64,
    /// Head of the intrusive TCB waiter list; threads link through
    /// `Tcb.eq_wait_next`. A TCB can only be on one waiter list at a
    /// time — the `PagerFaultBlocked` BlockedReason discriminant
    /// disambiguates the list owner.
    pub waiter_head: *mut Tcb,
    /// Next request in the owning `Pager`'s intrusive list.
    pub pager_next: *mut PendingPagerRequest,
    /// Next request in the per-pager hash chain keyed by
    /// `(mo_id, page_idx)`. Used by coalesce lookup at fault time.
    pub key_next: *mut PendingPagerRequest,
    /// 0 = free slot, 1 = active.
    pub active: u8,
    pub _pad1: [u8; 7],
}

impl PendingPagerRequest {
    pub const fn empty() -> Self {
        Self {
            pager: core::ptr::null_mut(),
            mo: core::ptr::null_mut(),
            mo_id: 0,
            page_idx: 0,
            access_flags: 0,
            state: PendingState::Pending as u8,
            _pad0: 0,
            request_epoch: 0,
            waiter_head: core::ptr::null_mut(),
            pager_next: core::ptr::null_mut(),
            key_next: core::ptr::null_mut(),
            active: 0,
            _pad1: [0; 7],
        }
    }
}

#[repr(C)]
struct PendingPool {
    entries: [PendingPagerRequest; MAX_PENDING_PAGER_REQUESTS],
    lock: SpinLock,
}

unsafe impl Sync for PendingPool {}

static mut PENDING_POOL: PendingPool = PendingPool {
    entries: [PendingPagerRequest::empty(); MAX_PENDING_PAGER_REQUESTS],
    lock: SpinLock::new(),
};

/// Allocate a free pending-request slot. Returns the slot index, or
/// `None` if the system-wide cap is exhausted. The slot is marked
/// `active` before this returns so a sibling allocator cannot grab it.
pub(crate) fn pending_alloc_slot() -> Option<u32> {
    let irq = unsafe { crate::mm::save_irq_disable() };
    let pool = unsafe { &mut *(&raw mut PENDING_POOL) };
    pool.lock.lock();
    let mut found = None;
    for (idx, e) in pool.entries.iter_mut().enumerate() {
        if e.active == 0 {
            *e = PendingPagerRequest::empty();
            e.active = 1;
            found = Some(idx as u32);
            break;
        }
    }
    pool.lock.unlock();
    unsafe { crate::mm::restore_irq(irq) };
    found
}

/// Free a slot back to the pool. Idempotent on already-free slots.
pub(crate) fn pending_free_slot(idx: u32) {
    let irq = unsafe { crate::mm::save_irq_disable() };
    let pool = unsafe { &mut *(&raw mut PENDING_POOL) };
    pool.lock.lock();
    if let Some(e) = pool.entries.get_mut(idx as usize) {
        if e.active != 0 {
            *e = PendingPagerRequest::empty();
        }
    }
    pool.lock.unlock();
    unsafe { crate::mm::restore_irq(irq) };
}

/// Resolve a slot index to a raw pointer for callers that already hold
/// the appropriate lock chain. Returns `None` for inactive slots.
///
/// # Safety
/// The returned pointer aliases pool storage; the caller must avoid
/// holding it across allocator calls that could reuse the slot.
pub(crate) unsafe fn pending_get(idx: u32) -> Option<*mut PendingPagerRequest> {
    let pool = unsafe { &mut *(&raw mut PENDING_POOL) };
    pool.entries
        .get_mut(idx as usize)
        .filter(|e| e.active != 0)
        .map(|e| e as *mut PendingPagerRequest)
}

/// Free a pending request by pointer after all waiters have stopped
/// referencing it through `Tcb.wait_object`.
///
/// # Safety
/// `req` must be a pointer previously returned by `pending_get`.
pub(crate) unsafe fn pending_free_ptr(req: *mut PendingPagerRequest) {
    if req.is_null() {
        return;
    }
    for idx in 0..MAX_PENDING_PAGER_REQUESTS as u32 {
        if unsafe { pending_get(idx) } == Some(req) {
            pending_free_slot(idx);
            break;
        }
    }
}

/// Wake every waiter from a drained request list and return the slots
/// to the global pending pool.
///
/// # Safety
/// `requests` must be a list produced by `Pager::drain_pending_locked`
/// or an equivalent unlink under the owning `Pager.lock`.
pub(crate) unsafe fn wake_and_free_drained_requests(mut requests: *mut PendingPagerRequest) {
    unsafe {
        while !requests.is_null() {
            let req = requests;
            requests = (*req).pager_next;
            (*req).pager_next = core::ptr::null_mut();
            let waiters = (*req).waiter_head;
            (*req).waiter_head = core::ptr::null_mut();
            crate::sched::scheduler::scheduler().wake_pager_request_waiters(waiters);
            pending_free_ptr(req);
        }
    }
}

/// Pager kernel object — held by userland (typically vfs), bound to an
/// `EventQueue`, and attached to one or more file-backed MOs.
#[repr(C)]
pub struct Pager {
    pub header: KernelObject,
    pub lock: SpinLock,
    pub _pad0: [u8; 7],
    /// Bumped on detach / pager-cap revocation. Bound observers use
    /// this to discard stale events whose snapshot lost a race against
    /// teardown.
    pub cancel_epoch: AtomicU64,
    /// Bound `EventQueue` raw pointer. Pinned via refcount while
    /// non-null; cleared at unbind / cleanup. Mutation requires
    /// `Pager.lock`.
    pub bound_eq: *mut EventQueue,
    /// Cookie supplied at bind time, surfaced in every emitted
    /// `PAGER_REQUEST` event so userspace can demux per-pager streams.
    pub cookie: u64,
    /// Head of the intrusive list of MOs attached to this pager,
    /// linked through `MemoryObject.pager_next`. Mutation requires
    /// `Pager.lock`.
    pub attached_mo_head: *mut MemoryObject,
    /// Head of the intrusive list of in-flight `PendingPagerRequest`s
    /// owned by this pager, linked through `PendingPagerRequest.pager_next`.
    pub pending_head: *mut PendingPagerRequest,
    /// Monotonic seq for new MO attachments. The kernel-internal
    /// `mo_id` returned to userspace by `MO_ATTACH_PAGER` is sourced
    /// here; ids are never reused within a single pager's lifetime.
    pub mo_id_seq: AtomicU64,
}

unsafe impl Sync for Pager {}

impl Pager {
    pub const fn new() -> Self {
        Self {
            header: KernelObject::new(ObjectType::Pager, 0),
            lock: SpinLock::new(),
            _pad0: [0; 7],
            cancel_epoch: AtomicU64::new(0),
            bound_eq: core::ptr::null_mut(),
            cookie: 0,
            attached_mo_head: core::ptr::null_mut(),
            pending_head: core::ptr::null_mut(),
            mo_id_seq: AtomicU64::new(1),
        }
    }

    /// Allocate the next monotonic `mo_id` for an MO attaching to this
    /// pager. The first id is `1` so `0` reads as "no pager attached"
    /// in `MemoryObject.pager_mo_id`.
    pub fn alloc_mo_id(&self) -> u64 {
        self.mo_id_seq.fetch_add(1, Ordering::AcqRel)
    }

    /// Bind the pager to an `EventQueue`. Caller has pinned `eq`'s
    /// refcount before calling. Returns the previous bound EQ pointer
    /// — non-null only if the pager was previously bound; the caller
    /// is responsible for releasing that pin.
    pub fn bind_eq(&mut self, eq: *mut EventQueue, cookie: u64) -> *mut EventQueue {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        let prev = self.bound_eq;
        self.bound_eq = eq;
        self.cookie = cookie;
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        prev
    }

    /// Splice an MO onto the attached list head. The MO's `pager` /
    /// `pager_mo_id` / `pager_epoch` fields are written by the caller
    /// under MO.commit_lock before this runs.
    pub fn attach_mo(&mut self, mo: *mut MemoryObject) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        unsafe {
            (*mo).pager_next = self.attached_mo_head;
            self.attached_mo_head = mo;
        }
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
    }

    /// Remove an MO from the attached list. No-op if the MO is not on
    /// this pager's list (e.g. detached by a sibling cascade already).
    pub fn detach_mo(&mut self, mo: *mut MemoryObject) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        let mut cursor: *mut *mut MemoryObject = &mut self.attached_mo_head;
        unsafe {
            while !(*cursor).is_null() {
                if *cursor == mo {
                    *cursor = (*mo).pager_next;
                    (*mo).pager_next = core::ptr::null_mut();
                    break;
                }
                cursor = &mut (**cursor).pager_next;
            }
        }
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
    }

    /// Snapshot of the bound EQ for use OUTSIDE the lock. Caller must
    /// pin the EQ before the snapshot expires.
    pub fn snapshot_bound_eq(&self) -> *mut EventQueue {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        let eq = self.bound_eq;
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        eq
    }

    /// Splice a fresh `PendingPagerRequest` onto the request list head.
    /// Caller has already populated the request fields and the list
    /// pointers were null on entry.
    pub fn link_pending(&mut self, req: *mut PendingPagerRequest) {
        unsafe {
            (*req).pager_next = self.pending_head;
            self.pending_head = req;
        }
    }

    /// Unlink a pending request from this pager's list. Caller already
    /// holds `Pager.lock`.
    pub fn unlink_pending_locked(&mut self, req: *mut PendingPagerRequest) {
        let mut cursor: *mut *mut PendingPagerRequest = &mut self.pending_head;
        unsafe {
            while !(*cursor).is_null() {
                if *cursor == req {
                    *cursor = (*req).pager_next;
                    (*req).pager_next = core::ptr::null_mut();
                    break;
                }
                cursor = &mut (**cursor).pager_next;
            }
        }
    }

    /// Drain pending requests into a standalone list linked through
    /// `pager_next`. Requests currently being supplied are skipped: the
    /// supplier owns their terminal transition and will wake/free them
    /// after committing outside `Pager.lock`.
    ///
    /// Caller holds `Pager.lock`. Returned requests remain active; the
    /// caller must wake their waiters and then `pending_free_ptr`.
    pub unsafe fn drain_pending_locked(
        &mut self,
        mo_id_filter: Option<u64>,
    ) -> *mut PendingPagerRequest {
        let mut drained_head: *mut PendingPagerRequest = core::ptr::null_mut();
        let mut cursor: *mut *mut PendingPagerRequest = &mut self.pending_head;
        unsafe {
            while !(*cursor).is_null() {
                let req = *cursor;
                let matches_filter = mo_id_filter.map_or(true, |mo_id| (*req).mo_id == mo_id);
                if matches_filter && (*req).state != PendingState::Supplied as u8 {
                    *cursor = (*req).pager_next;
                    (*req).pager_next = drained_head;
                    (*req).state = PendingState::Reclaimed as u8;
                    drained_head = req;
                } else {
                    cursor = &mut (*req).pager_next;
                }
            }
        }
        drained_head
    }

    /// Run during the reaper-driven destroy of a `Pager`. Bumps
    /// `cancel_epoch`, clears the bound EQ pointer, and returns the
    /// snapshot for the caller to release plus all non-supply pending
    /// requests for the caller to wake/free outside `Pager.lock`.
    pub fn cleanup(&mut self) -> (*mut EventQueue, *mut PendingPagerRequest) {
        let irq = unsafe { crate::mm::save_irq_disable() };
        self.lock.lock();
        self.cancel_epoch.fetch_add(1, Ordering::AcqRel);
        let prev_eq = self.bound_eq;
        self.bound_eq = core::ptr::null_mut();
        let attached = self.attached_mo_head;
        self.attached_mo_head = core::ptr::null_mut();
        let drained = unsafe { self.drain_pending_locked(None) };
        self.lock.unlock();
        unsafe { crate::mm::restore_irq(irq) };
        let self_ptr: *mut Pager = self as *mut Pager;
        let mut mo = attached;
        unsafe {
            while !mo.is_null() {
                let next = (*mo).pager_next;
                (*mo).pager_next = core::ptr::null_mut();
                (*mo).commit_lock.lock();
                if (*mo).pager == self_ptr {
                    (*mo).pager = core::ptr::null_mut();
                    (*mo).pager_mo_id = 0;
                    (*mo).pager_epoch = 0;
                }
                (*mo).commit_lock.unlock();
                mo = next;
            }
        }
        (prev_eq, drained)
    }
}
