//! IRQ Handler
//!
//! Kernel object for routing hardware interrupts to userspace via the
//! event plane. Supports shared IRQs: multiple handlers can be
//! registered for the same IRQ line via a singly-linked list per IRQ.
//! Each handler is independently acknowledged; `dispatch_irq()` asserts
//! `STATE_SIGNALED` on every registered handler — the assertion drives
//! `WatcherList::publish` and (if bound) links the handler onto the bound
//! `EventQueue`'s priority interrupt lane.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{KernelObject, ObjectType};
use crate::event::event_queue::EventQueue;
use crate::event::watcher_list::WatcherList;
use crate::mm::SpinLock;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
const STATE_SIGNALED: u64 = uapi::KERNITE_STATE_SIGNALED as u64;

/// Maximum number of hardware IRQs
pub const MAX_IRQS: usize = 256;

/// Dedicated lock protecting the IRQ_HANDLERS table.
///
/// Required because dispatch_irq() runs in interrupt context on any CPU
/// while register/unregister run from syscall context.
static IRQ_LOCK: SpinLock = SpinLock::new();

/// IRQ Handler kernel object
#[repr(C)]
pub struct IrqHandler {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Hardware IRQ number
    pub irq_num: u32,
    /// Watchable state word (`STATE_SIGNALED` set on fire, cleared on ack).
    pub state_flags: AtomicU64,
    /// Per-handler watcher list — `Watch` registrations against this
    /// IRQ wake on `STATE_SIGNALED`.
    pub watcher_list: WatcherList,
    /// Bound `EventQueue` (cap-mediated delivery path; `EVENT_TYPE_IRQ`
    /// records are pushed when the IRQ fires).
    pub bound_eq: AtomicPtr<EventQueue>,
    /// Caller-supplied cookie surfaced in fired records.
    pub bound_cookie: AtomicU64,
    /// Whether this handler is active (registered in the global table)
    pub active: bool,
    /// Whether this IRQ uses level-triggered delivery (PCI) vs edge-triggered (ISA)
    pub level_triggered: bool,
    /// Next handler in chain for the same IRQ (shared IRQ support)
    pub next: *mut IrqHandler,
    /// Intrusive link in the bound `EventQueue`'s priority interrupt lane;
    /// null when unlinked. Manipulated only under that queue's lock, but atomic
    /// because the handler is also touched from interrupt context.
    pub eq_next: AtomicPtr<IrqHandler>,
    /// Whether this handler is currently on its bound queue's interrupt lane.
    /// Set/cleared only under `EventQueue.lock`; guards re-link (coalescing)
    /// and is independent of `STATE_SIGNALED`.
    pub eq_queued: AtomicBool,
}

impl IrqHandler {
    pub const fn new(irq_num: u32) -> Self {
        Self {
            header: KernelObject::new(ObjectType::IrqHandler, 0),
            irq_num,
            state_flags: AtomicU64::new(0),
            watcher_list: WatcherList::new(),
            bound_eq: AtomicPtr::new(core::ptr::null_mut()),
            bound_cookie: AtomicU64::new(0),
            active: false,
            level_triggered: false,
            next: core::ptr::null_mut(),
            eq_next: AtomicPtr::new(core::ptr::null_mut()),
            eq_queued: AtomicBool::new(false),
        }
    }

    /// Mark the IRQ fired: assert `STATE_SIGNALED`, publish to any
    /// registered watches, and link this handler onto the bound
    /// `EventQueue`'s priority interrupt lane if present.
    pub fn signal_fire(&self) {
        let prev = self.state_flags.fetch_or(STATE_SIGNALED, Ordering::Release);
        // Link the bound queue's priority interrupt lane FIRST, before
        // publishing the watcher edge below. If a `Watch` on `STATE_SIGNALED`
        // and an `IRQ_BIND_EQ` target the same queue, a waiter woken by the
        // watcher publish must find the IRQ lane entry already present so it
        // drains ahead of the ring. The handler is the reserved delivery slot
        // (no-drop); the record is synthesized on dequeue. SAFETY: the bind
        // reference keeps `eq` live, `signal_fire` runs under IRQ_LOCK so unbind
        // cannot tear it down concurrently, and `eq` / `self` are distinct
        // objects (no aliasing).
        let eq = self.bound_eq.load(Ordering::Acquire);
        if !eq.is_null() {
            let this = self as *const IrqHandler as *mut IrqHandler;
            unsafe {
                (*eq).link_irq(this);
            }
        }
        if (prev & STATE_SIGNALED) == 0 {
            // The watcher list publishes under its own lock via interior
            // mutability, so a shared `&self` suffices (no cast). SAFETY:
            // `publish` is `unsafe` for the state-flag visibility ordering,
            // which the `fetch_or` above established.
            unsafe { self.watcher_list.publish(STATE_SIGNALED) };
        }
    }

    /// Userland ack — clear `STATE_SIGNALED` so the next fire publishes
    /// again.
    pub fn signal_ack(&self) {
        self.state_flags
            .fetch_and(!STATE_SIGNALED, Ordering::Release);
    }

    /// Cleanup when IRQ handler is destroyed.
    ///
    /// Unregisters from the global IRQ table; bound `EventQueue` ref is
    /// released by the IRQ_HANDLER bind/unbind path on the syscall side.
    pub fn cleanup(&mut self) {
        if self.active {
            unregister_handler(self as *mut IrqHandler);
            self.active = false;
        }
        // Unbind under IRQ_LOCK, unlinking from the queue's interrupt lane
        // before the bind reference is released.
        unsafe { irq_handler_unbind_eq(self as *mut IrqHandler) };
        unsafe { self.watcher_list.drain_closed() };
    }
}

/// Bind `eq` to `handler` so each IRQ fire links the handler onto the queue's
/// priority interrupt lane. Serialized under `IRQ_LOCK` so it cannot race
/// `dispatch_irq` / `signal_fire`. Returns `false` — without touching
/// `bound_cookie` — if the handler is already bound.
///
/// # Safety
/// `handler` and `eq` must point at live objects. On success this takes a
/// reference on `eq` that `irq_handler_unbind_eq` (or `cleanup`) releases.
pub unsafe fn irq_handler_bind_eq(
    handler: *mut IrqHandler,
    eq: *mut EventQueue,
    cookie: u64,
) -> bool {
    let irq = unsafe { crate::mm::save_irq_disable() };
    IRQ_LOCK.lock();
    let bound = unsafe {
        if !(*handler).bound_eq.load(Ordering::Acquire).is_null() {
            false
        } else {
            // Pin the queue, store the cookie, then publish `bound_eq` last.
            // `IRQ_LOCK` excludes `signal_fire`, so a fire that later observes
            // a non-null `bound_eq` always observes the matching cookie.
            crate::cap::increment_refcount(eq as *mut crate::cap::KernelObject);
            (*handler).bound_cookie.store(cookie, Ordering::Release);
            (*handler).bound_eq.store(eq, Ordering::Release);
            true
        }
    };
    IRQ_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
    bound
}

/// Detach `handler`'s bound queue, unlinking it from the queue's interrupt
/// lane first. Serialized under `IRQ_LOCK` (which `dispatch_irq` holds), so the
/// unlink and `bound_eq` clear cannot race `signal_fire`. The bind reference is
/// released after the locks drop — a release may run a destructor, which must
/// not hold `IRQ_LOCK`. No-op if nothing is bound.
///
/// # Safety
/// `handler` must point at a live `IrqHandler`.
pub unsafe fn irq_handler_unbind_eq(handler: *mut IrqHandler) {
    let irq = unsafe { crate::mm::save_irq_disable() };
    IRQ_LOCK.lock();
    let eq = unsafe {
        (*handler)
            .bound_eq
            .swap(core::ptr::null_mut(), Ordering::AcqRel)
    };
    if !eq.is_null() {
        // IRQ_LOCK → EventQueue.lock: unlink before the reference is released.
        unsafe { (*eq).unlink_irq(handler) };
    }
    unsafe { (*handler).bound_cookie.store(0, Ordering::Release) };
    IRQ_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
    if !eq.is_null() {
        unsafe {
            crate::cap::release_object(
                eq as *mut crate::cap::KernelObject,
                crate::cap::ObjectType::EventQueue,
            );
        }
    }
}

/// Acknowledge a fired IRQ: clear `STATE_SIGNALED`. Serialized under `IRQ_LOCK`
/// so the ack cannot land between a `signal_fire` that has linked the lane /
/// woken a consumer and that same `signal_fire` publishing the watcher edge.
/// Without this, a consumer woken by the lane delivery could clear
/// `STATE_SIGNALED` first, and the later watcher publish would fire an armed
/// watch with a stale edge.
///
/// # Safety
/// `handler` must point at a live `IrqHandler`.
pub unsafe fn irq_handler_ack(handler: *const IrqHandler) {
    let irq = unsafe { crate::mm::save_irq_disable() };
    IRQ_LOCK.lock();
    unsafe { (*handler).signal_ack() };
    // `dispatch_irq` masks level-triggered lines at the controller until the
    // consumer acks; unmask now so the next assertion is delivered. Done under
    // IRQ_LOCK so the mask (in `dispatch_irq`) and this unmask are serialized —
    // the IOAPIC IOREGSEL/IOWIN pair is shared, lock-free MMIO and would corrupt
    // under a concurrent dispatch's mask on another CPU.
    if unsafe { (*handler).level_triggered } {
        crate::arch::ioapic_unmask_level(unsafe { (*handler).irq_num });
    }
    IRQ_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq) };
}

/// Global IRQ handler table — each entry is the head of a linked list of handlers.
static mut IRQ_HANDLERS: [*mut IrqHandler; MAX_IRQS] = [core::ptr::null_mut(); MAX_IRQS];

/// Dispatch an IRQ from the IDT handler.
///
/// Called from the interrupt handler when a hardware IRQ fires. Walks the
/// handler chain and asserts `STATE_SIGNALED` on each entry — `signal_fire`
/// publishes to any registered watches and links into the bound
/// `EventQueue`'s priority interrupt lane. Acquires IRQ_LOCK internally.
/// Level-triggered lines are masked at the controller until userland's
/// `signal_ack` clears the bit.
pub fn dispatch_irq(irq_num: usize) {
    if irq_num >= MAX_IRQS {
        return;
    }

    // SAFETY: IRQs are already disabled by hardware interrupt entry.
    // We still save/restore for consistency with other IRQ_LOCK callers.
    let irq_flag = unsafe { crate::mm::save_irq_disable() };
    let mut any_level_triggered = false;

    IRQ_LOCK.lock();
    unsafe {
        let mut cur = (*(&raw const IRQ_HANDLERS))[irq_num];
        while !cur.is_null() {
            let h = &mut *cur;
            if h.level_triggered {
                any_level_triggered = true;
            }
            h.signal_fire();
            cur = h.next;
        }
    }
    // Mask level lines while still holding IRQ_LOCK so the controller mask is
    // serialized against `irq_handler_ack`'s unmask. The IOAPIC IOREGSEL/IOWIN
    // pair is shared, lock-free MMIO; masking outside the lock would race a
    // concurrent ack's unmask on another CPU and corrupt the register select.
    if any_level_triggered {
        crate::arch::ioapic_mask(irq_num as u32);
    }

    IRQ_LOCK.unlock();

    unsafe { crate::mm::restore_irq(irq_flag) };
}

/// Register an IRQ handler by prepending it to the chain for its IRQ.
///
/// Acquires IRQ_LOCK internally (IRQ-safe).
pub fn register_handler(irq_num: usize, handler: *mut IrqHandler) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }

    let irq_flag = unsafe { crate::mm::save_irq_disable() };
    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held; single-writer access to IRQ_HANDLERS.
    unsafe {
        let head = (*(&raw const IRQ_HANDLERS))[irq_num];
        (*handler).next = head;
        (*handler).active = true;
        (*(&raw mut IRQ_HANDLERS))[irq_num] = handler;
    }
    IRQ_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq_flag) };
    true
}

/// Check whether any handler is registered for this IRQ.
///
/// Acquires IRQ_LOCK internally (IRQ-safe).
pub fn has_handlers(irq_num: usize) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }
    let irq_flag = unsafe { crate::mm::save_irq_disable() };
    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held.
    let result = unsafe { !(*(&raw const IRQ_HANDLERS))[irq_num].is_null() };
    IRQ_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq_flag) };
    result
}

/// Remove a specific handler from its IRQ chain.
///
/// Acquires IRQ_LOCK internally (IRQ-safe).
pub fn unregister_handler(handler: *mut IrqHandler) {
    if handler.is_null() {
        return;
    }
    let irq_flag = unsafe { crate::mm::save_irq_disable() };
    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held; single-writer access to IRQ_HANDLERS.
    unsafe {
        let irq_num = (*handler).irq_num as usize;
        if irq_num >= MAX_IRQS {
            IRQ_LOCK.unlock();
            crate::mm::restore_irq(irq_flag);
            return;
        }
        (*handler).active = false;

        let head = (*(&raw const IRQ_HANDLERS))[irq_num];
        if head == handler {
            (*(&raw mut IRQ_HANDLERS))[irq_num] = (*handler).next;
        } else {
            let mut prev = head;
            while !prev.is_null() && (*prev).next != handler {
                prev = (*prev).next;
            }
            if !prev.is_null() {
                (*prev).next = (*handler).next;
            }
        }
        (*handler).next = core::ptr::null_mut();
    }
    IRQ_LOCK.unlock();
    unsafe { crate::mm::restore_irq(irq_flag) };
}
