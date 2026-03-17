//! IRQ Handler
//!
//! Kernel object for routing hardware interrupts to userspace via notifications.
//! Supports shared IRQs: multiple handlers can be registered for the same IRQ
//! line via a singly-linked list per IRQ. Each handler is independently
//! acknowledged; `dispatch_irq()` signals every acknowledged handler.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use crate::cap::{KernelObject, ObjectType};
use crate::mm::SpinLock;
use super::Notification;

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
    /// Bound notification (signals userspace when IRQ fires).
    /// Atomic for SMP safety: dispatch_irq reads on IRQ CPU, syscalls write on other CPUs.
    pub notification: AtomicPtr<Notification>,
    /// Whether the IRQ has been acknowledged by userspace.
    /// Atomic for SMP safety: dispatch_irq clears, syscall ack sets.
    pub acknowledged: AtomicBool,
    /// Whether this handler is active (registered in the global table)
    pub active: bool,
    /// Whether this IRQ uses level-triggered delivery (PCI) vs edge-triggered (ISA)
    pub level_triggered: bool,
    /// Next handler in chain for the same IRQ (shared IRQ support)
    pub next: *mut IrqHandler,
}

impl IrqHandler {
    pub const fn new(irq_num: u32) -> Self {
        Self {
            header: KernelObject::new(ObjectType::IrqHandler, 0),
            irq_num,
            notification: AtomicPtr::new(core::ptr::null_mut()),
            acknowledged: AtomicBool::new(true),
            active: false,
            level_triggered: false,
            next: core::ptr::null_mut(),
        }
    }

    /// Cleanup when IRQ handler is destroyed
    pub fn cleanup(&mut self) {
        if self.active {
            unregister_handler(self as *mut IrqHandler);
            self.active = false;
        }
        self.notification.store(core::ptr::null_mut(), Ordering::Release);
    }
}

/// Global IRQ handler table — each entry is the head of a linked list of handlers.
static mut IRQ_HANDLERS: [*mut IrqHandler; MAX_IRQS] = [core::ptr::null_mut(); MAX_IRQS];

/// Dispatch an IRQ from the IDT handler
///
/// Called from the interrupt handler when a hardware IRQ fires.
/// Walks the handler chain for the given IRQ and signals every
/// acknowledged handler's notification. Acquires IRQ_LOCK internally.
pub fn dispatch_irq(irq_num: usize) {
    if irq_num >= MAX_IRQS {
        return;
    }

    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held; single-writer access to IRQ_HANDLERS.
    unsafe {
        let mut cur = (*(&raw const IRQ_HANDLERS))[irq_num];
        let mut any_dispatched = false;
        while !cur.is_null() {
            let h = &mut *cur;
            let ntfn = h.notification.load(Ordering::Acquire);
            if h.acknowledged.load(Ordering::Acquire) && !ntfn.is_null() {
                h.acknowledged.store(false, Ordering::Release);
                (*ntfn).signal(1u64 << (irq_num % 64));
                any_dispatched = true;
            }
            cur = h.next;
        }
        if !any_dispatched && has_handlers_locked(irq_num) {
            crate::arch::ioapic_mask(irq_num as u32);
        }
    }
    IRQ_LOCK.unlock();
}

/// Register an IRQ handler by prepending it to the chain for its IRQ.
///
/// Acquires IRQ_LOCK internally.
pub fn register_handler(irq_num: usize, handler: *mut IrqHandler) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }

    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held; single-writer access to IRQ_HANDLERS.
    unsafe {
        let head = (*(&raw const IRQ_HANDLERS))[irq_num];
        (*handler).next = head;
        (*handler).active = true;
        (*(&raw mut IRQ_HANDLERS))[irq_num] = handler;
    }
    IRQ_LOCK.unlock();
    true
}

/// Check whether any handler is registered for this IRQ.
///
/// Acquires IRQ_LOCK internally.
pub fn has_handlers(irq_num: usize) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }
    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held.
    let result = unsafe { !(*(&raw const IRQ_HANDLERS))[irq_num].is_null() };
    IRQ_LOCK.unlock();
    result
}

/// Check whether any handler is registered (lock already held).
fn has_handlers_locked(irq_num: usize) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }
    unsafe { !(*(&raw const IRQ_HANDLERS))[irq_num].is_null() }
}

/// Check whether any handler in the chain has a bound notification.
///
/// Acquires IRQ_LOCK internally.
pub fn has_active_notification(irq_num: usize) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }
    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held.
    let result = unsafe {
        let mut cur = (*(&raw const IRQ_HANDLERS))[irq_num];
        let mut found = false;
        while !cur.is_null() {
            if !(*cur).notification.load(Ordering::Acquire).is_null() {
                found = true;
                break;
            }
            cur = (*cur).next;
        }
        found
    };
    IRQ_LOCK.unlock();
    result
}

/// Remove a specific handler from its IRQ chain.
///
/// Acquires IRQ_LOCK internally.
pub fn unregister_handler(handler: *mut IrqHandler) {
    if handler.is_null() {
        return;
    }
    IRQ_LOCK.lock();
    // SAFETY: IRQ_LOCK held; single-writer access to IRQ_HANDLERS.
    unsafe {
        let irq_num = (*handler).irq_num as usize;
        if irq_num >= MAX_IRQS {
            IRQ_LOCK.unlock();
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
}
