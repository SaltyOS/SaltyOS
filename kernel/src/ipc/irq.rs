//! IRQ Handler
//!
//! Kernel object for routing hardware interrupts to userspace via notifications.
//! Supports shared IRQs: multiple handlers can be registered for the same IRQ
//! line via a singly-linked list per IRQ. Each handler is independently
//! acknowledged; `dispatch_irq()` signals every acknowledged handler.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::cap::{KernelObject, ObjectType};
use super::Notification;

/// Maximum number of hardware IRQs
pub const MAX_IRQS: usize = 256;

/// IRQ Handler kernel object
#[repr(C)]
pub struct IrqHandler {
    /// Kernel object header (must be first for refcount access)
    pub header: KernelObject,
    /// Hardware IRQ number
    pub irq_num: u32,
    /// Bound notification (signals userspace when IRQ fires)
    pub notification: *mut Notification,
    /// Whether the IRQ has been acknowledged by userspace
    pub acknowledged: bool,
    /// Whether this handler is active (registered in the global table)
    pub active: bool,
    /// Next handler in chain for the same IRQ (shared IRQ support)
    pub next: *mut IrqHandler,
}

impl IrqHandler {
    pub const fn new(irq_num: u32) -> Self {
        Self {
            header: KernelObject::new(ObjectType::IrqHandler, 0),
            irq_num,
            notification: core::ptr::null_mut(),
            acknowledged: true,
            active: false,
            next: core::ptr::null_mut(),
        }
    }

    /// Cleanup when IRQ handler is destroyed
    pub fn cleanup(&mut self) {
        if self.active {
            // SAFETY: self is a valid IrqHandler pointer; unregister_handler
            // removes it from the per-IRQ chain.
            unregister_handler(self as *mut IrqHandler);
            self.active = false;
        }
        self.notification = core::ptr::null_mut();
    }
}

/// Global IRQ handler table — each entry is the head of a linked list of handlers.
static mut IRQ_HANDLERS: [*mut IrqHandler; MAX_IRQS] = [core::ptr::null_mut(); MAX_IRQS];

/// Dispatch an IRQ from the IDT handler
///
/// Called from the interrupt handler when a hardware IRQ fires.
/// Walks the handler chain for the given IRQ and signals every
/// acknowledged handler's notification.
pub fn dispatch_irq(irq_num: usize) {
    if irq_num >= MAX_IRQS {
        return;
    }

    // SAFETY: Called from interrupt context with interrupts disabled.
    // IRQ_HANDLERS is only mutated under SCHED_IPC_LOCK which cannot
    // be held during interrupt dispatch (EOI is sent before schedulable code).
    unsafe {
        let mut cur = (*(&raw const IRQ_HANDLERS))[irq_num];
        while !cur.is_null() {
            let h = &mut *cur;
            if h.acknowledged && !h.notification.is_null() {
                h.acknowledged = false;
                (*h.notification).signal(1u64 << (irq_num % 64));
            }
            cur = h.next;
        }
    }
}

/// Register an IRQ handler by prepending it to the chain for its IRQ.
///
/// Always succeeds for valid IRQ numbers (shared IRQs are allowed).
/// Caller must hold SCHED_IPC_LOCK.
pub fn register_handler(irq_num: usize, handler: *mut IrqHandler) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }

    // SAFETY: Caller holds SCHED_IPC_LOCK; single-writer access to IRQ_HANDLERS.
    unsafe {
        let head = (*(&raw const IRQ_HANDLERS))[irq_num];
        (*handler).next = head;
        (*handler).active = true;
        (*(&raw mut IRQ_HANDLERS))[irq_num] = handler;
        true
    }
}

/// Check whether any handler is registered for this IRQ.
///
/// Caller must hold SCHED_IPC_LOCK.
pub fn has_handlers(irq_num: usize) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }
    // SAFETY: Single-threaded access guarded by SCHED_IPC_LOCK at call site.
    unsafe { !(*(&raw const IRQ_HANDLERS))[irq_num].is_null() }
}

/// Check whether any handler in the chain has a bound notification.
///
/// Used to decide whether to mask the IOAPIC when a handler's notification
/// is cleared — only mask if no other handler still has an active notification.
///
/// Caller must hold SCHED_IPC_LOCK.
pub fn has_active_notification(irq_num: usize) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }
    // SAFETY: Caller holds SCHED_IPC_LOCK.
    unsafe {
        let mut cur = (*(&raw const IRQ_HANDLERS))[irq_num];
        while !cur.is_null() {
            if !(*cur).notification.is_null() {
                return true;
            }
            cur = (*cur).next;
        }
        false
    }
}

/// Remove a specific handler from its IRQ chain.
///
/// Caller must hold SCHED_IPC_LOCK.
pub fn unregister_handler(handler: *mut IrqHandler) {
    if handler.is_null() {
        return;
    }
    // SAFETY: Caller holds SCHED_IPC_LOCK; single-writer access to IRQ_HANDLERS.
    unsafe {
        let irq_num = (*handler).irq_num as usize;
        if irq_num >= MAX_IRQS {
            return;
        }
        (*handler).active = false;

        let head = (*(&raw const IRQ_HANDLERS))[irq_num];
        if head == handler {
            // Removing head of chain
            (*(&raw mut IRQ_HANDLERS))[irq_num] = (*handler).next;
        } else {
            // Walk chain to find predecessor
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
}
