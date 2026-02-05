//! IRQ Handler
//!
//! Kernel object for routing hardware interrupts to userspace via notifications.
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
}

impl IrqHandler {
    pub const fn new(irq_num: u32) -> Self {
        Self {
            header: KernelObject::new(ObjectType::IrqHandler, 0),
            irq_num,
            notification: core::ptr::null_mut(),
            acknowledged: true,
            active: false,
        }
    }

    /// Cleanup when IRQ handler is destroyed
    pub fn cleanup(&mut self) {
        if self.active {
            unregister_handler(self.irq_num as usize);
            self.active = false;
        }
        self.notification = core::ptr::null_mut();
    }
}

/// Global IRQ handler table
static mut IRQ_HANDLERS: [*mut IrqHandler; MAX_IRQS] = [core::ptr::null_mut(); MAX_IRQS];

/// Dispatch an IRQ from the IDT handler
///
/// Called from the interrupt handler when a hardware IRQ fires.
/// If a handler is registered and has a bound notification, signals it.
pub fn dispatch_irq(irq_num: usize) {
    if irq_num >= MAX_IRQS {
        return;
    }

    unsafe {
        let handler = IRQ_HANDLERS[irq_num];
        if handler.is_null() {
            return;
        }

        let h = &mut *handler;
        if !h.acknowledged {
            // IRQ not yet acknowledged by userspace, skip
            return;
        }

        // Mark as pending (unacknowledged)
        h.acknowledged = false;

        // Signal the bound notification
        if !h.notification.is_null() {
            let ntfn = &mut *h.notification;
            ntfn.signal(1u64 << (irq_num % 64));
        }
    }
}

/// Register an IRQ handler in the global table
///
/// Returns false if the IRQ already has a handler registered.
pub fn register_handler(irq_num: usize, handler: *mut IrqHandler) -> bool {
    if irq_num >= MAX_IRQS {
        return false;
    }

    unsafe {
        if !IRQ_HANDLERS[irq_num].is_null() {
            return false;
        }
        IRQ_HANDLERS[irq_num] = handler;
        (*handler).active = true;
        true
    }
}

/// Unregister an IRQ handler from the global table
pub fn unregister_handler(irq_num: usize) {
    if irq_num >= MAX_IRQS {
        return;
    }

    unsafe {
        let handler = IRQ_HANDLERS[irq_num];
        if !handler.is_null() {
            (*handler).active = false;
        }
        IRQ_HANDLERS[irq_num] = core::ptr::null_mut();
    }
}
