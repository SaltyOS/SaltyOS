//! GICv3 Generic Interrupt Controller (stub for Phase 1)
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Initialize the GIC distributor and CPU interface
pub fn init() {
    // TODO: Phase 3 — full GICv3 init
}

/// Send End-of-Interrupt for the given interrupt ID
pub fn eoi(_intid: u32) {
    // TODO: Phase 3
}

/// Enable a specific interrupt
pub fn enable_irq(_intid: u32) {
    // TODO: Phase 3
}
