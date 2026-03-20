//! Privileged Access Never (PAN) support — aarch64 equivalent of x86 SMAP
//!
//! SPDX-License-Identifier: GPL-2.0-only

/// Initialize PAN if available
pub fn init() {
    // TODO: Phase 2 — check ID_AA64MMFR1_EL1.PAN, enable via SCTLR_EL1.SPAN=0
}
