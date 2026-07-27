//! AArch64 boot entry point and AP trampoline
//!
//! SPDX-License-Identifier: GPL-2.0-only

// ---------------------------------------------------------------------------
// AP trampoline mailbox
// ---------------------------------------------------------------------------

/// Mailbox structure written by the BSP before calling PSCI CPU_ON.
/// The AP trampoline assembly reads this via ADRP (PC-relative) to
/// configure system registers and enable the MMU.
#[repr(C)]
pub struct ApMailbox {
    /// Kernel stack top for this AP.
    pub stack_top: u64,
    /// Active host MAIR value copied from the BSP.
    pub mair: u64,
    /// Active host TCR value copied from the BSP.
    pub tcr: u64,
    /// Active host SCTLR value copied from the BSP (includes M=1 to enable MMU).
    pub sctlr: u64,
    /// Shared bootstrap/full root loaded into the active host TTBR0.
    pub host_ttbr0: u64,
    /// Kernel root template loaded into TTBR1_EL1.
    pub compat_ttbr1: u64,
    /// Virtual address of the Rust AP entry function (`ap_entry`).
    pub entry_virt: u64,
}

/// Global AP mailbox — written by BSP, read by AP trampoline assembly.
/// Only one AP is started at a time, so a single mailbox suffices.
#[unsafe(no_mangle)]
pub static mut AP_MAILBOX: ApMailbox = ApMailbox {
    stack_top: 0,
    mair: 0,
    tcr: 0,
    sctlr: 0,
    host_ttbr0: 0,
    compat_ttbr1: 0,
    entry_virt: 0,
};
