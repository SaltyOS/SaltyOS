// SPDX-License-Identifier: GPL-2.0-only
//! AArch64 panic context capture.

use crate::kernel::stacktrace::{ArchPanicContext, ContextKind};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPanicContext {
    elr: u64,
    sp: u64,
    x29: u64,
    x30: u64,
    daif: u64,
    esr_el1: u64,
    far_el1: u64,
    ttbr0_el1: u64,
}

unsafe extern "C" {
    fn aarch64_stacktrace_capture_current(out: *mut RawPanicContext);
}

pub(crate) fn capture_current_panic_context() -> ArchPanicContext {
    let mut raw = RawPanicContext {
        elr: 0,
        sp: 0,
        x29: 0,
        x30: 0,
        daif: 0,
        esr_el1: 0,
        far_el1: 0,
        ttbr0_el1: 0,
    };
    // SAFETY: `raw` is a valid writable context buffer for the assembly helper.
    unsafe {
        aarch64_stacktrace_capture_current(&mut raw);
    }
    ArchPanicContext {
        kind: ContextKind::Generic,
        elr: raw.elr,
        sp: raw.sp,
        x29: raw.x29,
        x30: raw.x30,
        daif: raw.daif,
        esr_el1: raw.esr_el1,
        far_el1: raw.far_el1,
        ttbr0_el1: raw.ttbr0_el1,
    }
}
