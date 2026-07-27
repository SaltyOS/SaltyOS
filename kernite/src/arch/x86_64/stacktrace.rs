// SPDX-License-Identifier: GPL-2.0-only
//! x86_64 panic context capture.

use crate::kernel::stacktrace::{ArchPanicContext, ContextKind};

#[repr(C)]
#[derive(Clone, Copy)]
struct RawPanicContext {
    rip: u64,
    rsp: u64,
    rbp: u64,
    rflags: u64,
    cr2: u64,
    cr3: u64,
}

unsafe extern "C" {
    fn x86_stacktrace_capture_current(out: *mut RawPanicContext);
}

pub(crate) fn capture_current_panic_context() -> ArchPanicContext {
    let mut raw = RawPanicContext {
        rip: 0,
        rsp: 0,
        rbp: 0,
        rflags: 0,
        cr2: 0,
        cr3: 0,
    };
    // SAFETY: `raw` is a valid writable context buffer for the assembly helper.
    unsafe {
        x86_stacktrace_capture_current(&mut raw);
    }
    ArchPanicContext {
        kind: ContextKind::Generic,
        rip: raw.rip,
        rsp: raw.rsp,
        rbp: raw.rbp,
        rflags: raw.rflags,
        cr2: raw.cr2,
        cr3: raw.cr3,
        vector: 0,
        error_code: 0,
        irq_state: raw.rflags & (1 << 9),
    }
}
