//! Context Switch Implementation
//!
//! Uses explicit assembly to guarantee zero compiler-generated prologue/epilogue.
//! This is critical because context_switch manually reads [rsp] as the return
//! address — any compiler push (e.g. `push rax`) would break this assumption.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::sched::thread::Tcb;
pub use crate::sched::thread::ThreadContext;
use core::ffi::c_void;

// ThreadContext field offsets (repr(C), all u64):
//   rax=0x00 rbx=0x08 rcx=0x10 rdx=0x18 rsi=0x20 rdi=0x28
//   rbp=0x30 rsp=0x38 r8=0x40  r9=0x48  r10=0x50 r11=0x58
//   r12=0x60 r13=0x68 r14=0x70 r15=0x78 rip=0x80

// Rust-visible declarations so the rest of the kernel can call / reference them.
unsafe extern "sysv64" {
    /// Perform a context switch between two threads.
    ///
    /// Saves callee-saved registers + RIP into `old_context`,
    /// restores from `new_context`, and `ret`s to the new RIP.
    #[link_name = "context_switch"]
    fn raw_context_switch(
        old_context: *mut ThreadContext,
        new_context: *const ThreadContext,
        old_tcb: *mut c_void,
    );
}

unsafe extern "C" {
    /// Address of the usermode trampoline (used as a function pointer in TCB setup).
    pub fn usermode_trampoline() -> !;
}

/// Initialize a thread context for first execution
///
/// Sets up the context so that when context_switch is called to it,
/// execution begins at the specified entry point with the given stack.
pub unsafe fn init_thread_context(
    context: *mut ThreadContext,
    entry_point: extern "C" fn() -> !,
    stack_top: u64,
) {
    unsafe {
        (*context).rip = entry_point as u64;
        (*context).rsp = stack_top;
        (*context).rflags = 0x202; // Interrupts enabled
        (*context).cs = 0x08; // Kernel code segment
        (*context).ss = 0x10; // Kernel data segment

        (*context).rax = 0;
        (*context).rbx = 0;
        (*context).rcx = 0;
        (*context).rdx = 0;
        (*context).rsi = 0;
        (*context).rdi = 0;
        (*context).rbp = 0;
        (*context).r8 = 0;
        (*context).r9 = 0;
        (*context).r10 = 0;
        (*context).r11 = 0;
        (*context).r12 = 0;
        (*context).r13 = 0;
        (*context).r14 = 0;
        (*context).r15 = 0;
    }
}

#[inline(always)]
pub unsafe fn context_switch(
    old_context: *mut ThreadContext,
    new_context: *const ThreadContext,
    old_tcb: *mut Tcb,
) {
    unsafe {
        raw_context_switch(old_context, new_context, old_tcb.cast());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_offsets() {
        assert_eq!(core::mem::offset_of!(ThreadContext, rax), 0x00);
        assert_eq!(core::mem::offset_of!(ThreadContext, rbx), 0x08);
        assert_eq!(core::mem::offset_of!(ThreadContext, rbp), 0x30);
        assert_eq!(core::mem::offset_of!(ThreadContext, rsp), 0x38);
        assert_eq!(core::mem::offset_of!(ThreadContext, r12), 0x60);
        assert_eq!(core::mem::offset_of!(ThreadContext, r13), 0x68);
        assert_eq!(core::mem::offset_of!(ThreadContext, r14), 0x70);
        assert_eq!(core::mem::offset_of!(ThreadContext, r15), 0x78);
        assert_eq!(core::mem::offset_of!(ThreadContext, rip), 0x80);
    }
}
