//! Context Switch Implementation
//!
//! Uses global_asm! to guarantee zero compiler-generated prologue/epilogue.
//! This is critical because context_switch manually reads [rsp] as the return
//! address — any compiler push (e.g. `push rax`) would break this assumption.
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub use crate::sched::thread::ThreadContext;

// ---------------------------------------------------------------------------
// Pure-assembly context_switch and usermode_trampoline
// ---------------------------------------------------------------------------
//
// ThreadContext field offsets (repr(C), all u64):
//   rax=0x00 rbx=0x08 rcx=0x10 rdx=0x18 rsi=0x20 rdi=0x28
//   rbp=0x30 rsp=0x38 r8=0x40  r9=0x48  r10=0x50 r11=0x58
//   r12=0x60 r13=0x68 r14=0x70 r15=0x78 rip=0x80

core::arch::global_asm!(
    // -----------------------------------------------------------------
    // context_switch(old_context: *mut ThreadContext  [rdi],
    //                new_context: *const ThreadContext [rsi])
    //
    // Saves callee-saved registers + return address into old_context,
    // then restores from new_context and `ret`s to its saved RIP.
    // -----------------------------------------------------------------
    ".global context_switch",
    ".type context_switch, @function",
    "context_switch:",

    // === Save old context ===
    "mov rax, [rsp]",           // return address (pushed by `call`)
    "mov [rdi + 0x80], rax",   // save RIP

    "mov [rdi + 0x30], rbp",
    "mov [rdi + 0x08], rbx",
    "mov [rdi + 0x60], r12",
    "mov [rdi + 0x68], r13",
    "mov [rdi + 0x70], r14",
    "mov [rdi + 0x78], r15",

    "lea rax, [rsp + 8]",       // RSP as caller sees it (past return addr)
    "mov [rdi + 0x38], rax",

    // === Restore new context ===
    "mov rsp, [rsi + 0x38]",   // load new RSP

    "mov rax, [rsi + 0x80]",   // load new RIP
    "push rax",                 // push as return address

    "mov rbx, [rsi + 0x08]",
    "mov rbp, [rsi + 0x30]",
    "mov r12, [rsi + 0x60]",
    "mov r13, [rsi + 0x68]",
    "mov r14, [rsi + 0x70]",
    "mov r15, [rsi + 0x78]",

    "ret",
    ".size context_switch, . - context_switch",

    // -----------------------------------------------------------------
    // usermode_trampoline
    //
    // First-dispatch entry to user mode.  context_switch `ret`s here with:
    //   r12 = user RIP
    //   r13 = user RSP
    //   r14 = user PML4 physical address (CR3)
    //   r15 = user RFLAGS
    //
    // User segment selectors:
    //   SS = 0x1B  (user_data GDT slot 3 | RPL 3)
    //   CS = 0x23  (user_code GDT slot 4 | RPL 3)
    // -----------------------------------------------------------------
    ".global usermode_trampoline",
    ".type usermode_trampoline, @function",
    "usermode_trampoline:",
    // Enter usermode with IRQs suppressed until iretq installs user RFLAGS.
    // This avoids taking an interrupt on a half-built ring-3 frame.
    "cli",
    "mov cr3, r14",            // switch to user page tables
    "push 0x1B",               // SS
    "push r13",                // user RSP
    "push r15",                // RFLAGS
    "push 0x23",               // CS
    "push r12",                // user RIP
    // Zero all GPRs to prevent kernel address leaks to user mode.
    // context_switch only restores callee-saved regs; caller-saved regs
    // retain kernel values that would otherwise leak into ring 3.
    "xor eax, eax",
    "xor ebx, ebx",
    "xor ecx, ecx",
    "xor edx, edx",
    "xor esi, esi",
    "xor edi, edi",
    "xor ebp, ebp",
    "xor r8d, r8d",
    "xor r9d, r9d",
    "xor r10d, r10d",
    "xor r11d, r11d",
    "xor r12d, r12d",
    "xor r13d, r13d",
    "xor r14d, r14d",
    "xor r15d, r15d",
    "swapgs",
    "iretq",
    ".size usermode_trampoline, . - usermode_trampoline",
);

// Rust-visible declarations so the rest of the kernel can call / reference them.
unsafe extern "sysv64" {
    /// Perform a context switch between two threads.
    ///
    /// Saves callee-saved registers + RIP into `old_context`,
    /// restores from `new_context`, and `ret`s to the new RIP.
    pub fn context_switch(
        old_context: *mut ThreadContext,
        new_context: *const ThreadContext,
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
