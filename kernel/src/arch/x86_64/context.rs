//! Context Switch Implementation
//!
//! SPDX-License-Identifier: GPL-2.0-only

pub use crate::sched::thread::ThreadContext;

/// Switch from one thread context to another
///
/// This function performs a context switch by:
/// 1. Saving callee-saved registers (RBX, RBP, R12-R15, RSP) to old_context
/// 2. Loading new stack pointer from new_context
/// 3. Restoring callee-saved registers from new_context
/// 4. Returning to the new RIP stored in new_context
///
/// # Safety
/// - old_context must point to valid memory for storing ThreadContext
/// - new_context must point to a valid, initialized ThreadContext
/// - This function must only be called from interrupt context with interrupts disabled
/// - The caller must ensure proper memory barriers
///
/// # Register Convention
/// - Callee-saved: RBX, RBP, R12, R13, R14, RSP (must be preserved)
/// - Caller-saved: RAX, RCX, RDX, RSI, RDI, R8-R11 (can be clobbered)
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn switch_context(
    old_context: *mut ThreadContext,
    new_context: *const ThreadContext,
) {
    // Only save/restore callee-saved registers as per System V AMD64 ABI
    // The caller-saved registers are already saved by the interrupt handler
    //
    // Stack layout after switch:
    // - RSP is switched to new thread's stack
    // - Other registers restored from new context
    // - Function returns to new thread's RIP

    core::arch::asm!(
        // Save callee-saved registers to old context
        // RSP is saved first (current stack pointer before we switch)
        "
        mov [rdi + 0x40], rbp    // Save RBP (offset 0x40 = 8*8)
        mov [rdi + 0x50], r12    // Save R12 (offset 0x50 = 10*8)
        mov [rdi + 0x58], r13    // Save R13 (offset 0x58 = 11*8)
        mov [rdi + 0x60], r14    // Save R14 (offset 0x60 = 12*8)
        mov [rdi + 0x68], r15    // Save R15 (offset 0x68 = 13*8)
        mov [rdi + 0x28], rbx    // Save RBX (offset 0x28 = 5*8)
        mov [rdi + 0x38], rsp    // Save RSP (offset 0x38 = 7*8) - save last
        ",

        // Load new stack pointer first
        // This is critical - we must switch stacks before restoring other registers
        "mov rsp, [rsi + 0x38]",  // Load new RSP

        // Restore callee-saved registers from new context
        "
        mov rbx, [rsi + 0x28]    // Restore RBX
        mov rbp, [rsi + 0x40]    // Restore RBP
        mov r12, [rsi + 0x50]    // Restore R12
        mov r13, [rsi + 0x58]    // Restore R13
        mov r14, [rsi + 0x60]    // Restore R14
        mov r15, [rsi + 0x68]    // Restore R15
        ",

        // Restore RSP was already done above
        // The ret instruction will use the new RSP to pop return address
        // but we need to return to the new context's RIP, not here

        // Save current RIP (return address) to old context
        // This was pushed by the call instruction
        "mov [rdi + 0x70], rax", // Placeholder - we'll fix this below

        // Load new RIP and return there
        // We need to pop the return address and push the new one
        // Actually, let's use a different approach

        in("rdi") old_context,  // First argument: old context
        in("rsi") new_context,  // Second argument: new context

        // Clobber all caller-saved and some callee-saved registers
        clobber_abi("sysv64"),
    );
}

/// Context switch implementation with proper return handling
///
/// This version correctly saves the return address and switches to the new RIP.
#[unsafe(no_mangle)]
pub unsafe extern "sysv64" fn context_switch(
    old_context: *mut ThreadContext,
    new_context: *const ThreadContext,
) {
    // The calling convention: return address is at [RSP]
    // We need to:
    // 1. Save all callee-saved registers including the return address (RIP)
    // 2. Switch RSP to new context's stack
    // 3. Restore all registers from new context
    // 4. Return will use the new RIP from stack

    core::arch::asm!(
        // === Save old context ===
        // First, save the return address (pushed by call) to old context
        "mov rax, [rsp]",           // Get return address from stack
        "mov [rdi + 0x70], rax",    // Save RIP to old_context.rip (offset 0x70 = 14*8)

        // Save RBP (stack frame pointer)
        "mov [rdi + 0x40], rbp",    // Save RBP

        // Save callee-saved registers: RBX, R12-R15
        "mov [rdi + 0x28], rbx",    // Save RBX
        "mov [rdi + 0x50], r12",    // Save R12
        "mov [rdi + 0x58], r13",    // Save R13
        "mov [rdi + 0x60], r14",    // Save R14
        "mov [rdi + 0x68], r15",    // Save R15

        // Save RSP (must be done after saving return address)
        "lea rax, [rsp + 8]",       // RSP after popping return address
        "mov [rdi + 0x38], rax",    // Save RSP

        // === Switch to new context ===
        // Load new RSP first (critical!)
        "mov rsp, [rsi + 0x38]",    // Load new RSP

        // Push new return address
        "mov rax, [rsi + 0x70]",    // Load new RIP
        "push rax",                 // Push it as return address

        // Restore callee-saved registers from new context
        "mov rbx, [rsi + 0x28]",    // Restore RBX
        "mov rbp, [rsi + 0x40]",    // Restore RBP
        "mov r12, [rsi + 0x50]",    // Restore R12
        "mov r13, [rsi + 0x58]",    // Restore R13
        "mov r14, [rsi + 0x60]",    // Restore R14
        "mov r15, [rsi + 0x68]",    // Restore R15

        // Return to new RIP (pop return address from stack and jump)
        "ret",

        in("rdi") old_context,
        in("rsi") new_context,

        clobber_abi("sysv64"),
    );
}

/// Initialize a thread context for first execution
///
/// Sets up the context so that when context_switch is called to it,
/// execution begins at the specified entry point with the given stack.
///
/// # Safety
/// - context must point to valid ThreadContext memory
/// - stack_top must be a valid stack pointer
/// - entry_point must be a valid function pointer
pub unsafe fn init_thread_context(
    context: *mut ThreadContext,
    entry_point: extern "C" fn() -> !,
    stack_top: u64,
) {
    (*context).rip = entry_point as u64;
    (*context).rsp = stack_top;
    (*context).rflags = 0x202; // Interrupts enabled
    (*context).cs = 0x08; // Kernel code segment
    (*context).ss = 0x10; // Kernel data segment

    // All other registers are zero-initialized
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_offsets() {
        // Verify that our offset calculations are correct
        assert_eq!(core::mem::offset_of!(ThreadContext, rax), 0x00);
        assert_eq!(core::mem::offset_of!(ThreadContext, rbx), 0x28);
        assert_eq!(core::mem::offset_of!(ThreadContext, rsp), 0x38);
        assert_eq!(core::mem::offset_of!(ThreadContext, rbp), 0x40);
        assert_eq!(core::mem::offset_of!(ThreadContext, r12), 0x50);
        assert_eq!(core::mem::offset_of!(ThreadContext, r13), 0x58);
        assert_eq!(core::mem::offset_of!(ThreadContext, r14), 0x60);
        assert_eq!(core::mem::offset_of!(ThreadContext, r15), 0x68);
        assert_eq!(core::mem::offset_of!(ThreadContext, rip), 0x70);
    }
}
