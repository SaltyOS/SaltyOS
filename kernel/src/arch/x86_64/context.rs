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

    // ThreadContext field offsets (repr(C), all u64):
    //   rax=0x00 rbx=0x08 rcx=0x10 rdx=0x18 rsi=0x20 rdi=0x28
    //   rbp=0x30 rsp=0x38 r8=0x40  r9=0x48  r10=0x50 r11=0x58
    //   r12=0x60 r13=0x68 r14=0x70 r15=0x78 rip=0x80
    unsafe {
        core::arch::asm!(
            "mov [rdi + 0x30], rbp",
            "mov [rdi + 0x60], r12",
            "mov [rdi + 0x68], r13",
            "mov [rdi + 0x70], r14",
            "mov [rdi + 0x78], r15",
            "mov [rdi + 0x08], rbx",
            "mov [rdi + 0x38], rsp",

            "mov rsp, [rsi + 0x38]",

            "mov rbx, [rsi + 0x08]",
            "mov rbp, [rsi + 0x30]",
            "mov r12, [rsi + 0x60]",
            "mov r13, [rsi + 0x68]",
            "mov r14, [rsi + 0x70]",
            "mov r15, [rsi + 0x78]",

            "mov [rdi + 0x80], rax",

            in("rdi") old_context,
            in("rsi") new_context,

            clobber_abi("sysv64"),
        );
    }
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

    // ThreadContext field offsets (repr(C), all u64):
    //   rax=0x00 rbx=0x08 rcx=0x10 rdx=0x18 rsi=0x20 rdi=0x28
    //   rbp=0x30 rsp=0x38 r8=0x40  r9=0x48  r10=0x50 r11=0x58
    //   r12=0x60 r13=0x68 r14=0x70 r15=0x78 rip=0x80
    unsafe {
        core::arch::asm!(
            // === Save old context ===
            "mov rax, [rsp]",           // Get return address from stack
            "mov [rdi + 0x80], rax",    // Save RIP (offset 16*8)

            "mov [rdi + 0x30], rbp",    // Save RBP (offset 6*8)
            "mov [rdi + 0x08], rbx",    // Save RBX (offset 1*8)
            "mov [rdi + 0x60], r12",    // Save R12 (offset 12*8)
            "mov [rdi + 0x68], r13",    // Save R13 (offset 13*8)
            "mov [rdi + 0x70], r14",    // Save R14 (offset 14*8)
            "mov [rdi + 0x78], r15",    // Save R15 (offset 15*8)

            "lea rax, [rsp + 8]",       // RSP after popping return address
            "mov [rdi + 0x38], rax",    // Save RSP (offset 7*8)

            // === Switch to new context ===
            "mov rsp, [rsi + 0x38]",    // Load new RSP

            "mov rax, [rsi + 0x80]",    // Load new RIP
            "push rax",                 // Push as return address

            "mov rbx, [rsi + 0x08]",    // Restore RBX
            "mov rbp, [rsi + 0x30]",    // Restore RBP
            "mov r12, [rsi + 0x60]",    // Restore R12
            "mov r13, [rsi + 0x68]",    // Restore R13
            "mov r14, [rsi + 0x70]",    // Restore R14
            "mov r15, [rsi + 0x78]",    // Restore R15

            "ret",

            in("rdi") old_context,
            in("rsi") new_context,

            clobber_abi("sysv64"),
        );
    }
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
    unsafe {
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
}

/// Trampoline for first dispatch to user mode
///
/// context_switch restores callee-saved registers and `ret`s here.
/// Expected register state on entry:
///   r12 = user RIP
///   r13 = user RSP
///   r14 = user PML4 physical address (CR3)
///
/// User segment selectors (post GDT reorder):
///   SS = 0x1B (user_data at GDT slot 3 | RPL 3)
///   CS = 0x23 (user_code at GDT slot 4 | RPL 3)
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usermode_trampoline() -> ! {
    unsafe {
        core::arch::asm!(
            // Switch to user page tables
            "mov cr3, r14",
            // Build iretq frame on kernel stack
            "push 0x1B",       // SS (user data)
            "push r13",        // User RSP
            "push 0x202",      // RFLAGS (IF=1)
            "push 0x23",       // CS (user code)
            "push r12",        // User RIP
            // Switch GS to user GS base before entering user mode
            "swapgs",
            "iretq",
            options(noreturn)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_context_offsets() {
        // Verify that our offset calculations are correct
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
