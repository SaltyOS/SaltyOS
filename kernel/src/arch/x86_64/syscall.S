.section .text
.intel_syntax noprefix

# Syscall entry using the syscall instruction
# System V AMD64 ABI for syscall:
#   rax = syscall number
#   rdi, rsi, rdx, r10, r8, r9 = arguments (6 total)
#   rcx is used by syscall instruction for return address
#   r11 is used for rflags
#
# Returns:
#   rax = return value
.global syscall_entry
syscall_entry:
    swapgs

    mov r14, rsp
    lea rsp, [rip + syscall_stack_top]

    # Save registers clobbered by syscall
    push rcx
    push r11

    # Save callee-saved + syscall argument registers
    push rbx
    push rbp
    push r12
    push r13
    push r15
    push rdi
    push rsi
    push rdx
    push r10
    push r8
    push r9
    push r14

    # Align stack to 16 bytes (required by ABI)
    mov r15, rsp
    and rsp, -16

    # Set up arguments for Rust handler
    # Stack layout at r15:
    #  +0  r14 (user rsp)
    #  +8  r9
    # +16  r8
    # +24  r10
    # +32  rdx
    # +40  rsi
    # +48  rdi
    # +56  r15
    # +64  r13
    # +72  r12
    # +80  rbp
    # +88  rbx
    # +96  r11
    # +104 rcx
    mov rdi, rax          # syscall number
    mov rsi, [r15 + 48]   # arg1
    mov rdx, [r15 + 40]   # arg2
    mov rcx, [r15 + 32]   # arg3
    mov r8,  [r15 + 24]   # arg4
    mov r9,  [r15 + 16]   # arg5

    call syscall_handler

    # Restore stack pointer
    mov rsp, r15

    # Restore saved registers (rax holds return value)
    pop r14
    pop r9
    pop r8
    pop r10
    pop rdx
    pop rsi
    pop rdi
    pop r15
    pop r13
    pop r12
    pop rbp
    pop rbx
    pop r11
    pop rcx

    # Validate RCX is canonical before sysretq
    mov rax, rcx
    shl rax, 16
    sar rax, 16
    cmp rax, rcx
    jne .bad_sysret

    mov rsp, r14
    swapgs
    sysretq

.bad_sysret:
    # Build iret frame on kernel stack
    push 0x1b
    push r14
    push r11
    push 0x23
    push rcx
    swapgs
    iretq

.global syscall_entry_addr_asm
syscall_entry_addr_asm:
    lea rax, [rip + syscall_entry]
    ret

.section .bss
.align 16
syscall_stack:
    .skip 16384
syscall_stack_top:

.section .text
.global user_test_entry
user_test_entry:
    mov rax, 0xff
    mov rdi, 0x55
    syscall
.user_loop:
    jmp .user_loop

.global user_test_entry_addr_asm
user_test_entry_addr_asm:
    lea rax, [rip + user_test_entry]
    ret
