.intel_syntax noprefix
.section .text

.global context_switch
.type context_switch, @function
context_switch:
	.cfi_startproc
	.cfi_def_cfa %rsp, 8

	// Save old context.
	mov	rax, [rsp]
	mov	[rdi + 0x80], rax
	mov	[rdi + 0x30], rbp
	mov	[rdi + 0x08], rbx
	mov	[rdi + 0x60], r12
	mov	[rdi + 0x68], r13
	mov	[rdi + 0x70], r14
	mov	[rdi + 0x78], r15
	lea	rax, [rsp + 8]
	mov	[rdi + 0x38], rax

	push	rsi
	.cfi_adjust_cfa_offset 8
	mov	rdi, rdx
	call	sched_context_saved
	pop	rsi
	.cfi_adjust_cfa_offset -8
	.cfi_undefined %rip
	.cfi_def_cfa %rsp, 0

	// Restore new context.
	mov	rsp, [rsi + 0x38]
	mov	rax, [rsi + 0x80]
	push	rax
	mov	rbx, [rsi + 0x08]
	mov	rbp, [rsi + 0x30]
	mov	r12, [rsi + 0x60]
	mov	r13, [rsi + 0x68]
	mov	r14, [rsi + 0x70]
	mov	r15, [rsi + 0x78]
	ret
	.cfi_endproc
.size context_switch, . - context_switch

.global usermode_trampoline
.type usermode_trampoline, @function
usermode_trampoline:
	.cfi_startproc
	.cfi_def_cfa %rsp, 0
	.cfi_undefined %rip

	// Enter usermode with IRQs suppressed until iretq installs user RFLAGS.
	cli
	mov	cr3, r14
	push	0x1B
	push	r13
	push	r15
	push	0x23
	push	r12
	sub	rsp, 8
	call	sched_runtime_exit_to_user
	add	rsp, 8

	// Zero all GPRs to prevent kernel address leaks to user mode.
	xor	eax, eax
	xor	ebx, ebx
	xor	ecx, ecx
	xor	edx, edx
	xor	esi, esi
	xor	edi, edi
	xor	ebp, ebp
	xor	r8d, r8d
	xor	r9d, r9d
	xor	r10d, r10d
	xor	r11d, r11d
	xor	r12d, r12d
	xor	r13d, r13d
	xor	r14d, r14d
	xor	r15d, r15d
	swapgs
	iretq
	.cfi_endproc
.size usermode_trampoline, . - usermode_trampoline
