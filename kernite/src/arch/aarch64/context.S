.section .text

.p2align 2
.global aarch64_context_switch
.type aarch64_context_switch, %function
aarch64_context_switch:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	// x0 = pointer to old thread's saved SP location (*mut u64)
	// x1 = new thread's saved SP value (u64)
	// x2 = old thread's TCB pointer (*mut Tcb)

	// Save callee-saved registers on current stack (96 bytes)
	stp	x19, x20, [sp, #-96]!
	.cfi_def_cfa_offset 96
	stp	x21, x22, [sp, #16]
	stp	x23, x24, [sp, #32]
	stp	x25, x26, [sp, #48]
	stp	x27, x28, [sp, #64]
	stp	x29, x30, [sp, #80]
	.cfi_offset x29, -16
	.cfi_offset x30, -8

	mov	x19, x1
	mov	x20, x2

	// Save current SP to old thread's save location.
	mov	x2, sp
	str	x2, [x0]

	mov	x0, x20
	bl	sched_context_saved

	.cfi_undefined x30
	.cfi_def_cfa sp, 0

	// Switch to new thread's stack.
	mov	sp, x19

	// Restore callee-saved registers from new stack.
	ldp	x29, x30, [sp, #80]
	ldp	x27, x28, [sp, #64]
	ldp	x25, x26, [sp, #48]
	ldp	x23, x24, [sp, #32]
	ldp	x21, x22, [sp, #16]
	ldp	x19, x20, [sp], #96

	// Return to new thread (x30/LR has the return address).
	ret
	.cfi_endproc
.size aarch64_context_switch, . - aarch64_context_switch

.p2align 2
.global aarch64_write_user_return_state
.type aarch64_write_user_return_state, %function
aarch64_write_user_return_state:
	msr	ELR_EL1, x0
	msr	SPSR_EL1, x1
	msr	SP_EL0, x2
	ret
.size aarch64_write_user_return_state, . - aarch64_write_user_return_state

.p2align 2
.global aarch64_enter_user
.type aarch64_enter_user, %function
aarch64_enter_user:
	// x0 = ABI thread pointer. Publish it before clearing the rest of x0-x30.
	mov	x18, x0
	mov	x0, xzr
	mov	x1, xzr
	mov	x2, xzr
	mov	x3, xzr
	mov	x4, xzr
	mov	x5, xzr
	mov	x6, xzr
	mov	x7, xzr
	mov	x8, xzr
	mov	x9, xzr
	mov	x10, xzr
	mov	x11, xzr
	mov	x12, xzr
	mov	x13, xzr
	mov	x14, xzr
	mov	x15, xzr
	mov	x16, xzr
	mov	x17, xzr
	mov	x19, xzr
	mov	x20, xzr
	mov	x21, xzr
	mov	x22, xzr
	mov	x23, xzr
	mov	x24, xzr
	mov	x25, xzr
	mov	x26, xzr
	mov	x27, xzr
	mov	x28, xzr
	mov	x29, xzr
	mov	x30, xzr
	eret
.size aarch64_enter_user, . - aarch64_enter_user
