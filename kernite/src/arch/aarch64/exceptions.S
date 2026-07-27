// SPDX-License-Identifier: GPL-2.0-only

// ---- Register save macro ----
// Pushes x0-x30, SP_EL0, ELR_EL1, SPSR_EL1 onto the kernel stack.
// Frame size: 288 bytes (272 payload + 16 padding for alignment).
.macro SAVE_REGS
	sub	sp, sp, #288
	stp	x0, x1, [sp, #0]
	stp	x2, x3, [sp, #16]
	stp	x4, x5, [sp, #32]
	stp	x6, x7, [sp, #48]
	stp	x8, x9, [sp, #64]
	stp	x10, x11, [sp, #80]
	stp	x12, x13, [sp, #96]
	stp	x14, x15, [sp, #112]
	stp	x16, x17, [sp, #128]
	stp	x18, x19, [sp, #144]
	stp	x20, x21, [sp, #160]
	stp	x22, x23, [sp, #176]
	stp	x24, x25, [sp, #192]
	stp	x26, x27, [sp, #208]
	stp	x28, x29, [sp, #224]
	str	x30, [sp, #240]
	mrs	x0, SP_EL0
	str	x0, [sp, #248]
	mrs	x0, ELR_EL1
	str	x0, [sp, #256]
	mrs	x0, SPSR_EL1
	str	x0, [sp, #264]
.endm

// ---- Register restore macro ----
// Pops the saved state and returns via ERET.
.macro RESTORE_REGS
	ldr	x0, [sp, #264]
	msr	SPSR_EL1, x0
	ldr	x0, [sp, #256]
	msr	ELR_EL1, x0
	ldr	x0, [sp, #248]
	msr	SP_EL0, x0
	ldp	x28, x29, [sp, #224]
	ldr	x30, [sp, #240]
	ldp	x26, x27, [sp, #208]
	ldp	x24, x25, [sp, #192]
	ldp	x22, x23, [sp, #176]
	ldp	x20, x21, [sp, #160]
	ldp	x18, x19, [sp, #144]
	ldp	x16, x17, [sp, #128]
	ldp	x14, x15, [sp, #112]
	ldp	x12, x13, [sp, #96]
	ldp	x10, x11, [sp, #80]
	ldp	x8, x9, [sp, #64]
	ldp	x6, x7, [sp, #48]
	ldp	x4, x5, [sp, #32]
	ldp	x2, x3, [sp, #16]
	ldp	x0, x1, [sp, #0]
	add	sp, sp, #288
	eret
.endm

.section .text

// Must be 2048-byte aligned (VBAR_EL1 requirement).
.balign 2048
.global exception_vectors
exception_vectors:
	// Group 0: Current EL with SP0 (not used).
	.balign 128
	b	.
	.balign 128
	b	.
	.balign 128
	b	.
	.balign 128
	b	.

	// Group 1: Current EL with SPx.
	.balign 128
	b	el1_sync
	.balign 128
	b	el1_irq
	.balign 128
	b	.
	.balign 128
	b	el1_serror

	// Group 2: Lower EL using AArch64.
	.balign 128
	b	el0_sync
	.balign 128
	b	el0_irq
	.balign 128
	b	.
	.balign 128
	b	el0_serror

	// Group 3: Lower EL using AArch32 (not supported).
	.balign 128
	b	.
	.balign 128
	b	.
	.balign 128
	b	.
	.balign 128
	b	.

.type el1_sync, %function
el1_sync:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	.cfi_undefined x30
	SAVE_REGS
	.cfi_def_cfa_offset 288
	bl	sched_runtime_enter_kernel
	mov	x0, sp
	bl	el1_sync_handler
	RESTORE_REGS
	.cfi_endproc
.size el1_sync, . - el1_sync

.type el1_irq, %function
el1_irq:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	.cfi_undefined x30
	SAVE_REGS
	.cfi_def_cfa_offset 288
	bl	sched_runtime_enter_kernel
	mov	x0, sp
	bl	el1_irq_handler
	RESTORE_REGS
	.cfi_endproc
.size el1_irq, . - el1_irq

.type el0_sync, %function
el0_sync:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	.cfi_undefined x30
	SAVE_REGS
	.cfi_def_cfa_offset 288
	bl	sched_runtime_enter_kernel
	mov	x0, sp
	bl	el0_sync_handler
	bl	sched_runtime_exit_to_user
	RESTORE_REGS
	.cfi_endproc
.size el0_sync, . - el0_sync

.type el0_irq, %function
el0_irq:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	.cfi_undefined x30
	SAVE_REGS
	.cfi_def_cfa_offset 288
	bl	sched_runtime_enter_kernel
	mov	x0, sp
	bl	el0_irq_handler
	bl	sched_runtime_exit_to_user
	RESTORE_REGS
	.cfi_endproc
.size el0_irq, . - el0_irq

.type el1_serror, %function
el1_serror:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	.cfi_undefined x30
	SAVE_REGS
	.cfi_def_cfa_offset 288
	bl	sched_runtime_enter_kernel
	mov	x0, sp
	bl	el1_serror_handler
	RESTORE_REGS
	.cfi_endproc
.size el1_serror, . - el1_serror

.type el0_serror, %function
el0_serror:
	.cfi_startproc
	.cfi_def_cfa sp, 0
	.cfi_undefined x30
	SAVE_REGS
	.cfi_def_cfa_offset 288
	bl	sched_runtime_enter_kernel
	mov	x0, sp
	bl	el0_serror_handler
	bl	sched_runtime_exit_to_user
	RESTORE_REGS
	.cfi_endproc
.size el0_serror, . - el0_serror

.p2align 2
.global aarch64_exceptions_read_esr_el1
.type aarch64_exceptions_read_esr_el1, %function
aarch64_exceptions_read_esr_el1:
	mrs	x0, ESR_EL1
	ret
.size aarch64_exceptions_read_esr_el1, . - aarch64_exceptions_read_esr_el1

.p2align 2
.global aarch64_exceptions_read_far_el1
.type aarch64_exceptions_read_far_el1, %function
aarch64_exceptions_read_far_el1:
	mrs	x0, FAR_EL1
	ret
.size aarch64_exceptions_read_far_el1, . - aarch64_exceptions_read_far_el1

.p2align 2
.global aarch64_exceptions_read_daif
.type aarch64_exceptions_read_daif, %function
aarch64_exceptions_read_daif:
	mrs	x0, DAIF
	ret
.size aarch64_exceptions_read_daif, . - aarch64_exceptions_read_daif

.p2align 2
.global aarch64_exceptions_write_vbar_el1
.type aarch64_exceptions_write_vbar_el1, %function
aarch64_exceptions_write_vbar_el1:
	msr	VBAR_EL1, x0
	isb
	ret
.size aarch64_exceptions_write_vbar_el1, . - aarch64_exceptions_write_vbar_el1
