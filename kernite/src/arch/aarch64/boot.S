.section .text.boot, "ax"
.global _start
.type _start, %function
_start:
	// x0 = pointer to BootInfo (passed by bootloader), preserved throughout.

	// Mask all exceptions during early boot.
	msr	DAIFSet, #0xF

	// If firmware or the bootloader leaves us at EL2, switch to EL1h before
	// entering the normal kernel path.
	mrs	x9, CurrentEL
	lsr	x9, x9, #2
	cmp	x9, #2
	b.ne	.Lbsp_el1_entry

	msr	CNTHP_CTL_EL2, xzr
	msr	CNTP_CTL_EL0, xzr
	msr	CNTV_CTL_EL0, xzr
	mov	x9, #3
	msr	CNTHCTL_EL2, x9
	msr	CNTVOFF_EL2, xzr
	movz	x9, #0x8000, lsl #16
	msr	HCR_EL2, x9
	adrp	x1, _boot_stack_top
	add	x1, x1, :lo12:_boot_stack_top
	msr	SP_EL1, x1
	adrp	x1, exception_vectors
	add	x1, x1, :lo12:exception_vectors
	msr	VBAR_EL1, x1
	adrp	x9, .Lbsp_el1_entry
	add	x9, x9, :lo12:.Lbsp_el1_entry
	msr	ELR_EL2, x9
	mov	x9, #0x3C5
	msr	SPSR_EL2, x9
	isb
	eret

.Lbsp_el1_entry:
	// Set up kernel stack.
	adrp	x1, _boot_stack_top
	add	x1, x1, :lo12:_boot_stack_top
	mov	sp, x1

	// Replace Stage 3 temporary vectors immediately.
	adrp	x1, exception_vectors
	add	x1, x1, :lo12:exception_vectors
	msr	VBAR_EL1, x1
	isb

	// Zero BSS section.
	adrp	x1, _bss_start
	add	x1, x1, :lo12:_bss_start
	adrp	x2, _bss_end
	add	x2, x2, :lo12:_bss_end
1:
	cmp	x1, x2
	b.ge	2f
	str	xzr, [x1], #8
	b	1b
2:
	// x0 still holds BootInfo pointer from bootloader.
	bl	kmain

	// kmain should never return.
4:
	wfi
	b	4b

.section .bss
.align 16
_boot_stack_bottom:
	.space 16384
.global _boot_stack_top
_boot_stack_top:

.section .text
.balign 4096
.global _ap_trampoline_start
.type _ap_trampoline_start, %function
_ap_trampoline_start:
	// x0 = cpu_id (context_id from PSCI CPU_ON).

	// Mask all exceptions.
	msr	DAIFSet, #0xF

	// PSCI CPU_ON may start APs at EL2 even though the host kernel runs at EL1.
	mrs	x9, CurrentEL
	lsr	x9, x9, #2
	cmp	x9, #2
	b.ne	.Lap_el1_cont

	msr	CNTHP_CTL_EL2, xzr
	msr	CNTP_CTL_EL0, xzr
	msr	CNTV_CTL_EL0, xzr
	mov	x9, #3
	msr	CNTHCTL_EL2, x9
	msr	CNTVOFF_EL2, xzr
	movz	x9, #0x8000, lsl #16
	msr	HCR_EL2, x9
	adrp	x9, .Lap_el1_cont
	add	x9, x9, :lo12:.Lap_el1_cont
	msr	ELR_EL2, x9
	mov	x9, #0x3C5
	msr	SPSR_EL2, x9
	isb
	eret

.Lap_el1_cont:
	// Locate AP_MAILBOX via PC-relative addressing.
	adrp	x1, AP_MAILBOX
	add	x1, x1, :lo12:AP_MAILBOX

	// Set MAIR_EL1, TCR_EL1, TTBR0_EL1, and TTBR1_EL1 from the mailbox.
	ldr	x2, [x1, #8]
	msr	MAIR_EL1, x2
	ldr	x2, [x1, #16]
	msr	TCR_EL1, x2
	ldr	x2, [x1, #32]
	msr	TTBR0_EL1, x2
	ldr	x2, [x1, #40]
	msr	TTBR1_EL1, x2

	// Ensure system register writes are visible and invalidate stale TLB state.
	isb
	tlbi	vmalle1
	dsb	ish
	isb

	// Enable MMU by writing the BSP active host SCTLR value.
	ldr	x2, [x1, #24]
	msr	SCTLR_EL1, x2
	isb

.Lap_mmu_ready:
	// Enable FP/NEON access before entering Rust code.
	mov	x4, #(3 << 20)
	msr	CPACR_EL1, x4
	isb

	// Load AP kernel stack and virtual entry point from mailbox.
	ldr	x2, [x1, #0]
	ldr	x3, [x1, #48]

	// x0 still holds cpu_id for ap_entry(cpu_id).
	mov	sp, x2
	br	x3

.global _ap_trampoline_end
_ap_trampoline_end:
.size _ap_trampoline_start, . - _ap_trampoline_start
