.section .text

.p2align 2
.global aarch64_mod_save_irq_disable
.type aarch64_mod_save_irq_disable, %function
aarch64_mod_save_irq_disable:
	mrs	x0, DAIF
	msr	DAIFSet, #0x2
	ret
.size aarch64_mod_save_irq_disable, . - aarch64_mod_save_irq_disable

.p2align 2
.global aarch64_mod_restore_irq
.type aarch64_mod_restore_irq, %function
aarch64_mod_restore_irq:
	msr	DAIF, x0
	ret
.size aarch64_mod_restore_irq, . - aarch64_mod_restore_irq

.p2align 2
.global aarch64_mod_sti
.type aarch64_mod_sti, %function
aarch64_mod_sti:
	msr	DAIFClr, #0x2
	ret
.size aarch64_mod_sti, . - aarch64_mod_sti

.p2align 2
.global aarch64_mod_cli
.type aarch64_mod_cli, %function
aarch64_mod_cli:
	msr	DAIFSet, #0x2
	ret
.size aarch64_mod_cli, . - aarch64_mod_cli

.p2align 2
.global aarch64_mod_halt
.type aarch64_mod_halt, %function
aarch64_mod_halt:
	wfi
	ret
.size aarch64_mod_halt, . - aarch64_mod_halt

.p2align 2
.global aarch64_mod_current_el
.type aarch64_mod_current_el, %function
aarch64_mod_current_el:
	mrs	x0, CurrentEL
	lsr	x0, x0, #2
	ret
.size aarch64_mod_current_el, . - aarch64_mod_current_el

.p2align 2
.global aarch64_mod_read_mpidr_el1
.type aarch64_mod_read_mpidr_el1, %function
aarch64_mod_read_mpidr_el1:
	mrs	x0, MPIDR_EL1
	ret
.size aarch64_mod_read_mpidr_el1, . - aarch64_mod_read_mpidr_el1

.p2align 2
.global aarch64_mod_read_tpidr_el0
.type aarch64_mod_read_tpidr_el0, %function
aarch64_mod_read_tpidr_el0:
	mrs	x0, TPIDR_EL0
	ret
.size aarch64_mod_read_tpidr_el0, . - aarch64_mod_read_tpidr_el0

.p2align 2
.global aarch64_mod_write_tpidr_el0
.type aarch64_mod_write_tpidr_el0, %function
aarch64_mod_write_tpidr_el0:
	msr	TPIDR_EL0, x0
	ret
.size aarch64_mod_write_tpidr_el0, . - aarch64_mod_write_tpidr_el0

.p2align 2
.global aarch64_mod_read_cntpct_el0
.type aarch64_mod_read_cntpct_el0, %function
aarch64_mod_read_cntpct_el0:
	mrs	x0, CNTPCT_EL0
	ret
.size aarch64_mod_read_cntpct_el0, . - aarch64_mod_read_cntpct_el0

.p2align 2
.global aarch64_mod_read_cntfrq_el0
.type aarch64_mod_read_cntfrq_el0, %function
aarch64_mod_read_cntfrq_el0:
	mrs	x0, CNTFRQ_EL0
	ret
.size aarch64_mod_read_cntfrq_el0, . - aarch64_mod_read_cntfrq_el0

.p2align 2
.global aarch64_mod_read_currentel_raw
.type aarch64_mod_read_currentel_raw, %function
aarch64_mod_read_currentel_raw:
	mrs	x0, CurrentEL
	ret
.size aarch64_mod_read_currentel_raw, . - aarch64_mod_read_currentel_raw

.p2align 2
.global aarch64_mod_read_daif
.type aarch64_mod_read_daif, %function
aarch64_mod_read_daif:
	mrs	x0, DAIF
	ret
.size aarch64_mod_read_daif, . - aarch64_mod_read_daif

.p2align 2
.global aarch64_mod_read_esr_el1
.type aarch64_mod_read_esr_el1, %function
aarch64_mod_read_esr_el1:
	mrs	x0, ESR_EL1
	ret
.size aarch64_mod_read_esr_el1, . - aarch64_mod_read_esr_el1

.p2align 2
.global aarch64_mod_read_far_el1
.type aarch64_mod_read_far_el1, %function
aarch64_mod_read_far_el1:
	mrs	x0, FAR_EL1
	ret
.size aarch64_mod_read_far_el1, . - aarch64_mod_read_far_el1

.p2align 2
.global aarch64_mod_read_ttbr0_el1
.type aarch64_mod_read_ttbr0_el1, %function
aarch64_mod_read_ttbr0_el1:
	mrs	x0, TTBR0_EL1
	ret
.size aarch64_mod_read_ttbr0_el1, . - aarch64_mod_read_ttbr0_el1

.p2align 2
.global aarch64_mod_read_ttbr1_el1
.type aarch64_mod_read_ttbr1_el1, %function
aarch64_mod_read_ttbr1_el1:
	mrs	x0, TTBR1_EL1
	ret
.size aarch64_mod_read_ttbr1_el1, . - aarch64_mod_read_ttbr1_el1

.p2align 2
.global aarch64_mod_read_tcr_el1
.type aarch64_mod_read_tcr_el1, %function
aarch64_mod_read_tcr_el1:
	mrs	x0, TCR_EL1
	ret
.size aarch64_mod_read_tcr_el1, . - aarch64_mod_read_tcr_el1

.p2align 2
.global aarch64_mod_read_sctlr_el1
.type aarch64_mod_read_sctlr_el1, %function
aarch64_mod_read_sctlr_el1:
	mrs	x0, SCTLR_EL1
	ret
.size aarch64_mod_read_sctlr_el1, . - aarch64_mod_read_sctlr_el1

.p2align 2
.global aarch64_mod_write_sctlr_el1_isb
.type aarch64_mod_write_sctlr_el1_isb, %function
aarch64_mod_write_sctlr_el1_isb:
	msr	SCTLR_EL1, x0
	isb
	ret
.size aarch64_mod_write_sctlr_el1_isb, . - aarch64_mod_write_sctlr_el1_isb

.p2align 2
.global aarch64_mod_read_ctr_el0
.type aarch64_mod_read_ctr_el0, %function
aarch64_mod_read_ctr_el0:
	mrs	x0, CTR_EL0
	ret
.size aarch64_mod_read_ctr_el0, . - aarch64_mod_read_ctr_el0

.p2align 2
.global aarch64_mod_dsb_ishst_isb
.type aarch64_mod_dsb_ishst_isb, %function
aarch64_mod_dsb_ishst_isb:
	dsb	ishst
	isb
	ret
.size aarch64_mod_dsb_ishst_isb, . - aarch64_mod_dsb_ishst_isb

.p2align 2
.global aarch64_mod_dsb_ish
.type aarch64_mod_dsb_ish, %function
aarch64_mod_dsb_ish:
	dsb	ish
	ret
.size aarch64_mod_dsb_ish, . - aarch64_mod_dsb_ish

.p2align 2
.global aarch64_mod_isb
.type aarch64_mod_isb, %function
aarch64_mod_isb:
	isb
	ret
.size aarch64_mod_isb, . - aarch64_mod_isb

.p2align 2
.global aarch64_mod_dsb_sy_isb
.type aarch64_mod_dsb_sy_isb, %function
aarch64_mod_dsb_sy_isb:
	dsb	sy
	isb
	ret
.size aarch64_mod_dsb_sy_isb, . - aarch64_mod_dsb_sy_isb

.p2align 2
.global aarch64_mod_dc_civac
.type aarch64_mod_dc_civac, %function
aarch64_mod_dc_civac:
	dc	civac, x0
	ret
.size aarch64_mod_dc_civac, . - aarch64_mod_dc_civac

.p2align 2
.global aarch64_mod_ic_ivau
.type aarch64_mod_ic_ivau, %function
aarch64_mod_ic_ivau:
	ic	ivau, x0
	ret
.size aarch64_mod_ic_ivau, . - aarch64_mod_ic_ivau

.p2align 2
.global aarch64_mod_read_id_aa64isar0_el1
.type aarch64_mod_read_id_aa64isar0_el1, %function
aarch64_mod_read_id_aa64isar0_el1:
	mrs	x0, ID_AA64ISAR0_EL1
	ret
.size aarch64_mod_read_id_aa64isar0_el1, . - aarch64_mod_read_id_aa64isar0_el1

.p2align 2
.global aarch64_mod_read_id_aa64mmfr1_el1
.type aarch64_mod_read_id_aa64mmfr1_el1, %function
aarch64_mod_read_id_aa64mmfr1_el1:
	mrs	x0, ID_AA64MMFR1_EL1
	ret
.size aarch64_mod_read_id_aa64mmfr1_el1, . - aarch64_mod_read_id_aa64mmfr1_el1

.p2align 2
.global aarch64_mod_pan_clear
.type aarch64_mod_pan_clear, %function
aarch64_mod_pan_clear:
	.inst	0xD500409F
	ret
.size aarch64_mod_pan_clear, . - aarch64_mod_pan_clear

.p2align 2
.global aarch64_mod_pan_set
.type aarch64_mod_pan_set, %function
aarch64_mod_pan_set:
	.inst	0xD500419F
	ret
.size aarch64_mod_pan_set, . - aarch64_mod_pan_set
