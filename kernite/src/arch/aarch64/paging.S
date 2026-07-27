.section .text

.p2align 2
.global aarch64_paging_read_ttbr0_el1
.type aarch64_paging_read_ttbr0_el1, %function
aarch64_paging_read_ttbr0_el1:
	mrs	x0, TTBR0_EL1
	ret
.size aarch64_paging_read_ttbr0_el1, . - aarch64_paging_read_ttbr0_el1

.p2align 2
.global aarch64_paging_write_ttbr0_el1_flush_all
.type aarch64_paging_write_ttbr0_el1_flush_all, %function
aarch64_paging_write_ttbr0_el1_flush_all:
	dsb	ish
	msr	TTBR0_EL1, x0
	isb
	dsb	ishst
	tlbi	vmalle1is
	dsb	ish
	isb
	ret
.size aarch64_paging_write_ttbr0_el1_flush_all, . - aarch64_paging_write_ttbr0_el1_flush_all

.p2align 2
.global aarch64_paging_dsb_ishst_isb
.type aarch64_paging_dsb_ishst_isb, %function
aarch64_paging_dsb_ishst_isb:
	dsb	ishst
	isb
	ret
.size aarch64_paging_dsb_ishst_isb, . - aarch64_paging_dsb_ishst_isb

.p2align 2
.global aarch64_paging_invlpg_current_asid
.type aarch64_paging_invlpg_current_asid, %function
aarch64_paging_invlpg_current_asid:
	mrs	x1, TTBR0_EL1
	lsr	x1, x1, #48
	ubfx	x0, x0, #12, #44
	orr	x0, x0, x1, lsl #48
	dsb	ishst
	tlbi	vae1is, x0
	dsb	ish
	isb
	ret
.size aarch64_paging_invlpg_current_asid, . - aarch64_paging_invlpg_current_asid

.p2align 2
.global aarch64_paging_invlpg_asid
.type aarch64_paging_invlpg_asid, %function
aarch64_paging_invlpg_asid:
	ubfx	x0, x0, #12, #44
	and	x1, x1, #0xffff
	orr	x0, x0, x1, lsl #48
	dsb	ishst
	tlbi	vae1is, x0
	dsb	ish
	isb
	ret
.size aarch64_paging_invlpg_asid, . - aarch64_paging_invlpg_asid

.p2align 2
.global aarch64_paging_invlpg_all_asid
.type aarch64_paging_invlpg_all_asid, %function
aarch64_paging_invlpg_all_asid:
	ubfx	x0, x0, #12, #44
	dsb	ishst
	tlbi	vaae1is, x0
	dsb	ish
	isb
	ret
.size aarch64_paging_invlpg_all_asid, . - aarch64_paging_invlpg_all_asid

.p2align 2
.global aarch64_paging_flush_tlb_all
.type aarch64_paging_flush_tlb_all, %function
aarch64_paging_flush_tlb_all:
	dsb	ishst
	tlbi	vmalle1is
	dsb	ish
	isb
	ret
.size aarch64_paging_flush_tlb_all, . - aarch64_paging_flush_tlb_all

.p2align 2
.global aarch64_paging_flush_asid
.type aarch64_paging_flush_asid, %function
aarch64_paging_flush_asid:
	lsl	x0, x0, #48
	dsb	ishst
	tlbi	aside1is, x0
	dsb	ish
	isb
	ret
.size aarch64_paging_flush_asid, . - aarch64_paging_flush_asid

.p2align 2
.global aarch64_paging_flush_icache_all
.type aarch64_paging_flush_icache_all, %function
aarch64_paging_flush_icache_all:
	dsb	ish
	ic	ialluis
	dsb	ish
	isb
	ret
.size aarch64_paging_flush_icache_all, . - aarch64_paging_flush_icache_all

.p2align 2
.global aarch64_paging_dc_cvau
.type aarch64_paging_dc_cvau, %function
aarch64_paging_dc_cvau:
	dc	cvau, x0
	ret
.size aarch64_paging_dc_cvau, . - aarch64_paging_dc_cvau

.p2align 2
.global aarch64_paging_dc_cvac
.type aarch64_paging_dc_cvac, %function
aarch64_paging_dc_cvac:
	dc	cvac, x0
	ret
.size aarch64_paging_dc_cvac, . - aarch64_paging_dc_cvac

.p2align 2
.global aarch64_paging_dsb_ish
.type aarch64_paging_dsb_ish, %function
aarch64_paging_dsb_ish:
	dsb	ish
	ret
.size aarch64_paging_dsb_ish, . - aarch64_paging_dsb_ish

.p2align 2
.global aarch64_paging_dsb_ish_isb
.type aarch64_paging_dsb_ish_isb, %function
aarch64_paging_dsb_ish_isb:
	dsb	ish
	isb
	ret
.size aarch64_paging_dsb_ish_isb, . - aarch64_paging_dsb_ish_isb

.p2align 2
.global aarch64_paging_dsb_ishst
.type aarch64_paging_dsb_ishst, %function
aarch64_paging_dsb_ishst:
	dsb	ishst
	ret
.size aarch64_paging_dsb_ishst, . - aarch64_paging_dsb_ishst

.p2align 2
.global aarch64_paging_write_mair_el1_isb
.type aarch64_paging_write_mair_el1_isb, %function
aarch64_paging_write_mair_el1_isb:
	msr	MAIR_EL1, x0
	isb
	ret
.size aarch64_paging_write_mair_el1_isb, . - aarch64_paging_write_mair_el1_isb

.p2align 2
.global aarch64_paging_read_mair_el1
.type aarch64_paging_read_mair_el1, %function
aarch64_paging_read_mair_el1:
	mrs	x0, MAIR_EL1
	ret
.size aarch64_paging_read_mair_el1, . - aarch64_paging_read_mair_el1

.p2align 2
.global aarch64_paging_read_tcr_el1
.type aarch64_paging_read_tcr_el1, %function
aarch64_paging_read_tcr_el1:
	mrs	x0, TCR_EL1
	ret
.size aarch64_paging_read_tcr_el1, . - aarch64_paging_read_tcr_el1

.p2align 2
.global aarch64_paging_read_sctlr_el1
.type aarch64_paging_read_sctlr_el1, %function
aarch64_paging_read_sctlr_el1:
	mrs	x0, SCTLR_EL1
	ret
.size aarch64_paging_read_sctlr_el1, . - aarch64_paging_read_sctlr_el1
