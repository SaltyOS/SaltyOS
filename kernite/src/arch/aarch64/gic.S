.section .text

.p2align 2
.global aarch64_gic_mmio_read32
.type aarch64_gic_mmio_read32, %function
aarch64_gic_mmio_read32:
	ldr	w0, [x0]
	ret
.size aarch64_gic_mmio_read32, . - aarch64_gic_mmio_read32

.p2align 2
.global aarch64_gic_mmio_write32
.type aarch64_gic_mmio_write32, %function
aarch64_gic_mmio_write32:
	str	w1, [x0]
	ret
.size aarch64_gic_mmio_write32, . - aarch64_gic_mmio_write32

.p2align 2
.global aarch64_gic_mmio_write64
.type aarch64_gic_mmio_write64, %function
aarch64_gic_mmio_write64:
	str	x1, [x0]
	ret
.size aarch64_gic_mmio_write64, . - aarch64_gic_mmio_write64

.p2align 2
.global aarch64_gic_read_mpidr_el1
.type aarch64_gic_read_mpidr_el1, %function
aarch64_gic_read_mpidr_el1:
	mrs	x0, MPIDR_EL1
	ret
.size aarch64_gic_read_mpidr_el1, . - aarch64_gic_read_mpidr_el1

.p2align 2
.global aarch64_gic_icc_iar1_read
.type aarch64_gic_icc_iar1_read, %function
aarch64_gic_icc_iar1_read:
	mrs	x0, S3_0_C12_C12_0
	ret
.size aarch64_gic_icc_iar1_read, . - aarch64_gic_icc_iar1_read

.p2align 2
.global aarch64_gic_icc_eoir1_write
.type aarch64_gic_icc_eoir1_write, %function
aarch64_gic_icc_eoir1_write:
	msr	S3_0_C12_C12_1, x0
	ret
.size aarch64_gic_icc_eoir1_write, . - aarch64_gic_icc_eoir1_write

.p2align 2
.global aarch64_gic_icc_pmr_write
.type aarch64_gic_icc_pmr_write, %function
aarch64_gic_icc_pmr_write:
	msr	S3_0_C4_C6_0, x0
	ret
.size aarch64_gic_icc_pmr_write, . - aarch64_gic_icc_pmr_write

.p2align 2
.global aarch64_gic_icc_pmr_read
.type aarch64_gic_icc_pmr_read, %function
aarch64_gic_icc_pmr_read:
	mrs	x0, S3_0_C4_C6_0
	ret
.size aarch64_gic_icc_pmr_read, . - aarch64_gic_icc_pmr_read

.p2align 2
.global aarch64_gic_icc_bpr1_write
.type aarch64_gic_icc_bpr1_write, %function
aarch64_gic_icc_bpr1_write:
	msr	S3_0_C12_C12_3, x0
	ret
.size aarch64_gic_icc_bpr1_write, . - aarch64_gic_icc_bpr1_write

.p2align 2
.global aarch64_gic_icc_sre_read
.type aarch64_gic_icc_sre_read, %function
aarch64_gic_icc_sre_read:
	mrs	x0, S3_0_C12_C12_5
	ret
.size aarch64_gic_icc_sre_read, . - aarch64_gic_icc_sre_read

.p2align 2
.global aarch64_gic_icc_sre_write
.type aarch64_gic_icc_sre_write, %function
aarch64_gic_icc_sre_write:
	msr	S3_0_C12_C12_5, x0
	isb
	ret
.size aarch64_gic_icc_sre_write, . - aarch64_gic_icc_sre_write

.p2align 2
.global aarch64_gic_icc_igrpen1_write
.type aarch64_gic_icc_igrpen1_write, %function
aarch64_gic_icc_igrpen1_write:
	msr	S3_0_C12_C12_7, x0
	isb
	ret
.size aarch64_gic_icc_igrpen1_write, . - aarch64_gic_icc_igrpen1_write

.p2align 2
.global aarch64_gic_icc_ctlr_read
.type aarch64_gic_icc_ctlr_read, %function
aarch64_gic_icc_ctlr_read:
	mrs	x0, S3_0_C12_C12_4
	ret
.size aarch64_gic_icc_ctlr_read, . - aarch64_gic_icc_ctlr_read

.p2align 2
.global aarch64_gic_icc_ctlr_write
.type aarch64_gic_icc_ctlr_write, %function
aarch64_gic_icc_ctlr_write:
	msr	S3_0_C12_C12_4, x0
	ret
.size aarch64_gic_icc_ctlr_write, . - aarch64_gic_icc_ctlr_write

.p2align 2
.global aarch64_gic_icc_ap0r0_write
.type aarch64_gic_icc_ap0r0_write, %function
aarch64_gic_icc_ap0r0_write:
	msr	S3_0_C12_C8_4, x0
	ret
.size aarch64_gic_icc_ap0r0_write, . - aarch64_gic_icc_ap0r0_write

.p2align 2
.global aarch64_gic_icc_ap0r1_write
.type aarch64_gic_icc_ap0r1_write, %function
aarch64_gic_icc_ap0r1_write:
	msr	S3_0_C12_C8_5, x0
	ret
.size aarch64_gic_icc_ap0r1_write, . - aarch64_gic_icc_ap0r1_write

.p2align 2
.global aarch64_gic_icc_ap0r2_write
.type aarch64_gic_icc_ap0r2_write, %function
aarch64_gic_icc_ap0r2_write:
	msr	S3_0_C12_C8_6, x0
	ret
.size aarch64_gic_icc_ap0r2_write, . - aarch64_gic_icc_ap0r2_write

.p2align 2
.global aarch64_gic_icc_ap0r3_write
.type aarch64_gic_icc_ap0r3_write, %function
aarch64_gic_icc_ap0r3_write:
	msr	S3_0_C12_C8_7, x0
	ret
.size aarch64_gic_icc_ap0r3_write, . - aarch64_gic_icc_ap0r3_write

.p2align 2
.global aarch64_gic_icc_ap1r0_write
.type aarch64_gic_icc_ap1r0_write, %function
aarch64_gic_icc_ap1r0_write:
	msr	S3_0_C12_C9_0, x0
	ret
.size aarch64_gic_icc_ap1r0_write, . - aarch64_gic_icc_ap1r0_write

.p2align 2
.global aarch64_gic_icc_ap1r1_write
.type aarch64_gic_icc_ap1r1_write, %function
aarch64_gic_icc_ap1r1_write:
	msr	S3_0_C12_C9_1, x0
	ret
.size aarch64_gic_icc_ap1r1_write, . - aarch64_gic_icc_ap1r1_write

.p2align 2
.global aarch64_gic_icc_ap1r2_write
.type aarch64_gic_icc_ap1r2_write, %function
aarch64_gic_icc_ap1r2_write:
	msr	S3_0_C12_C9_2, x0
	ret
.size aarch64_gic_icc_ap1r2_write, . - aarch64_gic_icc_ap1r2_write

.p2align 2
.global aarch64_gic_icc_ap1r3_write
.type aarch64_gic_icc_ap1r3_write, %function
aarch64_gic_icc_ap1r3_write:
	msr	S3_0_C12_C9_3, x0
	ret
.size aarch64_gic_icc_ap1r3_write, . - aarch64_gic_icc_ap1r3_write

.p2align 2
.global aarch64_gic_icc_sgi1r_write
.type aarch64_gic_icc_sgi1r_write, %function
aarch64_gic_icc_sgi1r_write:
	msr	S3_0_C12_C11_5, x0
	isb
	ret
.size aarch64_gic_icc_sgi1r_write, . - aarch64_gic_icc_sgi1r_write

.p2align 2
.global aarch64_gic_icc_sre_el2_enable
.type aarch64_gic_icc_sre_el2_enable, %function
aarch64_gic_icc_sre_el2_enable:
	mrs	x0, ICC_SRE_EL2
	orr	x0, x0, #1
	msr	ICC_SRE_EL2, x0
	isb
	ret
.size aarch64_gic_icc_sre_el2_enable, . - aarch64_gic_icc_sre_el2_enable

.p2align 2
.global aarch64_gic_isb
.type aarch64_gic_isb, %function
aarch64_gic_isb:
	isb
	ret
.size aarch64_gic_isb, . - aarch64_gic_isb
