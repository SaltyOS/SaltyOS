.section .text

.p2align 2
.global aarch64_fpu_enable
.type aarch64_fpu_enable, %function
aarch64_fpu_enable:
	mrs	x0, CPACR_EL1
	orr	x0, x0, #(3 << 20)
	msr	CPACR_EL1, x0
	isb
	ret
.size aarch64_fpu_enable, . - aarch64_fpu_enable
