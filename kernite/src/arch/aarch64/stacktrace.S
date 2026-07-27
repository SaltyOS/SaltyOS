.section .text

.p2align 2
.global aarch64_stacktrace_capture_current
.type aarch64_stacktrace_capture_current, %function
aarch64_stacktrace_capture_current:
	mov	x9, x0
	str	x30, [x9, #0]
	mov	x10, sp
	str	x10, [x9, #8]
	str	x29, [x9, #16]
	str	x30, [x9, #24]
	mrs	x10, DAIF
	str	x10, [x9, #32]
	mrs	x10, ESR_EL1
	str	x10, [x9, #40]
	mrs	x10, FAR_EL1
	str	x10, [x9, #48]
	mrs	x10, TTBR0_EL1
	str	x10, [x9, #56]
	ret
.size aarch64_stacktrace_capture_current, . - aarch64_stacktrace_capture_current
