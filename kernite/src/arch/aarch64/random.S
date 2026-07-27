.section .text

.p2align 2
.global aarch64_random_rndr64_once
.type aarch64_random_rndr64_once, %function
aarch64_random_rndr64_once:
	mov	x2, x0
	mrs	x1, S3_3_C2_C4_0
	cset	w0, ne
	str	x1, [x2]
	ret
.size aarch64_random_rndr64_once, . - aarch64_random_rndr64_once
