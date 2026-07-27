.intel_syntax noprefix
.section .text

.global x86_random_rdrand64_once
.type x86_random_rdrand64_once, @function
x86_random_rdrand64_once:
	rdrand	rax
	setc	dl
	mov	qword ptr [rdi], rax
	movzx	eax, dl
	ret
.size x86_random_rdrand64_once, . - x86_random_rdrand64_once

.global x86_random_rdseed64_once
.type x86_random_rdseed64_once, @function
x86_random_rdseed64_once:
	rdseed	rax
	setc	dl
	mov	qword ptr [rdi], rax
	movzx	eax, dl
	ret
.size x86_random_rdseed64_once, . - x86_random_rdseed64_once
