.intel_syntax noprefix
.section .text

.global x86_fpu_read_cr0
.type x86_fpu_read_cr0, @function
x86_fpu_read_cr0:
	mov	rax, cr0
	ret
.size x86_fpu_read_cr0, . - x86_fpu_read_cr0

.global x86_fpu_write_cr0
.type x86_fpu_write_cr0, @function
x86_fpu_write_cr0:
	mov	cr0, rdi
	ret
.size x86_fpu_write_cr0, . - x86_fpu_write_cr0

.global x86_fpu_read_cr4
.type x86_fpu_read_cr4, @function
x86_fpu_read_cr4:
	mov	rax, cr4
	ret
.size x86_fpu_read_cr4, . - x86_fpu_read_cr4

.global x86_fpu_write_cr4
.type x86_fpu_write_cr4, @function
x86_fpu_write_cr4:
	mov	cr4, rdi
	ret
.size x86_fpu_write_cr4, . - x86_fpu_write_cr4

.global x86_fpu_xsetbv0
.type x86_fpu_xsetbv0, @function
x86_fpu_xsetbv0:
	mov	ecx, 0
	mov	rax, rdi
	mov	rdx, rdi
	shr	rdx, 32
	xsetbv
	ret
.size x86_fpu_xsetbv0, . - x86_fpu_xsetbv0

.global x86_fpu_fninit
.type x86_fpu_fninit, @function
x86_fpu_fninit:
	fninit
	ret
.size x86_fpu_fninit, . - x86_fpu_fninit

.global x86_fpu_xsave
.type x86_fpu_xsave, @function
x86_fpu_xsave:
	mov	eax, 3
	xor	edx, edx
	xsave	[rdi]
	ret
.size x86_fpu_xsave, . - x86_fpu_xsave

.global x86_fpu_xrstor
.type x86_fpu_xrstor, @function
x86_fpu_xrstor:
	mov	eax, 3
	xor	edx, edx
	xrstor	[rdi]
	ret
.size x86_fpu_xrstor, . - x86_fpu_xrstor

.global x86_fpu_fxsave
.type x86_fpu_fxsave, @function
x86_fpu_fxsave:
	fxsave	[rdi]
	ret
.size x86_fpu_fxsave, . - x86_fpu_fxsave

.global x86_fpu_fxrstor
.type x86_fpu_fxrstor, @function
x86_fpu_fxrstor:
	fxrstor	[rdi]
	ret
.size x86_fpu_fxrstor, . - x86_fpu_fxrstor
