.intel_syntax noprefix
.section .text

.global x86_stacktrace_capture_current
.type x86_stacktrace_capture_current, @function
x86_stacktrace_capture_current:
	mov	rax, [rsp]
	mov	[rdi + 0], rax
	lea	rax, [rsp + 8]
	mov	[rdi + 8], rax
	mov	[rdi + 16], rbp
	pushfq
	pop	rax
	mov	[rdi + 24], rax
	mov	rax, cr2
	mov	[rdi + 32], rax
	mov	rax, cr3
	mov	[rdi + 40], rax
	ret
.size x86_stacktrace_capture_current, . - x86_stacktrace_capture_current
