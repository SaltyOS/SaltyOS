.intel_syntax noprefix
.section .text

.global x86_cpu_rdtsc
.type x86_cpu_rdtsc, @function
x86_cpu_rdtsc:
	rdtsc
	shl	rdx, 32
	or	rax, rdx
	ret
.size x86_cpu_rdtsc, . - x86_cpu_rdtsc

.global x86_cpu_rdmsr
.type x86_cpu_rdmsr, @function
x86_cpu_rdmsr:
	mov	ecx, edi
	rdmsr
	shl	rdx, 32
	or	rax, rdx
	ret
.size x86_cpu_rdmsr, . - x86_cpu_rdmsr

.global x86_cpu_wrmsr
.type x86_cpu_wrmsr, @function
x86_cpu_wrmsr:
	mov	ecx, edi
	mov	rax, rsi
	mov	rdx, rsi
	shr	rdx, 32
	wrmsr
	ret
.size x86_cpu_wrmsr, . - x86_cpu_wrmsr

.global x86_cpu_set_per_cpu_canary
.type x86_cpu_set_per_cpu_canary, @function
x86_cpu_set_per_cpu_canary:
	mov	qword ptr gs:[32], rdi
	ret
.size x86_cpu_set_per_cpu_canary, . - x86_cpu_set_per_cpu_canary

.global x86_cpu_current_cpu
.type x86_cpu_current_cpu, @function
x86_cpu_current_cpu:
	mov	eax, dword ptr gs:[0]
	ret
.size x86_cpu_current_cpu, . - x86_cpu_current_cpu

.global x86_cpu_next_invoke_seq
.type x86_cpu_next_invoke_seq, @function
x86_cpu_next_invoke_seq:
	add	qword ptr gs:[24], 1
	mov	rax, qword ptr gs:[24]
	ret
.size x86_cpu_next_invoke_seq, . - x86_cpu_next_invoke_seq

.global x86_cpu_current_invoke_seq
.type x86_cpu_current_invoke_seq, @function
x86_cpu_current_invoke_seq:
	mov	rax, qword ptr gs:[24]
	ret
.size x86_cpu_current_invoke_seq, . - x86_cpu_current_invoke_seq

.global x86_cpu_set_kernel_stack
.type x86_cpu_set_kernel_stack, @function
x86_cpu_set_kernel_stack:
	mov	qword ptr gs:[8], rdi
	ret
.size x86_cpu_set_kernel_stack, . - x86_cpu_set_kernel_stack

.global x86_cpu_get_kernel_stack
.type x86_cpu_get_kernel_stack, @function
x86_cpu_get_kernel_stack:
	mov	rax, qword ptr gs:[8]
	ret
.size x86_cpu_get_kernel_stack, . - x86_cpu_get_kernel_stack
