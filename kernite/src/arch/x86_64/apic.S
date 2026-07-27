.intel_syntax noprefix
.section .text

.global x86_apic_rdtsc
.type x86_apic_rdtsc, @function
x86_apic_rdtsc:
	rdtsc
	shl	rdx, 32
	or	rax, rdx
	ret
.size x86_apic_rdtsc, . - x86_apic_rdtsc

.global x86_apic_cpuid1_edx
.type x86_apic_cpuid1_edx, @function
x86_apic_cpuid1_edx:
	push	rbx
	mov	eax, 1
	xor	ecx, ecx
	cpuid
	mov	eax, edx
	pop	rbx
	ret
.size x86_apic_cpuid1_edx, . - x86_apic_cpuid1_edx

.global x86_apic_rdmsr
.type x86_apic_rdmsr, @function
x86_apic_rdmsr:
	mov	ecx, edi
	rdmsr
	shl	rdx, 32
	or	rax, rdx
	ret
.size x86_apic_rdmsr, . - x86_apic_rdmsr

.global x86_apic_wrmsr
.type x86_apic_wrmsr, @function
x86_apic_wrmsr:
	mov	ecx, edi
	mov	rax, rsi
	mov	rdx, rsi
	shr	rdx, 32
	wrmsr
	ret
.size x86_apic_wrmsr, . - x86_apic_wrmsr
