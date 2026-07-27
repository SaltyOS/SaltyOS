.intel_syntax noprefix
.section .text

.global x86_cpuid_leaf
.type x86_cpuid_leaf, @function
x86_cpuid_leaf:
	mov	r8, rdx
	mov	eax, edi
	mov	ecx, esi
	push	rbx
	cpuid
	mov	dword ptr [r8], eax
	mov	dword ptr [r8 + 4], ebx
	mov	dword ptr [r8 + 8], ecx
	mov	dword ptr [r8 + 12], edx
	pop	rbx
	ret
.size x86_cpuid_leaf, . - x86_cpuid_leaf
