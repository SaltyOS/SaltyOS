.intel_syntax noprefix
.section .text

.global x86_ap_boot_rdmsr
.type x86_ap_boot_rdmsr, @function
x86_ap_boot_rdmsr:
	mov	ecx, edi
	rdmsr
	shl	rdx, 32
	or	rax, rdx
	ret
.size x86_ap_boot_rdmsr, . - x86_ap_boot_rdmsr

.global x86_ap_boot_wrmsr
.type x86_ap_boot_wrmsr, @function
x86_ap_boot_wrmsr:
	mov	ecx, edi
	mov	rax, rsi
	mov	rdx, rsi
	shr	rdx, 32
	wrmsr
	ret
.size x86_ap_boot_wrmsr, . - x86_ap_boot_wrmsr
