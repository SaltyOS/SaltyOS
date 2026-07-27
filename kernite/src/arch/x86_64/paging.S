.intel_syntax noprefix
.section .text

.global x86_paging_read_cr3
.type x86_paging_read_cr3, @function
x86_paging_read_cr3:
	mov	rax, cr3
	ret
.size x86_paging_read_cr3, . - x86_paging_read_cr3

.global x86_paging_write_cr3
.type x86_paging_write_cr3, @function
x86_paging_write_cr3:
	mov	cr3, rdi
	ret
.size x86_paging_write_cr3, . - x86_paging_write_cr3

.global x86_paging_invlpg
.type x86_paging_invlpg, @function
x86_paging_invlpg:
	invlpg	[rdi]
	ret
.size x86_paging_invlpg, . - x86_paging_invlpg

.global x86_paging_read_cr0
.type x86_paging_read_cr0, @function
x86_paging_read_cr0:
	mov	rax, cr0
	ret
.size x86_paging_read_cr0, . - x86_paging_read_cr0

.global x86_paging_write_cr0
.type x86_paging_write_cr0, @function
x86_paging_write_cr0:
	mov	cr0, rdi
	ret
.size x86_paging_write_cr0, . - x86_paging_write_cr0

.global x86_paging_wrmsr
.type x86_paging_wrmsr, @function
x86_paging_wrmsr:
	mov	ecx, edi
	mov	rax, rsi
	mov	rdx, rsi
	shr	rdx, 32
	wrmsr
	ret
.size x86_paging_wrmsr, . - x86_paging_wrmsr
