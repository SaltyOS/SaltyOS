.intel_syntax noprefix
.section .text

.global x86_mod_read_cr0
.type x86_mod_read_cr0, @function
x86_mod_read_cr0:
	mov	rax, cr0
	ret
.size x86_mod_read_cr0, . - x86_mod_read_cr0

.global x86_mod_read_cr2
.type x86_mod_read_cr2, @function
x86_mod_read_cr2:
	mov	rax, cr2
	ret
.size x86_mod_read_cr2, . - x86_mod_read_cr2

.global x86_mod_read_cr4
.type x86_mod_read_cr4, @function
x86_mod_read_cr4:
	mov	rax, cr4
	ret
.size x86_mod_read_cr4, . - x86_mod_read_cr4

.global x86_mod_read_rflags
.type x86_mod_read_rflags, @function
x86_mod_read_rflags:
	pushfq
	pop	rax
	ret
.size x86_mod_read_rflags, . - x86_mod_read_rflags

.global x86_mod_hlt
.type x86_mod_hlt, @function
x86_mod_hlt:
	hlt
	ret
.size x86_mod_hlt, . - x86_mod_hlt

.global x86_mod_cli
.type x86_mod_cli, @function
x86_mod_cli:
	cli
	ret
.size x86_mod_cli, . - x86_mod_cli

.global x86_mod_sti
.type x86_mod_sti, @function
x86_mod_sti:
	sti
	ret
.size x86_mod_sti, . - x86_mod_sti

.global x86_mod_outb
.type x86_mod_outb, @function
x86_mod_outb:
	mov	dx, di
	mov	al, sil
	out	dx, al
	ret
.size x86_mod_outb, . - x86_mod_outb

.global x86_mod_inb
.type x86_mod_inb, @function
x86_mod_inb:
	mov	dx, di
	xor	eax, eax
	in	al, dx
	ret
.size x86_mod_inb, . - x86_mod_inb

.global x86_mod_outw
.type x86_mod_outw, @function
x86_mod_outw:
	mov	dx, di
	mov	ax, si
	out	dx, ax
	ret
.size x86_mod_outw, . - x86_mod_outw

.global x86_mod_inw
.type x86_mod_inw, @function
x86_mod_inw:
	mov	dx, di
	xor	eax, eax
	in	ax, dx
	ret
.size x86_mod_inw, . - x86_mod_inw

.global x86_mod_outl
.type x86_mod_outl, @function
x86_mod_outl:
	mov	dx, di
	mov	eax, esi
	out	dx, eax
	ret
.size x86_mod_outl, . - x86_mod_outl

.global x86_mod_inl
.type x86_mod_inl, @function
x86_mod_inl:
	mov	dx, di
	in	eax, dx
	ret
.size x86_mod_inl, . - x86_mod_inl

.global x86_mod_rdmsr
.type x86_mod_rdmsr, @function
x86_mod_rdmsr:
	mov	ecx, edi
	rdmsr
	shl	rdx, 32
	or	rax, rdx
	ret
.size x86_mod_rdmsr, . - x86_mod_rdmsr

.global x86_mod_wrmsr
.type x86_mod_wrmsr, @function
x86_mod_wrmsr:
	mov	ecx, edi
	mov	rax, rsi
	mov	rdx, rsi
	shr	rdx, 32
	wrmsr
	ret
.size x86_mod_wrmsr, . - x86_mod_wrmsr

.global x86_mod_ud2
.type x86_mod_ud2, @function
x86_mod_ud2:
	ud2
1:
	hlt
	jmp	1b
.size x86_mod_ud2, . - x86_mod_ud2
