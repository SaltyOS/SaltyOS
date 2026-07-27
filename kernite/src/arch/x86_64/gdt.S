.intel_syntax noprefix
.section .text

.global x86_gdt_lgdt
.type x86_gdt_lgdt, @function
x86_gdt_lgdt:
	lgdt	[rdi]
	ret
.size x86_gdt_lgdt, . - x86_gdt_lgdt

.global x86_gdt_sgdt
.type x86_gdt_sgdt, @function
x86_gdt_sgdt:
	sgdt	[rdi]
	ret
.size x86_gdt_sgdt, . - x86_gdt_sgdt

.global x86_gdt_ltr
.type x86_gdt_ltr, @function
x86_gdt_ltr:
	mov	ax, di
	ltr	ax
	ret
.size x86_gdt_ltr, . - x86_gdt_ltr

.global x86_gdt_reload_segments
.type x86_gdt_reload_segments, @function
x86_gdt_reload_segments:
	push	0x08
	lea	rax, [rip + 1f]
	push	rax
	retfq
1:
	mov	ax, 0x10
	mov	ds, ax
	mov	es, ax
	mov	fs, ax
	mov	gs, ax
	mov	ss, ax
	ret
.size x86_gdt_reload_segments, . - x86_gdt_reload_segments
