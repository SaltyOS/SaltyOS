.intel_syntax noprefix
.section .text

.global x86_idt_lidt
.type x86_idt_lidt, @function
x86_idt_lidt:
	lidt	[rdi]
	ret
.size x86_idt_lidt, . - x86_idt_lidt

.global x86_idt_sidt
.type x86_idt_sidt, @function
x86_idt_sidt:
	sidt	[rdi]
	ret
.size x86_idt_sidt, . - x86_idt_sidt
