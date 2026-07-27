.intel_syntax noprefix
.section .text.boot, "ax"

.global _start
.type _start, @function
_start:
	// Set up kernel stack (stack grows down, so use the end of the array).
	lea	rsp, [rip + KERNEL_STACK + 16384]

	// Clear RFLAGS.
	push	0
	popfq

	// RDI already contains the boot_info pointer from the bootloader.
	call	kmain

	// kmain should never return.
2:
	hlt
	jmp	2b
.size _start, . - _start
