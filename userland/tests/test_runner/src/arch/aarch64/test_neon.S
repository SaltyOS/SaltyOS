#include <uapi/syscall.h>
#include <uapi/object.h>
#include <uapi/invoke.h>

#if KERNITE_SYS_INVOKE != 0
#error "test_neon.S yield helper assumes KERNITE_SYS_INVOKE == 0"
#endif
#if KERNITE_CAP_SELF_TCB != 0
#error "test_neon.S yield helper assumes KERNITE_CAP_SELF_TCB == 0"
#endif
#if KERNITE_INV_TCB_YIELD != 0x064
#error "test_neon.S yield helper assumes KERNITE_INV_TCB_YIELD == 0x064"
#endif

.section .text

.equ TEST_KERNITE_SYS_INVOKE, 0
.equ TEST_KERNITE_CAP_SELF_TCB, 0
.equ TEST_KERNITE_INV_TCB_YIELD, 0x064

.macro yield_self_tcb
	mov	x8, #TEST_KERNITE_SYS_INVOKE
	mov	x0, #TEST_KERNITE_CAP_SELF_TCB
	mov	x1, #TEST_KERNITE_INV_TCB_YIELD
	mov	x2, #0
	mov	x3, #0
	mov	x4, #0
	mov	x5, #0
	svc	#0
.endm

.p2align 2
.global test_neon_d0_syscall
.type test_neon_d0_syscall, %function
test_neon_d0_syscall:
	fmov	d0, x0
	yield_self_tcb
	fmov	x0, d0
	ret
.size test_neon_d0_syscall, . - test_neon_d0_syscall

.p2align 2
.global test_neon_d1_load
.type test_neon_d1_load, %function
test_neon_d1_load:
	fmov	d1, x0
	ret
.size test_neon_d1_load, . - test_neon_d1_load

.p2align 2
.global test_neon_d1_read
.type test_neon_d1_read, %function
test_neon_d1_read:
	fmov	x0, d1
	ret
.size test_neon_d1_read, . - test_neon_d1_read

.p2align 2
.global test_neon_d0_yield_loop
.type test_neon_d0_yield_loop, %function
test_neon_d0_yield_loop:
	str	x19, [sp, #-16]!
	fmov	d0, x0
	mov	x19, x1
.Ld0_yield_loop:
	cbz	x19, .Ld0_yield_done
	yield_self_tcb
	sub	x19, x19, #1
	b	.Ld0_yield_loop
.Ld0_yield_done:
	fmov	x0, d0
	ldr	x19, [sp], #16
	ret
.size test_neon_d0_yield_loop, . - test_neon_d0_yield_loop

.p2align 2
.global test_neon_all_registers_asm
.type test_neon_all_registers_asm, %function
test_neon_all_registers_asm:
	stp	x19, x20, [sp, #-16]!
	mov	x19, x0
	mov	x20, x1
	ldr	d0,  [x19]
	ldr	d1,  [x19, #8]
	ldr	d2,  [x19, #16]
	ldr	d3,  [x19, #24]
	ldr	d4,  [x19, #32]
	ldr	d5,  [x19, #40]
	ldr	d6,  [x19, #48]
	ldr	d7,  [x19, #56]
	ldr	d8,  [x19, #64]
	ldr	d9,  [x19, #72]
	ldr	d10, [x19, #80]
	ldr	d11, [x19, #88]
	ldr	d12, [x19, #96]
	ldr	d13, [x19, #104]
	ldr	d14, [x19, #112]
	ldr	d15, [x19, #120]
	ldr	d16, [x19, #128]
	ldr	d17, [x19, #136]
	ldr	d18, [x19, #144]
	ldr	d19, [x19, #152]
	ldr	d20, [x19, #160]
	ldr	d21, [x19, #168]
	ldr	d22, [x19, #176]
	ldr	d23, [x19, #184]
	ldr	d24, [x19, #192]
	ldr	d25, [x19, #200]
	ldr	d26, [x19, #208]
	ldr	d27, [x19, #216]
	ldr	d28, [x19, #224]
	ldr	d29, [x19, #232]
	ldr	d30, [x19, #240]
	ldr	d31, [x19, #248]
	yield_self_tcb
	yield_self_tcb
	yield_self_tcb
	str	d0,  [x20]
	str	d1,  [x20, #8]
	str	d2,  [x20, #16]
	str	d3,  [x20, #24]
	str	d4,  [x20, #32]
	str	d5,  [x20, #40]
	str	d6,  [x20, #48]
	str	d7,  [x20, #56]
	str	d8,  [x20, #64]
	str	d9,  [x20, #72]
	str	d10, [x20, #80]
	str	d11, [x20, #88]
	str	d12, [x20, #96]
	str	d13, [x20, #104]
	str	d14, [x20, #112]
	str	d15, [x20, #120]
	str	d16, [x20, #128]
	str	d17, [x20, #136]
	str	d18, [x20, #144]
	str	d19, [x20, #152]
	str	d20, [x20, #160]
	str	d21, [x20, #168]
	str	d22, [x20, #176]
	str	d23, [x20, #184]
	str	d24, [x20, #192]
	str	d25, [x20, #200]
	str	d26, [x20, #208]
	str	d27, [x20, #216]
	str	d28, [x20, #224]
	str	d29, [x20, #232]
	str	d30, [x20, #240]
	str	d31, [x20, #248]
	ldp	x19, x20, [sp], #16
	ret
.size test_neon_all_registers_asm, . - test_neon_all_registers_asm
