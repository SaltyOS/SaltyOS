.intel_syntax noprefix
#include <uapi/syscall.h>
#include <uapi/object.h>
#include <uapi/invoke.h>

#if KERNITE_SYS_INVOKE != 0
#error "test_sse.S yield helper assumes KERNITE_SYS_INVOKE == 0"
#endif
#if KERNITE_CAP_SELF_TCB != 0
#error "test_sse.S yield helper assumes KERNITE_CAP_SELF_TCB == 0"
#endif
#if KERNITE_INV_TCB_YIELD != 0x064
#error "test_sse.S yield helper assumes KERNITE_INV_TCB_YIELD == 0x064"
#endif

.section .text

.equ TEST_KERNITE_SYS_INVOKE, 0
.equ TEST_KERNITE_CAP_SELF_TCB, 0
.equ TEST_KERNITE_INV_TCB_YIELD, 0x064

.macro yield_self_tcb
	mov	eax, TEST_KERNITE_SYS_INVOKE
	mov	edi, TEST_KERNITE_CAP_SELF_TCB
	mov	esi, TEST_KERNITE_INV_TCB_YIELD
	xor	edx, edx
	xor	r10d, r10d
	xor	r8d, r8d
	xor	r9d, r9d
	syscall
.endm

.global test_sse_xmm0_syscall
.type test_sse_xmm0_syscall, @function
test_sse_xmm0_syscall:
	movq	xmm0, rdi
	yield_self_tcb
	movq	rax, xmm0
	ret
.size test_sse_xmm0_syscall, . - test_sse_xmm0_syscall

.global test_sse_xmm1_load
.type test_sse_xmm1_load, @function
test_sse_xmm1_load:
	movq	xmm1, rdi
	ret
.size test_sse_xmm1_load, . - test_sse_xmm1_load

.global test_sse_xmm1_read
.type test_sse_xmm1_read, @function
test_sse_xmm1_read:
	movq	rax, xmm1
	ret
.size test_sse_xmm1_read, . - test_sse_xmm1_read

.global test_sse_xmm0_yield_loop
.type test_sse_xmm0_yield_loop, @function
test_sse_xmm0_yield_loop:
	push	rbx
	movq	xmm0, rdi
	mov	rbx, rsi
.Lxmm0_yield_loop:
	test	rbx, rbx
	jz	.Lxmm0_yield_done
	yield_self_tcb
	dec	rbx
	jmp	.Lxmm0_yield_loop
.Lxmm0_yield_done:
	movq	rax, xmm0
	pop	rbx
	ret
.size test_sse_xmm0_yield_loop, . - test_sse_xmm0_yield_loop

.global test_sse_all_registers
.type test_sse_all_registers, @function
test_sse_all_registers:
	push	rbx
	mov	rbx, rsi
	movq	xmm0, qword ptr [rdi]
	movq	xmm1, qword ptr [rdi + 8]
	movq	xmm2, qword ptr [rdi + 16]
	movq	xmm3, qword ptr [rdi + 24]
	movq	xmm4, qword ptr [rdi + 32]
	movq	xmm5, qword ptr [rdi + 40]
	movq	xmm6, qword ptr [rdi + 48]
	movq	xmm7, qword ptr [rdi + 56]
	movq	xmm8, qword ptr [rdi + 64]
	movq	xmm9, qword ptr [rdi + 72]
	movq	xmm10, qword ptr [rdi + 80]
	movq	xmm11, qword ptr [rdi + 88]
	movq	xmm12, qword ptr [rdi + 96]
	movq	xmm13, qword ptr [rdi + 104]
	movq	xmm14, qword ptr [rdi + 112]
	movq	xmm15, qword ptr [rdi + 120]
	yield_self_tcb
	yield_self_tcb
	yield_self_tcb
	movq	qword ptr [rbx], xmm0
	movq	qword ptr [rbx + 8], xmm1
	movq	qword ptr [rbx + 16], xmm2
	movq	qword ptr [rbx + 24], xmm3
	movq	qword ptr [rbx + 32], xmm4
	movq	qword ptr [rbx + 40], xmm5
	movq	qword ptr [rbx + 48], xmm6
	movq	qword ptr [rbx + 56], xmm7
	movq	qword ptr [rbx + 64], xmm8
	movq	qword ptr [rbx + 72], xmm9
	movq	qword ptr [rbx + 80], xmm10
	movq	qword ptr [rbx + 88], xmm11
	movq	qword ptr [rbx + 96], xmm12
	movq	qword ptr [rbx + 104], xmm13
	movq	qword ptr [rbx + 112], xmm14
	movq	qword ptr [rbx + 120], xmm15
	pop	rbx
	ret
.size test_sse_all_registers, . - test_sse_all_registers
