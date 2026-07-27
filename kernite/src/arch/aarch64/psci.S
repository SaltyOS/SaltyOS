.section .text

.p2align 2
.global aarch64_psci_call0
.type aarch64_psci_call0, %function
aarch64_psci_call0:
	hvc	#0
	ret
.size aarch64_psci_call0, . - aarch64_psci_call0

.p2align 2
.global aarch64_psci_call3
.type aarch64_psci_call3, %function
aarch64_psci_call3:
	hvc	#0
	ret
.size aarch64_psci_call3, . - aarch64_psci_call3

.p2align 2
.global aarch64_psci_system_off
.type aarch64_psci_system_off, %function
aarch64_psci_system_off:
	mov	x0, #0x0008
	movk	x0, #0x8400, lsl #16
	hvc	#0
1:
	wfi
	b	1b
.size aarch64_psci_system_off, . - aarch64_psci_system_off

.p2align 2
.global aarch64_psci_system_reset
.type aarch64_psci_system_reset, %function
aarch64_psci_system_reset:
	mov	x0, #0x0009
	movk	x0, #0x8400, lsl #16
	hvc	#0
1:
	wfi
	b	1b
.size aarch64_psci_system_reset, . - aarch64_psci_system_reset
