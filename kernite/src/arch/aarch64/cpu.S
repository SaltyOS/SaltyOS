.section .text

.p2align 2
.global aarch64_cpu_write_tpidr_el1
.type aarch64_cpu_write_tpidr_el1, %function
aarch64_cpu_write_tpidr_el1:
	msr	TPIDR_EL1, x0
	ret
.size aarch64_cpu_write_tpidr_el1, . - aarch64_cpu_write_tpidr_el1

.p2align 2
.global aarch64_cpu_read_tpidr_el1
.type aarch64_cpu_read_tpidr_el1, %function
aarch64_cpu_read_tpidr_el1:
	mrs	x0, TPIDR_EL1
	ret
.size aarch64_cpu_read_tpidr_el1, . - aarch64_cpu_read_tpidr_el1
