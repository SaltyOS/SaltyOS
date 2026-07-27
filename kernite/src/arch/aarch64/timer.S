.section .text

.p2align 2
.global aarch64_timer_read_cntfrq_el0
.type aarch64_timer_read_cntfrq_el0, %function
aarch64_timer_read_cntfrq_el0:
	mrs	x0, CNTFRQ_EL0
	ret
.size aarch64_timer_read_cntfrq_el0, . - aarch64_timer_read_cntfrq_el0

.p2align 2
.global aarch64_timer_read_cntvct_el0
.type aarch64_timer_read_cntvct_el0, %function
aarch64_timer_read_cntvct_el0:
	mrs	x0, CNTVCT_EL0
	ret
.size aarch64_timer_read_cntvct_el0, . - aarch64_timer_read_cntvct_el0

.p2align 2
.global aarch64_timer_write_cntv_cval_el0
.type aarch64_timer_write_cntv_cval_el0, %function
aarch64_timer_write_cntv_cval_el0:
	msr	CNTV_CVAL_EL0, x0
	ret
.size aarch64_timer_write_cntv_cval_el0, . - aarch64_timer_write_cntv_cval_el0

.p2align 2
.global aarch64_timer_write_cntv_ctl_el0
.type aarch64_timer_write_cntv_ctl_el0, %function
aarch64_timer_write_cntv_ctl_el0:
	msr	CNTV_CTL_EL0, x0
	ret
.size aarch64_timer_write_cntv_ctl_el0, . - aarch64_timer_write_cntv_ctl_el0

.p2align 2
.global aarch64_timer_read_cntkctl_el1
.type aarch64_timer_read_cntkctl_el1, %function
aarch64_timer_read_cntkctl_el1:
	mrs	x0, CNTKCTL_EL1
	ret
.size aarch64_timer_read_cntkctl_el1, . - aarch64_timer_read_cntkctl_el1

.p2align 2
.global aarch64_timer_write_cntkctl_el1
.type aarch64_timer_write_cntkctl_el1, %function
aarch64_timer_write_cntkctl_el1:
	msr	CNTKCTL_EL1, x0
	ret
.size aarch64_timer_write_cntkctl_el1, . - aarch64_timer_write_cntkctl_el1
