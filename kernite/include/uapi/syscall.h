/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kernite syscall set.
 *
 * The kernel exposes a single trap — KERNITE_SYS_INVOKE — and every
 * userland operation reaches the kernel through capability invocation
 * dispatch (see invoke.h). The invocation target is the cap_ptr in
 * argument 0; the (cap.obj_type, label) pair in argument 1 selects the
 * operation; remaining arguments carry op-specific payload.
 */

#ifndef KERNITE_UAPI_SYSCALL_H
#define KERNITE_UAPI_SYSCALL_H

/* The single kernel trap. */
#define KERNITE_SYS_INVOKE 0ULL

#endif /* KERNITE_UAPI_SYSCALL_H */
