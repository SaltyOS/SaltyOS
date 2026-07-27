/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kernite error codes.
 *
 * Returned from KERNITE_SYS_INVOKE in the error register (architecture-
 * specific — see syscall ABI doc). 0 is always success; non-zero values
 * are stable and dense.
 *
 * Wire size is 64 bits. Callers must treat unknown codes as opaque;
 * the kernel may grow this table in compatible directions (new codes
 * at the tail).
 */

#ifndef KERNITE_UAPI_ERROR_H
#define KERNITE_UAPI_ERROR_H

#define KERNITE_OK                       0ULL

/* Invocation-target / cap resolution failures. */
#define KERNITE_ERR_INVALID_CAPABILITY   1ULL
#define KERNITE_ERR_INVALID_OPERATION    2ULL
#define KERNITE_ERR_INSUFFICIENT_RIGHTS  3ULL
#define KERNITE_ERR_INVALID_ARGUMENT     4ULL

/* Resource exhaustion / shape constraints. */
#define KERNITE_ERR_OUT_OF_MEMORY        5ULL
#define KERNITE_ERR_NOT_FOUND            6ULL
#define KERNITE_ERR_BUSY                 7ULL
#define KERNITE_ERR_ALREADY_EXISTS       8ULL

/* Blocking-op control flow. */
#define KERNITE_ERR_WOULD_BLOCK          9ULL
#define KERNITE_ERR_BAD_ADDRESS          10ULL
#define KERNITE_ERR_OUT_OF_RANGE         11ULL
#define KERNITE_ERR_CANCELLED            12ULL
#define KERNITE_ERR_RESTART              13ULL
#define KERNITE_ERR_DEADLOCK             14ULL
#define KERNITE_ERR_INTERRUPTED          15ULL

/* Size / capability constraints. */
#define KERNITE_ERR_TOO_LARGE            16ULL
#define KERNITE_ERR_NOT_SUPPORTED        17ULL
#define KERNITE_ERR_READONLY             18ULL

/* Slot / mapping conflicts. */
#define KERNITE_ERR_SLOT_OCCUPIED        19ULL
#define KERNITE_ERR_ALREADY_MAPPED       20ULL

/* IPC / event surface. */
#define KERNITE_ERR_PEER_CLOSED          21ULL
#define KERNITE_ERR_QUEUE_OVERFLOW       22ULL
#define KERNITE_ERR_WATCH_CANCELLED      23ULL

/* System-level failures. */
#define KERNITE_ERR_ABI_MISMATCH         25ULL
#define KERNITE_ERR_IO_ERROR             26ULL
#define KERNITE_ERR_TIMED_OUT            27ULL
#define KERNITE_ERR_PENDING              28ULL

/*
 * Kernel-side resource pool exhaustion that is NOT plain memory.
 * Distinct from KERNITE_ERR_OUT_OF_MEMORY: capability-slot freelist,
 * deadline-queue node pool, fault-pipe carrier pool, and similar
 * fixed-size kernel reservoirs surface this when full. Userland MUST
 * treat OUT_OF_MEMORY and INSUFFICIENT_RESOURCES as separate signals
 * — different mitigations apply (free user memory vs. wait / shrink
 * pool pressure / give up).
 */
#define KERNITE_ERR_INSUFFICIENT_RESOURCES 29ULL

#endif /* KERNITE_UAPI_ERROR_H */
