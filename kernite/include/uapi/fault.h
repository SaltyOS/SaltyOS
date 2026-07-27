/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Fault delivery labels.
 *
 * When a thread takes an unhandled fault and has a fault MessagePipe
 * bound (KERNITE_INV_TCB_SET_FAULT_PIPE), the kernel synthesises an
 * MpRecord whose label is one of these constants and the record words
 * carry diagnostic state.
 *
 * Layout per fault type:
 *
 *   PAGE_FAULT (length=4):
 *     words[0] = faulting virtual address
 *     words[1] = arch-encoded cause bits
 *     words[2] = faulting instruction pointer
 *     words[3] = is_instruction_fetch (0 = data, 1 = instr)
 *
 *   ILLEGAL_INSTRUCTION / BREAKPOINT (length=4):
 *     words[0] = exception vector / EC
 *     words[1] = error code / ESR
 *     words[2] = faulting instruction pointer
 *     words[3] = faulting stack pointer
 *
 *   USER_EXCEPTION (length=4):
 *     same shape as ILLEGAL_INSTRUCTION.
 *
 *   OOM (length=3):
 *     words[0] = faulting address (page-aligned)
 *     words[1] = faulting instruction pointer
 *     words[2] = reason code (0 = anon commit failed)
 *
 *   CAP (length=2):
 *     words[0] = invocation cap_ptr that triggered the fault
 *     words[1] = error code (KERNITE_ERR_*)
 */

#ifndef KERNITE_UAPI_FAULT_H
#define KERNITE_UAPI_FAULT_H

#include <stdint.h>

#define KERNITE_FAULT_NONE                0ULL
#define KERNITE_FAULT_PAGE_FAULT          1ULL
#define KERNITE_FAULT_ILLEGAL_INSTRUCTION 2ULL
#define KERNITE_FAULT_BREAKPOINT          3ULL
#define KERNITE_FAULT_USER_EXCEPTION      4ULL
#define KERNITE_FAULT_OOM                 5ULL
#define KERNITE_FAULT_CAP                 6ULL

#endif /* KERNITE_UAPI_FAULT_H */
