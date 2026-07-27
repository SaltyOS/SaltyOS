/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Kernel Handoff
 *
 * Builds BootInfo and transfers control to the kernel.
 */

#ifndef BOOT_STAGE3_HANDOFF_H
#define BOOT_STAGE3_HANDOFF_H

#include "../common/bootinfo_tlv.h"
#include "../common/stage2_info.h"
#include "../common/types.h"
#include "boot_alloc.h"
#include "elf.h"

/*
 * Build BootInfo structure
 *
 * @param buffer: Buffer to build BootInfo in
 * @param buffer_size: Size of buffer
 * @param stage2_info: Stage2Info from Stage 2
 * @param kernel: Kernel load result
 * @param initrd_addr: Initrd physical address (0 if none)
 * @param initrd_size: Initrd size (0 if none)
 * @param alloc_records: BootAlloc allocation records
 * @param alloc_record_count: Number of allocation records
 *
 * Returns: Pointer to completed BootInfo, or NULL on failure
 */
struct BootInfoHeader *handoff_build_bootinfo(
    void *buffer, size_t buffer_size, struct Stage2Info *stage2_info,
    uint32_t extra_flags, struct ElfLoadResult *kernel, uint64_t initrd_addr,
    uint64_t initrd_size, const struct BootAllocRecord *alloc_records,
    uint32_t alloc_record_count);

#endif /* BOOT_STAGE3_HANDOFF_H */
