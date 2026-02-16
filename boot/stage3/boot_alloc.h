/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Dynamic Boot Memory Allocator
 *
 * Provides a unified allocation interface for both BIOS and UEFI paths.
 * All allocations are tracked in a record array that is passed to
 * handoff_build_bootinfo() so the kernel's memory map includes every
 * region occupied by the bootloader.
 *
 * BIOS backend: bump allocator over E820 usable regions (>= min_addr).
 * UEFI backend: wrapper around AllocatePages with record tracking.
 */

#ifndef BOOT_STAGE3_BOOT_ALLOC_H
#define BOOT_STAGE3_BOOT_ALLOC_H

#include "../common/types.h"

#define BOOT_ALLOC_MAX_RECORDS 16

/* Allocation purpose tags - mapped to BootInfo memmap types by handoff */
enum BootAllocTag {
    BOOT_ALLOC_PAGE_TABLES = 0,  /* -> MEMMAP_BOOTLOADER */
    BOOT_ALLOC_KERNEL      = 1,  /* -> MEMMAP_KERNEL */
    BOOT_ALLOC_INITRD      = 2,  /* -> MEMMAP_INITRD */
    BOOT_ALLOC_BOOTINFO    = 3,  /* -> MEMMAP_BOOTINFO */
    BOOT_ALLOC_STACK       = 4,  /* -> MEMMAP_BOOTLOADER */
    BOOT_ALLOC_GENERIC     = 5,  /* -> MEMMAP_BOOTLOADER */
};

struct BootAllocRecord {
    uint64_t phys_addr;
    uint64_t size;
    uint32_t tag;     /* enum BootAllocTag */
    uint32_t _pad;
};

struct BootAlloc {
    struct BootAllocRecord records[BOOT_ALLOC_MAX_RECORDS];
    uint32_t record_count;
    uint32_t mode;    /* BOOT_MODE_BIOS or BOOT_MODE_UEFI */

    /* BIOS bump allocator state */
    uint64_t watermark;          /* Next allocation address */
    uint64_t e820_addr;          /* Address of E820Entry array */
    uint32_t e820_count;
    uint32_t _pad;

    /* UEFI boot services pointer (NULL after ExitBootServices) */
    uint64_t uefi_bs;
};

/*
 * Initialize BIOS bump allocator.
 *
 * Allocations start at min_addr and scan E820 usable regions upward.
 * Only regions below 4GB are used (32-bit BIOS compatibility).
 *
 * @param ba: BootAlloc structure to initialize
 * @param e820_addr: Physical address of E820Entry array
 * @param e820_count: Number of E820 entries
 * @param min_addr: Minimum allocation address (typically MB(2))
 */
void boot_alloc_init_bios(struct BootAlloc *ba,
                           uint64_t e820_addr, uint32_t e820_count,
                           uint64_t min_addr);

/*
 * Initialize UEFI allocator wrapper.
 *
 * @param ba: BootAlloc structure to initialize
 * @param bs: EFI_BOOT_SERVICES pointer (cast to uint64_t)
 */
void boot_alloc_init_uefi(struct BootAlloc *ba, uint64_t bs);

/*
 * Allocate memory.
 *
 * BIOS: bump-allocates from E820 usable regions.
 * UEFI: calls AllocatePages.
 *
 * @param ba: Initialized BootAlloc
 * @param size: Bytes to allocate (rounded up to page size)
 * @param align: Alignment (must be power of 2, >= PAGE_SIZE_4K)
 * @param tag: Purpose tag for memory map
 *
 * Returns: Physical address of allocation, or 0 on failure.
 */
uint64_t boot_alloc(struct BootAlloc *ba, uint64_t size,
                     uint64_t align, uint32_t tag);

/*
 * Retroactively register an external allocation.
 *
 * Used for UEFI-allocated buffers (e.g. initrd loaded by uefi_load_file)
 * that should appear in the kernel memory map.
 *
 * @param ba: Initialized BootAlloc
 * @param addr: Physical address of allocation
 * @param size: Size of allocation
 * @param tag: Purpose tag
 */
void boot_alloc_register(struct BootAlloc *ba, uint64_t addr,
                          uint64_t size, uint32_t tag);

/*
 * Finalize UEFI allocator.
 *
 * Clears the Boot Services pointer after ExitBootServices.
 * Must be called before ExitBootServices to prevent accidental use.
 *
 * @param ba: Initialized BootAlloc
 */
void boot_alloc_finalize_uefi(struct BootAlloc *ba);

#endif /* BOOT_STAGE3_BOOT_ALLOC_H */
