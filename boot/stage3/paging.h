/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Page Table Setup (Architecture-Neutral Interface)
 *
 * This header defines the architecture-neutral interface for page table
 * operations. The actual implementation is architecture-specific and
 * located in arch/<ARCH>/paging.c.
 *
 * Supported architectures:
 *   - x86_64: 4-level page tables (PML4/PDPT/PD/PT)
 *   - aarch64: (future) 4-level page tables with configurable granule
 */

#ifndef BOOT_STAGE3_PAGING_H
#define BOOT_STAGE3_PAGING_H

#include "../common/types.h"

/* =============================================================================
 * Architecture-Neutral Constants
 *
 * These are common across architectures and used by higher-level code.
 * =============================================================================
 */

/* Common page sizes (used by paging interface) */
#define PAGING_PAGE_4K      (4ULL * 1024)
#define PAGING_PAGE_2M      (2ULL * 1024 * 1024)
#define PAGING_PAGE_1G      (1ULL * 1024 * 1024 * 1024)

/* =============================================================================
 * Public API - Architecture-Neutral Interface
 *
 * These functions are implemented by each architecture's paging.c
 * =============================================================================
 */

/*
 * Initialize page tables for kernel
 *
 * Creates the page table structure required for kernel execution:
 * - Identity map for bootloader use
 * - Higher-half mapping for kernel at architecture-specific base
 * - Direct physical memory map (optional, architecture-dependent)
 *
 * @param kernel_phys: Physical address where kernel is loaded
 * @param kernel_size: Size of kernel in bytes
 *
 * Returns: Physical address of root page table, or 0 on failure
 *          (PML4 on x86_64, TTBR0/TTBR1 on aarch64)
 */
uint64_t paging_init(uint64_t kernel_phys, uint64_t kernel_size);

/*
 * Map a region in the page tables
 *
 * Maps a contiguous physical region to a virtual address range.
 * The mapping granularity is architecture-dependent.
 *
 * @param root_table: Physical address of root page table
 * @param virt: Virtual address to map (aligned to page size)
 * @param phys: Physical address to map to (aligned to page size)
 * @param size: Size of region to map
 * @param flags: Architecture-specific page flags
 *
 * Returns: 0 on success, -1 on failure
 */
int paging_map_region(uint64_t root_table, uint64_t virt, uint64_t phys,
                      uint64_t size, uint64_t flags);

/*
 * Load the page table root into hardware
 *
 * Activates the page tables by loading the root table address
 * into the appropriate control register (CR3 on x86_64, TTBR on aarch64).
 *
 * @param root_table: Physical address of root page table
 */
void paging_load_cr3(uint64_t root_table);

/*
 * Initialize page tables using a dynamically allocated pool
 *
 * Used by the UEFI path where page tables can't use fixed addresses
 * because memory is allocated via Boot Services.
 *
 * @param pt_pool_base: Physical address of page table pool
 * @param pt_pool_size: Size of pool in bytes
 * @param kernel_phys: Physical address where kernel is loaded
 * @param kernel_size: Size of kernel in bytes
 *
 * Returns: Physical address of root page table, or 0 on failure
 */
uint64_t paging_init_dynamic(uint64_t pt_pool_base, uint64_t pt_pool_size,
                              uint64_t kernel_phys, uint64_t kernel_size);

/*
 * Get the kernel virtual base address
 *
 * Returns the architecture-specific kernel virtual base address.
 * This is where the kernel expects to be mapped.
 *
 * Returns: Virtual address of kernel base
 *          (0xFFFFFFFF80000000 on x86_64)
 */
uint64_t paging_get_kernel_virt_base(void);

#endif /* BOOT_STAGE3_PAGING_H */
