/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - x86_64 Page Table Implementation
 *
 * x86_64-specific page table constants, macros, and layout definitions.
 * This file should only be included by the x86_64 paging implementation.
 */

#ifndef BOOT_STAGE3_ARCH_X86_PAGING_IMPL_H
#define BOOT_STAGE3_ARCH_X86_PAGING_IMPL_H

#include "../../../common/types.h"

/* =============================================================================
 * Page Table Entry Flags (x86_64 specific)
 * =============================================================================
 */

#define PAGE_PRESENT    (1ULL << 0)     /* P - Page is present */
#define PAGE_WRITE      (1ULL << 1)     /* R/W - Read/Write */
#define PAGE_USER       (1ULL << 2)     /* U/S - User/Supervisor */
#define PAGE_PWT        (1ULL << 3)     /* PWT - Page Write-Through */
#define PAGE_PCD        (1ULL << 4)     /* PCD - Page Cache Disable */
#define PAGE_ACCESSED   (1ULL << 5)     /* A - Accessed */
#define PAGE_DIRTY      (1ULL << 6)     /* D - Dirty */
#define PAGE_HUGE       (1ULL << 7)     /* PS - Page Size (2MB/1GB page) */
#define PAGE_GLOBAL     (1ULL << 8)     /* G - Global */
#define PAGE_NX         (1ULL << 63)    /* NX - No Execute */

/* Common flag combinations */
#define PAGE_RW         (PAGE_PRESENT | PAGE_WRITE)
#define PAGE_RWX        (PAGE_PRESENT | PAGE_WRITE)
#define PAGE_KERNEL_RW  (PAGE_PRESENT | PAGE_WRITE | PAGE_GLOBAL)
#define PAGE_KERNEL_RO  (PAGE_PRESENT | PAGE_GLOBAL)

/* =============================================================================
 * Page Sizes
 * =============================================================================
 */

#define PAGING_SIZE_4K  (4ULL * 1024)
#define PAGING_SIZE_2M  (2ULL * 1024 * 1024)
#define PAGING_SIZE_1G  (1ULL * 1024 * 1024 * 1024)

/* =============================================================================
 * Page Table Index Extraction Macros
 *
 * x86_64 uses 4-level page tables:
 *   PML4 (bits 47:39) -> PDPT (bits 38:30) -> PD (bits 29:21) -> PT (bits 20:12)
 *
 * Each level has 512 entries (9 bits = 0x1FF mask)
 * =============================================================================
 */

#define PML4_INDEX(addr)    (((addr) >> 39) & 0x1FF)
#define PDPT_INDEX(addr)    (((addr) >> 30) & 0x1FF)
#define PD_INDEX(addr)      (((addr) >> 21) & 0x1FF)
#define PT_INDEX(addr)      (((addr) >> 12) & 0x1FF)

/* =============================================================================
 * Kernel Virtual Address Layout (x86_64 Higher Half)
 *
 * x86_64 canonical address space:
 *   0x0000000000000000 - 0x00007FFFFFFFFFFF : User space (128 TB)
 *   0x0000800000000000 - 0xFFFF7FFFFFFFFFFF : Non-canonical hole
 *   0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF : Kernel space (128 TB)
 *
 * SaltyOS kernel layout:
 *   0xFFFF800000000000 : Direct physical memory mapping
 *   0xFFFFFFFF80000000 : Kernel code/data (-2GB, higher half)
 * =============================================================================
 */

#define KERNEL_VIRT_BASE        0xFFFFFFFF80000000ULL   /* -2GB */
#define KERNEL_PHYS_MAP_BASE    0xFFFF800000000000ULL   /* Direct physical map */

#endif /* BOOT_STAGE3_ARCH_X86_PAGING_IMPL_H */
