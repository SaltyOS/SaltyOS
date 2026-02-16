/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 Common Definitions
 *
 * Stage 3 is the policy loader - it loads and relocates the kernel,
 * builds BootInfo, and transfers control to the kernel.
 */

#ifndef BOOT_STAGE3_STAGE3_H
#define BOOT_STAGE3_STAGE3_H

#include "../common/types.h"
#include "../common/manifest.h"
#include "../common/bootinfo_tlv.h"
#include "../common/stage2_info.h"

/* Stage 3 version */
#define STAGE3_VERSION_MAJOR 1
#define STAGE3_VERSION_MINOR 0
#define STAGE3_VERSION_PATCH 0

/* Error codes */
#define STAGE3_OK               0
#define STAGE3_ERR_STAGE2_INFO  1
#define STAGE3_ERR_MANIFEST     2
#define STAGE3_ERR_NO_KERNEL    3
#define STAGE3_ERR_ELF_INVALID  4
#define STAGE3_ERR_ELF_LOAD     5
#define STAGE3_ERR_MEMORY       6
#define STAGE3_ERR_PAGING       7
#define STAGE3_ERR_DISK         8

/* Kernel loading constraints */
#define KERNEL_MIN_LOAD_ADDR    MB(2)       /* Load kernel at >=2MB */
#define KERNEL_LOAD_ALIGN       MB(2)       /* 2MB alignment for huge pages */
#define KERNEL_LOWMEM_ALIGN     KB(4)       /* 4KB alignment for low-memory load path */
#define LOWMEM_TOTAL_BYTES      MB(8)       /* BIOS low-memory mode threshold */
#define KERNEL_MAX_SIZE         MB(64)      /* Maximum kernel size */

/* BootInfo buffer size (dynamically allocated by BootAlloc) */
#define BOOTINFO_BUFFER_SIZE    KB(16)      /* 16KB for BootInfo */

/* Initial kernel stack size (dynamically allocated by BootAlloc) */
#define KERNEL_STACK_SIZE       KB(64)      /* 64KB stack */

/* ELF file scratch buffer (extended memory below kernel load area) */
#define FILE_SCRATCH_ADDR       0x100000    /* 1MB - free extended memory */
#define FILE_SCRATCH_LIMIT      0x180000    /* 1.5MB - before kernel stack */

/* Global Stage 3 context */
struct Stage3Context {
    struct Stage2Info *stage2_info;
    struct BootManifestHeader *manifest;
    struct BootInfoBuilder bootinfo_builder;

    /* Kernel info */
    uint64_t kernel_phys_base;
    uint64_t kernel_virt_base;
    uint64_t kernel_size;
    uint64_t kernel_entry;

    /* Initrd info (optional) */
    uint64_t initrd_phys_addr;
    uint64_t initrd_size;

    /* Kernel stack (dynamically allocated) */
    uint64_t kernel_stack_top;

    /* Boot disk */
    uint8_t boot_drive;
};

/* Global context */
extern struct Stage3Context g_ctx;

/* Entry point (called from assembly/stage2) */
void stage3_entry(struct Stage2Info *info);

/* Panic and halt */
NORETURN void stage3_panic(const char *msg);

#endif /* BOOT_STAGE3_STAGE3_H */
