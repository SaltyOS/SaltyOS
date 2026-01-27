/* SaltyOS Boot Common Types
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef SALTYOS_BOOT_TYPES_H
#define SALTYOS_BOOT_TYPES_H

/* Fixed-width integer types */
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;

typedef signed char      int8_t;
typedef signed short     int16_t;
typedef signed int       int32_t;
typedef signed long long int64_t;

typedef uint64_t size_t;
typedef int64_t  ssize_t;
typedef uint64_t uintptr_t;

/* Boolean */
#ifndef __cplusplus
#ifndef __bool_true_false_are_defined
#if __STDC_VERSION__ >= 202311L
/* C23: bool is a keyword */
#else
typedef unsigned char bool;
#define true  1
#define false 0
#endif
#define __bool_true_false_are_defined 1
#endif
#endif

/* NULL */
#define NULL ((void *)0)

/* Memory kinds (matching kernel MemoryKind) */
#define MEMORY_USABLE           1
#define MEMORY_RESERVED         2
#define MEMORY_ACPI_RECLAIMABLE 3
#define MEMORY_ACPI_NVS         4
#define MEMORY_BAD              5
#define MEMORY_BOOTLOADER       6
#define MEMORY_KERNEL           7

/* Memory map entry */
struct memory_map_entry {
    uint64_t base;
    uint64_t length;
    uint32_t kind;
    uint32_t reserved;
};

/* Framebuffer info */
struct framebuffer_info {
    uint64_t addr;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint8_t  bpp;
    uint8_t  reserved[3];
};

/* Boot info passed to kernel */
#define BOOT_INFO_MAGIC 0x53414C5459425421ULL  /* "SALTYBTI" */

struct boot_info {
    uint64_t magic;
    struct memory_map_entry *memory_map;
    size_t   memory_map_len;
    uint64_t kernel_phys_base;     /* Kernel physical base address */
    uint64_t kernel_virt_base;     /* Kernel virtual base address */
    uint64_t initrd_addr;
    uint64_t initrd_size;
    char    *cmdline;
    uint64_t rsdp_addr;
    struct framebuffer_info framebuffer;
};

#endif /* SALTYOS_BOOT_TYPES_H */
