/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Common Types
 *
 * Basic type definitions for bootloader code.
 * These types support both 32-bit and 64-bit compilation.
 */

#ifndef BOOT_COMMON_TYPES_H
#define BOOT_COMMON_TYPES_H

/* Fixed-width integer types */
typedef unsigned char      uint8_t;
typedef signed char        int8_t;
typedef unsigned short     uint16_t;
typedef signed short       int16_t;
typedef unsigned int       uint32_t;
typedef signed int         int32_t;
typedef unsigned long long uint64_t;
typedef signed long long   int64_t;

/* Size types - architecture dependent */
#if defined(__x86_64__) || defined(__aarch64__)
typedef uint64_t size_t;
typedef int64_t  ssize_t;
typedef uint64_t uintptr_t;
typedef int64_t  intptr_t;
#define SIZE_MAX    UINT64_MAX
#else
/* 32-bit architecture */
typedef uint32_t size_t;
typedef int32_t  ssize_t;
typedef uint32_t uintptr_t;
typedef int32_t  intptr_t;
#define SIZE_MAX    UINT32_MAX
#endif

/* Boolean type */
#ifndef __cplusplus
typedef unsigned char bool;
#define true  1
#define false 0
#endif

/* NULL pointer */
#ifndef NULL
#define NULL ((void*)0)
#endif

/* Architecture identifiers */
#define ARCH_X86_64    1
#define ARCH_AARCH64   2
#define ARCH_RISCV64   3
#define ARCH_X86       4  /* 32-bit x86 */

/* Boot mode identifiers */
#define BOOT_MODE_BIOS 1
#define BOOT_MODE_UEFI 2

/* Alignment and packing macros */
#define PACKED       __attribute__((packed))
#define ALIGNED(n)   __attribute__((aligned(n)))
#define NORETURN     __attribute__((noreturn))
#define UNUSED       __attribute__((unused))
#define SECTION(s)   __attribute__((section(s)))

/* Utility macros */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define MIN(a, b)       ((a) < (b) ? (a) : (b))
#define MAX(a, b)       ((a) > (b) ? (a) : (b))
#define ALIGN_UP(x, a)   (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))

/* Page and sector sizes */
#define PAGE_SIZE_4K   4096
#define PAGE_SIZE_2M   (2 * 1024 * 1024)
#define SECTOR_SIZE    512

/* Memory size helpers */
#define KB(x) ((x) * 1024ULL)
#define MB(x) ((x) * 1024ULL * 1024ULL)
#define GB(x) ((x) * 1024ULL * 1024ULL * 1024ULL)

/* Integer limits */
#define INT8_MIN    (-128)
#define INT8_MAX    127
#define UINT8_MAX   255
#define INT16_MIN   (-32768)
#define INT16_MAX   32767
#define UINT16_MAX  65535
#define INT32_MIN   (-2147483647 - 1)
#define INT32_MAX   2147483647
#define UINT32_MAX  4294967295U
#define INT64_MIN   (-9223372036854775807LL - 1)
#define INT64_MAX   9223372036854775807LL
#define UINT64_MAX  18446744073709551615ULL

#endif /* BOOT_COMMON_TYPES_H */
