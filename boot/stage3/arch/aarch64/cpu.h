/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - AArch64 CPU Operations
 */

#ifndef BOOT_STAGE3_ARCH_AARCH64_CPU_H
#define BOOT_STAGE3_ARCH_AARCH64_CPU_H

#include "../../../common/types.h"

/* Memory barrier instructions */
static inline void dsb_sy(void)
{
    __asm__ volatile("dsb sy" ::: "memory");
}

static inline void dsb_ish(void)
{
    __asm__ volatile("dsb ish" ::: "memory");
}

static inline void isb(void)
{
    __asm__ volatile("isb" ::: "memory");
}

static inline void wfi(void)
{
    __asm__ volatile("wfi");
}

/* System register access */
static inline uint64_t read_sctlr_el1(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, SCTLR_EL1" : "=r"(val));
    return val;
}

static inline void write_sctlr_el1(uint64_t val)
{
    __asm__ volatile("msr SCTLR_EL1, %0" :: "r"(val));
    isb();
}

static inline uint64_t read_tcr_el1(void)
{
    uint64_t val;
    __asm__ volatile("mrs %0, TCR_EL1" : "=r"(val));
    return val;
}

static inline void write_tcr_el1(uint64_t val)
{
    __asm__ volatile("msr TCR_EL1, %0" :: "r"(val));
    isb();
}

static inline void write_mair_el1(uint64_t val)
{
    __asm__ volatile("msr MAIR_EL1, %0" :: "r"(val));
    isb();
}

static inline void write_ttbr0_el1(uint64_t val)
{
    __asm__ volatile("msr TTBR0_EL1, %0" :: "r"(val));
    isb();
}

static inline void write_ttbr1_el1(uint64_t val)
{
    __asm__ volatile("msr TTBR1_EL1, %0" :: "r"(val));
    isb();
}

static inline void tlbi_vmalle1(void)
{
    __asm__ volatile("tlbi vmalle1" ::: "memory");
    dsb_ish();
    isb();
}

#endif /* BOOT_STAGE3_ARCH_AARCH64_CPU_H */
