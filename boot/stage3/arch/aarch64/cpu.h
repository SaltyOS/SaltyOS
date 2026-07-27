/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - AArch64 CPU Operations
 */

#ifndef BOOT_STAGE3_ARCH_AARCH64_CPU_H
#define BOOT_STAGE3_ARCH_AARCH64_CPU_H

#include "../../../common/types.h"
#include "paging_impl.h"

/* Memory barrier instructions */
static inline void dsb_sy(void) { __asm__ volatile("dsb sy" ::: "memory"); }

static inline void dsb_ish(void) { __asm__ volatile("dsb ish" ::: "memory"); }

static inline void isb(void) { __asm__ volatile("isb" ::: "memory"); }

static inline void wfi(void) { __asm__ volatile("wfi"); }

static inline void mask_all_exceptions(void) {
  __asm__ volatile("msr DAIFSet, #0xF" ::: "memory");
  isb();
}

static inline uint64_t current_el(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, CurrentEL" : "=r"(val));
  return val >> 2;
}

static inline uint64_t read_ctr_el0(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, CTR_EL0" : "=r"(val));
  return val;
}

static inline uint64_t dcache_line_size(void) {
  uint64_t shift = (read_ctr_el0() >> 16) & 0xF;
  uint64_t line = 4ULL << shift;
  return line ? line : 64;
}

static inline uint64_t icache_line_size(void) {
  uint64_t shift = read_ctr_el0() & 0xF;
  uint64_t line = 4ULL << shift;
  return line ? line : 64;
}

static inline void flush_dcache_poc_range(uint64_t addr, uint64_t size) {
  if (size == 0)
    return;

  uint64_t line = dcache_line_size();
  uint64_t start = addr & ~(line - 1);
  uint64_t end = (addr + size + line - 1) & ~(line - 1);

  for (uint64_t cur = start; cur < end; cur += line)
    __asm__ volatile("dc civac, %0" ::"r"(cur) : "memory");

  dsb_sy();
}

static inline void invalidate_icache_range(uint64_t addr, uint64_t size) {
  if (size == 0)
    return;

  uint64_t line = icache_line_size();
  uint64_t start = addr & ~(line - 1);
  uint64_t end = (addr + size + line - 1) & ~(line - 1);

  dsb_sy();

  for (uint64_t cur = start; cur < end; cur += line)
    __asm__ volatile("ic ivau, %0" ::"r"(cur) : "memory");

  dsb_sy();
  isb();
}

/* System register access */
static inline uint64_t read_sctlr_el1(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, SCTLR_EL1" : "=r"(val));
  return val;
}

static inline uint64_t read_sctlr_el2(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, SCTLR_EL2" : "=r"(val));
  return val;
}

static inline void write_sctlr_el1(uint64_t val) {
  __asm__ volatile("msr SCTLR_EL1, %0" ::"r"(val));
  isb();
}

static inline void write_sctlr_el2(uint64_t val) {
  __asm__ volatile("msr SCTLR_EL2, %0" ::"r"(val));
  isb();
}

static inline uint64_t read_tcr_el1(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, TCR_EL1" : "=r"(val));
  return val;
}

static inline uint64_t read_tcr_el2(void) {
  uint64_t val;
  __asm__ volatile("mrs %0, TCR_EL2" : "=r"(val));
  return val;
}

static inline void write_tcr_el1(uint64_t val) {
  __asm__ volatile("msr TCR_EL1, %0" ::"r"(val));
  isb();
}

static inline void write_tcr_el2(uint64_t val) {
  __asm__ volatile("msr TCR_EL2, %0" ::"r"(val));
  isb();
}

static inline void write_mair_el1(uint64_t val) {
  __asm__ volatile("msr MAIR_EL1, %0" ::"r"(val));
  isb();
}

static inline void write_mair_el2(uint64_t val) {
  __asm__ volatile("msr MAIR_EL2, %0" ::"r"(val));
  isb();
}

static inline void write_ttbr0_el1(uint64_t val) {
  __asm__ volatile("msr TTBR0_EL1, %0" ::"r"(val));
  isb();
}

static inline void write_ttbr0_el2(uint64_t val) {
  __asm__ volatile("msr TTBR0_EL2, %0" ::"r"(val));
  isb();
}

static inline uint64_t build_tcr_el2_value(void) {
  uint64_t tcr = read_tcr_el2();

  /* Preserve firmware-programmed RES1 and implementation-defined bits
   * while replacing the translation geometry/cacheability fields that
   * Stage 3 relies on for the native EL2 host mapping. */
  tcr &= ~((0x3FULL << 0) | (1ULL << 7) | (0xFFULL << 8) | (0x7ULL << 16));
  tcr |= TCR_EL2_VALUE;
  return tcr;
}

static inline void write_ttbr1_el1(uint64_t val) {
  __asm__ volatile("msr TTBR1_EL1, %0" ::"r"(val));
  isb();
}

static inline void tlbi_vmalle1(void) {
  __asm__ volatile("tlbi vmalle1" ::: "memory");
  dsb_sy();
  isb();
}

static inline void tlbi_alle2(void) {
  __asm__ volatile("tlbi alle2" ::: "memory");
  dsb_sy();
  isb();
}

static inline void paging_load_root_current_el(uint64_t root_table) {
  if (current_el() == 2) {
    write_mair_el2(MAIR_EL1_VALUE);
    write_tcr_el2(build_tcr_el2_value());
    dsb_sy();
    write_ttbr0_el2(root_table);
    dsb_sy();
    tlbi_alle2();

    uint64_t sctlr = read_sctlr_el2();
    sctlr |= (1ULL << 0);  /* M bit: enable MMU */
    sctlr |= (1ULL << 2);  /* C bit: data cache enable */
    sctlr |= (1ULL << 12); /* I bit: instruction cache enable */
    sctlr &= ~(1ULL << 1); /* A bit: disable alignment checking */
    write_sctlr_el2(sctlr);
  } else {
    write_mair_el1(MAIR_EL1_VALUE);
    write_tcr_el1(TCR_EL1_VALUE);
    dsb_sy();
    write_ttbr0_el1(root_table);
    write_ttbr1_el1(root_table);
    dsb_sy();
    tlbi_vmalle1();

    uint64_t sctlr = read_sctlr_el1();
    sctlr |= (1ULL << 0);  /* M bit: enable MMU */
    sctlr |= (1ULL << 2);  /* C bit: data cache enable */
    sctlr |= (1ULL << 12); /* I bit: instruction cache enable */
    sctlr |= (1ULL << 26); /* UCI: allow EL0 IC IVAU / DC CVAU instructions */
    sctlr &= ~(1ULL << 1); /* A bit: disable alignment checking */
    write_sctlr_el1(sctlr);
  }
}

#endif /* BOOT_STAGE3_ARCH_AARCH64_CPU_H */
