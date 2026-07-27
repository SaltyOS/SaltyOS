/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - x86 CPU Operations
 *
 * Common CPU operations for x86 (both 32-bit and 64-bit).
 */

#ifndef BOOT_STAGE3_ARCH_X86_CPU_H
#define BOOT_STAGE3_ARCH_X86_CPU_H

#include "../../../common/types.h"

/* I/O port operations */
static inline void outb(uint16_t port, uint8_t value) {
  __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value;
  __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

static inline void outw(uint16_t port, uint16_t value) {
  __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint16_t inw(uint16_t port) {
  uint16_t value;
  __asm__ volatile("inw %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

static inline void outl(uint16_t port, uint32_t value) {
  __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint32_t inl(uint16_t port) {
  uint32_t value;
  __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

/* Control register operations */
static inline uint32_t read_cr0(void) {
  uint32_t value;
  __asm__ volatile("mov %%cr0, %0" : "=r"(value));
  return value;
}

static inline void write_cr0(uint32_t value) {
  __asm__ volatile("mov %0, %%cr0" : : "r"(value));
}

static inline uint32_t read_cr3(void) {
  uint32_t value;
  __asm__ volatile("mov %%cr3, %0" : "=r"(value));
  return value;
}

static inline void write_cr3(uint32_t value) {
  __asm__ volatile("mov %0, %%cr3" : : "r"(value));
}

static inline uint32_t read_cr4(void) {
  uint32_t value;
  __asm__ volatile("mov %%cr4, %0" : "=r"(value));
  return value;
}

static inline void write_cr4(uint32_t value) {
  __asm__ volatile("mov %0, %%cr4" : : "r"(value));
}

/* CPUID */
static inline void cpuid(uint32_t leaf, uint32_t *eax, uint32_t *ebx,
                         uint32_t *ecx, uint32_t *edx) {
  __asm__ volatile("cpuid"
                   : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                   : "a"(leaf), "c"(0));
}

/* MSR operations */
static inline uint64_t read_msr(uint32_t msr) {
  uint32_t lo, hi;
  __asm__ volatile("rdmsr" : "=a"(lo), "=d"(hi) : "c"(msr));
  return ((uint64_t)hi << 32) | lo;
}

static inline void write_msr(uint32_t msr, uint64_t value) {
  uint32_t lo = (uint32_t)value;
  uint32_t hi = (uint32_t)(value >> 32);
  __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

/* Halt CPU */
static inline void cpu_halt(void) { __asm__ volatile("cli; hlt"); }

/* Disable interrupts */
static inline void cli(void) { __asm__ volatile("cli"); }

/* Enable interrupts */
static inline void sti(void) { __asm__ volatile("sti"); }

/* Memory barrier */
static inline void memory_barrier(void) { __asm__ volatile("" : : : "memory"); }

/* CPUID feature flags */
#define CPUID_FEAT_EDX_PAE (1 << 6)
#define CPUID_FEAT_EDX_PSE (1 << 3)
#define CPUID_FEAT_EDX_MSR (1 << 5)

/* Extended CPUID for long mode detection */
static inline bool cpu_supports_long_mode(void) {
  uint32_t eax, ebx, ecx, edx;

  /* Check if extended CPUID is supported */
  cpuid(0x80000000, &eax, &ebx, &ecx, &edx);
  if (eax < 0x80000001)
    return false;

  /* Check for long mode support (bit 29 in EDX) */
  cpuid(0x80000001, &eax, &ebx, &ecx, &edx);
  return (edx & (1 << 29)) != 0;
}

#endif /* BOOT_STAGE3_ARCH_X86_CPU_H */
