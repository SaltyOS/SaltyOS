/* SPDX-License-Identifier: GPL-2.0-only */
/* AArch64 syscall primitives for rtld */

#ifndef RTLD_ARCH_SYSCALL_H
#define RTLD_ARCH_SYSCALL_H

#include <stdint.h>

static inline void rtld_putc_arch(char c) {
    register uint64_t x0 __asm__("x0") = (unsigned char)c;
    register uint64_t x1 __asm__("x1") = 0;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    register uint64_t x4 __asm__("x4") = 0;
    register uint64_t x5 __asm__("x5") = 0;
    register uint64_t x8 __asm__("x8") = SYS_DEBUG_PUTCHAR;
    __asm__ volatile("svc #0"
        : : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory");
}

static inline void rtld_putbuf_arch(const char *buf, uint64_t len) {
    register uint64_t x0 __asm__("x0") = (uint64_t)(uintptr_t)buf;
    register uint64_t x1 __asm__("x1") = len;
    register uint64_t x2 __asm__("x2") = 0;
    register uint64_t x3 __asm__("x3") = 0;
    register uint64_t x4 __asm__("x4") = 0;
    register uint64_t x5 __asm__("x5") = 0;
    register uint64_t x8 __asm__("x8") = SYS_DEBUG_PUTBUF;
    __asm__ volatile("svc #0"
        : : "r"(x0), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory");
}

static inline struct rtld_syscall_result rtld_syscall_arch(
    uint64_t syscall_num, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5
) {
    struct rtld_syscall_result result;
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;
    register uint64_t x5 __asm__("x5") = a5;
    register uint64_t x8 __asm__("x8") = syscall_num;
    __asm__ volatile("svc #0"
        : "+r"(x0), "+r"(x1)
        : "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory");
    result.error = x0;
    result.value = x1;
    return result;
}

/* _start entry */
static inline void __attribute__((naked, noreturn)) rtld_start_arch(void) {
    __asm__ volatile(
        "mov x0, sp\n"
        "bl rtld_main\n"
        : : : "memory"
    );
}

/* Jump to executable entry point */
static inline void __attribute__((noreturn)) rtld_jump_entry_arch(uint64_t sp, void *entry) {
    __asm__ volatile(
        "mov sp, %0\n"
        "mov x29, xzr\n"
        "mov x30, xzr\n"
        "br %1\n"
        : : "r"(sp), "r"(entry)
        : "memory"
    );
    __builtin_unreachable();
}

#endif
