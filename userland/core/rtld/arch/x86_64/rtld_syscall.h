/* SPDX-License-Identifier: GPL-2.0-only */
/* x86_64 syscall primitives for rtld */

#ifndef RTLD_ARCH_SYSCALL_H
#define RTLD_ARCH_SYSCALL_H

#include <stdint.h>

static inline void rtld_putc_arch(char c) {
    register uint64_t r10 __asm__("r10") = 0;
    register uint64_t r8  __asm__("r8")  = 0;
    register uint64_t r9  __asm__("r9")  = 0;
    __asm__ volatile("syscall"
        : : "a"((uint64_t)SYS_DEBUG_PUTCHAR), "D"((uint64_t)(unsigned char)c),
            "S"((uint64_t)0), "d"((uint64_t)0),
            "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
}

static inline void rtld_putbuf_arch(const char *buf, uint64_t len) {
    register uint64_t r10 __asm__("r10") = 0;
    register uint64_t r8  __asm__("r8")  = 0;
    register uint64_t r9  __asm__("r9")  = 0;
    __asm__ volatile("syscall"
        : : "a"((uint64_t)SYS_DEBUG_PUTBUF),
            "D"((uint64_t)(uintptr_t)buf),
            "S"(len), "d"((uint64_t)0),
            "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
}

static inline struct rtld_syscall_result rtld_syscall_arch(
    uint64_t syscall_num, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5
) {
    struct rtld_syscall_result result;
    register uint64_t r10 __asm__("r10") = a3;
    register uint64_t r8  __asm__("r8")  = a4;
    register uint64_t r9  __asm__("r9")  = a5;
    __asm__ volatile("syscall"
        : "=a"(result.error), "=d"(result.value)
        : "a"(syscall_num), "D"(a0), "S"(a1), "d"(a2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

/* _start entry */
static inline void __attribute__((naked, noreturn)) rtld_start_arch(void) {
    __asm__ volatile(
        "mov %%rsp, %%rdi\n"
        "call rtld_main\n"
        : : : "memory"
    );
}

#endif
