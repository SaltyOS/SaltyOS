/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * 64-bit unsigned division and modulo for 32-bit code
 *
 * GCC/Clang 32-bit code needs these helper functions for 64-bit operations.
 * These are normally provided by libgcc/compiler-rt, but we're freestanding.
 */

#include "types.h"

/*
 * 64-bit unsigned division
 */
uint64_t __udivdi3(uint64_t num, uint64_t den)
{
    uint64_t quot = 0, qbit = 1;

    if (den == 0) {
        /* Division by zero - return 0 (could also hang) */
        return 0;
    }

    /* Left-align divisor and count */
    while ((int64_t)den >= 0 && den < num) {
        den <<= 1;
        qbit <<= 1;
    }

    while (qbit) {
        if (den <= num) {
            num -= den;
            quot += qbit;
        }
        den >>= 1;
        qbit >>= 1;
    }

    return quot;
}

/*
 * 64-bit unsigned modulo
 */
uint64_t __umoddi3(uint64_t num, uint64_t den)
{
    uint64_t qbit = 1;

    if (den == 0) {
        return 0;
    }

    while ((int64_t)den >= 0 && den < num) {
        den <<= 1;
        qbit <<= 1;
    }

    while (qbit) {
        if (den <= num) {
            num -= den;
        }
        den >>= 1;
        qbit >>= 1;
    }

    return num;
}

/*
 * 64-bit signed division
 */
int64_t __divdi3(int64_t num, int64_t den)
{
    int neg = 0;

    if (num < 0) {
        num = -num;
        neg = !neg;
    }
    if (den < 0) {
        den = -den;
        neg = !neg;
    }

    uint64_t result = __udivdi3((uint64_t)num, (uint64_t)den);
    return neg ? -(int64_t)result : (int64_t)result;
}

/*
 * 64-bit signed modulo
 */
int64_t __moddi3(int64_t num, int64_t den)
{
    int neg = 0;

    if (num < 0) {
        num = -num;
        neg = 1;
    }
    if (den < 0) {
        den = -den;
    }

    uint64_t result = __umoddi3((uint64_t)num, (uint64_t)den);
    return neg ? -(int64_t)result : (int64_t)result;
}
