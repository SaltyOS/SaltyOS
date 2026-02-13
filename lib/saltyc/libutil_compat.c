/* FreeBSD compat — BSD libutil functions for ported FreeBSD utilities */
/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * libutil_compat.c — BSD utility functions for SaltyOS
 *
 * Real implementations of expand_number() and fgetln() used by
 * FreeBSD's head(1) and tail(1).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

/*
 * expand_number — Parse human-readable size strings.
 *
 * Converts strings like "10K", "5M", "2G" into byte counts using
 * 1024-based multipliers. Returns 0 on success, -1 on error (EINVAL
 * for bad format, ERANGE for overflow).
 */
int
expand_number(const char *buf, int64_t *num)
{
    char *endptr;
    int64_t val;
    int shift;

    if (buf == NULL || *buf == '\0') {
        errno = EINVAL;
        return -1;
    }

    val = strtoll(buf, &endptr, 0);

    if (endptr == buf) {
        /* No digits parsed */
        errno = EINVAL;
        return -1;
    }

    shift = 0;
    if (*endptr != '\0') {
        switch (*endptr) {
        case 'k': case 'K':
            shift = 10;
            break;
        case 'm': case 'M':
            shift = 20;
            break;
        case 'g': case 'G':
            shift = 30;
            break;
        case 't': case 'T':
            shift = 40;
            break;
        case 'p': case 'P':
            shift = 50;
            break;
        case 'e': case 'E':
            shift = 60;
            break;
        default:
            errno = EINVAL;
            return -1;
        }
        endptr++;
        /* Allow trailing 'b' or 'B' (e.g., "10KB") */
        if (*endptr == 'b' || *endptr == 'B')
            endptr++;
        /* Nothing else allowed */
        if (*endptr != '\0') {
            errno = EINVAL;
            return -1;
        }
    }

    if (shift > 0) {
        /* Check for overflow before shifting */
        if (val > (INT64_MAX >> shift) || val < (INT64_MIN >> shift)) {
            errno = ERANGE;
            return -1;
        }
        val <<= shift;
    }

    *num = val;
    return 0;
}

/*
 * fgetln — Read one line from a FILE stream.
 *
 * Returns a pointer to a static internal buffer containing the line
 * (including the newline if present), and sets *lenp to the line length.
 * The buffer is only valid until the next call to fgetln().
 *
 * Returns NULL on EOF or error.
 */
char *
fgetln(FILE *fp, size_t *lenp)
{
    static char *buf = NULL;
    static size_t bufsz = 0;
    ssize_t len;

    if (fp == NULL || lenp == NULL) {
        return NULL;
    }

    len = getline(&buf, &bufsz, fp);
    if (len < 0) {
        *lenp = 0;
        return NULL;
    }

    *lenp = (size_t)len;
    return buf;
}

/*
 * humanize_number — Format a byte count into a human-readable string.
 *
 * Converts e.g. 104857600 → "100M". Supports HN_AUTOSCALE, HN_B,
 * HN_NOSPACE, HN_DECIMAL, HN_DIVISOR_1000.
 *
 * Returns the length written (not including NUL), or -1 on error.
 */

#define HN_DECIMAL      0x01
#define HN_NOSPACE      0x02
#define HN_B            0x04
#define HN_DIVISOR_1000 0x08

#define HN_GETSCALE     0x10
#define HN_AUTOSCALE    0x20

int
humanize_number(char *buf, size_t len, int64_t bytes,
    const char *suffix, int scale, int flags)
{
    static const char prefixes_1024[] = " KMGTPE";
    static const char prefixes_1000[] = " kMGTPE";
    const char *prefixes;
    int64_t divisor, val;
    int sign, idx, maxidx, r;
    size_t sufflen;

    if (buf == NULL || len < 1 || suffix == NULL)
        return -1;

    sufflen = strlen(suffix);
    prefixes = (flags & HN_DIVISOR_1000) ? prefixes_1000 : prefixes_1024;
    divisor = (flags & HN_DIVISOR_1000) ? 1000 : 1024;
    maxidx = 6; /* up to 'E' (exbi/exa) */

    sign = 1;
    val = bytes;
    if (val < 0) {
        sign = -1;
        val = -val;
    }

    if (scale & HN_AUTOSCALE) {
        idx = 0;
        while (val >= 10000 && idx < maxidx) {
            val /= divisor;
            idx++;
        }
        /* Try to get at least a single digit before decimal */
        if (val >= divisor && idx < maxidx) {
            val /= divisor;
            idx++;
        }
    } else if (scale & HN_GETSCALE) {
        idx = 0;
        int64_t tmp = val;
        while (tmp >= 10000 && idx < maxidx) {
            tmp /= divisor;
            idx++;
        }
        if (tmp >= divisor && idx < maxidx) {
            tmp /= divisor;
            idx++;
        }
        return idx;
    } else {
        /* Fixed scale */
        idx = scale;
        if (idx < 0) idx = 0;
        if (idx > maxidx) idx = maxidx;
        for (int i = 0; i < idx; i++)
            val /= divisor;
    }

    /* Format into buffer */
    if (idx == 0 && prefixes[0] == ' ') {
        /* No prefix needed — just the number + suffix */
        if (flags & HN_DECIMAL)
            r = snprintf(buf, len, "%lld%s%s",
                (long long)(sign * val),
                (flags & HN_NOSPACE) ? "" : " ",
                suffix);
        else
            r = snprintf(buf, len, "%lld%s%s",
                (long long)(sign * val),
                (flags & HN_NOSPACE) ? "" : " ",
                suffix);
    } else {
        char pfx[3];
        pfx[0] = prefixes[idx];
        pfx[1] = '\0';
        if ((flags & HN_B) && prefixes[idx] != ' ') {
            pfx[1] = 'B';
            pfx[2] = '\0';
        }

        if (flags & HN_DECIMAL) {
            /* Compute one decimal digit by re-doing the division */
            int64_t orig = (bytes < 0) ? -bytes : bytes;
            for (int i = 0; i < idx - 1; i++)
                orig /= divisor;
            int frac = 0;
            if (idx > 0 && orig > 0) {
                frac = (int)((orig * 10 / divisor) % 10);
            }
            if (frac > 0)
                r = snprintf(buf, len, "%lld.%d%s%s%s",
                    (long long)(sign * val), frac,
                    (flags & HN_NOSPACE) ? "" : " ",
                    pfx, suffix);
            else
                r = snprintf(buf, len, "%lld%s%s%s",
                    (long long)(sign * val),
                    (flags & HN_NOSPACE) ? "" : " ",
                    pfx, suffix);
        } else {
            r = snprintf(buf, len, "%lld%s%s%s",
                (long long)(sign * val),
                (flags & HN_NOSPACE) ? "" : " ",
                pfx, suffix);
        }
    }

    if (r < 0 || (size_t)r >= len)
        return -1;

    return r;
}

/*
 * dehumanize_number — Parse a humanized number string back to int64_t.
 * Thin wrapper around expand_number.
 */
int
dehumanize_number(const char *str, int64_t *size)
{
    return expand_number(str, size);
}
