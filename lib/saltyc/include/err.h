/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ERR_H__
#define __ERR_H__

#include <stdarg.h>

void err(int eval, const char *fmt, ...) __attribute__((noreturn, format(printf, 2, 3)));
void errx(int eval, const char *fmt, ...) __attribute__((noreturn, format(printf, 2, 3)));
void warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void warnx(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

void verr(int eval, const char *fmt, va_list ap) __attribute__((noreturn));
void verrx(int eval, const char *fmt, va_list ap) __attribute__((noreturn));
void vwarn(const char *fmt, va_list ap);
void vwarnx(const char *fmt, va_list ap);

void errc(int eval, int code, const char *fmt, ...) __attribute__((noreturn, format(printf, 3, 4)));
void warnc(int code, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#endif /* __ERR_H__ */
