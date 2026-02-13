/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __STDARG_H__
#define __STDARG_H__

typedef __builtin_va_list va_list;
#define va_start(ap, param) __builtin_va_start(ap, param)
#define va_end(ap) __builtin_va_end(ap)
#define va_arg(ap, type) __builtin_va_arg(ap, type)
#define va_copy(dest, src) __builtin_va_copy(dest, src)

#endif /* __STDARG_H__ */
