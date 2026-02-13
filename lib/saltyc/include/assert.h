/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASSERT_H__
#define __ASSERT_H__

extern void abort(void);

#ifdef NDEBUG
#define assert(expr) ((void)0)
#else
#define assert(expr) \
    ((expr) ? (void)0 : abort())
#endif

#endif /* __ASSERT_H__ */
