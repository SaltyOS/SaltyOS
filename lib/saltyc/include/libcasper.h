/* SPDX-License-Identifier: GPL-2.0-only */
/* Casper compatibility — no Capsicum on SaltyOS */
#ifndef __LIBCASPER_H__
#define __LIBCASPER_H__

typedef void *cap_channel_t;

static inline cap_channel_t *cap_init(void) { return (cap_channel_t *)0; }
static inline void cap_close(cap_channel_t *chan) { (void)chan; }

#endif /* __LIBCASPER_H__ */
