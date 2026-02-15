/* SPDX-License-Identifier: GPL-2.0-only */
/* FreeBSD sys/cdefs.h compatibility */
#ifndef __SYS_CDEFS_H__
#define __SYS_CDEFS_H__

#define __FBSDID(s)
#define __SCCSID(s)
#define __RCSID(s)

#ifndef __BEGIN_DECLS
#ifdef __cplusplus
#define __BEGIN_DECLS   extern "C" {
#define __END_DECLS     }
#else
#define __BEGIN_DECLS
#define __END_DECLS
#endif
#endif

#ifndef __dead2
#define __dead2         __attribute__((noreturn))
#endif
#ifndef __unused
#define __unused        __attribute__((unused))
#endif
#ifndef __packed
#define __packed        __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x)    __attribute__((aligned(x)))
#endif
#ifndef __printflike
#define __printflike(a,b) __attribute__((format(printf,a,b)))
#endif
#ifndef __printf0like
#define __printf0like(a,b) __attribute__((format(printf,a,b)))
#endif
#ifndef __scanflike
#define __scanflike(a,b) __attribute__((format(scanf,a,b)))
#endif
#ifndef __weak_reference
#define __weak_reference(sym,alias)
#endif

#ifndef __restrict
#define __restrict restrict
#endif

/* FreeBSD version macros */
#ifndef __FreeBSD__
#define __FreeBSD__ 14
#endif
#ifndef __FreeBSD_version
#define __FreeBSD_version 1402000
#endif

/* Visibility */
#ifndef __exported
#define __exported __attribute__((visibility("default")))
#endif
#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

/* Type qualifiers */
#ifndef __volatile
#define __volatile volatile
#endif
#ifndef __const
#define __const const
#endif

/* Compiler feature checks */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

/* Minimum/Maximum macros if not already defined */
#ifndef __min
#define __min(a, b) ((a) < (b) ? (a) : (b))
#endif
#ifndef __max
#define __max(a, b) ((a) > (b) ? (a) : (b))
#endif

#endif /* __SYS_CDEFS_H__ */
