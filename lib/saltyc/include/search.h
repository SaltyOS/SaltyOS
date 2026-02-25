/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __SEARCH_H__
#define __SEARCH_H__

#include <stddef.h>

typedef enum {
    preorder,
    postorder,
    endorder,
    leaf
} VISIT;

extern void *tsearch(const void *key, void **rootp,
                     int (*compar)(const void *, const void *));
extern void *tfind(const void *key, void *const *rootp,
                   int (*compar)(const void *, const void *));
extern void *tdelete(const void *key, void **rootp,
                     int (*compar)(const void *, const void *));
extern void  twalk(const void *root,
                   void (*action)(const void *, VISIT, int));

#endif /* __SEARCH_H__ */
