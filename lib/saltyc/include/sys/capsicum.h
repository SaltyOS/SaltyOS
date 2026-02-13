/* SPDX-License-Identifier: GPL-2.0-only */
/* Capsicum stubs — empty on SaltyOS */
#ifndef __SYS_CAPSICUM_H__
#define __SYS_CAPSICUM_H__

#include <sys/types.h>
#include <stdint.h>

typedef struct cap_rights { uint64_t cr_rights[2]; } cap_rights_t;

#define cap_rights_init(rights, ...) __cap_rights_init(0, rights, 0ULL)
#define cap_rights_set(rights, ...) (rights)

static inline cap_rights_t *
__cap_rights_init(int version, cap_rights_t *rights, ...)
{
    (void)version;
    if (rights) {
        rights->cr_rights[0] = 0;
        rights->cr_rights[1] = 0;
    }
    return rights;
}

static inline int cap_rights_limit(int fd, const cap_rights_t *rights)
{
    (void)fd; (void)rights;
    return 0;
}

static inline int cap_enter(void)
{
    return 0;
}

#endif /* __SYS_CAPSICUM_H__ */
