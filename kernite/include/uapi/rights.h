/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Capability rights.
 *
 * Bitmask carried inline in every capability slot. Mint operations may
 * only narrow rights; copy/move preserves them.
 */

#ifndef KERNITE_UAPI_RIGHTS_H
#define KERNITE_UAPI_RIGHTS_H

#define KERNITE_RIGHT_NONE       0u
#define KERNITE_RIGHT_READ       (1u << 0)
#define KERNITE_RIGHT_WRITE      (1u << 1)
#define KERNITE_RIGHT_EXECUTE    (1u << 2)
#define KERNITE_RIGHT_GRANT      (1u << 3)
#define KERNITE_RIGHT_MAP        (1u << 4)
#define KERNITE_RIGHT_CONFIGURE  (1u << 5)
#define KERNITE_RIGHT_RESUME     (1u << 6)
#define KERNITE_RIGHT_DUPLICATE  (1u << 7)
#define KERNITE_RIGHT_SIGNAL     (1u << 8)
#define KERNITE_RIGHT_WAIT       (1u << 9)
#define KERNITE_RIGHT_TRANSFER   (1u << 10)

#define KERNITE_RIGHT_ALL        0x7FFu

#endif /* KERNITE_UAPI_RIGHTS_H */
