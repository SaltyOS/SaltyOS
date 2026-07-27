/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kernite ABI version.
 *
 * Bumped on any wire-format / dispatch table / object layout change
 * that crosses the syscall boundary. Userland verifies at startup via
 * the SystemInfo cap; mismatch → KERNITE_ERR_ABI_MISMATCH.
 */

#ifndef KERNITE_UAPI_VERSION_H
#define KERNITE_UAPI_VERSION_H

#define KERNITE_ABI_MAJOR 0u
#define KERNITE_ABI_MINOR 0u
#define KERNITE_ABI_PATCH 2u

/*
 * Packed (major << 32) | (minor << 16) | patch — used for a single
 * 64-bit equality check at userland startup. Bump alongside the
 * MAJOR / MINOR / PATCH triple above when the ABI changes.
 */
#define KERNITE_ABI_VERSION 0x0000000000000002ULL

#define KERNITE_ABI_VERSION_STR "0.0.2"

#endif /* KERNITE_UAPI_VERSION_H */
