/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * VSpace mapping ABI — region kinds + page flag bits.
 *
 * Userland tags every VSPACE_MAP request with a KERNITE_REGION_KIND_*
 * value so the kernel can classify and gate per-VMA policy (stack
 * growth, COW, demand-fault routing). Page flags are the low-level
 * permission bits stored in the PTE; passed inline with VSPACE_MAP /
 * VSPACE_PROTECT requests.
 */

#ifndef KERNITE_UAPI_VMEM_H
#define KERNITE_UAPI_VMEM_H

/* ---- VMA region classification (passed to VSPACE_MAP). ---- */

#define KERNITE_REGION_KIND_NONE       0u
#define KERNITE_REGION_KIND_IMAGE_TEXT 1u
#define KERNITE_REGION_KIND_IMAGE_DATA 2u
#define KERNITE_REGION_KIND_IMAGE_BSS  3u
#define KERNITE_REGION_KIND_HEAP       4u
#define KERNITE_REGION_KIND_STACK      5u
#define KERNITE_REGION_KIND_MMAP       6u
#define KERNITE_REGION_KIND_SHARED_LIB 7u

/* ---- Page flag bits (PTE-visible). ---- */

#define KERNITE_PAGE_FLAG_NONE       0u
#define KERNITE_PAGE_FLAG_WRITABLE   (1u << 0)
#define KERNITE_PAGE_FLAG_USER       (1u << 1)
#define KERNITE_PAGE_FLAG_EXECUTABLE (1u << 2)
#define KERNITE_PAGE_FLAG_COW        (1u << 3)
#define KERNITE_PAGE_FLAG_DEMAND     (1u << 4)
#define KERNITE_PAGE_FLAG_NOCACHE    (1u << 5)
#define KERNITE_VSPACE_MAP_MO_FLAG_DEMAND (1u << 6)
#define KERNITE_PAGE_FLAG_WRITETHROUGH (1u << 7)

#endif /* KERNITE_UAPI_VMEM_H */
