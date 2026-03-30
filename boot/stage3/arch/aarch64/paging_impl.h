/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - AArch64 Page Table Constants
 *
 * 4KB granule, 4-level page tables (L0-L3)
 * L0: 512GB per entry (bits 47:39)
 * L1: 1GB per entry (bits 38:30)
 * L2: 2MB per entry (bits 29:21)
 * L3: 4KB per entry (bits 20:12)
 */

#ifndef BOOT_STAGE3_ARCH_AARCH64_PAGING_IMPL_H
#define BOOT_STAGE3_ARCH_AARCH64_PAGING_IMPL_H

/* Descriptor types */
#define PTE_VALID           (1ULL << 0)
#define PTE_TABLE           (1ULL << 1)  /* Table descriptor (L0-L2) */
#define PTE_BLOCK           (0ULL << 1)  /* Block descriptor (L1-L2) */
#define PTE_PAGE            (1ULL << 1)  /* Page descriptor (L3) */

/* Lower attributes */
#define PTE_ATTR_IDX(n)     (((uint64_t)(n)) << 2) /* AttrIndx[2:0] for MAIR */
#define PTE_NS              (1ULL << 5)
#define PTE_AP_RW_EL1       (0ULL << 6) /* AP[2:1] = 00: RW at EL1, no EL0 */
#define PTE_AP_RW_ALL       (1ULL << 6) /* AP[2:1] = 01: RW at EL1 and EL0 */
#define PTE_AP_RO_EL1       (2ULL << 6) /* AP[2:1] = 10: RO at EL1, no EL0 */
#define PTE_AP_RO_ALL       (3ULL << 6) /* AP[2:1] = 11: RO at EL1 and EL0 */
#define PTE_SH_NS           (0ULL << 8) /* Non-shareable */
#define PTE_SH_OS           (2ULL << 8) /* Outer Shareable */
#define PTE_SH_IS           (3ULL << 8) /* Inner Shareable */
#define PTE_AF              (1ULL << 10) /* Access Flag */

/* Upper attributes */
#define PTE_PXN             (1ULL << 53) /* Privileged Execute Never */
#define PTE_UXN             (1ULL << 54) /* Unprivileged Execute Never */

/* Address mask for output address (bits 47:12) */
#define PTE_ADDR_MASK       0x0000FFFFFFFFF000ULL

/* MAIR indices (matching kernel MAIR_EL1 config) */
#define MAIR_IDX_DEVICE_nGnRnE  0  /* Device non-Gathering, non-Reordering, non-Early */
#define MAIR_IDX_NORMAL_NC       1  /* Normal Non-Cacheable */
#define MAIR_IDX_NORMAL_WB       2  /* Normal Write-Back Cacheable */

/* MAIR_EL1 value encoding */
#define MAIR_DEVICE_nGnRnE  0x00ULL
#define MAIR_NORMAL_NC       0x44ULL  /* Inner/Outer Non-Cacheable */
#define MAIR_NORMAL_WB       0xFFULL  /* Inner/Outer Write-Back, Read-Allocate, Write-Allocate */

#define MAIR_EL1_VALUE ( \
    (MAIR_DEVICE_nGnRnE << (8 * MAIR_IDX_DEVICE_nGnRnE)) | \
    (MAIR_NORMAL_NC << (8 * MAIR_IDX_NORMAL_NC)) | \
    (MAIR_NORMAL_WB << (8 * MAIR_IDX_NORMAL_WB)) \
)

/* Standard block/page attribute combos */
#define PTE_KERNEL_CODE     (PTE_VALID | PTE_AF | PTE_SH_IS | PTE_ATTR_IDX(MAIR_IDX_NORMAL_WB) | PTE_AP_RO_EL1 | PTE_UXN)
#define PTE_KERNEL_DATA     (PTE_VALID | PTE_AF | PTE_SH_IS | PTE_ATTR_IDX(MAIR_IDX_NORMAL_WB) | PTE_AP_RW_EL1 | PTE_PXN | PTE_UXN)
#define PTE_KERNEL_RWX      (PTE_VALID | PTE_AF | PTE_SH_IS | PTE_ATTR_IDX(MAIR_IDX_NORMAL_WB) | PTE_AP_RW_EL1)
#define PTE_DEVICE          (PTE_VALID | PTE_AF | PTE_SH_NS | PTE_ATTR_IDX(MAIR_IDX_DEVICE_nGnRnE) | PTE_AP_RW_EL1 | PTE_PXN | PTE_UXN)

/* Kernel virtual base for higher-half mapping.
 *
 * With TCR_EL1/EL2 configured for a 48-bit VA space (T0SZ/T1SZ = 16), the
 * upper canonical range starts at 0xFFFF800000000000. 0xFFFF000000000000 is
 * non-canonical for 48-bit translation and faults immediately on instruction
 * fetch when Stage 3 branches to the relocated kernel entry.
 */
#define KERNEL_VIRT_BASE    0xFFFF800000000000ULL

/* TCR_EL1 configuration for 48-bit VA, 4KB granule */
#define TCR_T0SZ(n)         ((uint64_t)(n))         /* TTBR0 VA size = 64 - n */
#define TCR_T1SZ(n)         ((uint64_t)(n) << 16)   /* TTBR1 VA size = 64 - n */
#define TCR_TG0_4K          (0ULL << 14)
#define TCR_TG1_4K          (2ULL << 30)
#define TCR_SH0_IS          (3ULL << 12)
#define TCR_SH1_IS          (3ULL << 28)
#define TCR_ORGN0_WB_WA     (1ULL << 10)
#define TCR_IRGN0_WB_WA     (1ULL << 8)
#define TCR_ORGN1_WB_WA     (1ULL << 26)
#define TCR_IRGN1_WB_WA     (1ULL << 24)
#define TCR_IPS_48BIT       (5ULL << 32)

#define TCR_EL1_VALUE ( \
    TCR_T0SZ(16) | TCR_T1SZ(16) | \
    TCR_TG0_4K | TCR_TG1_4K | \
    TCR_SH0_IS | TCR_SH1_IS | \
    TCR_ORGN0_WB_WA | TCR_IRGN0_WB_WA | \
    TCR_ORGN1_WB_WA | TCR_IRGN1_WB_WA | \
    TCR_IPS_48BIT \
)

/* TCR_EL2 configuration for 48-bit VA, 4KB granule */
#define TCR_EL2_PS_48BIT    (5ULL << 16)

#define TCR_EL2_VALUE ( \
    TCR_T0SZ(16) | \
    TCR_TG0_4K | \
    TCR_SH0_IS | \
    TCR_ORGN0_WB_WA | TCR_IRGN0_WB_WA | \
    TCR_EL2_PS_48BIT \
)

#endif /* BOOT_STAGE3_ARCH_AARCH64_PAGING_IMPL_H */
