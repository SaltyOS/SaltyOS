/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - AArch64 Page Table Setup
 *
 * Sets up 4-level page tables (4KB granule) for the kernel.
 * Creates identity map in TTBR0 and kernel higher-half in TTBR1.
 */

#include "paging_impl.h"
#include "cpu.h"
#include "../../paging.h"
#include "../../../common/string.h"
#include "../../../common/print.h"
#include "../../config.h"

#define AARCH64_QEMU_VIRT_RAM_BASE    0x40000000ULL

/* Page table allocator */
static uint64_t next_page_table = 0;
static uint64_t page_table_limit = 0;

static uint64_t alloc_page_table(void)
{
    if (next_page_table >= page_table_limit)
        return 0;

    uint64_t addr = next_page_table;
    next_page_table += 4096;
    memset((void *)(uintptr_t)addr, 0, 4096);
    return addr;
}

/* Write a page table entry */
static void write_pte(uint64_t table_addr, unsigned int index, uint64_t value)
{
    volatile uint64_t *entry = (volatile uint64_t *)(uintptr_t)(table_addr + index * 8);
    *entry = value;
}

/* Read a page table entry */
static uint64_t read_pte(uint64_t table_addr, unsigned int index)
{
    volatile uint64_t *entry = (volatile uint64_t *)(uintptr_t)(table_addr + index * 8);
    return *entry;
}

/* Get or create a next-level table */
static uint64_t get_or_create_table(uint64_t parent, unsigned int index)
{
    uint64_t entry = read_pte(parent, index);
    if (entry & PTE_VALID) {
        return entry & PTE_ADDR_MASK;
    }
    uint64_t new_table = alloc_page_table();
    if (new_table == 0)
        return 0;
    write_pte(parent, index, new_table | PTE_VALID | PTE_TABLE);
    return new_table;
}

/* Map a 2MB block at L2 level */
static int map_2m_block(uint64_t l0_table, uint64_t virt, uint64_t phys, uint64_t flags)
{
    unsigned int l0_idx = (virt >> 39) & 0x1FF;
    unsigned int l1_idx = (virt >> 30) & 0x1FF;
    unsigned int l2_idx = (virt >> 21) & 0x1FF;

    uint64_t l1 = get_or_create_table(l0_table, l0_idx);
    if (l1 == 0) return -1;

    uint64_t l2 = get_or_create_table(l1, l1_idx);
    if (l2 == 0) return -1;

    /* Block descriptor at L2 (2MB) */
    write_pte(l2, l2_idx, (phys & ~0x1FFFFFULL) | flags | PTE_AF | PTE_VALID);
    return 0;
}

int paging_map_region(uint64_t root_table, uint64_t virt, uint64_t phys,
                      uint64_t size, uint64_t flags)
{
    uint64_t offset;
    for (offset = 0; offset < size; offset += PAGING_PAGE_2M) {
        if (map_2m_block(root_table, virt + offset, phys + offset, flags) != 0) {
            print_str("paging_map_region: failed to map 2MB block\n");
            return -1;
        }
    }
    return 0;
}

void paging_load_cr3(uint64_t root_table)
{
    /* Configure MAIR */
    write_mair_el1(MAIR_EL1_VALUE);

    /* Configure TCR */
    write_tcr_el1(TCR_EL1_VALUE);

    /* Load TTBR0 (identity map and user space) */
    write_ttbr0_el1(root_table);

    /* Load TTBR1 (kernel higher-half, same table for now) */
    write_ttbr1_el1(root_table);

    /* Full TLB invalidation */
    tlbi_vmalle1();

    /* Enable MMU via SCTLR_EL1 */
    uint64_t sctlr = read_sctlr_el1();
    sctlr |= (1ULL << 0);  /* M bit: enable MMU */
    sctlr |= (1ULL << 2);  /* C bit: data cache enable */
    sctlr |= (1ULL << 12); /* I bit: instruction cache enable */
    sctlr |= (1ULL << 26); /* UCI: allow EL0 IC IVAU / DC CVAU instructions */
    sctlr &= ~(1ULL << 1); /* A bit: disable alignment checking */
    write_sctlr_el1(sctlr);
}

uint64_t paging_init_dynamic(uint64_t pt_pool_base, uint64_t pt_pool_size,
                              uint64_t kernel_phys, uint64_t kernel_size,
                              uint64_t identity_end)
{
    next_page_table = pt_pool_base;
    page_table_limit = pt_pool_base + pt_pool_size;

    /* Allocate L0 table (root) */
    uint64_t l0 = alloc_page_table();
    if (l0 == 0) return 0;

    /* Flags for kernel mapping: RWX for simplicity during boot */
    uint64_t kern_flags = PTE_SH_IS | PTE_ATTR_IDX(MAIR_IDX_NORMAL_WB) | PTE_AP_RW_EL1;

    /*
     * Identity map [QEMU_VIRT_RAM_BASE, identity_end) so the kernel can
     * access all boot allocations. Guest RAM starts at 0x40000000 on the
     * QEMU virt platform, so the map begins there.
     */
    uint64_t id_limit = identity_end;
    if (id_limit < AARCH64_QEMU_VIRT_RAM_BASE + PAGING_PAGE_2M)
        id_limit = AARCH64_QEMU_VIRT_RAM_BASE + PAGING_PAGE_2M;
    /* Round up to 2 MB */
    id_limit = (id_limit + PAGING_PAGE_2M - 1) & ~(PAGING_PAGE_2M - 1);

    uint64_t addr;
    for (addr = AARCH64_QEMU_VIRT_RAM_BASE;
         addr < id_limit;
         addr += PAGING_PAGE_2M) {
        if (map_2m_block(l0, addr, addr, kern_flags) != 0)
            return 0;
    }

    /* Map kernel at higher half */
    uint64_t kernel_virt = paging_get_kernel_virt_base();
    uint64_t map_size = (kernel_size + PAGING_PAGE_2M - 1) & ~(PAGING_PAGE_2M - 1);
    for (addr = 0; addr < map_size; addr += PAGING_PAGE_2M) {
        if (map_2m_block(l0, kernel_virt + addr, kernel_phys + addr, kern_flags) != 0)
            return 0;
    }

    /* Map UART for early serial (0x0900_0000, 2MB block) */
    uint64_t uart_flags = PTE_SH_NS | PTE_ATTR_IDX(MAIR_IDX_DEVICE_nGnRnE) | PTE_AP_RW_EL1 | PTE_PXN | PTE_UXN;
    if (map_2m_block(l0, 0x09000000ULL, 0x09000000ULL, uart_flags) != 0)
        return 0;

    return l0;
}

uint64_t paging_get_kernel_virt_base(void)
{
    return KERNEL_VIRT_BASE;
}
