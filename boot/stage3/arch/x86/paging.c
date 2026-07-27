/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - x86_64 Page Table Setup Implementation
 *
 * Sets up page tables for the 64-bit kernel while running in 32-bit mode.
 * The page tables are constructed in memory and will be used when
 * switching to long mode.
 *
 * This is the x86_64-specific implementation. It implements the
 * architecture-neutral interface defined in paging.h.
 */

#include "../../paging.h"
#include "../../../common/print.h"
#include "../../../common/string.h"
#include "../../config.h"
#include "paging_impl.h"

/* =============================================================================
 * Page Table Allocator
 *
 * Uses uintptr_t so this works in both 32-bit (BIOS) and 64-bit (UEFI) builds.
 * =============================================================================
 */

static uintptr_t next_page_table = 0;
static uintptr_t page_table_limit = 0;

static uintptr_t alloc_page_table(void) {
  if (next_page_table >= page_table_limit)
    return 0;

  uintptr_t addr = next_page_table;
  next_page_table += 4096;

  /* Clear the page */
  memset((void *)addr, 0, 4096);

  return addr;
}

/* =============================================================================
 * Page Table Entry Helpers
 * =============================================================================
 */

static void write_pte(uintptr_t addr, uint64_t value) {
#if defined(__x86_64__)
  volatile uint64_t *ptr = (volatile uint64_t *)addr;
  *ptr = value;
#else
  /* In 32-bit mode, write two 32-bit halves */
  volatile uint32_t *ptr = (volatile uint32_t *)addr;
  ptr[0] = (uint32_t)value;
  ptr[1] = (uint32_t)(value >> 32);
#endif
}

static uint64_t read_pte(uintptr_t addr) {
#if defined(__x86_64__)
  volatile uint64_t *ptr = (volatile uint64_t *)addr;
  return *ptr;
#else
  volatile uint32_t *ptr = (volatile uint32_t *)addr;
  return ((uint64_t)ptr[1] << 32) | ptr[0];
#endif
}

/* =============================================================================
 * Public API Implementation
 * =============================================================================
 */

/*
 * Internal: set up identity map + higher-half kernel mapping
 *
 * pml4 must already be a valid zeroed page table address.
 * The allocator (next_page_table / page_table_limit) must be configured.
 */
static uint64_t paging_setup_maps(uintptr_t pml4, uint64_t kernel_phys,
                                  uint64_t kernel_size, uint64_t identity_end) {
  /*
   * Set up page tables for:
   * - Identity map for [0, identity_end) (using 2MB pages)
   * - Higher-half kernel mapping at KERNEL_VIRT_BASE (0xFFFFFFFF80000000)
   *
   * IMPORTANT: Identity map and higher-half map use SEPARATE
   * page table structures to avoid aliasing.
   */

  /* === Identity Map: PML4[0] → id_pdpt → id_pd[0..N] ===
   *
   * Map enough physical memory so the kernel can access all boot
   * allocations (kernel ELF, initrd, BootInfo, PT pool) before it
   * sets up its own direct physical map.
   *
   * identity_end is rounded up to 1 GB granularity (one PD per GB).
   */
  uint64_t id_end = identity_end;
  if (id_end < PAGING_SIZE_1G)
    id_end = PAGING_SIZE_1G;
  /* Round up to 1 GB boundary */
  uint32_t num_gbs = (uint32_t)((id_end + PAGING_SIZE_1G - 1) / PAGING_SIZE_1G);
  /* Cap at 512 GB (PDPT capacity) */
  if (num_gbs > 512)
    num_gbs = 512;

  uintptr_t id_pdpt = alloc_page_table();
  if (id_pdpt == 0) {
    print_line("Paging: Failed to allocate identity PDPT");
    return 0;
  }

  write_pte(pml4, (uint64_t)id_pdpt | PAGE_RW);

  uint64_t phys = 0;
  for (uint32_t gb = 0; gb < num_gbs; gb++) {
    uintptr_t id_pd = alloc_page_table();
    if (id_pd == 0) {
      print_line("Paging: Failed to allocate identity PD");
      return 0;
    }
    write_pte(id_pdpt + gb * 8, (uint64_t)id_pd | PAGE_RW);

    for (int i = 0; i < 512; i++) {
      write_pte(id_pd + i * 8, phys | PAGE_RW | PAGE_HUGE);
      phys += PAGING_SIZE_2M;
    }
  }

#if CONFIG_DEBUG
  print_str("Paging: Identity map ");
  print_dec(num_gbs);
  print_str(" GB\n");
#endif

  /* === Higher-Half: PML4[511] → hh_pdpt → hh_pd === */
  uintptr_t hh_pdpt = alloc_page_table();
  uintptr_t hh_pd = alloc_page_table();
  if (hh_pdpt == 0 || hh_pd == 0) {
    print_line("Paging: Failed to allocate higher-half tables");
    return 0;
  }

  write_pte(pml4 + 511 * 8, (uint64_t)hh_pdpt | PAGE_RW);
  write_pte(hh_pdpt + 510 * 8, (uint64_t)hh_pd | PAGE_RW);

  /* Map kernel physical pages at KERNEL_VIRT_BASE using 2MB pages */
  if (kernel_phys != 0 && kernel_size != 0) {
    uint64_t kphys = ALIGN_DOWN(kernel_phys, PAGING_SIZE_2M);
    uint64_t kend = ALIGN_UP(kernel_phys + kernel_size, PAGING_SIZE_2M);
    uint32_t pd_idx = PD_INDEX(KERNEL_VIRT_BASE);

    while (kphys < kend) {
      write_pte(hh_pd + pd_idx * 8, kphys | PAGE_KERNEL_RW | PAGE_HUGE);
      kphys += PAGING_SIZE_2M;
      pd_idx++;
    }

#if CONFIG_DEBUG
    print_str("Paging: Mapped kernel at higher-half\n");
#endif
  }

  return (uint64_t)pml4;
}

uint64_t paging_init_dynamic(uint64_t pt_pool_base, uint64_t pt_pool_size,
                             uint64_t kernel_phys, uint64_t kernel_size,
                             uint64_t identity_end) {
  /* Use the provided pool as PML4 + allocator source */
  uintptr_t pml4 = (uintptr_t)pt_pool_base;

  /* Allocator starts after the PML4 page */
  next_page_table = (uintptr_t)(pt_pool_base + 4096);
  page_table_limit = (uintptr_t)(pt_pool_base + pt_pool_size);

#if CONFIG_DEBUG
  print_str("Paging (dynamic): pool=");
  print_hex(pt_pool_base, 16);
  print_str(" size=");
  print_hex(pt_pool_size, 16);
  print_char('\n');
#endif

  /* Clear PML4 */
  memset((void *)pml4, 0, 4096);

  return paging_setup_maps(pml4, kernel_phys, kernel_size, identity_end);
}

int paging_map_region(uint64_t pml4_addr, uint64_t virt, uint64_t phys,
                      uint64_t size, uint64_t flags) {
  uintptr_t pml4 = (uintptr_t)pml4_addr;

  /* Round to 2MB pages for simplicity */
  virt = ALIGN_DOWN(virt, PAGING_SIZE_2M);
  phys = ALIGN_DOWN(phys, PAGING_SIZE_2M);
  size = ALIGN_UP(size, PAGING_SIZE_2M);

  while (size > 0) {
    uint32_t pml4_idx = PML4_INDEX(virt);
    uint32_t pdpt_idx = PDPT_INDEX(virt);
    uint32_t pd_idx = PD_INDEX(virt);

    /* Get or create PDPT */
    uintptr_t pdpt;
    uint64_t pml4_entry = read_pte(pml4 + pml4_idx * 8);
    if (pml4_entry & PAGE_PRESENT) {
      pdpt = (uintptr_t)(pml4_entry & ~0xFFFULL);
    } else {
      pdpt = alloc_page_table();
      if (pdpt == 0)
        return -1;
      write_pte(pml4 + pml4_idx * 8, (uint64_t)pdpt | PAGE_RW);
    }

    /* Get or create PD */
    uintptr_t pd;
    uint64_t pdpt_entry = read_pte(pdpt + pdpt_idx * 8);
    if (pdpt_entry & PAGE_PRESENT) {
      /* Check if it's a 1GB page */
      if (pdpt_entry & PAGE_HUGE) {
        /* Already mapped as 1GB page, skip */
        virt += PAGING_SIZE_1G;
        phys += PAGING_SIZE_1G;
        if (size > PAGING_SIZE_1G)
          size -= PAGING_SIZE_1G;
        else
          size = 0;
        continue;
      }
      pd = (uintptr_t)(pdpt_entry & ~0xFFFULL);
    } else {
      pd = alloc_page_table();
      if (pd == 0)
        return -1;
      write_pte(pdpt + pdpt_idx * 8, (uint64_t)pd | PAGE_RW);
    }

    /* Map 2MB page */
    uint64_t pd_entry = read_pte(pd + pd_idx * 8);
    if (!(pd_entry & PAGE_PRESENT)) {
      write_pte(pd + pd_idx * 8, phys | flags);
    }

    virt += PAGING_SIZE_2M;
    phys += PAGING_SIZE_2M;
    size -= PAGING_SIZE_2M;
  }

  return 0;
}

void paging_load_cr3(uint64_t pml4) {
#if defined(__x86_64__)
  __asm__ volatile("mov %0, %%cr3" : : "r"(pml4) : "memory");
#else
  /* In 32-bit mode, CR3 only uses the lower 32 bits */
  uint32_t pml4_32 = (uint32_t)pml4;
  __asm__ volatile("mov %0, %%cr3" : : "r"(pml4_32) : "memory");
#endif
}

uint64_t paging_get_kernel_virt_base(void) { return KERNEL_VIRT_BASE; }
