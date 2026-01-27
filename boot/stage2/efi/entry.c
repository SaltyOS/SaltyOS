/* SaltyOS Stage 2 EFI Entry Point
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * UEFI wrapper for Stage 2
 * EFI application entry point that sets up context and calls common Stage2 code
 */

#include "efi.h"
#include "../common/stage2.h"
#include "../../common/print.h"

/* Page table entry flags */
#define PAGE_PRESENT    (1ULL << 0)
#define PAGE_WRITABLE   (1ULL << 1)

/* Page table structures */
typedef struct {
    uint64_t entries[512];
} __attribute__((aligned(4096))) page_table_t;

/* Simple memset */
static void memset_local(void *s, int c, uint64_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
}

/* Add kernel mapping to existing UEFI page tables
 * This is safer than replacing CR3 because it preserves all existing mappings
 */
static int add_kernel_mapping(EFI_SYSTEM_TABLE *st) {
    uint64_t cr0;
    uint64_t cr3;
    page_table_t *pml4;
    uint64_t pml4_entry;
    page_table_t *pdpt;
    uint64_t pdpt_entry;
    page_table_t *pd;
    page_table_t *pd_stack;
    uint64_t pd_entry;
    page_table_t *pt;
    page_table_t *pt_stack;
    EFI_STATUS status;
    uint64_t pt_phys;

    /* Get current CR3 (UEFI's page table) */
    __asm__ volatile("mov %%cr3, %0" : "=r"(cr3));

    /* Convert to virtual pointer (UEFI uses identity mapping for page tables) */
    pml4 = (page_table_t *)cr3;

    /* UEFI may mark page tables read-only; temporarily disable WP to edit */
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0 & ~(1ULL << 16)) : "memory");

    /* === Navigate to higher-half kernel mapping === */
    /* PML4[511] should point to PDPT for 0xFFFFFFFF........ */
    pml4_entry = pml4->entries[511];

    if (pml4_entry == 0) {
        /* Need to create a new PDPT */
        status = st->boot_services->allocate_pages(
            AllocateAnyPages,
            EFI_LOADER_DATA,
            1,
            &pt_phys
        );
        if (status != EFI_SUCCESS) {
            return -1;
        }
        pdpt = (page_table_t *)pt_phys;
        memset_local(pdpt, 0, 4096);
        pml4->entries[511] = pt_phys | PAGE_PRESENT | PAGE_WRITABLE;
    } else {
        pdpt = (page_table_t *)(pml4_entry & ~0xFFF);
    }

    /* === PDPT[510] for 0xFFFFFFFF80000000+ === */
    pdpt_entry = pdpt->entries[510];

    if (pdpt_entry == 0) {
        /* Need to create a new PD */
        status = st->boot_services->allocate_pages(
            AllocateAnyPages,
            EFI_LOADER_DATA,
            1,
            &pt_phys
        );
        if (status != EFI_SUCCESS) {
            return -1;
        }
        pd = (page_table_t *)pt_phys;
        memset_local(pd, 0, 4096);
        pdpt->entries[510] = pt_phys | PAGE_PRESENT | PAGE_WRITABLE;
    } else {
        pd = (page_table_t *)(pdpt_entry & ~0xFFF);
    }

    /* === PD[0] for the first 2MB of higher-half kernel === */
    pd_entry = pd->entries[0];

    if (pd_entry == 0) {
        /* Need to create a new PT */
        status = st->boot_services->allocate_pages(
            AllocateAnyPages,
            EFI_LOADER_DATA,
            1,
            &pt_phys
        );
        if (status != EFI_SUCCESS) {
            return -1;
        }
        pt = (page_table_t *)pt_phys;
        memset_local(pt, 0, 4096);
        pd->entries[0] = pt_phys | PAGE_PRESENT | PAGE_WRITABLE;
    } else {
        pt = (page_table_t *)(pd_entry & ~0xFFF);
    }

    /* === Map 0xFFFFFFFF80000000+ -> physical 0x100000+ === */
    /* Map 2MB (512 * 4KB pages) for kernel code/data */
    for (int i = 0; i < 512; i++) {
        pt->entries[i] = (uint64_t)(0x100000 + i * 0x1000) | PAGE_PRESENT | PAGE_WRITABLE;
    }

    /* Flush TLB to ensure new mappings take effect */
    __asm__ volatile("mov %%cr3, %%rax; mov %%rax, %%cr3" ::: "rax");

    /* === PDPT[509] for stack area 0xFFFFFFFF7FC00000 - 0xFFFFFFFF7FFFFFFF === */
    pdpt_entry = pdpt->entries[509];

    if (pdpt_entry == 0) {
        status = st->boot_services->allocate_pages(
            AllocateAnyPages,
            EFI_LOADER_DATA,
            1,
            &pt_phys
        );
        if (status != EFI_SUCCESS) {
            return -1;
        }
        pd_stack = (page_table_t *)pt_phys;
        memset_local(pd_stack, 0, 4096);
        pdpt->entries[509] = pt_phys | PAGE_PRESENT | PAGE_WRITABLE;
    } else {
        pd_stack = (page_table_t *)(pdpt_entry & ~0xFFF);
    }

    /* Stack PD: map last entry (511) to a PT */
    pd_entry = pd_stack->entries[511];

    if (pd_entry == 0) {
        status = st->boot_services->allocate_pages(
            AllocateAnyPages,
            EFI_LOADER_DATA,
            1,
            &pt_phys
        );
        if (status != EFI_SUCCESS) {
            return -1;
        }
        pt_stack = (page_table_t *)pt_phys;
        memset_local(pt_stack, 0, 4096);
        pd_stack->entries[511] = pt_phys | PAGE_PRESENT | PAGE_WRITABLE;
    } else {
        pt_stack = (page_table_t *)(pd_entry & ~0xFFF);
    }

    /* Map 2MB for stack probing: virtual top -> physical 0 */
    for (int i = 0; i < 512; i++) {
        pt_stack->entries[i] = (uint64_t)(0 + i * 0x1000) | PAGE_PRESENT | PAGE_WRITABLE;
    }

    /* Restore write-protect */
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");

    return 0;
}

EFI_STATUS EFIAPI stage2_efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st) {
    serial_init();
    println("S2: entry");
    int (*load_stage3_fn)(void **, size_t *);
    int (*load_kernel_fn)(void **, size_t *);

    /* Add kernel mapping to UEFI's page tables
     * This maps 0xFFFFFFFF80000000 -> 0x100000 so stage3 can jump to the kernel
     */
    println("S2: add_kernel_mapping");
    if (add_kernel_mapping(st) != 0) {
        println("S2: add_kernel_mapping failed");
        for (;;) {
            __asm__ volatile("cli; hlt");
        }
    }
    println("S2: mapping ok");

    /* Initialize all EFI subsystems */
    println("S2: init file");
    efi_file_init(image, st);
    println("S2: init memory");
    efi_memory_init(st);
    println("S2: init fb");
    efi_fb_init(st);
    println("S2: init acpi");
    efi_acpi_init(st);

    /* Get file loading callbacks */
    println("S2: get callbacks");
    efi_file_get_callbacks(&load_stage3_fn, &load_kernel_fn);

    /* Set up stage2_context for UEFI */
    struct stage2_context ctx;
    memset_local(&ctx, 0, sizeof(ctx));

    ctx.kernel_phys_base = 0x100000ULL;
    ctx.kernel_virt_base = 0xFFFFFFFF80000000ULL;

    /* Platform-specific callbacks */
    ctx.load_stage3 = load_stage3_fn;
    ctx.load_kernel = load_kernel_fn;
    ctx.get_memory_map = (int (*)(struct memory_map_entry **, size_t *))efi_get_memory_map_fn_ptr;
    ctx.get_rsdp = (uint64_t (*)(void))efi_find_rsdp_fn_ptr;
    ctx.get_framebuffer = (struct framebuffer_info (*)(void))efi_get_framebuffer_fn_ptr;

    println("S2: call stage2_main");

    /* Call common Stage2 */
    stage2_main(&ctx);

    println("S2: stage2_main returned");

    /* Should not return; if it does, just return success */
    return EFI_SUCCESS;
}
