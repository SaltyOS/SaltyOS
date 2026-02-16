/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Dynamic Boot Memory Allocator Implementation
 *
 * BIOS backend: bump allocator over E820 usable regions.
 * UEFI backend: wrapper around AllocatePages.
 */

#include "boot_alloc.h"
#include "config.h"
#include "../common/print.h"
#include "../common/string.h"
#include "../common/stage2_info.h"

#ifdef STAGE3_UEFI
#include "../common/efi/efi_types.h"
#include "../common/efi/efi_protocol.h"
#endif

/* 4GB limit for BIOS bump allocator (32-bit code compatibility) */
#define BIOS_ALLOC_LIMIT    GB(4)

static void record_alloc(struct BootAlloc *ba, uint64_t addr,
                          uint64_t size, uint32_t tag)
{
    if (ba->record_count >= BOOT_ALLOC_MAX_RECORDS) {
        print_line("BootAlloc: record overflow!");
        /* Continue anyway - the kernel just won't know about this region */
        return;
    }

    struct BootAllocRecord *rec = &ba->records[ba->record_count];
    rec->phys_addr = addr;
    rec->size = size;
    rec->tag = tag;
    rec->_pad = 0;
    ba->record_count++;
}

/* ========================================================================= */
/* BIOS Bump Allocator                                                       */
/* ========================================================================= */

void boot_alloc_init_bios(struct BootAlloc *ba,
                           uint64_t e820_addr, uint32_t e820_count,
                           uint64_t min_addr)
{
    memset(ba, 0, sizeof(*ba));
    ba->mode = BOOT_MODE_BIOS;
    ba->e820_addr = e820_addr;
    ba->e820_count = e820_count;
    ba->watermark = min_addr;
}

/*
 * BIOS bump allocator: scan E820 usable regions starting from watermark.
 *
 * Walks the E820 map looking for a usable region that can satisfy the
 * allocation (watermark-aligned + size fits within the region, below 4GB).
 * On success, advances the watermark past the allocation.
 */
static uint64_t bios_alloc(struct BootAlloc *ba, uint64_t size, uint64_t align)
{
    struct E820Entry *entries = (struct E820Entry *)(uintptr_t)ba->e820_addr;
    uint32_t count = ba->e820_count;

    for (uint32_t i = 0; i < count; i++) {
        if (entries[i].type != 1)  /* E820_USABLE */
            continue;

        uint64_t region_base = entries[i].base;
        uint64_t region_end = region_base + entries[i].length;

        /* Stay below 4GB for 32-bit BIOS code */
        if (region_base >= BIOS_ALLOC_LIMIT)
            continue;
        if (region_end > BIOS_ALLOC_LIMIT)
            region_end = BIOS_ALLOC_LIMIT;

        /* Start from watermark or region base, whichever is higher */
        uint64_t start = ba->watermark;
        if (start < region_base)
            start = region_base;

        start = ALIGN_UP(start, align);

        if (start + size <= region_end) {
            ba->watermark = start + size;
            return start;
        }
    }

    return 0;
}

/* ========================================================================= */
/* UEFI AllocatePages Wrapper                                                */
/* ========================================================================= */

#ifdef STAGE3_UEFI
void boot_alloc_init_uefi(struct BootAlloc *ba, uint64_t bs)
{
    memset(ba, 0, sizeof(*ba));
    ba->mode = BOOT_MODE_UEFI;
    ba->uefi_bs = bs;
}

static uint64_t uefi_alloc(struct BootAlloc *ba, uint64_t size, uint64_t align)
{
    EFI_BOOT_SERVICES *bs = (EFI_BOOT_SERVICES *)(uintptr_t)ba->uefi_bs;
    if (!bs)
        return 0;

    /*
     * AllocatePages works in 4KB page units.
     * If alignment > 4KB, over-allocate and align within the block.
     */
    uint64_t alloc_size = size;
    if (align > EFI_PAGE_SIZE)
        alloc_size += align;

    UINTN pages = EFI_SIZE_TO_PAGES(alloc_size);
    uint64_t addr = 0;

    EFI_STATUS status = bs->AllocatePages(AllocateAnyPages, EfiLoaderData,
                                           pages, &addr);
    if (EFI_ERROR(status))
        return 0;

    /* Zero the allocated memory */
    memset((void *)(uintptr_t)addr, 0, pages * EFI_PAGE_SIZE);

    /* Align within the over-allocated block */
    uint64_t aligned = ALIGN_UP(addr, align);
    return aligned;
}

void boot_alloc_finalize_uefi(struct BootAlloc *ba)
{
    ba->uefi_bs = 0;
}
#else
/* Stubs for BIOS build */
void boot_alloc_init_uefi(struct BootAlloc *ba, uint64_t bs)
{
    (void)ba; (void)bs;
}

void boot_alloc_finalize_uefi(struct BootAlloc *ba)
{
    (void)ba;
}
#endif /* STAGE3_UEFI */

/* ========================================================================= */
/* Common Interface                                                          */
/* ========================================================================= */

uint64_t boot_alloc(struct BootAlloc *ba, uint64_t size,
                     uint64_t align, uint32_t tag)
{
    if (size == 0)
        return 0;

    /* Enforce minimum 4KB alignment */
    if (align < PAGE_SIZE_4K)
        align = PAGE_SIZE_4K;

    /* Round size up to page boundary */
    size = ALIGN_UP(size, PAGE_SIZE_4K);

    uint64_t addr = 0;

    if (ba->mode == BOOT_MODE_BIOS) {
        addr = bios_alloc(ba, size, align);
    }
#ifdef STAGE3_UEFI
    else if (ba->mode == BOOT_MODE_UEFI) {
        addr = uefi_alloc(ba, size, align);
    }
#endif

    if (addr == 0) {
        print_str("BootAlloc: failed to allocate ");
        print_hex((uint32_t)size, 8);
        print_str(" bytes (tag=");
        print_dec(tag);
        print_str(")\n");
        return 0;
    }

    record_alloc(ba, addr, size, tag);

#if CONFIG_DEBUG
    print_str("BootAlloc: ");
    print_hex64(addr);
    print_str(" size=");
    print_hex((uint32_t)size, 8);
    print_str(" tag=");
    print_dec(tag);
    print_char('\n');
#endif

    return addr;
}

void boot_alloc_register(struct BootAlloc *ba, uint64_t addr,
                          uint64_t size, uint32_t tag)
{
    /* Round size up to page boundary for consistent reporting */
    size = ALIGN_UP(size, PAGE_SIZE_4K);
    record_alloc(ba, addr, size, tag);

#if CONFIG_DEBUG
    print_str("BootAlloc (register): ");
    print_hex64(addr);
    print_str(" size=");
    print_hex((uint32_t)size, 8);
    print_str(" tag=");
    print_dec(tag);
    print_char('\n');
#endif
}
