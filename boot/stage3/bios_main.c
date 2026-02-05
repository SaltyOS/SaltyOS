/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 BIOS Entry Point
 *
 * Stage 3 BIOS path: loads the manifest, kernel, and initrd
 * using BTX for disk I/O, sets up page tables, and transfers control
 * to the kernel via 32-bit → 64-bit mode switch.
 *
 * Entry state (from Stage 2):
 * - 32-bit protected mode
 * - A20 line enabled
 * - Interrupts disabled
 * - EDI = Stage2Info physical address (passed on stack in cdecl)
 * - BTX trampoline initialized for BIOS disk access
 */

#include "../common/types.h"
#include "../common/print.h"
#include "../common/manifest.h"
#include "../common/bootinfo_tlv.h"
#include "../common/stage2_info.h"
#include "stage3.h"
#include "config.h"
#include "elf.h"
#include "paging.h"
#include "handoff.h"
#include "disk/disk.h"
#include "fs/fs.h"
#include "arch/x86/bios/mode_switch.h"

/* Manifest buffer address */
#define MANIFEST_BUFFER_ADDR    0x28000
#define MANIFEST_BUFFER_SIZE    KB(32)

/* Bounce buffer for temporary reads (shared with bios_disk.c) */
#define BOUNCE_BUF              0x60000

/* Kernel load address (chosen from memory map) */
#define KERNEL_DEFAULT_LOAD     MB(2)

/* ELF preread size in sectors */
#define ELF_PREREAD_SECTORS     8

/* BootInfo buffer (aligned) */
static uint8_t bootinfo_buffer[KB(16)] ALIGNED(4096);

/* Kernel loading area */
static uint64_t kernel_load_area = KERNEL_DEFAULT_LOAD;

/*
 * Find suitable memory region for kernel
 */
static uint64_t find_kernel_load_address(struct Stage2Info *info, uint64_t size)
{
    if (!info || info->memmap_count == 0)
        return KERNEL_DEFAULT_LOAD;

    struct E820Entry *entries = (struct E820Entry *)(uintptr_t)info->memmap_addr;
    uint32_t count = info->memmap_count;

    /* Look for usable region >= 2MB aligned */
    for (uint32_t i = 0; i < count; i++) {
        if (entries[i].type != 1)  /* E820_USABLE */
            continue;

        uint64_t base = entries[i].base;
        uint64_t end = base + entries[i].length;

        /* Must be above 2MB to avoid bootloader areas */
        if (end <= KERNEL_DEFAULT_LOAD)
            continue;

        if (base < KERNEL_DEFAULT_LOAD)
            base = KERNEL_DEFAULT_LOAD;

        /* Align to 2MB */
        base = ALIGN_UP(base, KERNEL_LOAD_ALIGN);

        /* Check if region is large enough */
        if (base + size <= end)
            return base;
    }

    /* Fallback to default */
    return KERNEL_DEFAULT_LOAD;
}

/*
 * Stage 3 main entry point
 *
 * Called from entry.asm in 32-bit protected mode.
 */
void stage3_entry(struct Stage2Info *info)
{
    /* Initialize serial output */
    print_init(PRINT_TARGET_SERIAL);

    print_line("=== SaltyOS Stage 3 ===");

    /* Validate Stage2Info */
    if (!info || info->magic != STAGE2_MAGIC) {
        stage3_panic("Invalid Stage2Info");
    }

#if CONFIG_DEBUG
    print_str("Stage2Info at ");
    print_hex((uintptr_t)info, 8);
    print_str(" boot_mode=");
    print_dec(info->boot_mode);
    print_str(" memmap_count=");
    print_dec(info->memmap_count);
    print_char('\n');
#endif

    /* Initialize global context */
    g_ctx.stage2_info = info;
    g_ctx.boot_drive = info->boot_drive;
    g_ctx.kernel_phys_base = 0;
    g_ctx.kernel_entry = 0;
    g_ctx.initrd_phys_addr = 0;
    g_ctx.initrd_size = 0;

    /* Initialize disk subsystem */
    if (disk_init(info->boot_drive) != DISK_OK) {
        stage3_panic("Failed to initialize disk");
    }

    /* Load manifest from disk */
    print_line("Loading manifest...");
    if (disk_read(&g_boot_disk, BRA_START_LBA, MANIFEST_SECTORS,
                  (void *)MANIFEST_BUFFER_ADDR) != DISK_OK) {
        stage3_panic("Failed to load manifest");
    }

    /* Validate manifest */
    struct BootManifestHeader *manifest =
        (struct BootManifestHeader *)MANIFEST_BUFFER_ADDR;

    if (!manifest_header_valid(manifest, MANIFEST_BUFFER_SIZE)) {
        stage3_panic("Invalid Boot Manifest");
    }

    g_ctx.manifest = manifest;

#if CONFIG_DEBUG
    print_str("Manifest: version=");
    print_dec(manifest->version);
    print_str(" entries=");
    print_dec(manifest->entry_count);
    print_char('\n');
#endif

    /* Find kernel entry in manifest */
    const struct BootManifestEntry *kernel_entry_info =
        manifest_find_entry(manifest, MANIFEST_ENTRY_KERNEL);

    if (!kernel_entry_info) {
        stage3_panic("No kernel in manifest");
    }

#if CONFIG_DEBUG
    print_str("Kernel: size=");
    print_hex((uint32_t)kernel_entry_info->size_bytes, 8);
    print_str(" extents=");
    print_dec(kernel_entry_info->extent_count);
    print_char('\n');
#endif

    uint64_t kernel_file_size = kernel_entry_info->size_bytes;

    /*
     * Pre-read the first 8 sectors (4KB) of the kernel to parse the
     * ELF header and program headers. This gives us the actual memory
     * footprint before we commit to a load address.
     */
    uint8_t *elf_preread = (uint8_t *)BOUNCE_BUF;

    if (kernel_entry_info->extent_count == 0) {
        stage3_panic("Kernel has no extents");
    }

    if (disk_read(&g_boot_disk, kernel_entry_info->extents[0].lba,
                  ELF_PREREAD_SECTORS, elf_preread) != DISK_OK) {
        stage3_panic("Failed to pre-read kernel ELF header");
    }

    /* Validate ELF header from pre-read buffer */
    int err = elf_validate((struct Elf64_Ehdr *)elf_preread);
    if (err != ELF_OK) {
        print_str("ELF validation failed: ");
        print_dec(err);
        print_char('\n');
        stage3_panic("Invalid kernel ELF");
    }

    /* Calculate actual kernel memory size from ELF program headers */
    uint64_t min_vaddr, max_vaddr;
    err = elf_calc_size(elf_preread, &min_vaddr, &max_vaddr);
    if (err != ELF_OK) {
        stage3_panic("Failed to calculate kernel size");
    }

    uint64_t elf_mem_size = max_vaddr - min_vaddr;
    elf_mem_size = ALIGN_UP(elf_mem_size, KERNEL_LOAD_ALIGN);

    /*
     * Find suitable load address with actual sizes:
     * we need space for the raw file buffer + processed kernel segments.
     */
    uint64_t total_needed = ALIGN_UP(kernel_file_size, KERNEL_LOAD_ALIGN) + elf_mem_size;
    kernel_load_area = find_kernel_load_address(info, total_needed);

    print_str("Kernel load area: ");
    print_hex((uint32_t)kernel_load_area, 8);
    print_char('\n');

    /* Load full kernel ELF from disk */
    print_line("Loading kernel...");
    void *kernel_buffer = (void *)(uintptr_t)kernel_load_area;

    {
        ssize_t loaded = fs_load_from_entry(&g_boot_disk, kernel_entry_info,
                                            kernel_buffer, total_needed);
        if (loaded < 0) {
            stage3_panic("Failed to load kernel");
        }
    }

    /* Compute final load address for processed kernel segments (after file buffer) */
    uint64_t final_load_addr = kernel_load_area + kernel_file_size;
    final_load_addr = ALIGN_UP(final_load_addr, KERNEL_LOAD_ALIGN);

#if CONFIG_DEBUG
    print_str("ELF: vaddr range ");
    print_hex((uint32_t)(min_vaddr >> 32), 8);
    print_hex((uint32_t)min_vaddr, 8);
    print_str(" - ");
    print_hex((uint32_t)(max_vaddr >> 32), 8);
    print_hex((uint32_t)max_vaddr, 8);
    print_char('\n');
    print_str("Loading to ");
    print_hex((uint32_t)(final_load_addr >> 32), 8);
    print_hex((uint32_t)final_load_addr, 8);
    print_char('\n');
#endif

    /* Load kernel ELF segments */
    struct ElfLoadResult load_result;
    err = elf_load(kernel_buffer, kernel_file_size,
                   final_load_addr,      /* physical copy destination */
                   paging_get_kernel_virt_base(),      /* virtual base for relocations */
                   &load_result);
    if (err != ELF_OK) {
        print_str("ELF load failed: ");
        print_dec(err);
        print_char('\n');
        stage3_panic("Failed to load kernel");
    }

    g_ctx.kernel_phys_base = load_result.phys_base;
    g_ctx.kernel_virt_base = load_result.virt_base;
    g_ctx.kernel_size = load_result.mem_size;
    g_ctx.kernel_entry = load_result.entry;

    print_str("Kernel loaded: entry=");
    print_hex((uint32_t)(load_result.entry >> 32), 8);
    print_hex((uint32_t)load_result.entry, 8);
    print_char('\n');

    /* Find and load initrd if present */
    const struct BootManifestEntry *initrd_entry =
        manifest_find_entry(manifest, MANIFEST_ENTRY_INITRD);

    if (initrd_entry && initrd_entry->size_bytes > 0) {
        /* Calculate initrd load address (after kernel) */
        uint64_t initrd_addr = g_ctx.kernel_phys_base + g_ctx.kernel_size;
        initrd_addr = ALIGN_UP(initrd_addr, PAGE_SIZE_4K);

        print_str("Loading initrd to ");
        print_hex((uint32_t)initrd_addr, 8);
        print_str(" size=");
        print_hex((uint32_t)initrd_entry->size_bytes, 8);
        print_char('\n');

        ssize_t initrd_loaded = fs_load_from_entry(
            &g_boot_disk, initrd_entry,
            (void *)(uintptr_t)initrd_addr, initrd_entry->size_bytes);
        if (initrd_loaded < 0) {
            print_line("Warning: Failed to load initrd");
        } else {
            g_ctx.initrd_phys_addr = initrd_addr;
            g_ctx.initrd_size = initrd_entry->size_bytes;
            print_line("Initrd loaded");
        }
    }

    /* Set up page tables */
    print_line("Setting up page tables...");
    uint64_t pml4 = paging_init(g_ctx.kernel_phys_base, g_ctx.kernel_size);
    if (pml4 == 0) {
        stage3_panic("Failed to set up page tables");
    }

    /* Build BootInfo */
    print_line("Building BootInfo...");
    struct BootInfoHeader *bootinfo = handoff_build_bootinfo(
        bootinfo_buffer, sizeof(bootinfo_buffer),
        info, &load_result,
        g_ctx.initrd_phys_addr, g_ctx.initrd_size);

    if (!bootinfo) {
        stage3_panic("Failed to build BootInfo");
    }

    print_line("Entering long mode and jumping to kernel...");

    /* Switch to long mode and jump to kernel */
    enter_long_mode_and_jump(
        (uint32_t)pml4,
        g_ctx.kernel_entry,
        (uint64_t)(uintptr_t)bootinfo,
        KERNEL_STACK_ADDR + KERNEL_STACK_SIZE);

    /* Never reached */
    stage3_panic("Returned from kernel");
}
