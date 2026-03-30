/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 BIOS Entry Point
 *
 * Stage 3 BIOS path: loads the manifest, kernel, and initrd
 * using BTX for disk I/O, sets up page tables, and transfers control
 * to the kernel via 32-bit -> 64-bit mode switch.
 *
 * Entry state (from Stage 2):
 * - 32-bit protected mode
 * - A20 line enabled
 * - Interrupts disabled
 * - EDI = Stage2Info physical address (passed on stack in cdecl)
 * - BTX is initialized here after selecting a low-memory workspace
 */

#include "../common/types.h"
#include "../common/print.h"
#include "../common/fb_console.h"
#include "../common/manifest.h"
#include "../common/bootinfo_tlv.h"
#include "../common/stage2_info.h"
#include "../common/arch/x86/bios/v86.h"
#include "stage3.h"
#include "config.h"
#include "elf.h"
#include "paging.h"
#include "handoff.h"
#include "boot_alloc.h"
#include "disk/disk.h"
#include "fs/fs.h"
#include "arch/x86/bios/mode_switch.h"

/* Manifest buffer address */
#define MANIFEST_BUFFER_ADDR    0x28000
#define MANIFEST_BUFFER_SIZE    KB(32)

/* Bounce buffer for temporary reads (shared with bios_disk.c) */
#define BOUNCE_BUF              0x60000

/*
 * BTX low-memory workspace search window.
 *
 * Keep this below manifest/memmap/stage3 load areas, and above the legacy
 * Stage2 region. We select a usable E820 range inside this window at runtime.
 */
#define BTX_WORKSPACE_WINDOW_BASE   0x18000U
#define BTX_WORKSPACE_WINDOW_LIMIT  0x28000U

/* ELF preread size in sectors */
#define ELF_PREREAD_SECTORS     8

/* Page table pool size */
#define PT_POOL_SIZE            KB(128)

/* Sum usable RAM above 1MB from BIOS E820 map. */
static uint64_t total_usable_ram(struct Stage2Info *info)
{
    if (!info || info->memmap_count == 0)
        return 0;

    struct E820Entry *entries = (struct E820Entry *)(uintptr_t)info->memmap_addr;
    uint32_t count = info->memmap_count;
    uint64_t total = 0;

    for (uint32_t i = 0; i < count; i++) {
        if (entries[i].type != 1)  /* E820_USABLE */
            continue;

        uint64_t base = entries[i].base;
        uint64_t end = base + entries[i].length;

        if (end <= MB(1))
            continue;
        if (base < MB(1))
            base = MB(1);

        if (end > base)
            total += (end - base);
    }

    return total;
}

/* Pick a low-memory workspace for BTX from the BIOS E820 map. */
static uint32_t alloc_btx_workspace(const struct Stage2Info *info)
{
    if (!info || info->memmap_format != MEMMAP_FORMAT_E820 ||
        info->memmap_count == 0) {
        return 0;
    }

    const struct E820Entry *entries =
        (const struct E820Entry *)(uintptr_t)info->memmap_addr;

    for (uint32_t i = 0; i < info->memmap_count; i++) {
        if (entries[i].type != 1)  /* E820_USABLE */
            continue;

        uint64_t region_base = entries[i].base;
        uint64_t region_end = entries[i].base + entries[i].length;
        if (region_end <= region_base)
            continue;

        if (region_end <= BTX_WORKSPACE_WINDOW_BASE ||
            region_base >= BTX_WORKSPACE_WINDOW_LIMIT) {
            continue;
        }

        if (region_base < BTX_WORKSPACE_WINDOW_BASE)
            region_base = BTX_WORKSPACE_WINDOW_BASE;
        if (region_end > BTX_WORKSPACE_WINDOW_LIMIT)
            region_end = BTX_WORKSPACE_WINDOW_LIMIT;

        uint32_t candidate =
            (uint32_t)ALIGN_UP((uint32_t)region_base, V86_WORKSPACE_ALIGN);

        if ((uint64_t)candidate + V86_WORKSPACE_SIZE <= region_end)
            return candidate;
    }

    return 0;
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

    /* Initialize framebuffer console if available */
    if (info && (info->flags & STAGE2_FLAG_HAS_FRAMEBUFFER) &&
        info->framebuffer_addr != 0) {
        fb_console_init(info->framebuffer_addr,
                        info->framebuffer_width, info->framebuffer_height,
                        info->framebuffer_pitch, info->framebuffer_bpp,
                        info->fb_red_pos, info->fb_green_pos, info->fb_blue_pos);
        print_add_target(PRINT_TARGET_FB);
    }

    print_line("=== SaltyOS Stage 3 ===");

    /* Validate Stage2Info */
    if (!info || info->magic != STAGE2_MAGIC) {
        stage3_panic("Invalid Stage2Info");
    }

    uint32_t btx_workspace = alloc_btx_workspace(info);
    if (btx_workspace == 0) {
        stage3_panic("Failed to allocate BTX workspace");
    }

    if (v86_init(btx_workspace, V86_WORKSPACE_SIZE) != 0) {
        stage3_panic("Failed to initialize BTX");
    }

#if CONFIG_DEBUG
    print_str("Stage2Info at ");
    print_hex((uintptr_t)info, 8);
    print_str(" boot_mode=");
    print_dec(info->boot_mode);
    print_str(" memmap_count=");
    print_dec(info->memmap_count);
    print_str(" btx_ws=");
    print_hex(btx_workspace, 8);
    print_char('\n');
#endif

    uint64_t usable_bytes = total_usable_ram(info);
    bool lowmem_mode = (usable_bytes != 0 && usable_bytes <= LOWMEM_TOTAL_BYTES);
    uint64_t kernel_align = lowmem_mode ? KERNEL_LOWMEM_ALIGN : KERNEL_LOAD_ALIGN;

#if CONFIG_DEBUG
    print_str("Usable RAM above 1MB: ");
    print_hex64(usable_bytes);
    print_char('\n');
    print_str("Kernel load alignment: ");
    print_hex((uint32_t)kernel_align, 8);
    print_char('\n');
    if (lowmem_mode) {
        print_line("Lowmem mode: enabled");
    }
#endif

    /* Initialize global context */
    g_ctx.stage2_info = info;
    g_ctx.boot_drive = info->boot_drive;
    g_ctx.kernel_phys_base = 0;
    g_ctx.kernel_entry = 0;
    g_ctx.initrd_phys_addr = 0;
    g_ctx.initrd_size = 0;

    /* Initialize BootAlloc (bump allocator starting at 2MB) */
    struct BootAlloc ba;
    boot_alloc_init_bios(&ba, info->memmap_addr, info->memmap_count, MB(2));

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
    elf_mem_size = ALIGN_UP(elf_mem_size, kernel_align);

    /*
     * Find suitable load address via BootAlloc.
     *
     * Split-load strategy: if the raw ELF file fits in the scratch area
     * at 1MB (below the kernel load region), load it there and only
     * allocate aligned space for the processed segments. In normal mode this
     * is 2MB-aligned for huge-page friendliness; in lowmem mode it is 4KB.
     * This avoids wasting large alignment padding between file buffer and
     * final segments, enabling boot on systems with as little as 4MB RAM.
     *
     * For large kernels (>512KB), fall back to a contiguous allocation
     * that places both file buffer and segments in one block.
     *
     * The scratch area (FILE_SCRATCH_ADDR) is temporary and NOT tracked by
     * BootAlloc. BootAlloc starts at MB(2), above the scratch area.
     */
    void *kernel_buffer;
    uint64_t final_load_addr;
    uint64_t kernel_load_area;

    if (kernel_file_size <= (FILE_SCRATCH_LIMIT - FILE_SCRATCH_ADDR)) {
        /* Small kernel: use 1MB scratch area for raw ELF file */
        kernel_buffer = (void *)FILE_SCRATCH_ADDR;

        print_line("Loading kernel (split-load)...");
        ssize_t loaded = fs_load_from_entry(&g_boot_disk, kernel_entry_info,
                                            kernel_buffer, kernel_file_size);
        if (loaded < 0) {
            stage3_panic("Failed to load kernel");
        }

        /* Allocate space for processed segments only */
        kernel_load_area = boot_alloc(&ba, elf_mem_size, kernel_align,
                                       BOOT_ALLOC_KERNEL);
        if (kernel_load_area == 0) {
            print_str("Need kernel bytes: ");
            print_hex((uint32_t)elf_mem_size, 8);
            print_char('\n');
            stage3_panic("Insufficient RAM for kernel");
        }
        final_load_addr = kernel_load_area;
    } else {
        /* Large kernel: contiguous allocation (file buffer + segments) */
        uint64_t total_needed = ALIGN_UP(kernel_file_size, kernel_align) + elf_mem_size;
        kernel_load_area = boot_alloc(&ba, total_needed, kernel_align,
                                       BOOT_ALLOC_KERNEL);
        if (kernel_load_area == 0) {
            print_str("Need kernel bytes: ");
            print_hex((uint32_t)total_needed, 8);
            print_char('\n');
            stage3_panic("Insufficient RAM for kernel");
        }
        kernel_buffer = (void *)(uintptr_t)kernel_load_area;

        print_line("Loading kernel...");
        ssize_t loaded = fs_load_from_entry(&g_boot_disk, kernel_entry_info,
                                            kernel_buffer, total_needed);
        if (loaded < 0) {
            stage3_panic("Failed to load kernel");
        }

        final_load_addr = kernel_load_area + kernel_file_size;
        final_load_addr = ALIGN_UP(final_load_addr, kernel_align);
    }

    print_str("Kernel load area: ");
    print_hex((uint32_t)kernel_load_area, 8);
    print_char('\n');

#if CONFIG_DEBUG
    print_str("ELF: vaddr range ");
    print_hex64(min_vaddr);
    print_str(" - ");
    print_hex64(max_vaddr);
    print_char('\n');
    print_str("Loading to ");
    print_hex64(final_load_addr);
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
    print_hex64(load_result.entry);
    print_char('\n');

    /* Initrd is required now that kernel fallback init path is removed. */
    const struct BootManifestEntry *initrd_entry =
        manifest_find_entry(manifest, MANIFEST_ENTRY_INITRD);

    if (!initrd_entry || initrd_entry->size_bytes == 0) {
        stage3_panic("Missing required initrd");
    }

    /* Allocate space for initrd via BootAlloc */
    uint64_t initrd_addr = boot_alloc(&ba, initrd_entry->size_bytes,
                                       PAGE_SIZE_4K, BOOT_ALLOC_INITRD);
    if (initrd_addr == 0) {
        stage3_panic("Failed to allocate initrd memory");
    }

    print_str("Loading initrd to ");
    print_hex((uint32_t)initrd_addr, 8);
    print_str(" size=");
    print_hex((uint32_t)initrd_entry->size_bytes, 8);
    print_char('\n');

    ssize_t initrd_loaded = fs_load_from_entry(
        &g_boot_disk, initrd_entry,
        (void *)(uintptr_t)initrd_addr, initrd_entry->size_bytes);
    if (initrd_loaded < 0) {
        stage3_panic("Failed to load required initrd");
    }
    g_ctx.initrd_phys_addr = initrd_addr;
    g_ctx.initrd_size = initrd_entry->size_bytes;
    print_line("Initrd loaded");

    /* Allocate page table pool via BootAlloc */
    uint64_t pt_pool = boot_alloc(&ba, PT_POOL_SIZE, PAGE_SIZE_4K,
                                   BOOT_ALLOC_PAGE_TABLES);
    if (pt_pool == 0) {
        stage3_panic("Failed to allocate page table pool");
    }

    /* Set up page tables using dynamic pool */
    print_line("Setting up page tables...");
    uint64_t pml4 = paging_init_dynamic(pt_pool, PT_POOL_SIZE,
                                         g_ctx.kernel_phys_base,
                                         g_ctx.kernel_size,
                                         PAGING_PAGE_1G);
    if (pml4 == 0) {
        stage3_panic("Failed to set up page tables");
    }

    /* Allocate kernel stack via BootAlloc */
    uint64_t stack_addr = boot_alloc(&ba, KERNEL_STACK_SIZE, PAGE_SIZE_4K,
                                      BOOT_ALLOC_STACK);
    if (stack_addr == 0) {
        stage3_panic("Failed to allocate kernel stack");
    }
    g_ctx.kernel_stack_top = stack_addr + KERNEL_STACK_SIZE;

    /* Allocate BootInfo buffer via BootAlloc */
    uint64_t bi_buf = boot_alloc(&ba, BOOTINFO_BUFFER_SIZE, PAGE_SIZE_4K,
                                  BOOT_ALLOC_BOOTINFO);
    if (bi_buf == 0) {
        stage3_panic("Failed to allocate BootInfo buffer");
    }

    /* Build BootInfo */
    print_line("Building BootInfo...");
    struct BootInfoHeader *bootinfo = handoff_build_bootinfo(
        (void *)(uintptr_t)bi_buf, BOOTINFO_BUFFER_SIZE,
        info, 0, &load_result,
        g_ctx.initrd_phys_addr, g_ctx.initrd_size,
        ba.records, ba.record_count);

    if (!bootinfo) {
        stage3_panic("Failed to build BootInfo");
    }

    print_line("Entering long mode and jumping to kernel...");

    /* Switch to long mode and jump to kernel */
    enter_long_mode_and_jump(
        (uint32_t)pml4,
        g_ctx.kernel_entry,
        (uint64_t)(uintptr_t)bootinfo,
        g_ctx.kernel_stack_top);

    /* Never reached */
    stage3_panic("Returned from kernel");
}
