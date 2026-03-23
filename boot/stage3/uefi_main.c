/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 UEFI Entry Point
 *
 * Stage 3 UEFI path: called from Stage 2 UEFI with Boot Services alive.
 * Already in 64-bit long mode with UEFI identity paging.
 *
 * Uses Boot Services to:
 * 1. Load kernel from ESP
 * 2. Allocate memory for kernel segments and page tables
 * 3. GetMemoryMap + ExitBootServices
 * 4. Set up page tables
 * 5. Build BootInfo and jump to kernel
 */

#include "../common/types.h"
#include "../common/print.h"
#include "../common/fb_console.h"
#include "../common/bootinfo_tlv.h"
#include "../common/stage2_info.h"
#include "../common/efi/efi_types.h"
#include "../common/efi/efi_protocol.h"
#include "stage3.h"
#include "config.h"
#include "elf.h"
#include "paging.h"
#include "handoff.h"
#include "boot_alloc.h"

/* GUIDs for UEFI file loading */
static EFI_GUID s_LoadedImageGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID s_FileSysGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID s_FileInfoGuid = { 0x09576E92, 0x6D3F, 0x11D2,
    { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };

static CHAR16 s_KernelPath[] = { '\\','E','F','I','\\','S','A','L','T','Y',
    'O','S','\\','k','e','r','n','e','l','.','e','l','f', 0 };

static CHAR16 s_InitrdPath[] = { '\\','E','F','I','\\','S','A','L','T','Y',
    'O','S','\\','i','n','i','t','r','d','.','i','m','g', 0 };

/* Page table pool: 32 pages = 128KB */
#define PT_POOL_PAGES   32

/*
 * Load a file from ESP using UEFI Boot Services
 *
 * Returns allocated buffer address in *out_buf, size in *out_size.
 * Caller must not free (we're about to ExitBootServices).
 */
static int uefi_load_file(EFI_BOOT_SERVICES *bs, EFI_HANDLE image_handle,
                          CHAR16 *path, void **out_buf, uint64_t *out_size)
{
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *li;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    EFI_FILE_PROTOCOL *root, *file;
    UINTN info_size, file_size;
    EFI_FILE_INFO *finfo;
    UINTN pages;
    uint64_t buf_addr;

    status = bs->HandleProtocol(image_handle, &s_LoadedImageGuid, (void **)&li);
    if (EFI_ERROR(status)) return -1;

    status = bs->HandleProtocol(li->DeviceHandle, &s_FileSysGuid, (void **)&fs);
    if (EFI_ERROR(status)) return -1;

    status = fs->OpenVolume(fs, &root);
    if (EFI_ERROR(status)) return -1;

    status = root->Open(root, &file, path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) { root->Close(root); return -1; }

    /* Get file size */
    info_size = 0;
    file->GetInfo(file, &s_FileInfoGuid, &info_size, NULL);

    status = bs->AllocatePool(EfiLoaderData, info_size, (void **)&finfo);
    if (EFI_ERROR(status)) { file->Close(file); root->Close(root); return -1; }

    status = file->GetInfo(file, &s_FileInfoGuid, &info_size, finfo);
    if (EFI_ERROR(status)) { bs->FreePool(finfo); file->Close(file); root->Close(root); return -1; }

    file_size = (UINTN)finfo->FileSize;
    bs->FreePool(finfo);

    /* Allocate pages for the file */
    pages = EFI_SIZE_TO_PAGES(file_size);
    buf_addr = 0;
    status = bs->AllocatePages(AllocateAnyPages, EfiLoaderData, pages, &buf_addr);
    if (EFI_ERROR(status)) { file->Close(file); root->Close(root); return -1; }

    /* Read file */
    status = file->Read(file, &file_size, (void *)buf_addr);
    file->Close(file);
    root->Close(root);

    if (EFI_ERROR(status)) return -1;

    *out_buf = (void *)buf_addr;
    *out_size = file_size;
    return 0;
}

/*
 * Stage 3 64-bit entry point (UEFI path)
 *
 * Called from Stage 2 UEFI with Boot Services still alive.
 * We're already in 64-bit long mode with UEFI identity paging.
 *
 * Stage 2 passes EFI System Table and Image Handle via Stage2Info.
 */
void stage3_entry_64(struct Stage2Info *info)
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

    print_line("=== SaltyOS Stage 3 (64-bit) ===");

    /* Validate Stage2Info */
    if (!info || info->magic != STAGE2_MAGIC) {
        stage3_panic("Invalid Stage2Info");
    }

    print_str("Boot mode: UEFI (64-bit)\n");

    /* Get EFI context from Stage2Info */
    EFI_SYSTEM_TABLE *systable = (EFI_SYSTEM_TABLE *)(uintptr_t)info->efi_system_table;
    EFI_HANDLE image_handle = (EFI_HANDLE)(uintptr_t)info->efi_image_handle;

    if (!systable || !image_handle) {
        stage3_panic("No EFI context in Stage2Info");
    }

    EFI_BOOT_SERVICES *bs = systable->BootServices;

    /* Initialize BootAlloc (UEFI wrapper) */
    struct BootAlloc ba;
    boot_alloc_init_uefi(&ba, (uint64_t)(uintptr_t)bs);

    /* Load kernel from ESP (temp buffer, not tracked by BootAlloc) */
    print_line("Loading kernel from ESP...");
    void *kernel_buffer = NULL;
    uint64_t kernel_file_size = 0;

    if (uefi_load_file(bs, image_handle, s_KernelPath,
                       &kernel_buffer, &kernel_file_size) != 0) {
        stage3_panic("Failed to load kernel from ESP");
    }

    print_str("Kernel loaded: addr=0x");
    print_hex((uint64_t)(uintptr_t)kernel_buffer, 16);
    print_str(" size=");
    print_hex(kernel_file_size, 8);
    print_char('\n');

    /* Load initrd from ESP (required). Register with BootAlloc. */
    void *initrd_buffer = NULL;
    uint64_t initrd_file_size = 0;
    if (uefi_load_file(bs, image_handle, s_InitrdPath,
                        &initrd_buffer, &initrd_file_size) == 0) {
        /* Register uefi_load_file's allocation with BootAlloc */
        boot_alloc_register(&ba, (uint64_t)(uintptr_t)initrd_buffer,
                            initrd_file_size, BOOT_ALLOC_INITRD);
        print_str("Initrd loaded: addr=0x");
        print_hex((uint64_t)(uintptr_t)initrd_buffer, 16);
        print_str(" size=");
        print_hex(initrd_file_size, 8);
        print_char('\n');
    } else {
        stage3_panic("Failed to load required initrd from ESP");
    }

    /* Validate ELF header */
    int err = elf_validate((struct Elf64_Ehdr *)kernel_buffer);
    if (err != ELF_OK) {
        print_str("ELF validation failed: ");
        print_dec(err);
        print_char('\n');
        stage3_panic("Invalid kernel ELF");
    }

    /* Calculate kernel size from ELF */
    uint64_t min_vaddr, max_vaddr;
    err = elf_calc_size(kernel_buffer, &min_vaddr, &max_vaddr);
    if (err != ELF_OK) {
        stage3_panic("Failed to calculate kernel size");
    }

    uint64_t elf_mem_size = max_vaddr - min_vaddr;

    /*
     * Allocate pages for kernel segments via BootAlloc.
     * Prefer 2MB alignment, but fall back to 4KB alignment under low memory.
     */
    uint64_t kernel_align = KERNEL_LOAD_ALIGN;
    uint64_t kernel_pages_addr = boot_alloc(&ba, elf_mem_size + kernel_align,
                                             PAGE_SIZE_4K, BOOT_ALLOC_KERNEL);
    if (kernel_pages_addr == 0) {
        kernel_align = KERNEL_LOWMEM_ALIGN;
        kernel_pages_addr = boot_alloc(&ba, elf_mem_size + kernel_align,
                                        PAGE_SIZE_4K, BOOT_ALLOC_KERNEL);
        if (kernel_pages_addr == 0) {
            stage3_panic("Failed to allocate kernel pages");
        }
        print_line("Kernel allocation fallback: 4KB alignment");
    }
    uint64_t final_load_addr = ALIGN_UP(kernel_pages_addr, kernel_align);

    /* Load kernel ELF segments */
    struct ElfLoadResult load_result;
    err = elf_load(kernel_buffer, kernel_file_size,
                   final_load_addr,
                   paging_get_kernel_virt_base(),
                   &load_result);
    if (err != ELF_OK) {
        print_str("ELF load failed: ");
        print_dec(err);
        print_char('\n');
        stage3_panic("Failed to load kernel");
    }

    print_str("Kernel relocated: entry=0x");
    print_hex(load_result.entry, 16);
    print_char('\n');

    /* Allocate page table pool via BootAlloc */
    uint64_t pt_pool_base = boot_alloc(&ba, PT_POOL_PAGES * 4096,
                                        PAGE_SIZE_4K, BOOT_ALLOC_PAGE_TABLES);
    if (pt_pool_base == 0) {
        stage3_panic("Failed to allocate page table pages");
    }

    /* Allocate kernel stack via BootAlloc */
    uint64_t stack_addr = boot_alloc(&ba, KERNEL_STACK_SIZE, PAGE_SIZE_4K,
                                      BOOT_ALLOC_STACK);
    if (stack_addr == 0) {
        stage3_panic("Failed to allocate kernel stack");
    }

    /* Allocate BootInfo buffer via BootAlloc */
    uint64_t bi_buf = boot_alloc(&ba, BOOTINFO_BUFFER_SIZE, PAGE_SIZE_4K,
                                  BOOT_ALLOC_BOOTINFO);
    if (bi_buf == 0) {
        stage3_panic("Failed to allocate BootInfo buffer");
    }

    /* Finalize BootAlloc before ExitBootServices */
    boot_alloc_finalize_uefi(&ba);

    /*
     * GetMemoryMap + ExitBootServices
     *
     * Must be done as the last Boot Services calls. Any call between
     * GetMemoryMap and ExitBootServices can invalidate the map key.
     *
     * Use 2-step dynamic allocation: query required size first, then
     * allocate with margin (AllocatePool itself adds map entries).
     */
    print_line("Exiting Boot Services...");

    UINTN memmap_size = 0;
    UINTN map_key, desc_size;
    uint32_t desc_version;
    uint8_t *memmap_buf = NULL;

    /* Step 1: Query required size */
    EFI_STATUS efi_status = bs->GetMemoryMap(&memmap_size, NULL,
                                  &map_key, &desc_size, &desc_version);
    /* Expected: EFI_BUFFER_TOO_SMALL, memmap_size now holds required size */

    /* Step 2: Allocate with margin (allocation itself adds entries) */
    memmap_size += 2 * desc_size;
    efi_status = bs->AllocatePool(EfiLoaderData, memmap_size,
                                  (void **)&memmap_buf);
    if (EFI_ERROR(efi_status)) {
        stage3_panic("AllocatePool for memory map failed");
    }

    /* Step 3: Get actual map */
    efi_status = bs->GetMemoryMap(&memmap_size,
                                  (EFI_MEMORY_DESCRIPTOR *)memmap_buf,
                                  &map_key, &desc_size, &desc_version);
    if (EFI_ERROR(efi_status)) {
        stage3_panic("GetMemoryMap failed");
    }

    /* Store memory map in Stage2Info for BootInfo construction */
    info->memmap_addr = (uint64_t)(uintptr_t)memmap_buf;
    info->memmap_count = (uint32_t)(memmap_size / desc_size);
    info->memmap_entry_size = (uint16_t)desc_size;
    info->memmap_format = MEMMAP_FORMAT_UEFI;

    efi_status = bs->ExitBootServices(image_handle, map_key);
    if (EFI_ERROR(efi_status)) {
        /*
         * Retry: map may have changed between GetMemoryMap and
         * ExitBootServices. Re-query with the existing buffer
         * (already large enough since we added margin).
         */
        efi_status = bs->GetMemoryMap(&memmap_size,
                                      (EFI_MEMORY_DESCRIPTOR *)memmap_buf,
                                      &map_key, &desc_size, &desc_version);
        if (EFI_ERROR(efi_status)) {
            stage3_panic("GetMemoryMap retry failed");
        }

        info->memmap_count = (uint32_t)(memmap_size / desc_size);

        efi_status = bs->ExitBootServices(image_handle, map_key);
        if (EFI_ERROR(efi_status)) {
            stage3_panic("ExitBootServices failed");
        }
    }

    /*
     * After ExitBootServices:
     * - No more UEFI Boot Services
     * - We own all memory
     * - Set up page tables and jump to kernel
     */

    /* Compute the highest physical address used by boot allocations
     * so the identity map covers everything the kernel needs to access
     * before it sets up its own direct physical map. */
    uint64_t boot_max_addr = 0;
    for (uint32_t i = 0; i < ba.record_count; i++) {
        uint64_t end = ba.records[i].phys_addr + ba.records[i].size;
        if (end > boot_max_addr)
            boot_max_addr = end;
    }

    /* Set up page tables using dynamically allocated pool */
    uint64_t pml4 = paging_init_dynamic(pt_pool_base, PT_POOL_PAGES * 4096,
                                         load_result.phys_base, load_result.mem_size,
                                         boot_max_addr);
    if (pml4 == 0) {
        stage3_panic("Failed to set up page tables");
    }

    /* Build BootInfo */
    struct BootInfoHeader *bootinfo = handoff_build_bootinfo(
        (void *)(uintptr_t)bi_buf, BOOTINFO_BUFFER_SIZE,
        info, &load_result,
        (uint64_t)(uintptr_t)initrd_buffer, initrd_file_size,
        ba.records, ba.record_count);

    if (!bootinfo) {
        stage3_panic("Failed to build BootInfo");
    }

    /* Load new page table */
    paging_load_cr3(pml4);

    /* Jump to kernel */
#if defined(__aarch64__)
    __asm__ volatile(
        "mov sp, %0\n\t"
        "mov x0, %1\n\t"
        "br  %2\n\t"
        :
        : "r"((uint64_t)(stack_addr + KERNEL_STACK_SIZE)),
          "r"((uint64_t)(uintptr_t)bootinfo),
          "r"(load_result.entry)
        : "memory"
    );
#else
    __asm__ volatile(
        "mov %0, %%rsp\n\t"
        "xor %%rbp, %%rbp\n\t"
        "mov %1, %%rdi\n\t"
        "jmp *%2\n\t"
        :
        : "r"((uint64_t)(stack_addr + KERNEL_STACK_SIZE)),
          "r"((uint64_t)(uintptr_t)bootinfo),
          "r"(load_result.entry)
        : "memory"
    );
#endif

    stage3_panic("Returned from kernel");
}
