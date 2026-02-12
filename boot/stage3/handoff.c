/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Kernel Handoff Implementation
 *
 * Builds the BootInfo structure and prepares for kernel handoff.
 * Note: The actual jump to kernel is handled by mode_switch.asm
 * since it requires switching from 32-bit to 64-bit mode.
 */

#include "handoff.h"
#include "../common/print.h"
#include "../common/string.h"
#include "config.h"

struct BootInfoHeader *handoff_build_bootinfo(
    void *buffer,
    size_t buffer_size,
    struct Stage2Info *stage2_info,
    struct ElfLoadResult *kernel,
    uint64_t initrd_addr,
    uint64_t initrd_size)
{
    struct BootInfoBuilder builder;

    bootinfo_builder_init(&builder, buffer, buffer_size);

    /* Set architecture */
    builder.hdr->arch = ARCH_X86_64;

    /* Set flags */
    if (stage2_info->boot_mode == BOOT_MODE_UEFI)
        builder.hdr->flags |= BOOTINFO_FLAG_UEFI_BOOT;
    if (stage2_info->framebuffer_addr != 0)
        builder.hdr->flags |= BOOTINFO_FLAG_HAS_FB;

    /* Add memory map */
    if (stage2_info->memmap_addr && stage2_info->memmap_count > 0) {
        struct BootInfoMemMapEntry *entries;
        uint32_t count = stage2_info->memmap_count;

        /* Allocate temporary buffer for converted entries + 4 reservation entries */
        uint32_t max_entries = count + 4;
        if (max_entries > CONFIG_MAX_MEM_REGIONS)
            max_entries = CONFIG_MAX_MEM_REGIONS;
        size_t entries_size = max_entries * sizeof(struct BootInfoMemMapEntry);
        entries = (struct BootInfoMemMapEntry *)((uint8_t *)buffer + buffer_size - entries_size);

        if (stage2_info->memmap_format == MEMMAP_FORMAT_UEFI) {
            /*
             * UEFI memory map: EFI_MEMORY_DESCRIPTOR entries with variable stride.
             * Walk by memmap_entry_size bytes (descriptor size from GetMemoryMap).
             */
            uint8_t *map_base = (uint8_t *)(uintptr_t)stage2_info->memmap_addr;
            uint32_t stride = stage2_info->memmap_entry_size;

            /* EFI memory type constants (matching EFI_MEMORY_TYPE enum) */
            enum {
                EFI_RESERVED            = 0,
                EFI_LOADER_CODE         = 1,
                EFI_LOADER_DATA         = 2,
                EFI_BS_CODE             = 3,
                EFI_BS_DATA             = 4,
                EFI_RT_CODE             = 5,
                EFI_RT_DATA             = 6,
                EFI_CONVENTIONAL        = 7,
                EFI_UNUSABLE            = 8,
                EFI_ACPI_RECLAIM        = 9,
                EFI_ACPI_NVS            = 10,
                EFI_MMIO                = 11,
                EFI_MMIO_PORT           = 12,
                EFI_PAL_CODE            = 13,
                EFI_PERSISTENT          = 14,
            };

            for (uint32_t i = 0; i < count; i++) {
                /* EFI_MEMORY_DESCRIPTOR layout:
                 *   uint32_t Type          (offset 0)
                 *   uint64_t PhysicalStart (offset 4, may be padded to 8)
                 *   uint64_t VirtualStart  (offset 8+8=16)
                 *   uint64_t NumberOfPages (offset 16+8=24)
                 *   uint64_t Attribute     (offset 24+8=32)
                 *
                 * But the struct has padding: Type(4) + pad(4) + PhysStart(8) + ...
                 * So we cast to a minimal struct matching the ABI layout.
                 */
                struct {
                    uint32_t Type;
                    uint32_t _pad;
                    uint64_t PhysicalStart;
                    uint64_t VirtualStart;
                    uint64_t NumberOfPages;
                    uint64_t Attribute;
                } *desc = (void *)(map_base + i * stride);

                entries[i].base = desc->PhysicalStart;
                entries[i].length = desc->NumberOfPages * 4096;

                /* Convert EFI memory types to BootInfo types */
                switch (desc->Type) {
                case EFI_LOADER_CODE:
                case EFI_LOADER_DATA:
                case EFI_BS_CODE:
                case EFI_BS_DATA:
                case EFI_CONVENTIONAL:
                    entries[i].type = MEMMAP_USABLE;
                    break;
                case EFI_ACPI_RECLAIM:
                    entries[i].type = MEMMAP_ACPI_RECL;
                    break;
                case EFI_ACPI_NVS:
                    entries[i].type = MEMMAP_ACPI_NVS;
                    break;
                case EFI_UNUSABLE:
                    entries[i].type = MEMMAP_BAD;
                    break;
                default:
                    entries[i].type = MEMMAP_RESERVED;
                    break;
                }
                entries[i].reserved = 0;
            }
        } else {
            /* E820 memory map (BIOS path) */
            struct E820Entry *e820 = (struct E820Entry *)(uintptr_t)stage2_info->memmap_addr;

            for (uint32_t i = 0; i < count; i++) {
                entries[i].base = e820[i].base;
                entries[i].length = e820[i].length;

                /* Convert E820 types to BootInfo types */
                switch (e820[i].type) {
                case 1:  /* E820_USABLE */
                    entries[i].type = MEMMAP_USABLE;
                    break;
                case 2:  /* E820_RESERVED */
                    entries[i].type = MEMMAP_RESERVED;
                    break;
                case 3:  /* E820_ACPI_RECL */
                    entries[i].type = MEMMAP_ACPI_RECL;
                    break;
                case 4:  /* E820_ACPI_NVS */
                    entries[i].type = MEMMAP_ACPI_NVS;
                    break;
                case 5:  /* E820_BAD */
                    entries[i].type = MEMMAP_BAD;
                    break;
                default:
                    entries[i].type = MEMMAP_RESERVED;
                    break;
                }
                entries[i].reserved = 0;
            }
        }

        /*
         * Append reservation entries so the kernel knows which regions
         * are occupied by the bootloader, kernel image, and BootInfo.
         */
        uint32_t total = count;

        /* Reserve boot page tables (active until kernel replaces CR3) */
        if (total < CONFIG_MAX_MEM_REGIONS) {
            entries[total].base = 0x80000;
            entries[total].length = 0x9F000 - 0x80000;
            entries[total].type = MEMMAP_BOOTLOADER;
            entries[total].reserved = 0;
            total++;
        }

        /* Reserve kernel image region */
        if (total < CONFIG_MAX_MEM_REGIONS && kernel->phys_base != 0) {
            entries[total].base = kernel->phys_base;
            entries[total].length = kernel->mem_size;
            entries[total].type = MEMMAP_KERNEL;
            entries[total].reserved = 0;
            total++;
        }

        /* Reserve initrd region */
        if (total < CONFIG_MAX_MEM_REGIONS && initrd_addr != 0 && initrd_size != 0) {
            entries[total].base = initrd_addr;
            entries[total].length = initrd_size;
            entries[total].type = MEMMAP_INITRD;
            entries[total].reserved = 0;
            total++;
        }

        /* Reserve BootInfo buffer region */
        if (total < CONFIG_MAX_MEM_REGIONS) {
            entries[total].base = (uint64_t)(uintptr_t)buffer;
            entries[total].length = buffer_size;
            entries[total].type = MEMMAP_BOOTINFO;
            entries[total].reserved = 0;
            total++;
        }

        bootinfo_builder_add_tlv(&builder, TLV_MEMMAP,
                                 entries, total * sizeof(struct BootInfoMemMapEntry));
    }

    /* Add kernel image info */
    struct BootInfoKernelImage kernel_info = {
        .phys_base = kernel->phys_base,
        .virt_base = kernel->virt_base,
        .size = kernel->mem_size,
        .entry_point = kernel->entry,
    };
    bootinfo_builder_add_tlv(&builder, TLV_KERNEL_IMAGE,
                             &kernel_info, sizeof(kernel_info));

    /* Add initrd if present */
    if (initrd_addr != 0 && initrd_size != 0) {
        struct BootInfoInitrd initrd_info = {
            .phys_addr = initrd_addr,
            .size = initrd_size,
        };
        bootinfo_builder_add_tlv(&builder, TLV_INITRD,
                                 &initrd_info, sizeof(initrd_info));
    }

    /* Add framebuffer if present */
    if (stage2_info->framebuffer_addr != 0) {
        /*
         * Use pixel format from Stage2Info if populated (UEFI path),
         * otherwise fall back to BGR888 (common VGA/VBE default).
         */
        bool has_pixel_fmt = stage2_info->fb_red_size != 0;
        struct BootInfoFramebuffer fb_info = {
            .phys_addr = stage2_info->framebuffer_addr,
            .width = stage2_info->framebuffer_width,
            .height = stage2_info->framebuffer_height,
            .pitch = stage2_info->framebuffer_pitch,
            .bpp = stage2_info->framebuffer_bpp,
            .red_pos = has_pixel_fmt ? stage2_info->fb_red_pos : 16,
            .red_size = has_pixel_fmt ? stage2_info->fb_red_size : 8,
            .green_pos = has_pixel_fmt ? stage2_info->fb_green_pos : 8,
            .green_size = has_pixel_fmt ? stage2_info->fb_green_size : 8,
            .blue_pos = has_pixel_fmt ? stage2_info->fb_blue_pos : 0,
            .blue_size = has_pixel_fmt ? stage2_info->fb_blue_size : 8,
        };
        bootinfo_builder_add_tlv(&builder, TLV_FRAMEBUFFER,
                                 &fb_info, sizeof(fb_info));
    }

    /* Add ACPI RSDP if present */
    if (stage2_info->rsdp_addr != 0) {
        struct BootInfoACPI acpi_info = {
            .rsdp_addr = stage2_info->rsdp_addr,
            .revision = stage2_info->acpi_revision,
        };
        bootinfo_builder_add_tlv(&builder, TLV_ACPI_RSDP,
                                 &acpi_info, sizeof(acpi_info));
    }

    /* Add SMBIOS if present */
    if (stage2_info->smbios_addr != 0) {
        struct BootInfoSMBIOS smbios_info = {
            .entry_point = stage2_info->smbios_addr,
            .major_version = stage2_info->smbios_major,
            .minor_version = stage2_info->smbios_minor,
        };
        bootinfo_builder_add_tlv(&builder, TLV_SMBIOS,
                                 &smbios_info, sizeof(smbios_info));
    }

    /* Add bootloader info */
    struct BootInfoLoader loader_info = {
        .name = "SaltyOS Boot",
        .version_major = 1,
        .version_minor = 0,
        .version_patch = 0,
    };
    bootinfo_builder_add_tlv(&builder, TLV_LOADER_INFO,
                             &loader_info, sizeof(loader_info));

    /* Finish building */
    bootinfo_builder_finish(&builder);

#if CONFIG_DEBUG
    print_str("BootInfo: size=");
    print_dec(builder.hdr->total_size);
    print_str(" TLVs=");
    print_dec(builder.tlv_count);
    print_char('\n');
#endif

    return builder.hdr;
}
