/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage2Info Structure
 *
 * Stage2Info is passed from Stage 2 to Stage 3.
 * It contains platform information collected during early boot.
 */

#ifndef BOOT_COMMON_STAGE2_INFO_H
#define BOOT_COMMON_STAGE2_INFO_H

#include "types.h"

/* Stage2Info magic: "STAG" */
#define STAGE2_MAGIC   0x53544147u
#define STAGE2_VERSION 1

/* Memory map format identifiers */
#define MEMMAP_FORMAT_E820   1
#define MEMMAP_FORMAT_UEFI   2

/* Stage2Info flags */
#define STAGE2_FLAG_A20_ENABLED     (1 << 0)
#define STAGE2_FLAG_LONG_MODE       (1 << 1)
#define STAGE2_FLAG_PAGING_ENABLED  (1 << 2)
#define STAGE2_FLAG_HAS_FRAMEBUFFER (1 << 3)
#define STAGE2_FLAG_HAS_ACPI        (1 << 4)
#define STAGE2_FLAG_HAS_SMBIOS      (1 << 5)

/*
 * E820 memory map entry (BIOS)
 */
struct E820Entry {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t acpi_attr;  /* ACPI 3.0 extended attributes */
} PACKED;

#define E820_MAX_ENTRIES 64

/*
 * Stage2Info - Information passed from Stage 2 to Stage 3
 *
 * This structure is populated by Stage 2 and validated by Stage 3.
 */
struct Stage2Info {
    /* Header */
    uint32_t magic;           /* STAGE2_MAGIC */
    uint16_t version;         /* STAGE2_VERSION */
    uint16_t arch;            /* Architecture (ARCH_*) */

    /* Boot mode and flags */
    uint32_t boot_mode;       /* BOOT_MODE_BIOS or BOOT_MODE_UEFI */
    uint32_t flags;           /* Stage2 flags */

    /* Boot disk information */
    uint8_t  boot_drive;      /* BIOS drive number (DL) */
    uint8_t  reserved1[3];
    uint32_t reserved2;

    /* Manifest location */
    uint64_t manifest_lba;    /* LBA of boot manifest */

    /* Memory map */
    uint64_t memmap_addr;     /* Physical address of memory map */
    uint32_t memmap_count;    /* Number of entries */
    uint16_t memmap_entry_size;  /* Size of each entry */
    uint8_t  memmap_format;   /* MEMMAP_FORMAT_* */
    uint8_t  reserved3;

    /* Firmware tables */
    uint64_t rsdp_addr;       /* ACPI RSDP address (0 if not found) */
    uint64_t dtb_addr;        /* Device tree address (0 if not found) */
    uint64_t smbios_addr;     /* SMBIOS entry point (0 if not found) */

    /* Framebuffer (optional) */
    uint64_t framebuffer_addr;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_bpp;

    /* Paging structures (if set up by Stage 2) */
    uint64_t pml4_addr;       /* PML4 table address (0 if not set up) */

    /* Stage 3 loading info */
    uint64_t stage3_addr;     /* Where Stage 3 was loaded */
    uint64_t stage3_size;     /* Stage 3 size */

    /* Preloaded kernel (optional, for BIOS path) */
    uint64_t kernel_preload_addr;  /* 0 if not preloaded */
    uint64_t kernel_preload_size;

    /* Framebuffer pixel format (populated by UEFI Stage 2) */
    uint8_t  fb_red_pos;      /* Red field bit position */
    uint8_t  fb_red_size;     /* Red field bit width */
    uint8_t  fb_green_pos;    /* Green field bit position */
    uint8_t  fb_green_size;   /* Green field bit width */
    uint8_t  fb_blue_pos;     /* Blue field bit position */
    uint8_t  fb_blue_size;    /* Blue field bit width */

    /* Firmware version info (populated by UEFI Stage 2) */
    uint8_t  acpi_revision;   /* ACPI revision (0=1.0, 2=2.0+) */
    uint8_t  smbios_major;    /* SMBIOS major version */
    uint8_t  smbios_minor;    /* SMBIOS minor version */

    /* EFI context (passed to Stage 3 for Boot Services access) */
    uint64_t efi_system_table;   /* EFI_SYSTEM_TABLE* (0 for BIOS) */
    uint64_t efi_image_handle;   /* EFI_HANDLE (0 for BIOS) */

    /* Reserved for future use */
    uint8_t  reserved4[7];
} PACKED;

/*
 * Helper function to validate Stage2Info
 */
static inline bool stage2_info_valid(const struct Stage2Info *info)
{
    if (!info)
        return false;
    if (info->magic != STAGE2_MAGIC)
        return false;
    if (info->version != STAGE2_VERSION)
        return false;
    if (info->memmap_addr == 0 || info->memmap_count == 0)
        return false;
    return true;
}

/*
 * Memory layout constants for Stage 2
 *
 * Real Mode layout (before long mode):
 *   0x00500 - 0x005FF  BDA extension (reserved)
 *   0x00600 - 0x006FF  Real mode stack (grows down from 0x6FF)
 *   0x01000 - 0x010FF  Stage2Info (256 bytes)
 *   0x01100 - 0x05FFF  Free (unused)
 *   0x06000 - 0x06FFF  BTX kernel stack (4 KB)
 *   0x07000 - 0x07BFF  V86 mode stack (grows down from 0x7FFF)
 *   0x07C00 - 0x07DFF  MBR (Stage 1)
 *   0x07E00 - 0x07FFF  Stage 2 stack (real mode, grows down)
 *   0x08000 - 0x17FFF  Stage 2 code (64 KB)
 *   0x18000 - 0x27FFF  Free
 *   0x28000 - 0x2FFFF  Boot Manifest buffer (32 KB)
 *   0x30000 - 0x3FFFF  Memory map buffer (64 KB)
 *   0x40000 - 0x7FFFF  Stage 3 load area (256 KB)
 *   0x80000 - 0x9EFFF  Page tables (124 KB)
 *   0x9F000 - 0x9FBFF  Free / protected mode stack
 *   0x9FC00 - 0x9FFFF  Extended BDA
 *   0xA0000 - 0xFFFFF  Video memory & ROM
 */
#define STAGE2_STACK_TOP      0x7FFF
#define STAGE2_LOAD_ADDR      0x8000
#define STAGE2_MAX_SIZE       KB(64)
#define STAGE3_LOAD_ADDR      0x40000
#define STAGE3_MAX_SIZE       KB(256)
#define MANIFEST_BUFFER_ADDR  0x28000
#define MANIFEST_BUFFER_SIZE  KB(32)
#define MEMMAP_BUFFER_ADDR    0x30000
#define MEMMAP_BUFFER_SIZE    KB(64)
#define PAGE_TABLE_ADDR       0x80000

/* Long Mode stack (above 1MB) */
#define LONGMODE_STACK_TOP    0x200000  /* 2 MB */
#define LONGMODE_STACK_SIZE   KB(64)

#endif /* BOOT_COMMON_STAGE2_INFO_H */
