/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - BootInfo TLV Structures
 *
 * BootInfo is a stable ABI contract between the bootloader and kernel.
 * It uses a TLV (Type-Length-Value) format for extensibility.
 * All addresses are physical unless specified otherwise.
 */

#ifndef BOOT_COMMON_BOOTINFO_TLV_H
#define BOOT_COMMON_BOOTINFO_TLV_H

#include "types.h"

/* BootInfo magic: "SALTYBOO" in little-endian */
#define BOOTINFO_MAGIC   0x53414C5459424F4FULL
#define BOOTINFO_VERSION 1

/* TLV type identifiers */
enum BootInfoTLVType {
    TLV_END          = 0,   /* End marker (no data) */
    TLV_MEMMAP       = 1,   /* Memory map */
    TLV_KERNEL_IMAGE = 2,   /* Kernel image info */
    TLV_INITRD       = 3,   /* Initial ramdisk */
    TLV_CMDLINE      = 4,   /* Kernel command line */
    TLV_FRAMEBUFFER  = 5,   /* Framebuffer info */
    TLV_ACPI_RSDP    = 6,   /* ACPI RSDP address */
    TLV_DTB          = 7,   /* Device Tree Blob address */
    TLV_SMBIOS       = 8,   /* SMBIOS entry point */
    TLV_BOOT_TIME    = 9,   /* Boot timestamp */
    TLV_LOADER_INFO  = 10,  /* Bootloader identification */
};

/* Memory map entry types (E820-compatible) */
enum MemMapType {
    MEMMAP_USABLE      = 1,  /* Available for use */
    MEMMAP_RESERVED    = 2,  /* Reserved by firmware */
    MEMMAP_ACPI_RECL   = 3,  /* ACPI reclaimable */
    MEMMAP_ACPI_NVS    = 4,  /* ACPI NVS */
    MEMMAP_BAD         = 5,  /* Bad memory */
    MEMMAP_BOOTLOADER  = 16, /* Used by bootloader */
    MEMMAP_KERNEL      = 17, /* Kernel image */
    MEMMAP_INITRD      = 18, /* Initial ramdisk */
    MEMMAP_BOOTINFO    = 19, /* BootInfo structure */
};

/* BootInfo header flags */
#define BOOTINFO_FLAG_UEFI_BOOT    (1 << 0)  /* Booted via UEFI */
#define BOOTINFO_FLAG_SECURE_BOOT  (1 << 1)  /* Secure boot active */
#define BOOTINFO_FLAG_HAS_FB       (1 << 2)  /* Framebuffer available */
#define BOOTINFO_FLAG_STAGE3_EL2   (1 << 4)  /* Stage3 entered kernel path from EL2 */

/*
 * BootInfoHeader - Main BootInfo header
 *
 * Passed to kernel via RDI register (x86_64).
 * The header is followed by a series of TLV records.
 */
struct BootInfoHeader {
    uint64_t magic;        /* BOOTINFO_MAGIC */
    uint16_t version;      /* BOOTINFO_VERSION */
    uint16_t arch;         /* Architecture (ARCH_*) */
    uint32_t total_size;   /* Total size including all TLVs */
    uint32_t flags;        /* Header flags */
    uint32_t reserved;
} PACKED;

/*
 * BootInfoTLV - TLV record header
 *
 * Each TLV consists of this header followed by `length` bytes of data.
 * TLVs are 8-byte aligned.
 */
struct BootInfoTLV {
    uint16_t type;      /* BootInfoTLVType */
    uint16_t reserved;
    uint32_t length;    /* Length of data following this header */
} PACKED;

/*
 * Memory map entry
 */
struct BootInfoMemMapEntry {
    uint64_t base;      /* Physical base address */
    uint64_t length;    /* Region length in bytes */
    uint32_t type;      /* MemMapType */
    uint32_t reserved;
} PACKED;

/*
 * TLV_MEMMAP data: array of BootInfoMemMapEntry
 * Count = tlv->length / sizeof(BootInfoMemMapEntry)
 */

/*
 * Kernel image info (TLV_KERNEL_IMAGE)
 */
struct BootInfoKernelImage {
    uint64_t phys_base;     /* Physical load address */
    uint64_t virt_base;     /* Virtual base (from ELF) */
    uint64_t size;          /* Total size in memory */
    uint64_t entry_point;   /* Entry point address */
} PACKED;

/*
 * Initial ramdisk info (TLV_INITRD)
 */
struct BootInfoInitrd {
    uint64_t phys_addr;     /* Physical address */
    uint64_t size;          /* Size in bytes */
} PACKED;

/*
 * Framebuffer info (TLV_FRAMEBUFFER)
 */
struct BootInfoFramebuffer {
    uint64_t phys_addr;     /* Framebuffer physical address */
    uint32_t width;         /* Width in pixels */
    uint32_t height;        /* Height in pixels */
    uint32_t pitch;         /* Bytes per scanline */
    uint32_t bpp;           /* Bits per pixel */
    uint8_t  red_pos;       /* Red field position */
    uint8_t  red_size;      /* Red field size */
    uint8_t  green_pos;     /* Green field position */
    uint8_t  green_size;    /* Green field size */
    uint8_t  blue_pos;      /* Blue field position */
    uint8_t  blue_size;     /* Blue field size */
    uint8_t  reserved[2];
} PACKED;

/*
 * ACPI RSDP info (TLV_ACPI_RSDP)
 */
struct BootInfoACPI {
    uint64_t rsdp_addr;     /* Physical address of RSDP */
    uint8_t  revision;      /* ACPI revision (0 = 1.0, 2 = 2.0+) */
    uint8_t  reserved[7];
} PACKED;

/*
 * Device Tree Blob info (TLV_DTB)
 */
struct BootInfoDTB {
    uint64_t phys_addr;     /* Physical address of DTB */
    uint64_t size;          /* Size in bytes */
} PACKED;

/*
 * SMBIOS info (TLV_SMBIOS)
 */
struct BootInfoSMBIOS {
    uint64_t entry_point;   /* SMBIOS entry point address */
    uint8_t  major_version; /* SMBIOS major version */
    uint8_t  minor_version; /* SMBIOS minor version */
    uint8_t  reserved[6];
} PACKED;

/*
 * Bootloader info (TLV_LOADER_INFO)
 */
struct BootInfoLoader {
    uint8_t  name[32];      /* Loader name (null-terminated) */
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t version_patch;
    uint16_t reserved;
} PACKED;

/*
 * Helper macros for TLV traversal
 */

/* Get pointer to TLV data */
#define TLV_DATA(tlv) ((void *)((uint8_t *)(tlv) + sizeof(struct BootInfoTLV)))

/* Get next TLV (8-byte aligned) */
#define TLV_NEXT(tlv) ((struct BootInfoTLV *)( \
    (uint8_t *)(tlv) + sizeof(struct BootInfoTLV) + \
    ALIGN_UP((tlv)->length, 8)))

/* Get first TLV after header */
#define BOOTINFO_FIRST_TLV(hdr) \
    ((struct BootInfoTLV *)((uint8_t *)(hdr) + sizeof(struct BootInfoHeader)))

/* Check if TLV is within bounds */
#define TLV_IN_BOUNDS(hdr, tlv) \
    ((uint8_t *)(tlv) < (uint8_t *)(hdr) + (hdr)->total_size)

/*
 * Helper function to find a TLV by type
 */
static inline const struct BootInfoTLV *bootinfo_find_tlv(
    const struct BootInfoHeader *hdr, enum BootInfoTLVType type)
{
    if (!hdr || hdr->magic != BOOTINFO_MAGIC)
        return NULL;

    const struct BootInfoTLV *tlv = BOOTINFO_FIRST_TLV(hdr);

    while (TLV_IN_BOUNDS(hdr, tlv) && tlv->type != TLV_END) {
        if (tlv->type == type)
            return tlv;
        tlv = TLV_NEXT(tlv);
    }

    return NULL;
}

/*
 * BootInfo builder context (used by Stage 3)
 */
struct BootInfoBuilder {
    struct BootInfoHeader *hdr;  /* Header being built */
    uint8_t *current;            /* Current write position */
    uint8_t *end;                /* End of buffer */
    uint32_t tlv_count;          /* Number of TLVs added */
};

static inline void bootinfo_builder_init(
    struct BootInfoBuilder *builder,
    void *buffer,
    size_t buffer_size)
{
    builder->hdr = (struct BootInfoHeader *)buffer;
    builder->current = (uint8_t *)buffer + sizeof(struct BootInfoHeader);
    builder->end = (uint8_t *)buffer + buffer_size;
    builder->tlv_count = 0;

    builder->hdr->magic = BOOTINFO_MAGIC;
    builder->hdr->version = BOOTINFO_VERSION;
    builder->hdr->arch = ARCH_X86_64;
    builder->hdr->total_size = sizeof(struct BootInfoHeader);
    builder->hdr->flags = 0;
    builder->hdr->reserved = 0;
}

static inline bool bootinfo_builder_add_tlv(
    struct BootInfoBuilder *builder,
    enum BootInfoTLVType type,
    const void *data,
    uint32_t length)
{
    uint32_t aligned_len = ALIGN_UP(length, 8);
    uint32_t total_size = sizeof(struct BootInfoTLV) + aligned_len;

    if (builder->current + total_size > builder->end)
        return false;

    struct BootInfoTLV *tlv = (struct BootInfoTLV *)builder->current;
    tlv->type = type;
    tlv->reserved = 0;
    tlv->length = length;

    if (data && length > 0) {
        uint8_t *dest = (uint8_t *)TLV_DATA(tlv);
        const uint8_t *src = (const uint8_t *)data;
        for (uint32_t i = 0; i < length; i++)
            dest[i] = src[i];
        /* Zero padding */
        for (uint32_t i = length; i < aligned_len; i++)
            dest[i] = 0;
    }

    builder->current += total_size;
    builder->hdr->total_size += total_size;
    builder->tlv_count++;

    return true;
}

static inline void bootinfo_builder_finish(struct BootInfoBuilder *builder)
{
    /* Add end marker */
    if (builder->current + sizeof(struct BootInfoTLV) <= builder->end) {
        struct BootInfoTLV *end = (struct BootInfoTLV *)builder->current;
        end->type = TLV_END;
        end->reserved = 0;
        end->length = 0;
        builder->hdr->total_size += sizeof(struct BootInfoTLV);
    }
}

#endif /* BOOT_COMMON_BOOTINFO_TLV_H */
