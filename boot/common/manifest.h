/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Boot Manifest Structures
 *
 * The Boot Manifest is the single source of truth for boot contents.
 * It describes boot images via raw block extents, eliminating filesystem
 * dependency in the critical boot path.
 */

#ifndef BOOT_COMMON_MANIFEST_H
#define BOOT_COMMON_MANIFEST_H

#include "types.h"

/* Boot Manifest magic: "SALTYMAN" in little-endian */
#define BOOT_MANIFEST_MAGIC   0x53414C54594D414EULL
#define BOOT_MANIFEST_VERSION 1

/* Maximum number of extents per entry */
#define MAX_EXTENTS 8

/* Manifest entry types */
enum ManifestEntryType {
    MANIFEST_ENTRY_KERNEL = 1,
    MANIFEST_ENTRY_INITRD = 2,
    MANIFEST_ENTRY_STAGE3 = 3,
    MANIFEST_ENTRY_CONFIG = 4,
};

/* Manifest entry flags */
#define MANIFEST_FLAG_REQUIRED   (1 << 0)  /* Entry must be present */
#define MANIFEST_FLAG_COMPRESSED (1 << 1)  /* Entry is compressed */
#define MANIFEST_FLAG_VERIFIED   (1 << 2)  /* Entry has been verified */

/* Manifest header flags */
#define MANIFEST_HDR_FLAG_HAS_CHECKSUM (1 << 0)

/*
 * ManifestExtent - Describes a contiguous region on disk
 *
 * Extents are read sequentially and concatenated to form the complete image.
 */
struct ManifestExtent {
    uint64_t lba;           /* Starting LBA */
    uint32_t sector_count;  /* Number of sectors (512 bytes each) */
    uint32_t reserved;
} PACKED;

/*
 * BootManifestHeader - Main manifest header
 *
 * Located at BRA_START_LBA (default: 2048).
 * Validation of this header is mandatory before proceeding with boot.
 */
struct BootManifestHeader {
    uint64_t magic;           /* BOOT_MANIFEST_MAGIC */
    uint16_t version;         /* BOOT_MANIFEST_VERSION */
    uint16_t header_size;     /* Size of this header */
    uint32_t manifest_size;   /* Total manifest size including entries */

    uint32_t flags;           /* Header flags */
    uint16_t arch;            /* Target architecture (ARCH_*) */
    uint16_t entry_count;     /* Number of entries */

    uint64_t entry_table_off; /* Offset to entry table from manifest start */
    uint64_t checksum;        /* CRC64 (computed with this field zeroed) */
} PACKED;

/*
 * BootManifestEntry - Describes a single boot component
 *
 * Each entry describes one boot image (kernel, initrd, etc.) and its
 * location on disk as a series of extents.
 */
struct BootManifestEntry {
    uint16_t type;            /* ManifestEntryType */
    uint16_t flags;           /* Entry flags */
    uint32_t id;              /* Unique entry identifier */

    uint64_t size_bytes;      /* Total size in bytes */
    uint64_t load_align;      /* Required load alignment */

    uint32_t extent_count;    /* Number of valid extents */
    uint32_t reserved;

    struct ManifestExtent extents[MAX_EXTENTS];
} PACKED;

/*
 * Boot Reserved Area layout constants
 *
 * BRA_START_LBA: Start of Boot Reserved Area (1 MiB offset)
 * All boot components are stored at fixed offsets within the BRA.
 */
#define BRA_START_LBA       2048    /* 1 MiB / 512 = 2048 sectors */

/* Default layout within BRA (can be overridden by manifest) */
#define MANIFEST_LBA        BRA_START_LBA           /* Manifest at BRA start */
#define MANIFEST_SECTORS    64                      /* 32 KB for manifest */
#define STAGE2_LBA          (BRA_START_LBA + 64)    /* Stage 2 after manifest */
#define STAGE2_SECTORS      128                     /* 64 KB for Stage 2 */
#define STAGE3_LBA          (STAGE2_LBA + 128)      /* Stage 3 after Stage 2 */
#define STAGE3_SECTORS      512                     /* 256 KB for Stage 3 */
#define KERNEL_LBA          (STAGE3_LBA + 512)      /* Kernel after Stage 3 */

/*
 * CRC64-ECMA-182 computation (reflected/LSB-first, lookup table based)
 *
 * Polynomial: 0x42F0E1EBA9EA3693 (used in reflected/LSB-first mode)
 */
static inline uint64_t manifest_crc64(const void *data, size_t len)
{
    /* CRC64-ECMA-182 lookup table (256 entries, reflected/LSB-first) */
    static const uint64_t crc64_table[256] = {
        0x0000000000000000ULL, 0x3C3B78E888D80FE1ULL, 0x7876F1D111B01FC2ULL, 0x444D893999681023ULL,
        0x750C207570B452A3ULL, 0x4937589DF86C5D42ULL, 0x0D7AD1A461044D61ULL, 0x3141A94CE9DC4280ULL,
        0x6FF9833DB2BCC861ULL, 0x53C2FBD53A64C780ULL, 0x178F72ECA30CD7A3ULL, 0x2BB40A042BD4D842ULL,
        0x1AF5A348C2089AC2ULL, 0x26CEDBA04AD09523ULL, 0x62835299D3B88500ULL, 0x5EB82A715B608AE1ULL,
        0x5A12C5AC36ADFDE5ULL, 0x6629BD44BE75F204ULL, 0x2264347D271DE227ULL, 0x1E5F4C95AFC5EDC6ULL,
        0x2F1EE5D94619AF46ULL, 0x13259D31CEC1A0A7ULL, 0x5768140857A9B084ULL, 0x6B536CE0DF71BF65ULL,
        0x35EB469184113584ULL, 0x09D03E790CC93A65ULL, 0x4D9DB74095A12A46ULL, 0x71A6CFA81D7925A7ULL,
        0x40E766E4F4A56727ULL, 0x7CDC1E0C7C7D68C6ULL, 0x38919735E51578E5ULL, 0x04AAEFDD6DCD7704ULL,
        0x31C4488F3E8F96EDULL, 0x0DFF3067B657990CULL, 0x49B2B95E2F3F892FULL, 0x7589C1B6A7E786CEULL,
        0x44C868FA4E3BC44EULL, 0x78F31012C6E3CBAFULL, 0x3CBE992B5F8BDB8CULL, 0x0085E1C3D753D46DULL,
        0x5E3DCBB28C335E8CULL, 0x6206B35A04EB516DULL, 0x264B3A639D83414EULL, 0x1A70428B155B4EAFULL,
        0x2B31EBC7FC870C2FULL, 0x170A932F745F03CEULL, 0x53471A16ED3713EDULL, 0x6F7C62FE65EF1C0CULL,
        0x6BD68D2308226B08ULL, 0x57EDF5CB80FA64E9ULL, 0x13A07CF2199274CAULL, 0x2F9B041A914A7B2BULL,
        0x1EDAAD56789639ABULL, 0x22E1D5BEF04E364AULL, 0x66AC5C8769262669ULL, 0x5A97246FE1FE2988ULL,
        0x042F0E1EBA9EA369ULL, 0x381476F63246AC88ULL, 0x7C59FFCFAB2EBCABULL, 0x4062872723F6B34AULL,
        0x71232E6BCA2AF1CAULL, 0x4D18568342F2FE2BULL, 0x0955DFBADB9AEE08ULL, 0x356EA7525342E1E9ULL,
        0x6388911E7D1F2DDAULL, 0x5FB3E9F6F5C7223BULL, 0x1BFE60CF6CAF3218ULL, 0x27C51827E4773DF9ULL,
        0x1684B16B0DAB7F79ULL, 0x2ABFC98385737098ULL, 0x6EF240BA1C1B60BBULL, 0x52C9385294C36F5AULL,
        0x0C711223CFA3E5BBULL, 0x304A6ACB477BEA5AULL, 0x7407E3F2DE13FA79ULL, 0x483C9B1A56CBF598ULL,
        0x797D3256BF17B718ULL, 0x45464ABE37CFB8F9ULL, 0x010BC387AEA7A8DAULL, 0x3D30BB6F267FA73BULL,
        0x399A54B24BB2D03FULL, 0x05A12C5AC36ADFDEULL, 0x41ECA5635A02CFFDULL, 0x7DD7DD8BD2DAC01CULL,
        0x4C9674C73B06829CULL, 0x70AD0C2FB3DE8D7DULL, 0x34E085162AB69D5EULL, 0x08DBFDFEA26E92BFULL,
        0x5663D78FF90E185EULL, 0x6A58AF6771D617BFULL, 0x2E15265EE8BE079CULL, 0x122E5EB66066087DULL,
        0x236FF7FA89BA4AFDULL, 0x1F548F120162451CULL, 0x5B19062B980A553FULL, 0x67227EC310D25ADEULL,
        0x524CD9914390BB37ULL, 0x6E77A179CB48B4D6ULL, 0x2A3A28405220A4F5ULL, 0x160150A8DAF8AB14ULL,
        0x2740F9E43324E994ULL, 0x1B7B810CBBFCE675ULL, 0x5F3608352294F656ULL, 0x630D70DDAA4CF9B7ULL,
        0x3DB55AACF12C7356ULL, 0x018E224479F47CB7ULL, 0x45C3AB7DE09C6C94ULL, 0x79F8D39568446375ULL,
        0x48B97AD9819821F5ULL, 0x7482023109402E14ULL, 0x30CF8B0890283E37ULL, 0x0CF4F3E018F031D6ULL,
        0x085E1C3D753D46D2ULL, 0x346564D5FDE54933ULL, 0x7028EDEC648D5910ULL, 0x4C139504EC5556F1ULL,
        0x7D523C4805891471ULL, 0x416944A08D511B90ULL, 0x0524CD9914390BB3ULL, 0x391FB5719CE10452ULL,
        0x67A79F00C7818EB3ULL, 0x5B9CE7E84F598152ULL, 0x1FD16ED1D6319171ULL, 0x23EA16395EE99E90ULL,
        0x12ABBF75B735DC10ULL, 0x2E90C79D3FEDD3F1ULL, 0x6ADD4EA4A685C3D2ULL, 0x56E6364C2E5DCC33ULL,
        0x42F0E1EBA9EA3693ULL, 0x7ECB990321323972ULL, 0x3A86103AB85A2951ULL, 0x06BD68D2308226B0ULL,
        0x37FCC19ED95E6430ULL, 0x0BC7B97651866BD1ULL, 0x4F8A304FC8EE7BF2ULL, 0x73B148A740367413ULL,
        0x2D0962D61B56FEF2ULL, 0x11321A3E938EF113ULL, 0x557F93070AE6E130ULL, 0x6944EBEF823EEED1ULL,
        0x580542A36BE2AC51ULL, 0x643E3A4BE33AA3B0ULL, 0x2073B3727A52B393ULL, 0x1C48CB9AF28ABC72ULL,
        0x18E224479F47CB76ULL, 0x24D95CAF179FC497ULL, 0x6094D5968EF7D4B4ULL, 0x5CAFAD7E062FDB55ULL,
        0x6DEE0432EFF399D5ULL, 0x51D57CDA672B9634ULL, 0x1598F5E3FE438617ULL, 0x29A38D0B769B89F6ULL,
        0x771BA77A2DFB0317ULL, 0x4B20DF92A5230CF6ULL, 0x0F6D56AB3C4B1CD5ULL, 0x33562E43B4931334ULL,
        0x0217870F5D4F51B4ULL, 0x3E2CFFE7D5975E55ULL, 0x7A6176DE4CFF4E76ULL, 0x465A0E36C4274197ULL,
        0x7334A9649765A07EULL, 0x4F0FD18C1FBDAF9FULL, 0x0B4258B586D5BFBCULL, 0x3779205D0E0DB05DULL,
        0x06388911E7D1F2DDULL, 0x3A03F1F96F09FD3CULL, 0x7E4E78C0F661ED1FULL, 0x427500287EB9E2FEULL,
        0x1CCD2A5925D9681FULL, 0x20F652B1AD0167FEULL, 0x64BBDB88346977DDULL, 0x5880A360BCB1783CULL,
        0x69C10A2C556D3ABCULL, 0x55FA72C4DDB5355DULL, 0x11B7FBFD44DD257EULL, 0x2D8C8315CC052A9FULL,
        0x29266CC8A1C85D9BULL, 0x151D14202910527AULL, 0x51509D19B0784259ULL, 0x6D6BE5F138A04DB8ULL,
        0x5C2A4CBDD17C0F38ULL, 0x6011345559A400D9ULL, 0x245CBD6CC0CC10FAULL, 0x1867C58448141F1BULL,
        0x46DFEFF5137495FAULL, 0x7AE4971D9BAC9A1BULL, 0x3EA91E2402C48A38ULL, 0x029266CC8A1C85D9ULL,
        0x33D3CF8063C0C759ULL, 0x0FE8B768EB18C8B8ULL, 0x4BA53E517270D89BULL, 0x779E46B9FAA8D77AULL,
        0x217870F5D4F51B49ULL, 0x1D43081D5C2D14A8ULL, 0x590E8124C545048BULL, 0x6535F9CC4D9D0B6AULL,
        0x54745080A44149EAULL, 0x684F28682C99460BULL, 0x2C02A151B5F15628ULL, 0x1039D9B93D2959C9ULL,
        0x4E81F3C86649D328ULL, 0x72BA8B20EE91DCC9ULL, 0x36F7021977F9CCEAULL, 0x0ACC7AF1FF21C30BULL,
        0x3B8DD3BD16FD818BULL, 0x07B6AB559E258E6AULL, 0x43FB226C074D9E49ULL, 0x7FC05A848F9591A8ULL,
        0x7B6AB559E258E6ACULL, 0x4751CDB16A80E94DULL, 0x031C4488F3E8F96EULL, 0x3F273C607B30F68FULL,
        0x0E66952C92ECB40FULL, 0x325DEDC41A34BBEEULL, 0x761064FD835CABCDULL, 0x4A2B1C150B84A42CULL,
        0x1493366450E42ECDULL, 0x28A84E8CD83C212CULL, 0x6CE5C7B54154310FULL, 0x50DEBF5DC98C3EEEULL,
        0x619F161120507C6EULL, 0x5DA46EF9A888738FULL, 0x19E9E7C031E063ACULL, 0x25D29F28B9386C4DULL,
        0x10BC387AEA7A8DA4ULL, 0x2C87409262A28245ULL, 0x68CAC9ABFBCA9266ULL, 0x54F1B14373129D87ULL,
        0x65B0180F9ACEDF07ULL, 0x598B60E71216D0E6ULL, 0x1DC6E9DE8B7EC0C5ULL, 0x21FD913603A6CF24ULL,
        0x7F45BB4758C645C5ULL, 0x437EC3AFD01E4A24ULL, 0x07334A9649765A07ULL, 0x3B08327EC1AE55E6ULL,
        0x0A499B3228721766ULL, 0x3672E3DAA0AA1887ULL, 0x723F6AE339C208A4ULL, 0x4E04120BB11A0745ULL,
        0x4AAEFDD6DCD77041ULL, 0x7695853E540F7FA0ULL, 0x32D80C07CD676F83ULL, 0x0EE374EF45BF6062ULL,
        0x3FA2DDA3AC6322E2ULL, 0x0399A54B24BB2D03ULL, 0x47D42C72BDD33D20ULL, 0x7BEF549A350B32C1ULL,
        0x25577EEB6E6BB820ULL, 0x196C0603E6B3B7C1ULL, 0x5D218F3A7FDBA7E2ULL, 0x611AF7D2F703A803ULL,
        0x505B5E9E1EDFEA83ULL, 0x6C6026769607E562ULL, 0x282DAF4F0F6FF541ULL, 0x1416D7A787B7FAA0ULL,
    };

    const uint8_t *p = (const uint8_t *)data;
    uint64_t crc = UINT64_MAX;
    for (size_t i = 0; i < len; i++)
        crc = crc64_table[(uint8_t)(crc ^ p[i])] ^ (crc >> 8);
    return crc ^ UINT64_MAX;
}

/*
 * Helper functions for manifest validation
 */
static inline bool manifest_header_valid(const struct BootManifestHeader *hdr,
                                          size_t buffer_size)
{
    if (!hdr)
        return false;
    if (buffer_size < sizeof(struct BootManifestHeader))
        return false;
    if (hdr->magic != BOOT_MANIFEST_MAGIC)
        return false;
    if (hdr->version != BOOT_MANIFEST_VERSION)
        return false;
    if (hdr->header_size < sizeof(struct BootManifestHeader))
        return false;

    /* Validate manifest_size against buffer bounds */
    if (hdr->manifest_size < hdr->header_size)
        return false;
    if (hdr->manifest_size > buffer_size)
        return false;

    /* Validate entry table bounds */
    if (hdr->entry_count > 0) {
        if (hdr->entry_table_off < hdr->header_size)
            return false;
        if (hdr->entry_table_off > hdr->manifest_size)
            return false;
        uint64_t entries_end = hdr->entry_table_off +
            (uint64_t)hdr->entry_count * sizeof(struct BootManifestEntry);
        if (entries_end > hdr->manifest_size)
            return false;
    }

    /* Verify CRC64 checksum if present */
    if (hdr->flags & MANIFEST_HDR_FLAG_HAS_CHECKSUM) {
        /* Zero the checksum field in-place, compute over full manifest, restore */
        struct BootManifestHeader *mutable_hdr = (struct BootManifestHeader *)hdr;
        uint64_t saved = mutable_hdr->checksum;
        mutable_hdr->checksum = 0;
        uint64_t computed = manifest_crc64(mutable_hdr, mutable_hdr->manifest_size);
        mutable_hdr->checksum = saved;
        if (computed != saved)
            return false;
    }

    return true;
}

static inline const struct BootManifestEntry *manifest_get_entry(
    const struct BootManifestHeader *hdr, uint16_t index)
{
    if (!hdr || index >= hdr->entry_count)
        return NULL;

    /* Validate entry_table_off is within manifest bounds */
    uint64_t entry_end = hdr->entry_table_off +
        (uint64_t)(index + 1) * sizeof(struct BootManifestEntry);
    if (entry_end > hdr->manifest_size)
        return NULL;

    const uint8_t *base = (const uint8_t *)hdr;
    const struct BootManifestEntry *entries =
        (const struct BootManifestEntry *)(base + hdr->entry_table_off);

    return &entries[index];
}

static inline const struct BootManifestEntry *manifest_find_entry(
    const struct BootManifestHeader *hdr, enum ManifestEntryType type)
{
    if (!hdr)
        return NULL;

    for (uint16_t i = 0; i < hdr->entry_count; i++) {
        const struct BootManifestEntry *entry = manifest_get_entry(hdr, i);
        if (entry && entry->type == type)
            return entry;
    }

    return NULL;
}

#endif /* BOOT_COMMON_MANIFEST_H */
