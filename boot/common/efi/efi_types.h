/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Type Definitions
 *
 * Basic UEFI types, status codes, and memory type definitions.
 * Based on UEFI Specification 2.9.
 */

#ifndef BOOT_COMMON_EFI_EFI_TYPES_H
#define BOOT_COMMON_EFI_EFI_TYPES_H

#include "../types.h"

/* =============================================================================
 * Calling Convention
 *
 * UEFI uses Microsoft x64 calling convention (MS ABI) on x86_64.
 * Parameters: RCX, RDX, R8, R9, then stack
 * Return: RAX
 * Caller-saved: RAX, RCX, RDX, R8, R9, R10, R11
 * Callee-saved: RBX, RBP, RDI, RSI, R12-R15
 * =============================================================================
 */

/*
 * UEFI on x86_64 requires Microsoft x64 ABI regardless of toolchain target.
 * Some clang target combinations may still default to SysV ABI, so force it.
 */
#if defined(__x86_64__) || defined(_M_X64)
#define EFIAPI __attribute__((ms_abi))
#else
#define EFIAPI
#endif

/* =============================================================================
 * Basic Types
 * =============================================================================
 */

typedef uint64_t    EFI_STATUS;
typedef void       *EFI_HANDLE;
typedef void       *EFI_EVENT;
typedef uint64_t    EFI_LBA;
typedef uint64_t    EFI_TPL;
typedef uint64_t    UINTN;
typedef int64_t     INTN;
typedef uint8_t     BOOLEAN;
typedef uint16_t    CHAR16;
typedef void        VOID;

/* GUID structure (128-bit) */
typedef struct {
    uint32_t    Data1;
    uint16_t    Data2;
    uint16_t    Data3;
    uint8_t     Data4[8];
} EFI_GUID;

/* Time structure */
typedef struct {
    uint16_t    Year;       /* 1900 - 9999 */
    uint8_t     Month;      /* 1 - 12 */
    uint8_t     Day;        /* 1 - 31 */
    uint8_t     Hour;       /* 0 - 23 */
    uint8_t     Minute;     /* 0 - 59 */
    uint8_t     Second;     /* 0 - 59 */
    uint8_t     Pad1;
    uint32_t    Nanosecond; /* 0 - 999,999,999 */
    int16_t     TimeZone;   /* -1440 to 1440 or 2047 */
    uint8_t     Daylight;
    uint8_t     Pad2;
} EFI_TIME;

/* =============================================================================
 * Boolean Values
 * =============================================================================
 */

#define FALSE   0
#define TRUE    1

/* =============================================================================
 * Status Codes
 *
 * High bit set = error, clear = success/warning
 * =============================================================================
 */

#define EFI_SUCCESS                     0
#define EFI_LOAD_ERROR                  (0x8000000000000001ULL)
#define EFI_INVALID_PARAMETER           (0x8000000000000002ULL)
#define EFI_UNSUPPORTED                 (0x8000000000000003ULL)
#define EFI_BAD_BUFFER_SIZE             (0x8000000000000004ULL)
#define EFI_BUFFER_TOO_SMALL            (0x8000000000000005ULL)
#define EFI_NOT_READY                   (0x8000000000000006ULL)
#define EFI_DEVICE_ERROR                (0x8000000000000007ULL)
#define EFI_WRITE_PROTECTED             (0x8000000000000008ULL)
#define EFI_OUT_OF_RESOURCES            (0x8000000000000009ULL)
#define EFI_VOLUME_CORRUPTED            (0x800000000000000AULL)
#define EFI_VOLUME_FULL                 (0x800000000000000BULL)
#define EFI_NO_MEDIA                    (0x800000000000000CULL)
#define EFI_MEDIA_CHANGED               (0x800000000000000DULL)
#define EFI_NOT_FOUND                   (0x800000000000000EULL)
#define EFI_ACCESS_DENIED               (0x800000000000000FULL)
#define EFI_NO_RESPONSE                 (0x8000000000000010ULL)
#define EFI_NO_MAPPING                  (0x8000000000000011ULL)
#define EFI_TIMEOUT                     (0x8000000000000012ULL)
#define EFI_NOT_STARTED                 (0x8000000000000013ULL)
#define EFI_ALREADY_STARTED             (0x8000000000000014ULL)
#define EFI_ABORTED                     (0x8000000000000015ULL)
#define EFI_ICMP_ERROR                  (0x8000000000000016ULL)
#define EFI_TFTP_ERROR                  (0x8000000000000017ULL)
#define EFI_PROTOCOL_ERROR              (0x8000000000000018ULL)
#define EFI_INCOMPATIBLE_VERSION        (0x8000000000000019ULL)
#define EFI_SECURITY_VIOLATION          (0x800000000000001AULL)
#define EFI_CRC_ERROR                   (0x800000000000001BULL)
#define EFI_END_OF_MEDIA                (0x800000000000001CULL)
#define EFI_END_OF_FILE                 (0x800000000000001FULL)
#define EFI_INVALID_LANGUAGE            (0x8000000000000020ULL)
#define EFI_COMPROMISED_DATA            (0x8000000000000021ULL)

/* Warning codes (success with warning) */
#define EFI_WARN_UNKNOWN_GLYPH          1
#define EFI_WARN_DELETE_FAILURE         2
#define EFI_WARN_WRITE_FAILURE          3
#define EFI_WARN_BUFFER_TOO_SMALL       4

/* Error checking macro */
#define EFI_ERROR(Status)   (((int64_t)(Status)) < 0)

/* =============================================================================
 * Memory Types
 * =============================================================================
 */

typedef enum {
    EfiReservedMemoryType,          /* 0 - Not usable */
    EfiLoaderCode,                  /* 1 - UEFI application code */
    EfiLoaderData,                  /* 2 - UEFI application data */
    EfiBootServicesCode,            /* 3 - Boot services code */
    EfiBootServicesData,            /* 4 - Boot services data */
    EfiRuntimeServicesCode,         /* 5 - Runtime services code */
    EfiRuntimeServicesData,         /* 6 - Runtime services data */
    EfiConventionalMemory,          /* 7 - Free memory */
    EfiUnusableMemory,              /* 8 - Memory with errors */
    EfiACPIReclaimMemory,           /* 9 - ACPI tables (reclaimable) */
    EfiACPIMemoryNVS,               /* 10 - ACPI NVS memory */
    EfiMemoryMappedIO,              /* 11 - MMIO */
    EfiMemoryMappedIOPortSpace,     /* 12 - MMIO port space */
    EfiPalCode,                     /* 13 - Processor firmware */
    EfiPersistentMemory,            /* 14 - Persistent memory */
    EfiMaxMemoryType                /* 15 - End marker */
} EFI_MEMORY_TYPE;

/* Memory descriptor (returned by GetMemoryMap) */
typedef struct {
    uint32_t        Type;           /* EFI_MEMORY_TYPE */
    uint64_t        PhysicalStart;  /* Physical address */
    uint64_t        VirtualStart;   /* Virtual address (for SetVirtualAddressMap) */
    uint64_t        NumberOfPages;  /* Number of 4KB pages */
    uint64_t        Attribute;      /* Memory attributes */
} EFI_MEMORY_DESCRIPTOR;

/* Memory attributes */
#define EFI_MEMORY_UC               0x0000000000000001ULL  /* Uncacheable */
#define EFI_MEMORY_WC               0x0000000000000002ULL  /* Write-combining */
#define EFI_MEMORY_WT               0x0000000000000004ULL  /* Write-through */
#define EFI_MEMORY_WB               0x0000000000000008ULL  /* Write-back */
#define EFI_MEMORY_UCE              0x0000000000000010ULL  /* Uncacheable, exported */
#define EFI_MEMORY_WP               0x0000000000001000ULL  /* Write-protected */
#define EFI_MEMORY_RP               0x0000000000002000ULL  /* Read-protected */
#define EFI_MEMORY_XP               0x0000000000004000ULL  /* Execute-protected */
#define EFI_MEMORY_NV               0x0000000000008000ULL  /* Non-volatile */
#define EFI_MEMORY_MORE_RELIABLE    0x0000000000010000ULL  /* More reliable */
#define EFI_MEMORY_RO               0x0000000000020000ULL  /* Read-only */
#define EFI_MEMORY_SP               0x0000000000040000ULL  /* Specific purpose */
#define EFI_MEMORY_CPU_CRYPTO       0x0000000000080000ULL  /* CPU crypto capable */
#define EFI_MEMORY_RUNTIME          0x8000000000000000ULL  /* Needs runtime mapping */

/* Page size for UEFI */
#define EFI_PAGE_SIZE               4096
#define EFI_PAGE_MASK               0xFFF
#define EFI_PAGE_SHIFT              12

/* Size to pages conversion */
#define EFI_SIZE_TO_PAGES(Size)     (((Size) + EFI_PAGE_MASK) >> EFI_PAGE_SHIFT)
#define EFI_PAGES_TO_SIZE(Pages)    ((Pages) << EFI_PAGE_SHIFT)

/* =============================================================================
 * Allocate Type (for AllocatePages)
 * =============================================================================
 */

typedef enum {
    AllocateAnyPages,       /* Allocate any available range */
    AllocateMaxAddress,     /* Allocate below specified address */
    AllocateAddress,        /* Allocate at specified address */
    MaxAllocateType
} EFI_ALLOCATE_TYPE;

/* =============================================================================
 * Open Protocol Attributes
 * =============================================================================
 */

#define EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL    0x00000001
#define EFI_OPEN_PROTOCOL_GET_PROTOCOL          0x00000002
#define EFI_OPEN_PROTOCOL_TEST_PROTOCOL         0x00000004
#define EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER   0x00000008
#define EFI_OPEN_PROTOCOL_BY_DRIVER             0x00000010
#define EFI_OPEN_PROTOCOL_EXCLUSIVE             0x00000020

/* =============================================================================
 * Locate Search Type (for LocateHandle)
 * =============================================================================
 */

typedef enum {
    AllHandles,
    ByRegisterNotify,
    ByProtocol
} EFI_LOCATE_SEARCH_TYPE;

/* =============================================================================
 * Table Header (common to all UEFI tables)
 * =============================================================================
 */

typedef struct {
    uint64_t    Signature;
    uint32_t    Revision;
    uint32_t    HeaderSize;
    uint32_t    CRC32;
    uint32_t    Reserved;
} EFI_TABLE_HEADER;

/* =============================================================================
 * Well-Known GUIDs
 * =============================================================================
 */

/* EFI_LOADED_IMAGE_PROTOCOL_GUID */
#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
    { 0x5B1B31A1, 0x9562, 0x11D2, { 0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }

/* EFI_BLOCK_IO_PROTOCOL_GUID */
#define EFI_BLOCK_IO_PROTOCOL_GUID \
    { 0x964E5B21, 0x6459, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }

/* EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID */
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
    { 0x0964E5B22, 0x6459, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }

/* EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID */
#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID \
    { 0x9042A9DE, 0x23DC, 0x4A38, { 0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A } }

/* EFI_DEVICE_PATH_PROTOCOL_GUID */
#define EFI_DEVICE_PATH_PROTOCOL_GUID \
    { 0x09576E91, 0x6D3F, 0x11D2, { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } }

/* ACPI 2.0 Table GUID */
#define EFI_ACPI_20_TABLE_GUID \
    { 0x8868E871, 0xE4F1, 0x11D3, { 0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81 } }

/* ACPI 1.0 Table GUID */
#define EFI_ACPI_TABLE_GUID \
    { 0xEB9D2D30, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }

/* SMBIOS Table GUID */
#define SMBIOS_TABLE_GUID \
    { 0xEB9D2D31, 0x2D88, 0x11D3, { 0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }

/* SMBIOS3 Table GUID */
#define SMBIOS3_TABLE_GUID \
    { 0xF2FD1544, 0x9794, 0x4A2C, { 0x99, 0x2E, 0xE5, 0xBB, 0xCF, 0x20, 0xE3, 0x94 } }

#endif /* BOOT_COMMON_EFI_EFI_TYPES_H */
