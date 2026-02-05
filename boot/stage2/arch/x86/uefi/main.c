/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Stage 2 Main Entry Point
 *
 * Stage 2 in UEFI mode is a thin bridge:
 * - Collects firmware info (ACPI, SMBIOS, GOP)
 * - Loads Stage 3 from ESP
 * - Passes EFI System Table and Image Handle to Stage 3 via Stage2Info
 * - Jumps to Stage 3 WITH Boot Services still alive
 *
 * Stage 3 is responsible for loading the kernel, calling ExitBootServices,
 * and jumping to the kernel.
 */

#include "../../../../common/efi/efi_types.h"
#include "../../../../common/efi/efi_protocol.h"
#include "../../../../common/efi/print.h"
#include "../../../../common/types.h"
#include "../../../../common/stage2_info.h"

/* File paths on ESP */
static CHAR16 Stage3Path[] = L"\\EFI\\SALTYOS\\stage3.bin";

/* GUIDs */
static EFI_GUID LoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID SimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID GraphicsOutputProtocolGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
static EFI_GUID Acpi20TableGuid = EFI_ACPI_20_TABLE_GUID;
static EFI_GUID AcpiTableGuid = EFI_ACPI_TABLE_GUID;
static EFI_GUID Smbios3TableGuid = SMBIOS3_TABLE_GUID;
static EFI_GUID SmbiosTableGuid = SMBIOS_TABLE_GUID;
static EFI_GUID FileInfoGuid = { 0x09576E92, 0x6D3F, 0x11D2,
    { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };

/* Global pointers */
static EFI_SYSTEM_TABLE *gST;
static EFI_BOOT_SERVICES *gBS;
static EFI_HANDLE gImageHandle;

/* Stage2Info to pass to Stage 3 */
static struct Stage2Info g_stage2_info;

/* Stage 3 load address */
#define UEFI_STAGE3_LOAD_ADDR    0x100000    /* 1MB */

/* Convenience wrappers using the shared print utilities */
#define Print(s)             efi_print(s)
#define PrintHex(v)          efi_print_hex(v)
#define PrintDec(v)          efi_print_dec(v)
#define PrintError(m, s)     efi_print_error(m, s)

/*
 * Compare two GUIDs
 */
static int GuidCompare(EFI_GUID *g1, EFI_GUID *g2)
{
    uint8_t *p1 = (uint8_t *)g1;
    uint8_t *p2 = (uint8_t *)g2;
    for (int i = 0; i < 16; i++) {
        if (p1[i] != p2[i])
            return p1[i] - p2[i];
    }
    return 0;
}

/*
 * Find ACPI RSDP from configuration tables
 */
static uint64_t FindAcpiRsdp(void)
{
    UINTN i;

    /* First try ACPI 2.0 */
    for (i = 0; i < gST->NumberOfTableEntries; i++) {
        if (GuidCompare(&gST->ConfigurationTable[i].VendorGuid, &Acpi20TableGuid) == 0) {
            return (uint64_t)(uintptr_t)gST->ConfigurationTable[i].VendorTable;
        }
    }

    /* Fall back to ACPI 1.0 */
    for (i = 0; i < gST->NumberOfTableEntries; i++) {
        if (GuidCompare(&gST->ConfigurationTable[i].VendorGuid, &AcpiTableGuid) == 0) {
            return (uint64_t)(uintptr_t)gST->ConfigurationTable[i].VendorTable;
        }
    }

    return 0;
}

/*
 * Find SMBIOS entry point from configuration tables
 */
static uint64_t FindSmbios(uint8_t *out_major, uint8_t *out_minor)
{
    UINTN i;

    /* First try SMBIOS 3.0 (64-bit entry point) */
    for (i = 0; i < gST->NumberOfTableEntries; i++) {
        if (GuidCompare(&gST->ConfigurationTable[i].VendorGuid, &Smbios3TableGuid) == 0) {
            uint8_t *ep = (uint8_t *)gST->ConfigurationTable[i].VendorTable;
            *out_major = ep[7];
            *out_minor = ep[8];
            return (uint64_t)(uintptr_t)ep;
        }
    }

    /* Fall back to SMBIOS 2.x (32-bit entry point) */
    for (i = 0; i < gST->NumberOfTableEntries; i++) {
        if (GuidCompare(&gST->ConfigurationTable[i].VendorGuid, &SmbiosTableGuid) == 0) {
            uint8_t *ep = (uint8_t *)gST->ConfigurationTable[i].VendorTable;
            *out_major = ep[6];
            *out_minor = ep[7];
            return (uint64_t)(uintptr_t)ep;
        }
    }

    *out_major = 0;
    *out_minor = 0;
    return 0;
}

/*
 * Get Graphics Output Protocol info
 */
static EFI_STATUS GetFramebufferInfo(void)
{
    EFI_STATUS status;
    EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop;

    status = gBS->LocateProtocol(&GraphicsOutputProtocolGuid, NULL, (void **)&Gop);
    if (EFI_ERROR(status)) {
        Print(L"Warning: No GOP found, no framebuffer\r\n");
        g_stage2_info.framebuffer_addr = 0;
        return status;
    }

    g_stage2_info.framebuffer_addr = Gop->Mode->FrameBufferBase;
    g_stage2_info.framebuffer_width = Gop->Mode->Info->HorizontalResolution;
    g_stage2_info.framebuffer_height = Gop->Mode->Info->VerticalResolution;
    g_stage2_info.framebuffer_pitch = Gop->Mode->Info->PixelsPerScanLine * 4;
    g_stage2_info.framebuffer_bpp = 32;
    g_stage2_info.flags |= STAGE2_FLAG_HAS_FRAMEBUFFER;

    /* Set pixel format based on GOP PixelFormat */
    switch (Gop->Mode->Info->PixelFormat) {
    case PixelRedGreenBlueReserved8BitPerColor:
        g_stage2_info.fb_red_pos = 0;
        g_stage2_info.fb_red_size = 8;
        g_stage2_info.fb_green_pos = 8;
        g_stage2_info.fb_green_size = 8;
        g_stage2_info.fb_blue_pos = 16;
        g_stage2_info.fb_blue_size = 8;
        break;
    case PixelBlueGreenRedReserved8BitPerColor:
        g_stage2_info.fb_red_pos = 16;
        g_stage2_info.fb_red_size = 8;
        g_stage2_info.fb_green_pos = 8;
        g_stage2_info.fb_green_size = 8;
        g_stage2_info.fb_blue_pos = 0;
        g_stage2_info.fb_blue_size = 8;
        break;
    default:
        g_stage2_info.fb_red_pos = 16;
        g_stage2_info.fb_red_size = 8;
        g_stage2_info.fb_green_pos = 8;
        g_stage2_info.fb_green_size = 8;
        g_stage2_info.fb_blue_pos = 0;
        g_stage2_info.fb_blue_size = 8;
        break;
    }

    Print(L"Framebuffer: ");
    PrintDec(g_stage2_info.framebuffer_width);
    Print(L"x");
    PrintDec(g_stage2_info.framebuffer_height);
    Print(L" @ 0x");
    PrintHex(g_stage2_info.framebuffer_addr);
    Print(L"\r\n");

    return EFI_SUCCESS;
}

/*
 * Load a file from ESP into an allocated buffer
 */
static EFI_STATUS LoadFileAllocated(CHAR16 *Path, uint64_t LoadAddr,
                                    UINTN *FileSize)
{
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *File;
    UINTN FileInfoSize;
    EFI_FILE_INFO *FileInfo;
    UINTN Size;
    UINTN NumPages;

    /* Get loaded image protocol */
    status = gBS->HandleProtocol(
        gImageHandle,
        &LoadedImageProtocolGuid,
        (void **)&LoadedImage);
    if (EFI_ERROR(status))
        return status;

    /* Get file system protocol */
    status = gBS->HandleProtocol(
        LoadedImage->DeviceHandle,
        &SimpleFileSystemProtocolGuid,
        (void **)&FileSystem);
    if (EFI_ERROR(status))
        return status;

    /* Open root */
    status = FileSystem->OpenVolume(FileSystem, &Root);
    if (EFI_ERROR(status))
        return status;

    /* Open file */
    status = Root->Open(Root, &File, Path, EFI_FILE_MODE_READ, 0);
    if (EFI_ERROR(status)) {
        Root->Close(Root);
        return status;
    }

    /* Get file size */
    FileInfoSize = 0;
    status = File->GetInfo(File, &FileInfoGuid, &FileInfoSize, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        File->Close(File);
        Root->Close(Root);
        return status;
    }

    status = gBS->AllocatePool(EfiLoaderData, FileInfoSize, (void **)&FileInfo);
    if (EFI_ERROR(status)) {
        File->Close(File);
        Root->Close(Root);
        return status;
    }

    status = File->GetInfo(File, &FileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(status)) {
        gBS->FreePool(FileInfo);
        File->Close(File);
        Root->Close(Root);
        return status;
    }

    Size = (UINTN)FileInfo->FileSize;
    *FileSize = Size;
    gBS->FreePool(FileInfo);

    /* Allocate pages at the requested address */
    NumPages = EFI_SIZE_TO_PAGES(Size);
    status = gBS->AllocatePages(AllocateAddress, EfiLoaderCode, NumPages, &LoadAddr);
    if (EFI_ERROR(status)) {
        File->Close(File);
        Root->Close(Root);
        return status;
    }

    /* Read file */
    status = File->Read(File, &Size, (void *)LoadAddr);

    File->Close(File);
    Root->Close(Root);

    return status;
}

/*
 * Stage 3 entry function type (64-bit, already in long mode)
 */
typedef void (EFIAPI *Stage3Entry)(struct Stage2Info *info);

/*
 * UEFI Stage 2 entry point
 *
 * This is a thin bridge: collect firmware info, load Stage 3, and jump.
 * Boot Services remain alive for Stage 3 to use.
 */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    UINTN Stage3Size;
    Stage3Entry Stage3;

    /* Save globals */
    gST = SystemTable;
    gBS = SystemTable->BootServices;
    gImageHandle = ImageHandle;

    /* Initialize shared print utilities */
    efi_print_init(SystemTable);

    /* Print banner */
    Print(L"SaltyOS UEFI Stage 2\r\n");
    Print(L"====================\r\n\r\n");

    /* Initialize Stage2Info */
    /* Zero the structure first */
    uint8_t *p = (uint8_t *)&g_stage2_info;
    for (UINTN i = 0; i < sizeof(g_stage2_info); i++)
        p[i] = 0;

    g_stage2_info.magic = STAGE2_MAGIC;
    g_stage2_info.version = STAGE2_VERSION;
    g_stage2_info.arch = ARCH_X86_64;
    g_stage2_info.boot_mode = BOOT_MODE_UEFI;
    g_stage2_info.boot_drive = 0;
    g_stage2_info.flags = STAGE2_FLAG_LONG_MODE | STAGE2_FLAG_PAGING_ENABLED;

    /* Pass EFI context to Stage 3 */
    g_stage2_info.efi_system_table = (uint64_t)(uintptr_t)SystemTable;
    g_stage2_info.efi_image_handle = (uint64_t)(uintptr_t)ImageHandle;

    /* Kernel preload: 0 (Stage 3 will load via Boot Services) */
    g_stage2_info.kernel_preload_addr = 0;
    g_stage2_info.kernel_preload_size = 0;

    /* Find ACPI RSDP */
    g_stage2_info.rsdp_addr = FindAcpiRsdp();
    if (g_stage2_info.rsdp_addr) {
        Print(L"ACPI RSDP: 0x");
        PrintHex(g_stage2_info.rsdp_addr);
        Print(L"\r\n");
        g_stage2_info.flags |= STAGE2_FLAG_HAS_ACPI;

        uint8_t *rsdp = (uint8_t *)(uintptr_t)g_stage2_info.rsdp_addr;
        g_stage2_info.acpi_revision = rsdp[15];
    } else {
        Print(L"Warning: ACPI RSDP not found\r\n");
    }

    /* Find SMBIOS */
    {
        uint8_t smb_major = 0, smb_minor = 0;
        g_stage2_info.smbios_addr = FindSmbios(&smb_major, &smb_minor);
        if (g_stage2_info.smbios_addr) {
            g_stage2_info.smbios_major = smb_major;
            g_stage2_info.smbios_minor = smb_minor;
            g_stage2_info.flags |= STAGE2_FLAG_HAS_SMBIOS;
            Print(L"SMBIOS: 0x");
            PrintHex(g_stage2_info.smbios_addr);
            Print(L"\r\n");
        }
    }

    /* Get framebuffer info */
    GetFramebufferInfo();

    /*
     * Reserve stack region for Stage 3 entry assembly.
     * entry_uefi.asm sets RSP = 0x180000 (stack grows down), so we need
     * to ensure 0x170000-0x180000 (64KB) is not used by Boot Services.
     */
    {
        #define UEFI_STAGE3_STACK_BASE  0x170000  /* 64KB below 1.5MB */
        #define UEFI_STAGE3_STACK_PAGES 16        /* 64KB = 16 * 4KB pages */

        uint64_t stack_addr = UEFI_STAGE3_STACK_BASE;
        status = gBS->AllocatePages(AllocateAddress, EfiLoaderData,
                                     UEFI_STAGE3_STACK_PAGES, &stack_addr);
        if (EFI_ERROR(status)) {
            PrintError(L"AllocatePages(Stage3 stack)", status);
            return status;
        }
    }

    /* Load Stage 3 at fixed address using AllocatePages */
    Print(L"Loading Stage 3...\r\n");
    status = LoadFileAllocated(Stage3Path, UEFI_STAGE3_LOAD_ADDR, &Stage3Size);
    if (EFI_ERROR(status)) {
        PrintError(L"LoadFile(Stage3)", status);
        return status;
    }

    g_stage2_info.stage3_addr = UEFI_STAGE3_LOAD_ADDR;
    g_stage2_info.stage3_size = Stage3Size;

    Print(L"Stage 3 loaded at 0x");
    PrintHex(UEFI_STAGE3_LOAD_ADDR);
    Print(L" (");
    PrintDec(Stage3Size);
    Print(L" bytes)\r\n");

    /*
     * Jump to Stage 3 WITH Boot Services alive.
     * Stage 3 will use Boot Services to:
     * - Load kernel and manifest from ESP
     * - Allocate memory for kernel segments and page tables
     * - Get memory map and call ExitBootServices
     */
    Print(L"\r\nJumping to Stage 3...\r\n");

    Stage3 = (Stage3Entry)UEFI_STAGE3_LOAD_ADDR;
    Stage3(&g_stage2_info);

    /* Should never return */
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}
