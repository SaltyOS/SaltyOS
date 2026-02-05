/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Stage 1 Entry Point
 *
 * This is the UEFI boot entry point (BOOTX64.EFI).
 * It loads Stage 2 from the EFI System Partition and transfers control.
 *
 * In UEFI mode:
 * - We're already in 64-bit long mode
 * - We have access to Boot Services for memory allocation, file I/O
 * - No need for real mode BIOS calls
 */

#include "../../../../common/efi/efi_types.h"
#include "../../../../common/efi/efi_protocol.h"
#include "../../../../common/efi/print.h"

/* Stage 2 path on ESP */
static CHAR16 Stage2Path[] = L"\\EFI\\SALTYOS\\stage2.efi";

/* GUIDs we need */
static EFI_GUID LoadedImageProtocolGuid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
static EFI_GUID SimpleFileSystemProtocolGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static EFI_GUID FileInfoGuid = { 0x09576E92, 0x6D3F, 0x11D2,
    { 0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B } };

/* Global system table pointer */
static EFI_SYSTEM_TABLE *gST;
static EFI_BOOT_SERVICES *gBS;

/* Convenience wrappers using the shared print utilities */
#define Print(s)             efi_print(s)
#define PrintHex(v)          efi_print_hex(v)
#define PrintError(m, s)     efi_print_error(m, s)

/*
 * Load Stage 2 from ESP
 */
static EFI_STATUS LoadStage2(
    EFI_HANDLE ImageHandle,
    EFI_HANDLE *Stage2Handle)
{
    EFI_STATUS status;
    EFI_LOADED_IMAGE_PROTOCOL *LoadedImage;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *Stage2File;
    UINTN FileInfoSize;
    EFI_FILE_INFO *FileInfo;
    UINTN Stage2Size;
    void *Stage2Buffer;

    /* Get loaded image protocol for our image */
    status = gBS->HandleProtocol(
        ImageHandle,
        &LoadedImageProtocolGuid,
        (void **)&LoadedImage);
    if (EFI_ERROR(status)) {
        PrintError(L"HandleProtocol(LoadedImage)", status);
        return status;
    }

    /* Get file system protocol from the device we loaded from */
    status = gBS->HandleProtocol(
        LoadedImage->DeviceHandle,
        &SimpleFileSystemProtocolGuid,
        (void **)&FileSystem);
    if (EFI_ERROR(status)) {
        PrintError(L"HandleProtocol(FileSystem)", status);
        return status;
    }

    /* Open the root directory */
    status = FileSystem->OpenVolume(FileSystem, &Root);
    if (EFI_ERROR(status)) {
        PrintError(L"OpenVolume", status);
        return status;
    }

    /* Open Stage 2 file */
    status = Root->Open(
        Root,
        &Stage2File,
        Stage2Path,
        EFI_FILE_MODE_READ,
        0);
    if (EFI_ERROR(status)) {
        PrintError(L"Open(Stage2)", status);
        Root->Close(Root);
        return status;
    }

    /* Get file info to determine size */
    FileInfoSize = 0;
    status = Stage2File->GetInfo(Stage2File, &FileInfoGuid, &FileInfoSize, NULL);
    if (status != EFI_BUFFER_TOO_SMALL) {
        PrintError(L"GetInfo(size)", status);
        Stage2File->Close(Stage2File);
        Root->Close(Root);
        return status;
    }

    status = gBS->AllocatePool(EfiLoaderData, FileInfoSize, (void **)&FileInfo);
    if (EFI_ERROR(status)) {
        PrintError(L"AllocatePool(FileInfo)", status);
        Stage2File->Close(Stage2File);
        Root->Close(Root);
        return status;
    }

    status = Stage2File->GetInfo(Stage2File, &FileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(status)) {
        PrintError(L"GetInfo", status);
        gBS->FreePool(FileInfo);
        Stage2File->Close(Stage2File);
        Root->Close(Root);
        return status;
    }

    Stage2Size = (UINTN)FileInfo->FileSize;
    gBS->FreePool(FileInfo);

    Print(L"Stage 2 size: 0x");
    PrintHex(Stage2Size);
    Print(L" bytes\r\n");

    /* Allocate buffer for Stage 2 */
    status = gBS->AllocatePool(EfiLoaderData, Stage2Size, &Stage2Buffer);
    if (EFI_ERROR(status)) {
        PrintError(L"AllocatePool(Stage2)", status);
        Stage2File->Close(Stage2File);
        Root->Close(Root);
        return status;
    }

    /* Read Stage 2 into buffer */
    status = Stage2File->Read(Stage2File, &Stage2Size, Stage2Buffer);
    if (EFI_ERROR(status)) {
        PrintError(L"Read(Stage2)", status);
        gBS->FreePool(Stage2Buffer);
        Stage2File->Close(Stage2File);
        Root->Close(Root);
        return status;
    }

    Stage2File->Close(Stage2File);
    Root->Close(Root);

    /* Load Stage 2 as an EFI image */
    status = gBS->LoadImage(
        FALSE,                      /* BootPolicy */
        ImageHandle,                /* ParentImageHandle */
        NULL,                       /* DevicePath (use buffer) */
        Stage2Buffer,               /* SourceBuffer */
        Stage2Size,                 /* SourceSize */
        Stage2Handle);              /* ImageHandle */

    gBS->FreePool(Stage2Buffer);

    if (EFI_ERROR(status)) {
        PrintError(L"LoadImage(Stage2)", status);
        return status;
    }

    /*
     * Propagate DeviceHandle to Stage 2's LoadedImage.
     * LoadImage() with SourceBuffer and DevicePath=NULL leaves DeviceHandle
     * as NULL. Stage 2 needs it to access the ESP filesystem.
     */
    {
        EFI_LOADED_IMAGE_PROTOCOL *Stage2Li;
        status = gBS->HandleProtocol(
            *Stage2Handle,
            &LoadedImageProtocolGuid,
            (void **)&Stage2Li);
        if (EFI_ERROR(status)) {
            PrintError(L"HandleProtocol(Stage2 LoadedImage)", status);
            return status;
        }
        Stage2Li->DeviceHandle = LoadedImage->DeviceHandle;
    }

    return EFI_SUCCESS;
}

/*
 * EFI application entry point
 */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS status;
    EFI_HANDLE Stage2Handle;
    UINTN ExitDataSize;
    CHAR16 *ExitData;

    /* Save global pointers */
    gST = SystemTable;
    gBS = SystemTable->BootServices;

    /* Initialize shared print utilities */
    efi_print_init(SystemTable);

    /* Clear screen and print banner */
    gST->ConOut->ClearScreen(gST->ConOut);
    Print(L"SaltyOS UEFI Stage 1\r\n");
    Print(L"====================\r\n\r\n");

    /* Disable watchdog timer */
    gBS->SetWatchdogTimer(0, 0, 0, NULL);

    /* Load Stage 2 */
    Print(L"Loading Stage 2 from ");
    Print(Stage2Path);
    Print(L"...\r\n");

    status = LoadStage2(ImageHandle, &Stage2Handle);
    if (EFI_ERROR(status)) {
        Print(L"\r\nFailed to load Stage 2!\r\n");
        Print(L"Press any key to exit...\r\n");
        gBS->Stall(5000000);  /* 5 seconds */
        return status;
    }

    Print(L"Starting Stage 2...\r\n\r\n");

    /* Start Stage 2 */
    ExitDataSize = 0;
    ExitData = NULL;
    status = gBS->StartImage(Stage2Handle, &ExitDataSize, &ExitData);

    /* If Stage 2 returns, something went wrong */
    if (EFI_ERROR(status)) {
        PrintError(L"StartImage(Stage2)", status);
        if (ExitData) {
            Print(L"Exit data: ");
            Print(ExitData);
            Print(L"\r\n");
            gBS->FreePool(ExitData);
        }
    }

    Print(L"\r\nStage 2 returned unexpectedly!\r\n");
    Print(L"Press any key to exit...\r\n");
    gBS->Stall(5000000);

    return status;
}
