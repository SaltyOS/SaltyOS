/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - UEFI Protocol Definitions
 *
 * UEFI System Table, Boot Services, Runtime Services, and protocol
 * interface definitions. Based on UEFI Specification 2.9.
 */

#ifndef BOOT_COMMON_EFI_EFI_PROTOCOL_H
#define BOOT_COMMON_EFI_EFI_PROTOCOL_H

#include "efi_types.h"

/* Forward declarations */
struct _EFI_SYSTEM_TABLE;
struct _EFI_BOOT_SERVICES;
struct _EFI_RUNTIME_SERVICES;
struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/* =============================================================================
 * Configuration Table Entry
 * =============================================================================
 */

typedef struct {
  EFI_GUID VendorGuid;
  void *VendorTable;
} EFI_CONFIGURATION_TABLE;

/* =============================================================================
 * Simple Text Input Protocol
 * =============================================================================
 */

typedef struct {
  uint16_t ScanCode;
  CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
  EFI_STATUS(EFIAPI *Reset)(struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This,
                            BOOLEAN ExtendedVerification);
  EFI_STATUS(EFIAPI *ReadKeyStroke)(
      struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL *This, EFI_INPUT_KEY *Key);
  EFI_EVENT WaitForKey;
} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;

/* =============================================================================
 * Simple Text Output Protocol
 * =============================================================================
 */

typedef struct {
  int32_t MaxMode;
  int32_t Mode;
  int32_t Attribute;
  int32_t CursorColumn;
  int32_t CursorRow;
  BOOLEAN CursorVisible;
} SIMPLE_TEXT_OUTPUT_MODE;

typedef struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
  EFI_STATUS(EFIAPI *Reset)(struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                            BOOLEAN ExtendedVerification);
  EFI_STATUS(EFIAPI *OutputString)(
      struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, CHAR16 *String);
  EFI_STATUS(EFIAPI *TestString)(struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                                 CHAR16 *String);
  EFI_STATUS(EFIAPI *QueryMode)(struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                                UINTN ModeNumber, UINTN *Columns, UINTN *Rows);
  EFI_STATUS(EFIAPI *SetMode)(struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This,
                              UINTN ModeNumber);
  EFI_STATUS(EFIAPI *SetAttribute)(
      struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Attribute);
  EFI_STATUS(EFIAPI *ClearScreen)(
      struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This);
  EFI_STATUS(EFIAPI *SetCursorPosition)(
      struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, UINTN Column, UINTN Row);
  EFI_STATUS(EFIAPI *EnableCursor)(
      struct _EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *This, BOOLEAN Visible);
  SIMPLE_TEXT_OUTPUT_MODE *Mode;
} EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;

/* =============================================================================
 * Boot Services Table
 * =============================================================================
 */

typedef struct _EFI_BOOT_SERVICES {
  EFI_TABLE_HEADER Hdr;

  /* Task Priority Services */
  EFI_STATUS(EFIAPI *RaiseTPL)(EFI_TPL NewTpl);
  void(EFIAPI *RestoreTPL)(EFI_TPL OldTpl);

  /* Memory Services */
  EFI_STATUS(EFIAPI *AllocatePages)(EFI_ALLOCATE_TYPE Type,
                                    EFI_MEMORY_TYPE MemoryType, UINTN Pages,
                                    uint64_t *Memory);
  EFI_STATUS(EFIAPI *FreePages)(uint64_t Memory, UINTN Pages);
  EFI_STATUS(EFIAPI *GetMemoryMap)(UINTN *MemoryMapSize,
                                   EFI_MEMORY_DESCRIPTOR *MemoryMap,
                                   UINTN *MapKey, UINTN *DescriptorSize,
                                   uint32_t *DescriptorVersion);
  EFI_STATUS(EFIAPI *AllocatePool)(EFI_MEMORY_TYPE PoolType, UINTN Size,
                                   void **Buffer);
  EFI_STATUS(EFIAPI *FreePool)(void *Buffer);

  /* Event & Timer Services */
  EFI_STATUS(EFIAPI *CreateEvent)(uint32_t Type, EFI_TPL NotifyTpl,
                                  void *NotifyFunction, void *NotifyContext,
                                  EFI_EVENT *Event);
  EFI_STATUS(EFIAPI *SetTimer)(EFI_EVENT Event, uint32_t Type,
                               uint64_t TriggerTime);
  EFI_STATUS(EFIAPI *WaitForEvent)(UINTN NumberOfEvents, EFI_EVENT *Event,
                                   UINTN *Index);
  EFI_STATUS(EFIAPI *SignalEvent)(EFI_EVENT Event);
  EFI_STATUS(EFIAPI *CloseEvent)(EFI_EVENT Event);
  EFI_STATUS(EFIAPI *CheckEvent)(EFI_EVENT Event);

  /* Protocol Handler Services */
  EFI_STATUS(EFIAPI *InstallProtocolInterface)(EFI_HANDLE *Handle,
                                               EFI_GUID *Protocol,
                                               uint32_t InterfaceType,
                                               void *Interface);
  EFI_STATUS(EFIAPI *ReinstallProtocolInterface)(EFI_HANDLE Handle,
                                                 EFI_GUID *Protocol,
                                                 void *OldInterface,
                                                 void *NewInterface);
  EFI_STATUS(EFIAPI *UninstallProtocolInterface)(EFI_HANDLE Handle,
                                                 EFI_GUID *Protocol,
                                                 void *Interface);
  EFI_STATUS(EFIAPI *HandleProtocol)(EFI_HANDLE Handle, EFI_GUID *Protocol,
                                     void **Interface);
  void *Reserved;
  EFI_STATUS(EFIAPI *RegisterProtocolNotify)(EFI_GUID *Protocol,
                                             EFI_EVENT Event,
                                             void **Registration);
  EFI_STATUS(EFIAPI *LocateHandle)(EFI_LOCATE_SEARCH_TYPE SearchType,
                                   EFI_GUID *Protocol, void *SearchKey,
                                   UINTN *BufferSize, EFI_HANDLE *Buffer);
  EFI_STATUS(EFIAPI *LocateDevicePath)(EFI_GUID *Protocol, void **DevicePath,
                                       EFI_HANDLE *Device);
  EFI_STATUS(EFIAPI *InstallConfigurationTable)(EFI_GUID *Guid, void *Table);

  /* Image Services */
  EFI_STATUS(EFIAPI *LoadImage)(BOOLEAN BootPolicy,
                                EFI_HANDLE ParentImageHandle, void *DevicePath,
                                void *SourceBuffer, UINTN SourceSize,
                                EFI_HANDLE *ImageHandle);
  EFI_STATUS(EFIAPI *StartImage)(EFI_HANDLE ImageHandle, UINTN *ExitDataSize,
                                 CHAR16 **ExitData);
  EFI_STATUS(EFIAPI *Exit)(EFI_HANDLE ImageHandle, EFI_STATUS ExitStatus,
                           UINTN ExitDataSize, CHAR16 *ExitData);
  EFI_STATUS(EFIAPI *UnloadImage)(EFI_HANDLE ImageHandle);
  EFI_STATUS(EFIAPI *ExitBootServices)(EFI_HANDLE ImageHandle, UINTN MapKey);

  /* Miscellaneous Services */
  EFI_STATUS(EFIAPI *GetNextMonotonicCount)(uint64_t *Count);
  EFI_STATUS(EFIAPI *Stall)(UINTN Microseconds);
  EFI_STATUS(EFIAPI *SetWatchdogTimer)(UINTN Timeout, uint64_t WatchdogCode,
                                       UINTN DataSize, CHAR16 *WatchdogData);

  /* DriverSupport Services */
  EFI_STATUS(EFIAPI *ConnectController)(EFI_HANDLE ControllerHandle,
                                        EFI_HANDLE *DriverImageHandle,
                                        void *RemainingDevicePath,
                                        BOOLEAN Recursive);
  EFI_STATUS(EFIAPI *DisconnectController)(EFI_HANDLE ControllerHandle,
                                           EFI_HANDLE DriverImageHandle,
                                           EFI_HANDLE ChildHandle);

  /* Open and Close Protocol Services */
  EFI_STATUS(EFIAPI *OpenProtocol)(EFI_HANDLE Handle, EFI_GUID *Protocol,
                                   void **Interface, EFI_HANDLE AgentHandle,
                                   EFI_HANDLE ControllerHandle,
                                   uint32_t Attributes);
  EFI_STATUS(EFIAPI *CloseProtocol)(EFI_HANDLE Handle, EFI_GUID *Protocol,
                                    EFI_HANDLE AgentHandle,
                                    EFI_HANDLE ControllerHandle);
  EFI_STATUS(EFIAPI *OpenProtocolInformation)(EFI_HANDLE Handle,
                                              EFI_GUID *Protocol,
                                              void **EntryBuffer,
                                              UINTN *EntryCount);

  /* Library Services */
  EFI_STATUS(EFIAPI *ProtocolsPerHandle)(EFI_HANDLE Handle,
                                         EFI_GUID ***ProtocolBuffer,
                                         UINTN *ProtocolBufferCount);
  EFI_STATUS(EFIAPI *LocateHandleBuffer)(EFI_LOCATE_SEARCH_TYPE SearchType,
                                         EFI_GUID *Protocol, void *SearchKey,
                                         UINTN *NoHandles, EFI_HANDLE **Buffer);
  EFI_STATUS(EFIAPI *LocateProtocol)(EFI_GUID *Protocol, void *Registration,
                                     void **Interface);
  EFI_STATUS(EFIAPI *InstallMultipleProtocolInterfaces)(EFI_HANDLE *Handle,
                                                        ...);
  EFI_STATUS(EFIAPI *UninstallMultipleProtocolInterfaces)(EFI_HANDLE Handle,
                                                          ...);

  /* 32-bit CRC Services */
  EFI_STATUS(EFIAPI *CalculateCrc32)(void *Data, UINTN DataSize,
                                     uint32_t *Crc32);

  /* Miscellaneous Services */
  void(EFIAPI *CopyMem)(void *Destination, void *Source, UINTN Length);
  void(EFIAPI *SetMem)(void *Buffer, UINTN Size, uint8_t Value);
  EFI_STATUS(EFIAPI *CreateEventEx)(uint32_t Type, EFI_TPL NotifyTpl,
                                    void *NotifyFunction, void *NotifyContext,
                                    EFI_GUID *EventGroup, EFI_EVENT *Event);
} EFI_BOOT_SERVICES;

/* =============================================================================
 * Runtime Services Table (partial - we mainly need boot services)
 * =============================================================================
 */

typedef struct _EFI_RUNTIME_SERVICES {
  EFI_TABLE_HEADER Hdr;

  /* Time Services */
  EFI_STATUS(EFIAPI *GetTime)(EFI_TIME *Time, void *Capabilities);
  EFI_STATUS(EFIAPI *SetTime)(EFI_TIME *Time);
  EFI_STATUS(EFIAPI *GetWakeupTime)(BOOLEAN *Enabled, BOOLEAN *Pending,
                                    EFI_TIME *Time);
  EFI_STATUS(EFIAPI *SetWakeupTime)(BOOLEAN Enable, EFI_TIME *Time);

  /* Virtual Memory Services */
  EFI_STATUS(EFIAPI *SetVirtualAddressMap)(UINTN MemoryMapSize,
                                           UINTN DescriptorSize,
                                           uint32_t DescriptorVersion,
                                           EFI_MEMORY_DESCRIPTOR *VirtualMap);
  EFI_STATUS(EFIAPI *ConvertPointer)(UINTN DebugDisposition, void **Address);

  /* Variable Services */
  EFI_STATUS(EFIAPI *GetVariable)(CHAR16 *VariableName, EFI_GUID *VendorGuid,
                                  uint32_t *Attributes, UINTN *DataSize,
                                  void *Data);
  EFI_STATUS(EFIAPI *GetNextVariableName)(UINTN *VariableNameSize,
                                          CHAR16 *VariableName,
                                          EFI_GUID *VendorGuid);
  EFI_STATUS(EFIAPI *SetVariable)(CHAR16 *VariableName, EFI_GUID *VendorGuid,
                                  uint32_t Attributes, UINTN DataSize,
                                  void *Data);

  /* Miscellaneous Services */
  EFI_STATUS(EFIAPI *GetNextHighMonotonicCount)(uint32_t *HighCount);
  void(EFIAPI *ResetSystem)(uint32_t ResetType, EFI_STATUS ResetStatus,
                            UINTN DataSize, void *ResetData);

  /* UEFI 2.0 Capsule Services */
  EFI_STATUS(EFIAPI *UpdateCapsule)(void **CapsuleHeaderArray,
                                    UINTN CapsuleCount,
                                    uint64_t ScatterGatherList);
  EFI_STATUS(EFIAPI *QueryCapsuleCapabilities)(void **CapsuleHeaderArray,
                                               UINTN CapsuleCount,
                                               uint64_t *MaximumCapsuleSize,
                                               uint32_t *ResetType);
  EFI_STATUS(EFIAPI *QueryVariableInfo)(uint32_t Attributes,
                                        uint64_t *MaximumVariableStorageSize,
                                        uint64_t *RemainingVariableStorageSize,
                                        uint64_t *MaximumVariableSize);
} EFI_RUNTIME_SERVICES;

/* =============================================================================
 * System Table
 * =============================================================================
 */

#define EFI_SYSTEM_TABLE_SIGNATURE 0x5453595320494249ULL /* "IBI SYST" */
#define EFI_2_90_SYSTEM_TABLE_REVISION ((2 << 16) | 90)
#define EFI_SYSTEM_TABLE_REVISION EFI_2_90_SYSTEM_TABLE_REVISION

typedef struct _EFI_SYSTEM_TABLE {
  EFI_TABLE_HEADER Hdr;
  CHAR16 *FirmwareVendor;
  uint32_t FirmwareRevision;
  EFI_HANDLE ConsoleInHandle;
  EFI_SIMPLE_TEXT_INPUT_PROTOCOL *ConIn;
  EFI_HANDLE ConsoleOutHandle;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  EFI_HANDLE StandardErrorHandle;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr;
  EFI_RUNTIME_SERVICES *RuntimeServices;
  EFI_BOOT_SERVICES *BootServices;
  UINTN NumberOfTableEntries;
  EFI_CONFIGURATION_TABLE *ConfigurationTable;
} EFI_SYSTEM_TABLE;

/* =============================================================================
 * Loaded Image Protocol
 * =============================================================================
 */

#define EFI_LOADED_IMAGE_PROTOCOL_REVISION 0x1000

typedef struct {
  uint32_t Revision;
  EFI_HANDLE ParentHandle;
  EFI_SYSTEM_TABLE *SystemTable;

  /* Source location of the image */
  EFI_HANDLE DeviceHandle;
  void *FilePath; /* EFI_DEVICE_PATH_PROTOCOL */
  void *Reserved;

  /* Image's load options */
  uint32_t LoadOptionsSize;
  void *LoadOptions;

  /* Location where image was loaded */
  void *ImageBase;
  uint64_t ImageSize;
  EFI_MEMORY_TYPE ImageCodeType;
  EFI_MEMORY_TYPE ImageDataType;
  EFI_STATUS(EFIAPI *Unload)(EFI_HANDLE ImageHandle);
} EFI_LOADED_IMAGE_PROTOCOL;

/* =============================================================================
 * Block I/O Protocol
 * =============================================================================
 */

#define EFI_BLOCK_IO_PROTOCOL_REVISION2 0x00020001
#define EFI_BLOCK_IO_PROTOCOL_REVISION3 0x00020031

typedef struct {
  uint32_t MediaId;
  BOOLEAN RemovableMedia;
  BOOLEAN MediaPresent;
  BOOLEAN LogicalPartition;
  BOOLEAN ReadOnly;
  BOOLEAN WriteCaching;
  uint32_t BlockSize;
  uint32_t IoAlign;
  EFI_LBA LastBlock;

  /* Revision 2 */
  EFI_LBA LowestAlignedLba;
  uint32_t LogicalBlocksPerPhysicalBlock;

  /* Revision 3 */
  uint32_t OptimalTransferLengthGranularity;
} EFI_BLOCK_IO_MEDIA;

typedef struct _EFI_BLOCK_IO_PROTOCOL {
  uint64_t Revision;
  EFI_BLOCK_IO_MEDIA *Media;
  EFI_STATUS(EFIAPI *Reset)(struct _EFI_BLOCK_IO_PROTOCOL *This,
                            BOOLEAN ExtendedVerification);
  EFI_STATUS(EFIAPI *ReadBlocks)(struct _EFI_BLOCK_IO_PROTOCOL *This,
                                 uint32_t MediaId, EFI_LBA Lba,
                                 UINTN BufferSize, void *Buffer);
  EFI_STATUS(EFIAPI *WriteBlocks)(struct _EFI_BLOCK_IO_PROTOCOL *This,
                                  uint32_t MediaId, EFI_LBA Lba,
                                  UINTN BufferSize, void *Buffer);
  EFI_STATUS(EFIAPI *FlushBlocks)(struct _EFI_BLOCK_IO_PROTOCOL *This);
} EFI_BLOCK_IO_PROTOCOL;

/* =============================================================================
 * Simple File System Protocol
 * =============================================================================
 */

#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION 0x00010000

struct _EFI_FILE_PROTOCOL;

typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
  uint64_t Revision;
  EFI_STATUS(EFIAPI *OpenVolume)(struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This,
                                 struct _EFI_FILE_PROTOCOL **Root);
} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

/* File Protocol */
#define EFI_FILE_PROTOCOL_REVISION 0x00010000
#define EFI_FILE_PROTOCOL_REVISION2 0x00020000

/* File modes */
#define EFI_FILE_MODE_READ 0x0000000000000001ULL
#define EFI_FILE_MODE_WRITE 0x0000000000000002ULL
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL

/* File attributes */
#define EFI_FILE_READ_ONLY 0x0000000000000001ULL
#define EFI_FILE_HIDDEN 0x0000000000000002ULL
#define EFI_FILE_SYSTEM 0x0000000000000004ULL
#define EFI_FILE_RESERVED 0x0000000000000008ULL
#define EFI_FILE_DIRECTORY 0x0000000000000010ULL
#define EFI_FILE_ARCHIVE 0x0000000000000020ULL
#define EFI_FILE_VALID_ATTR 0x0000000000000037ULL

typedef struct {
  uint64_t Size;
  uint64_t FileSize;
  uint64_t PhysicalSize;
  EFI_TIME CreateTime;
  EFI_TIME LastAccessTime;
  EFI_TIME ModificationTime;
  uint64_t Attribute;
  CHAR16 FileName[]; /* Variable length */
} EFI_FILE_INFO;

typedef struct _EFI_FILE_PROTOCOL {
  uint64_t Revision;
  EFI_STATUS(EFIAPI *Open)(struct _EFI_FILE_PROTOCOL *This,
                           struct _EFI_FILE_PROTOCOL **NewHandle,
                           CHAR16 *FileName, uint64_t OpenMode,
                           uint64_t Attributes);
  EFI_STATUS(EFIAPI *Close)(struct _EFI_FILE_PROTOCOL *This);
  EFI_STATUS(EFIAPI *Delete)(struct _EFI_FILE_PROTOCOL *This);
  EFI_STATUS(EFIAPI *Read)(struct _EFI_FILE_PROTOCOL *This, UINTN *BufferSize,
                           void *Buffer);
  EFI_STATUS(EFIAPI *Write)(struct _EFI_FILE_PROTOCOL *This, UINTN *BufferSize,
                            void *Buffer);
  EFI_STATUS(EFIAPI *GetPosition)(struct _EFI_FILE_PROTOCOL *This,
                                  uint64_t *Position);
  EFI_STATUS(EFIAPI *SetPosition)(struct _EFI_FILE_PROTOCOL *This,
                                  uint64_t Position);
  EFI_STATUS(EFIAPI *GetInfo)(struct _EFI_FILE_PROTOCOL *This,
                              EFI_GUID *InformationType, UINTN *BufferSize,
                              void *Buffer);
  EFI_STATUS(EFIAPI *SetInfo)(struct _EFI_FILE_PROTOCOL *This,
                              EFI_GUID *InformationType, UINTN BufferSize,
                              void *Buffer);
  EFI_STATUS(EFIAPI *Flush)(struct _EFI_FILE_PROTOCOL *This);
  /* Revision 2 */
  EFI_STATUS(EFIAPI *OpenEx)(struct _EFI_FILE_PROTOCOL *This,
                             struct _EFI_FILE_PROTOCOL **NewHandle,
                             CHAR16 *FileName, uint64_t OpenMode,
                             uint64_t Attributes, void *Token);
  EFI_STATUS(EFIAPI *ReadEx)(struct _EFI_FILE_PROTOCOL *This, void *Token);
  EFI_STATUS(EFIAPI *WriteEx)(struct _EFI_FILE_PROTOCOL *This, void *Token);
  EFI_STATUS(EFIAPI *FlushEx)(struct _EFI_FILE_PROTOCOL *This, void *Token);
} EFI_FILE_PROTOCOL;

/* =============================================================================
 * Graphics Output Protocol (GOP)
 * =============================================================================
 */

typedef enum {
  PixelRedGreenBlueReserved8BitPerColor,
  PixelBlueGreenRedReserved8BitPerColor,
  PixelBitMask,
  PixelBltOnly,
  PixelFormatMax
} EFI_GRAPHICS_PIXEL_FORMAT;

typedef struct {
  uint32_t RedMask;
  uint32_t GreenMask;
  uint32_t BlueMask;
  uint32_t ReservedMask;
} EFI_PIXEL_BITMASK;

typedef struct {
  uint32_t Version;
  uint32_t HorizontalResolution;
  uint32_t VerticalResolution;
  EFI_GRAPHICS_PIXEL_FORMAT PixelFormat;
  EFI_PIXEL_BITMASK PixelInformation;
  uint32_t PixelsPerScanLine;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

typedef struct {
  uint32_t MaxMode;
  uint32_t Mode;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info;
  UINTN SizeOfInfo;
  uint64_t FrameBufferBase;
  UINTN FrameBufferSize;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct {
  uint8_t Blue;
  uint8_t Green;
  uint8_t Red;
  uint8_t Reserved;
} EFI_GRAPHICS_OUTPUT_BLT_PIXEL;

typedef enum {
  EfiBltVideoFill,
  EfiBltVideoToBltBuffer,
  EfiBltBufferToVideo,
  EfiBltVideoToVideo,
  EfiGraphicsOutputBltOperationMax
} EFI_GRAPHICS_OUTPUT_BLT_OPERATION;

typedef struct _EFI_GRAPHICS_OUTPUT_PROTOCOL {
  EFI_STATUS(EFIAPI *QueryMode)(struct _EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
                                uint32_t ModeNumber, UINTN *SizeOfInfo,
                                EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info);
  EFI_STATUS(EFIAPI *SetMode)(struct _EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
                              uint32_t ModeNumber);
  EFI_STATUS(EFIAPI *Blt)(struct _EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
                          EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer,
                          EFI_GRAPHICS_OUTPUT_BLT_OPERATION BltOperation,
                          UINTN SourceX, UINTN SourceY, UINTN DestinationX,
                          UINTN DestinationY, UINTN Width, UINTN Height,
                          UINTN Delta);
  EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

#endif /* BOOT_COMMON_EFI_EFI_PROTOCOL_H */
