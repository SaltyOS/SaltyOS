/* SaltyOS Stage 1 EFI Headers
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Basic EFI type definitions for Stage 1 UEFI loader
 */

#ifndef SALTYOS_STAGE1_EFI_EFI_H
#define SALTYOS_STAGE1_EFI_EFI_H

#include "../../common/types.h"

/* Calling convention (UEFI uses Microsoft x64 ABI on x86_64) */
#ifndef EFIAPI
#if defined(__x86_64__)
#define EFIAPI __attribute__((ms_abi))
#else
#define EFIAPI
#endif
#endif

/* Unsigned integer type (platform-dependent) */
typedef uintptr_t uintn_t;

/* EFI Status codes */
typedef int64_t EFI_STATUS;
#define EFI_SUCCESS              0
#define EFI_LOAD_ERROR           (1 | (1ULL << 63))
#define EFI_INVALID_PARAMETER    (2 | (1ULL << 63))
#define EFI_BUFFER_TOO_SMALL     (5 | (1ULL << 63))
#define EFI_NOT_FOUND            (14 | (1ULL << 63))

/* EFI basic types */
typedef void *EFI_HANDLE;
typedef uint16_t CHAR16;

/* EFI table header */
typedef struct {
    uint64_t signature;
    uint32_t revision;
    uint32_t header_size;
    uint32_t crc32;
    uint32_t reserved;
} EFI_TABLE_HEADER;

/* EFI GUID */
typedef struct {
    uint32_t data1;
    uint16_t data2;
    uint16_t data3;
    uint8_t  data4[8];
} EFI_GUID;

/* Forward declaration */
typedef struct _EFI_BOOT_SERVICES EFI_BOOT_SERVICES;

/* EFI Boot Services - must match UEFI spec layout exactly
 *
 * UEFI Boot Services Table offsets (x86_64):
 *   0: Hdr (24 bytes - EFI_TABLE_HEADER)
 *  24: RaiseTPL
 *  32: RestoreTPL
 *  40: AllocatePages
 *  48: FreePages
 *  56: GetMemoryMap
 *  64: AllocatePool
 *  72: FreePool
 *  80: CreateEvent
 *  88: SetTimer
 *  96: WaitForEvent
 * 104: SignalEvent
 * 112: CloseEvent
 * 120: CheckEvent
 * 128: InstallProtocolInterface
 * 136: ReinstallProtocolInterface
 * 144: UninstallProtocolInterface
 * 152: HandleProtocol
 * 160: Reserved
 * 168: RegisterProtocolNotify
 * 176: LocateHandle
 * 184: LocateDevicePath
 * 192: InstallConfigurationTable
 * 200: LoadImage
 * 208: StartImage
 * 216: Exit
 * 224: UnloadImage
 * 232: ExitBootServices
 */
typedef struct _EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER hdr;                           /* 0: Table header */
    void *raise_tpl;                                /* 24 */
    void *restore_tpl;                              /* 32 */
    void *allocate_pages;                           /* 40 */
    void *free_pages;                               /* 48 */
    void *get_memory_map;                           /* 56 */
    EFI_STATUS (EFIAPI *allocate_pool)(             /* 64 */
        uint32_t pool_type,
        uintn_t buffer_size,
        void **buffer
    );
    EFI_STATUS (EFIAPI *free_pool)(void *buffer);   /* 72 */
    void *create_event;                             /* 80 */
    void *set_timer;                                /* 88 */
    void *wait_for_event;                           /* 96 */
    void *signal_event;                             /* 104 */
    void *close_event;                              /* 112 */
    void *check_event;                              /* 120 */
    void *install_protocol_interface;               /* 128 */
    void *reinstall_protocol_interface;             /* 136 */
    void *uninstall_protocol_interface;             /* 144 */
    EFI_STATUS (EFIAPI *handle_protocol)(           /* 152 */
        EFI_HANDLE handle,
        EFI_GUID *protocol,
        void **interface
    );
    void *reserved;                                 /* 160 */
    void *register_protocol_notify;                 /* 168 */
    void *locate_handle;                            /* 176 */
    void *locate_device_path;                       /* 184 */
    void *install_configuration_table;              /* 192 */
    void *load_image;                               /* 200 */
    void *start_image;                              /* 208 */
    void *exit;                                     /* 216 */
    void *unload_image;                             /* 224 */
    void *exit_boot_services;                       /* 232 */
} EFI_BOOT_SERVICES;

/* EFI File Info */
typedef struct _EFI_FILE_INFO {
    uint64_t size;
    uint64_t file_size;
    uint64_t physical_size;
    uint64_t create_time;
    uint64_t last_access_time;
    uint64_t modification_time;
    uint64_t attribute;
    CHAR16  file_name[];
} EFI_FILE_INFO;

/* EFI_FILE_INFO GUID */
#define EFI_FILE_INFO_GUID \
    {0x09576e92,0x6d3f,0x11d2,{0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b}}

/* EFI System Table */
typedef struct _EFI_SYSTEM_TABLE {
    EFI_TABLE_HEADER hdr;
    CHAR16 *firmware_vendor;
    uint32_t firmware_revision;
    EFI_HANDLE console_in_handle;
    void *con_in;
    EFI_HANDLE console_out_handle;
    void *con_out;
    EFI_HANDLE standard_error_handle;
    void *std_err;
    void *runtime_services;
    EFI_BOOT_SERVICES *boot_services;
    uint64_t number_of_table_entries;
    void *configuration_table;
} EFI_SYSTEM_TABLE;

/* EFI loaded image protocol */
#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
    {0x5B1B31A1,0x9562,0x11d2,{0x8E,0x3F,0x00,0xA0,0xC9,0x69,0x72,0x3B}}

typedef struct _EFI_LOADED_IMAGE {
    uint32_t revision;
    EFI_HANDLE parent_handle;
    EFI_SYSTEM_TABLE *system_table;
    EFI_HANDLE device_handle;
    void *file_path;
    void *reserved;
    uint32_t load_options_size;
    void *load_options;
    void *image_base;
    uint64_t image_size;
    uint32_t code_type;
    uint32_t data_type;
    void *unload;
} EFI_LOADED_IMAGE;

/* EFI file protocol */
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
    {0x964E5B22,0x6459,0x11D2,{0x8E,0x39,0x00,0xA0,0xC9,0x69,0x72,0x3B}}

typedef struct _EFI_FILE_PROTOCOL EFI_FILE_PROTOCOL;

struct _EFI_FILE_PROTOCOL {
    uint64_t revision;
    EFI_STATUS (EFIAPI *open)(
        EFI_FILE_PROTOCOL *self,
        EFI_FILE_PROTOCOL **new_handle,
        const CHAR16 *file_name,
        uint64_t open_mode,
        uint64_t attributes
    );
    EFI_STATUS (EFIAPI *close)(EFI_FILE_PROTOCOL *self);
    EFI_STATUS (EFIAPI *delete_)(EFI_FILE_PROTOCOL *self);
    EFI_STATUS (EFIAPI *read)(
        EFI_FILE_PROTOCOL *self,
        uint64_t *buffer_size,
        void *buffer
    );
    EFI_STATUS (EFIAPI *write)(
        EFI_FILE_PROTOCOL *self,
        uint64_t *buffer_size,
        void *buffer
    );
    EFI_STATUS (EFIAPI *get_position)(
        EFI_FILE_PROTOCOL *self,
        uint64_t *position
    );
    EFI_STATUS (EFIAPI *set_position)(
        EFI_FILE_PROTOCOL *self,
        uint64_t position
    );
    EFI_STATUS (EFIAPI *get_info)(
        EFI_FILE_PROTOCOL *self,
        const EFI_GUID *information_type,
        uint64_t *buffer_size,
        void *buffer
    );
    EFI_STATUS (EFIAPI *set_info)(
        EFI_FILE_PROTOCOL *self,
        const EFI_GUID *information_type,
        uint64_t buffer_size,
        void *buffer
    );
    EFI_STATUS (EFIAPI *flush)(EFI_FILE_PROTOCOL *self);
};

typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;

struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
    uint64_t revision;
    EFI_STATUS (EFIAPI *open_volume)(
        EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *self,
        EFI_FILE_PROTOCOL **root
    );
};

/* EFI file mode */
#define EFI_FILE_MODE_READ  0x01
#define EFI_FILE_MODE_WRITE 0x02
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL

/* EFI memory type */
typedef uint32_t EFI_MEMORY_TYPE;
#define EFI_LOADER_DATA  2

#endif /* SALTYOS_STAGE1_EFI_EFI_H */
