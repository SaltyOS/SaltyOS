/* SaltyOS Stage 2 EFI Headers
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Basic EFI type definitions for Stage 2 UEFI wrapper
 */

#ifndef SALTYOS_STAGE2_EFI_EFI_H
#define SALTYOS_STAGE2_EFI_EFI_H

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
#define EFI_UNSUPPORTED          (3 | (1ULL << 63))
#define EFI_BAD_BUFFER_SIZE      (4 | (1ULL << 63))
#define EFI_BUFFER_TOO_SMALL     (5 | (1ULL << 63))
#define EFI_NOT_READY            (6 | (1ULL << 63))
#define EFI_DEVICE_ERROR         (7 | (1ULL << 63))
#define EFI_WRITE_PROTECTED      (8 | (1ULL << 63))
#define EFI_OUT_OF_RESOURCES     (9 | (1ULL << 63))
#define EFI_VOLUME_CORRUPTED     (10 | (1ULL << 63))
#define EFI_VOLUME_FULL          (11 | (1ULL << 63))
#define EFI_NO_MEDIA             (12 | (1ULL << 63))
#define EFI_MEDIA_CHANGED        (13 | (1ULL << 63))
#define EFI_NOT_FOUND            (14 | (1ULL << 63))
#define EFI_ACCESS_DENIED        (15 | (1ULL << 63))
#define EFI_NO_RESPONSE          (16 | (1ULL << 63))
#define EFI_NO_MAPPING           (17 | (1ULL << 63))
#define EFI_TIMEOUT              (18 | (1ULL << 63))
#define EFI_NOT_STARTED          (19 | (1ULL << 63))
#define EFI_ALREADY_STARTED      (20 | (1ULL << 63))
#define EFI_ABORTED              (21 | (1ULL << 63))
#define EFI_ICMP_ERROR           (22 | (1ULL << 63))
#define EFI_TFTP_ERROR           (23 | (1ULL << 63))
#define EFI_PROTOCOL_ERROR       (24 | (1ULL << 63))
#define EFI_INCOMPATIBLE_VERSION (25 | (1ULL << 63))
#define EFI_SECURITY_VIOLATION    (26 | (1ULL << 63))
#define EFI_CRC_ERROR            (27 | (1ULL << 63))
#define EFI_END_OF_MEDIA         (28 | (1ULL << 63))
#define EFI_END_OF_FILE          (31 | (1ULL << 63))
#define EFI_INVALID_LANGUAGE     (32 | (1ULL << 63))
#define EFI_COMPROMISED_DATA     (33 | (1ULL << 63))
#define EFI_IP_ADDRESS_CONFLICT  (34 | (1ULL << 63))
#define EFI_HTTP_ERROR           (35 | (1ULL << 63))

/* EFI basic types */
typedef void *EFI_HANDLE;
typedef uint16_t CHAR16;
typedef uint64_t EFI_PHYSICAL_ADDRESS;
typedef uint64_t EFI_VIRTUAL_ADDRESS;

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

/* EFI memory type */
typedef uint32_t EFI_MEMORY_TYPE;

/* EFI allocate pages type */
typedef enum {
    AllocateAnyPages,
    AllocateMaxAddress,
    AllocateAddress,
} EFI_ALLOCATE_TYPE;

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
 * 240: GetNextMonotonicCount
 * 248: Stall
 * 256: SetWatchdogTimer
 * 264: ConnectController
 * 272: DisconnectController
 * 280: OpenProtocol
 * 288: CloseProtocol
 * 296: OpenProtocolInformation
 * 304: ProtocolsPerHandle
 * 312: LocateHandleBuffer
 * 320: LocateProtocol
 */
typedef struct _EFI_BOOT_SERVICES {
    EFI_TABLE_HEADER hdr;                           /* 0: Table header (24 bytes) */
    void *raise_tpl;                                /* 24 */
    void *restore_tpl;                              /* 32 */
    EFI_STATUS (EFIAPI *allocate_pages)(            /* 40 */
        EFI_ALLOCATE_TYPE type,
        EFI_MEMORY_TYPE memory_type,
        uintn_t pages,
        uint64_t *memory
    );
    void *free_pages;                               /* 48 */
    EFI_STATUS (EFIAPI *get_memory_map)(            /* 56 */
        uintn_t *memory_map_size,
        void *memory_map,
        uintn_t *map_key,
        uintn_t *descriptor_size,
        uint32_t *descriptor_version
    );
    EFI_STATUS (EFIAPI *allocate_pool)(             /* 64 */
        EFI_MEMORY_TYPE pool_type,
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
    void *get_next_monotonic_count;                 /* 240 */
    void *stall;                                    /* 248 */
    void *set_watchdog_timer;                       /* 256 */
    void *connect_controller;                       /* 264 */
    void *disconnect_controller;                    /* 272 */
    void *open_protocol;                            /* 280 */
    void *close_protocol;                           /* 288 */
    void *open_protocol_information;                /* 296 */
    void *protocols_per_handle;                     /* 304 */
    EFI_STATUS (EFIAPI *locate_handle_buffer)(      /* 312 */
        uint32_t search_type,
        EFI_GUID *protocol,
        void *search_key,
        uintn_t *no_handles,
        EFI_HANDLE **buffer
    );
    EFI_STATUS (EFIAPI *locate_protocol)(           /* 320 */
        EFI_GUID *protocol,
        void *registration,
        void **interface
    );
} EFI_BOOT_SERVICES;

/* LocateHandleBuffer search types */
#define EFI_LOCATE_SEARCH_ALL_HANDLES        0
#define EFI_LOCATE_SEARCH_BY_REGISTER_NOTIFY 1
#define EFI_LOCATE_SEARCH_BY_PROTOCOL        2

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

/* EFI Graphics Output Mode Information */
typedef struct _EFI_GRAPHICS_OUTPUT_MODE_INFORMATION {
    uint32_t version;
    uint32_t horizontal_resolution;
    uint32_t vertical_resolution;
    uint32_t pixel_format;
    uint32_t pixels_per_scan_line;
} EFI_GRAPHICS_OUTPUT_MODE_INFORMATION;

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

/* EFI memory types */
#define EFI_RESERVED_MEMORY_TYPE     0
#define EFI_LOADER_CODE              1
#define EFI_LOADER_DATA              2
#define EFI_BOOT_SERVICES_CODE       3
#define EFI_BOOT_SERVICES_DATA       4
#define EFI_RUNTIME_SERVICES_CODE    5
#define EFI_RUNTIME_SERVICES_DATA    6
#define EFI_CONVENTIONAL_MEMORY      7
#define EFI_UNUSABLE_MEMORY          8
#define EFI_ACPI_RECLAIM_MEMORY      9
#define EFI_ACPI_MEMORY_NVS          10
#define EFI_MEMORY_MAPPED_IO         11
#define EFI_MEMORY_MAPPED_IO_PORT_SPACE 12
#define EFI_PAL_CODE                 13
#define EFI_PERSISTENT_MEMORY        14

/* EFI memory descriptor */
typedef struct {
    uint32_t type;
    uint32_t pad;
    uint64_t physical_start;
    uint64_t virtual_start;
    uint64_t number_of_pages;
    uint64_t attribute;
} EFI_MEMORY_DESCRIPTOR;

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
    EFI_MEMORY_TYPE code_type;
    EFI_MEMORY_TYPE data_type;
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

/* EFI graphics output protocol */
#define EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID \
    {0x9042A9DE,0x23DC,0x4A38,{0x96,0xFB,0x7A,0xDE,0xD0,0x80,0x51,0x6A}}

typedef struct {
    uint32_t max_mode;
    uint32_t mode;
    EFI_PHYSICAL_ADDRESS frame_buffer_base;
    uint32_t frame_buffer_size;
    EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *info;
} EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE;

typedef struct _EFI_GRAPHICS_OUTPUT_PROTOCOL {
    void *query_mode;
    EFI_STATUS (EFIAPI *set_mode)(void *, uint32_t);
    void *blt;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *mode;
} EFI_GRAPHICS_OUTPUT_PROTOCOL;

/* ACPI GUIDs */
#define ACPI_20_TABLE_GUID \
    {0x8868E871,0xE74F,0x11D3,{0xBC,0x18,0x00,0x80,0xC7,0x3C,0x88,0x81}}
#define ACPI_TABLE_GUID \
    {0xEB9D2D30,0x2D88,0x11D3,{0x9A,0x16,0x00,0x90,0x27,0x3F,0xC1,0x4D}}

/* EFI configuration table */
typedef struct {
    EFI_GUID vendor_guid;
    void *vendor_table;
} EFI_CONFIGURATION_TABLE;

/* EFI file mode */
#define EFI_FILE_MODE_READ  0x01
#define EFI_FILE_MODE_WRITE 0x02
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL

/* Function prototypes for Stage2/EFI modules */
void efi_file_init(EFI_HANDLE image, EFI_SYSTEM_TABLE *st);
void efi_file_get_callbacks(int (**load_stage3_fn)(void **, size_t *),
                             int (**load_kernel_fn)(void **, size_t *));
void efi_memory_init(EFI_SYSTEM_TABLE *st);
extern int (*efi_get_memory_map_fn_ptr)(struct memory_map_entry **, size_t *);
void efi_fb_init(EFI_SYSTEM_TABLE *st);
extern struct framebuffer_info (*efi_get_framebuffer_fn_ptr)(void);
void efi_acpi_init(EFI_SYSTEM_TABLE *st);
extern uint64_t (*efi_find_rsdp_fn_ptr)(void);

#endif /* SALTYOS_STAGE2_EFI_EFI_H */
