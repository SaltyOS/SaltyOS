/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS process startup ABI.
 *
 * The kernel or a userspace spawner enters a new ELF process at its
 * e_entry with a SysV argc/argv/envp/auxv stack. SaltyOS-specific
 * capability and layout state is referenced by AT_SALTYOS_STARTUP.
 */

#ifndef KERNITE_UAPI_STARTUP_H
#define KERNITE_UAPI_STARTUP_H

#include <stdint.h>

#define AT_SALTYOS_STARTUP 0x2005ULL

#define SALTYOS_STARTUP_MAGIC 0x31544C53U /* "SLT1" little-endian */
#define SALTYOS_STARTUP_VERSION 1U

#define SALTYOS_IMAGE_KIND_NONE 0U
#define SALTYOS_IMAGE_KIND_ELF  1U
#define SALTYOS_IMAGE_KIND_PE   2U

#define SALTYOS_STARTUP_MAX_MAPPED_IMAGES 16U
#define SALTYOS_STARTUP_IMAGE_NAME_LEN    32U

#define SALTYOS_CAP_TABLE_MAGIC   0x43544153U /* "SATC" little-endian */
#define SALTYOS_CAP_TABLE_VERSION 1U

#define SALTYOS_CAP_TBL_RIGHT_READ   (1U << 0)
#define SALTYOS_CAP_TBL_RIGHT_WRITE  (1U << 1)
#define SALTYOS_CAP_TBL_RIGHT_GRANT  (1U << 2)
#define SALTYOS_CAP_TBL_RIGHT_INVOKE (1U << 3)
#define SALTYOS_CAP_TBL_RIGHT_BADGE  (1U << 4)
#define SALTYOS_CAP_TBL_RIGHT_DEVICE (1U << 5)

#define SALTYOS_CAP_TBL_FLAG_BADGED       (1U << 0)
#define SALTYOS_CAP_TBL_FLAG_RAW          (1U << 1)
#define SALTYOS_CAP_TBL_FLAG_OPTIONAL     (1U << 2)
#define SALTYOS_CAP_TBL_FLAG_NOTIFICATION (1U << 3)
#define SALTYOS_CAP_TBL_FLAG_UNTYPED      (1U << 4)
#define SALTYOS_CAP_TBL_FLAG_DEVICE_UT    (1U << 5)
#define SALTYOS_CAP_TBL_FLAG_IO_PORT      (1U << 6)
/* Entry reserves a child CSpace slot but does not currently hold a live cap. */
#define SALTYOS_CAP_TBL_FLAG_RESERVED (1U << 7)

#define SALTYOS_CSPACE_LAYOUT_VERSION 1ULL
#define SALTYOS_CSPACE_FLAG_HAS_RECV_RANGE   (1ULL << 0)
#define SALTYOS_CSPACE_FLAG_HAS_EXPAND_RANGE (1ULL << 1)

typedef struct SaltyOSImageInfoV1 {
    uint32_t kind;
    uint32_t aux;
    uint64_t base;
    uint64_t size;
    uint64_t entry;
} SaltyOSImageInfoV1;

typedef struct SaltyOSMappedImageV1 {
    SaltyOSImageInfoV1 image;
    uint32_t name_len;
    uint8_t name[SALTYOS_STARTUP_IMAGE_NAME_LEN];
} SaltyOSMappedImageV1;

typedef struct SaltyOSFramebufferInfoV1 {
    uint64_t phys_addr;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint8_t bpp;
    uint8_t red_pos;
    uint8_t red_size;
    uint8_t green_pos;
    uint8_t green_size;
    uint8_t blue_pos;
    uint8_t blue_size;
    uint8_t reserved;
} SaltyOSFramebufferInfoV1;

typedef struct SaltyOSStartupLayoutV1 {
    uint32_t magic;
    uint32_t version;
    uint64_t flags;
    uint64_t ipc_buffer_vaddr;
    uint64_t scratch_vaddr;
    uint64_t dso_window_base;
    uint64_t dso_window_size;
    uint64_t cap_table_ptr;
    uint64_t cspace_layout_ptr;
    uint64_t boot_untyped_slot;
    uint64_t boot_untyped_size_bits;
    uint64_t boot_untyped_size_bytes;
    uint64_t boot_untyped_available_bytes;
    SaltyOSImageInfoV1 main_image;
    uint64_t mapped_image_count;
    SaltyOSMappedImageV1 mapped_images[SALTYOS_STARTUP_MAX_MAPPED_IMAGES];
    uint64_t preinstalled_slot_bitmap[2];
    SaltyOSFramebufferInfoV1 framebuffer;
} SaltyOSStartupLayoutV1;

typedef struct SaltyOSCspaceLayoutV1 {
    uint64_t version;
    uint64_t flags;
    uint64_t cnode_bits;
    uint64_t rtld_untyped_base;
    uint64_t rtld_untyped_count;
    uint64_t rtld_untyped_size_bits;
    uint64_t frame_slot_base;
    uint64_t frame_slot_limit;
    uint64_t alloc_base;
    uint64_t alloc_limit;
    uint64_t recv_base;
    uint64_t recv_limit;
    uint64_t expand_base;
    uint64_t expand_limit;
} SaltyOSCspaceLayoutV1;

typedef struct SaltyOSCapEntryV1 {
    uint32_t role_id;
    uint32_t slot;
    uint32_t rights;
    uint32_t flags;
} SaltyOSCapEntryV1;

typedef struct SaltyOSCapTableV1 {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
    SaltyOSCapEntryV1 entries[];
} SaltyOSCapTableV1;

typedef enum SaltyOSCapRole {
    SALTYOS_CAP_ROLE_INIT_CONTROL = 0x0001,
    SALTYOS_CAP_ROLE_SERVICE_EP = 0x0002,
    SALTYOS_CAP_ROLE_NAMESRV_CLIENT = 0x0003,
    SALTYOS_CAP_ROLE_VFS_CLIENT = 0x0004,
    SALTYOS_CAP_ROLE_MMSRV_CLIENT = 0x0005,
    SALTYOS_CAP_ROLE_MMSRV_AUTHORITY_RAW = 0x0006,
    SALTYOS_CAP_ROLE_RSRCSRV_CLIENT = 0x0007,
    SALTYOS_CAP_ROLE_RSRCSRV_AUTHORITY_RAW = 0x0008,
    SALTYOS_CAP_ROLE_CONSOLE_CLIENT = 0x0009,
    SALTYOS_CAP_ROLE_SIGNAL_PIPE = 0x000A,
    SALTYOS_CAP_ROLE_SERVICE_CLIENT_EP = 0x000B,
    SALTYOS_CAP_ROLE_INITRD_UNTYPED = 0x000C,
    SALTYOS_CAP_ROLE_FB_UNTYPED = 0x000D,
    SALTYOS_CAP_ROLE_PCI_IOPORT = 0x000E,
    SALTYOS_CAP_ROLE_COM1_IOPORT = 0x000F,
    SALTYOS_CAP_ROLE_WIN32SRV_CLIENT = 0x0010,
    SALTYOS_CAP_ROLE_CSPACE_NTFN = 0x0011,
    SALTYOS_CAP_ROLE_SC_CAP = 0x0012,
    SALTYOS_CAP_ROLE_COM1_IRQ = 0x0013,
    SALTYOS_CAP_ROLE_COM1_NTFN = 0x0014,
    SALTYOS_CAP_ROLE_KBD_IOPORT = 0x0015,
    SALTYOS_CAP_ROLE_KBD_IRQ = 0x0016,
    SALTYOS_CAP_ROLE_DEVICE_CONTROL = 0x0017,
    SALTYOS_CAP_ROLE_LOG_CLIENT = 0x0018,
    SALTYOS_CAP_ROLE_JIT_EXEC_AUTHORITY = 0x0019,
    SALTYOS_CAP_ROLE_KERNEL_RNG = 0x001D,
    SALTYOS_CAP_ROLE_CLOCK = 0x001E,
    SALTYOS_CAP_ROLE_SYSTEM_CONTROL = 0x001F,
    SALTYOS_CAP_ROLE_SYSTEM_INFO = 0x0020,
    SALTYOS_CAP_ROLE_KERNEL_DEBUG = 0x0021,
    SALTYOS_CAP_ROLE_LDSRV_CLIENT = 0x0022,
} SaltyOSCapRole;

#endif /* KERNITE_UAPI_STARTUP_H */
