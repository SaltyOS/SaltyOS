/* SaltyOS Stage 2 EFI File Loading
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * File loading from ESP (EFI System Partition)
 */

#include "efi.h"
#include "../common/stage2.h"
#include "../../common/print.h"

/* File paths in ESP */
#define STAGE3_PATH u"\\EFI\\SALTYOS\\stage3.bin"
#define KERNEL_PATH u"\\EFI\\SALTYOS\\kernel.elf"

/* EFI system table pointer (set by entry point) */
static EFI_SYSTEM_TABLE *g_st = NULL;
static EFI_HANDLE g_image = NULL;

/* Simple memcpy */
static void memcpy_local(void *dest, const void *src, uint64_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

/* Load file from ESP to newly allocated pool (returns via out pointer) */
static int efi_load_file_alloc(const CHAR16 *path, void **out_addr, uint64_t *size_out) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    EFI_FILE_PROTOCOL *root;
    EFI_FILE_PROTOCOL *file;
    EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_GUID loaded_img_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_FILE_INFO *file_info = NULL;
    uint64_t info_size = 0;
    EFI_GUID file_info_guid = EFI_FILE_INFO_GUID;

    /* Get loaded image protocol */
    status = g_st->boot_services->handle_protocol(
        g_image,
        &loaded_img_guid,
        (void **)&loaded_image
    );
    if (status != EFI_SUCCESS) {
        print("S2: LoadedImage prot err ");
        serial_puthex((uint64_t)status);
        println("");
        return -1;
    }

    /* Open file system (try device_handle, then locate_protocol, then locate_handle_buffer) */
    status = g_st->boot_services->handle_protocol(
        loaded_image->device_handle,
        &fs_guid,
        (void **)&fs
    );
    if (status != EFI_SUCCESS) {
        EFI_STATUS status2 = g_st->boot_services->locate_protocol(&fs_guid, NULL, (void **)&fs);
        if (status2 != EFI_SUCCESS) {
            uintn_t handle_count = 0;
            EFI_HANDLE *handles = NULL;
            EFI_STATUS status3 = g_st->boot_services->locate_handle_buffer(
                EFI_LOCATE_SEARCH_BY_PROTOCOL,
                &fs_guid,
                NULL,
                &handle_count,
                &handles
            );
            if (status3 == EFI_SUCCESS && handle_count > 0) {
                /* Try first handle */
                status3 = g_st->boot_services->handle_protocol(
                    handles[0],
                    &fs_guid,
                    (void **)&fs
                );
            }
            if (handles) {
                g_st->boot_services->free_pool(handles);
            }
            if (status3 != EFI_SUCCESS) {
                print("S2: SimpleFS err ");
                serial_puthex((uint64_t)status);
                print("/");
                serial_puthex((uint64_t)status2);
                print("/");
                serial_puthex((uint64_t)status3);
                println("");
                return -1;
            }
        }
    }

    /* Open volume */
    status = fs->open_volume(fs, &root);
    if (status != EFI_SUCCESS) {
        print("S2: open_volume err ");
        serial_puthex((uint64_t)status);
        println("");
        return -1;
    }

    /* Open file */
    status = root->open(root, &file, path, EFI_FILE_MODE_READ, 0);
    if (status != EFI_SUCCESS) {
        print("S2: open err ");
        serial_puthex((uint64_t)status);
        println("");
        return -1;
    }

    /* Query EFI_FILE_INFO size (two-step pattern) */
    status = file->get_info(file, &file_info_guid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || info_size == 0) {
        file->close(file);
        println("S2: info sz err");
        return -1;
    }

    status = g_st->boot_services->allocate_pool(EFI_LOADER_DATA, info_size, (void **)&file_info);
    if (status != EFI_SUCCESS) {
        file->close(file);
        println("S2: alloc info err");
        return -1;
    }

    status = file->get_info(file, &file_info_guid, &info_size, file_info);
    if (status != EFI_SUCCESS || info_size < sizeof(EFI_FILE_INFO)) {
        file->close(file);
        g_st->boot_services->free_pool(file_info);
        println("S2: info read err");
        return -1;
    }

    print("S2: file size ");
    serial_puthex((uint64_t)file_info->file_size);
    println("");

    /* Allocate destination buffer */
    status = g_st->boot_services->allocate_pool(EFI_LOADER_DATA, file_info->file_size, out_addr);
    if (status != EFI_SUCCESS) {
        file->close(file);
        g_st->boot_services->free_pool(file_info);
        println("S2: alloc buf err");
        return -1;
    }

    /* Read file with short-read handling */
    uint8_t *dst = (uint8_t *)(*out_addr);
    uint64_t total = 0;
    while (total < file_info->file_size) {
        uint64_t chunk = file_info->file_size - total;
        status = file->read(file, &chunk, dst + total);
        if (status != EFI_SUCCESS) {
            g_st->boot_services->free_pool(*out_addr);
            g_st->boot_services->free_pool(file_info);
            file->close(file);
            print("S2: read err ");
            serial_puthex((uint64_t)status);
            println("");
            return -1;
        }
        if (chunk == 0) {
            /* EOF before expected size */
            g_st->boot_services->free_pool(*out_addr);
            g_st->boot_services->free_pool(file_info);
            file->close(file);
            print("S2: read short ");
            serial_puthex(total);
            println("");
            return -1;
        }
        total += chunk;
    }

    file->close(file);
    g_st->boot_services->free_pool(file_info);

    if (size_out) {
        *size_out = total;
    }

    return 0;
}

/* Load Stage3 from ESP */
int efi_load_stage3(void **stage3_addr, size_t *size) {
    int ret = efi_load_file_alloc(STAGE3_PATH, stage3_addr, (uint64_t *)size);
    if (ret != 0) {
        println("S2: efi_load_stage3 failed");
    } else {
        print("S2: stage3 loaded @");
        serial_puthex((uint64_t)*stage3_addr);
        println("");
    }
    return ret;
}

/* Load kernel from ESP */
int efi_load_kernel(void **kernel_addr, size_t *size) {
    int ret = efi_load_file_alloc(KERNEL_PATH, kernel_addr, (uint64_t *)size);
    if (ret != 0) {
        println("S2: efi_load_kernel failed");
    } else {
        print("S2: kernel loaded @");
        serial_puthex((uint64_t)*kernel_addr);
        println("");
    }
    return ret;
}

/* Initialize EFI context for file operations */
void efi_file_init(EFI_HANDLE image, EFI_SYSTEM_TABLE *st) {
    g_image = image;
    g_st = st;
}

/* Load Stage3 from ESP (called by stage2 context) */
static int efi_load_stage3_callback(void **stage3_addr, size_t *size) {
    return efi_load_stage3(stage3_addr, size);
}

/* Load kernel from ESP (called by stage2 context) */
static int efi_load_kernel_callback(void **kernel_addr, size_t *size) {
    return efi_load_kernel(kernel_addr, size);
}

/* Get callbacks for stage2 context */
void efi_file_get_callbacks(int (**load_stage3_fn)(void **, size_t *),
                             int (**load_kernel_fn)(void **, size_t *)) {
    *load_stage3_fn = efi_load_stage3_callback;
    *load_kernel_fn = efi_load_kernel_callback;
}
