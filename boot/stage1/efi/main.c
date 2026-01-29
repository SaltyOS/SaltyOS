/* SaltyOS Stage 1 EFI Entry Point
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Minimal EFI loader for Stage 1
 * Just loads Stage2/EFI and jumps to it
 */

#include "efi.h"
#include "../../common/print.h"

/* EFI system table pointer */
static EFI_SYSTEM_TABLE *g_st = NULL;

/* Simple memset */
static void memset_local(void *s, int c, uint64_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
}

/* Simple memcpy */
static void memcpy_local(void *dest, const void *src, uint64_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
}

/* Load stage2.efi from ESP into memory buffer */
static EFI_STATUS load_stage2_image(EFI_HANDLE image, void **stage2_addr, uint64_t *stage2_size) {
    EFI_STATUS status;
    EFI_LOADED_IMAGE *loaded_image;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
    EFI_FILE_PROTOCOL *root;
    EFI_FILE_PROTOCOL *file;
    EFI_GUID fs_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_GUID loaded_img_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_GUID file_info_guid = EFI_FILE_INFO_GUID;
    EFI_FILE_INFO *info = NULL;
    uint64_t info_size = 0;

    /* Get loaded image protocol */
    status = g_st->boot_services->handle_protocol(
        image,
        &loaded_img_guid,
        (void **)&loaded_image
    );
    if (status != EFI_SUCCESS) {
        return status;
    }

    /* Open file system */
    status = g_st->boot_services->handle_protocol(
        loaded_image->device_handle,
        &fs_guid,
        (void **)&fs
    );
    if (status != EFI_SUCCESS) {
        return status;
    }

    /* Open volume */
    status = fs->open_volume(fs, &root);
    if (status != EFI_SUCCESS) {
        return status;
    }

    /* Open stage2.efi */
    status = root->open(root, &file, u"\\EFI\\SALTYOS\\stage2.efi", EFI_FILE_MODE_READ, 0);
    if (status != EFI_SUCCESS) {
        return status;
    }

    /* Query EFI_FILE_INFO size (two-step pattern) */
    status = file->get_info(file, &file_info_guid, &info_size, NULL);
    if (status != EFI_BUFFER_TOO_SMALL || info_size == 0) {
        file->close(file);
        return status;
    }

    status = g_st->boot_services->allocate_pool(EFI_LOADER_DATA, info_size, (void **)&info);
    if (status != EFI_SUCCESS) {
        file->close(file);
        return status;
    }

    status = file->get_info(file, &file_info_guid, &info_size, info);
    if (status != EFI_SUCCESS || info_size < sizeof(EFI_FILE_INFO)) {
        file->close(file);
        g_st->boot_services->free_pool(info);
        return status;
    }

    uint64_t file_size = info->file_size;

    /* Allocate memory for stage2.bin */
    status = g_st->boot_services->allocate_pool(
        EFI_LOADER_DATA,
        file_size,
        stage2_addr
    );
    if (status != EFI_SUCCESS) {
        file->close(file);
        g_st->boot_services->free_pool(info);
        return status;
    }

    /* Read file */
    uint64_t read_size = file_size;
    status = file->read(file, &read_size, *stage2_addr);
    file->close(file);
    g_st->boot_services->free_pool(info);

    if (status != EFI_SUCCESS || read_size != file_size) {
        g_st->boot_services->free_pool(*stage2_addr);
        return EFI_LOAD_ERROR;
    }

    *stage2_size = file_size;
    return EFI_SUCCESS;
}

/* EFI entry point */
EFI_STATUS EFIAPI efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *st) {
    EFI_STATUS status;
    void *stage2_addr = NULL;
    uint64_t stage2_size = 0;
    EFI_HANDLE stage2_image = NULL;

    g_st = st;

    /* Initialize serial for early diagnostics */
    serial_init();
    println("S1: SaltyOS UEFI");

    /* Load stage2.efi into memory buffer */
    status = load_stage2_image(image, &stage2_addr, &stage2_size);
    if (status != EFI_SUCCESS) {
        print("S1: load_stage2_image failed: ");
        serial_puthex((uint64_t)status);
        println("");
        return status;
    }

    print("S1: loaded stage2 (size=");
    serial_puthex(stage2_size);
    println(")");

    /* Load the PE/COFF image from memory */
    typedef EFI_STATUS (EFIAPI *load_image_fn)(
        uint8_t boot_policy,
        EFI_HANDLE parent_image_handle,
        void *device_path,
        void *source_buffer,
        uint64_t source_size,
        EFI_HANDLE *image_handle
    );

    load_image_fn load_image = (load_image_fn)g_st->boot_services->load_image;

    status = load_image(0, image, NULL, stage2_addr, stage2_size, &stage2_image);
    if (status != EFI_SUCCESS) {
        g_st->boot_services->free_pool(stage2_addr);
        print("S1: LoadImage failed: ");
        serial_puthex((uint64_t)status);
        println("");
        return status;
    }

    /* Buffer no longer needed after LoadImage */
    g_st->boot_services->free_pool(stage2_addr);

    println("S1: LoadImage ok, starting stage2");

    /* Start the loaded image */
    typedef EFI_STATUS (EFIAPI *start_image_fn)(
        EFI_HANDLE image_handle,
        uint64_t *exit_data_size,
        CHAR16 **exit_data
    );

    start_image_fn start_image = (start_image_fn)g_st->boot_services->start_image;

    status = start_image(stage2_image, NULL, NULL);

    print("S1: StartImage returned: ");
    serial_puthex((uint64_t)status);
    println("");

    /* Should not return; if it does, propagate status */
    return status;
}
