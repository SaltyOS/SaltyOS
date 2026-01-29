/* SaltyOS Stage 2 BIOS Disk I/O
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * BIOS disk I/O using int 0x13 AH=0x42 (LBA extensions)
 * Called via assembly helper functions
 */

#include "../common/stage2.h"
#include "../../common/print.h"
#include "../../common/types.h"

/* External assembly helper function */
extern uint64_t bios_read_disk_lba(void *buf, uint64_t lba, uint64_t sectors);

/* LBA values (defined in helpers.asm) */
extern uint64_t stage3_lba;
extern uint64_t kernel_lba;

/* Constants */
#define STAGE3_LOAD_ADDR  ((void *)0x10000ULL)
#define KERNEL_TEMP_ADDR  ((void *)0x20000ULL)
#define KERNEL_DEST_ADDR  ((void *)0x1000000ULL)  /* 16MB */
#define STAGE3_SECTORS    64
#define MAX_KERNEL_SECTORS 16384

/* ELF64 header offsets */
#define ELF64_E_PHOFF     32
#define ELF64_E_PHENTSIZE 54
#define ELF64_E_PHNUM     56
#define ELF64_E_TYPE      16
#define PT_LOAD           1   /* Changed from ET_LOAD (2) to PT_LOAD (1) */

/* Load Stage3 from disk */
int bios_load_stage3(void **addr, size_t *size) {
    println("S2: BIOS loading Stage3");

    void *buf = STAGE3_LOAD_ADDR;
    uint64_t sectors = STAGE3_SECTORS;

    uint64_t read = bios_read_disk_lba(buf, stage3_lba, sectors);
    if ((int64_t)read < 0) {
        println("S2: Stage3 disk read failed");
        return -1;
    }

    *addr = buf;
    *size = sectors * 512;

    print("S2: Stage3 loaded size=");
    serial_puthex(*size);
    println("");

    return 0;
}

/* Load kernel ELF from disk */
int bios_load_kernel(void **addr, size_t *size) {
    println("S2: BIOS loading kernel");

    uint8_t *temp_buf = (uint8_t *)KERNEL_TEMP_ADDR;
    uint8_t *dest_buf = (uint8_t *)KERNEL_DEST_ADDR;

    /* Step 1: Read first sector (ELF header) to temp buffer */
    uint64_t read = bios_read_disk_lba(temp_buf, kernel_lba, 1);
    if ((int64_t)read < 0) {
        println("S2: Kernel header read failed");
        return -1;
    }

    /* Step 2: Validate ELF magic */
    if (*(uint32_t *)temp_buf != 0x464C457F) {  /* "\x7FELF" */
        println("S2: Invalid ELF magic");
        return -1;
    }

    /* Step 3: Parse program headers to find file size */
    uint32_t phoff = *(uint32_t *)(temp_buf + ELF64_E_PHOFF);
    uint16_t phnum = *(uint16_t *)(temp_buf + ELF64_E_PHNUM);
    uint16_t phentsize = *(uint16_t *)(temp_buf + ELF64_E_PHENTSIZE);

    uint32_t max_offset = 0;

    for (uint16_t i = 0; i < phnum; i++) {
        uint8_t *phdr = temp_buf + phoff + (i * phentsize);
        uint32_t p_type = *(uint32_t *)(phdr + 0);
        uint64_t p_offset = *(uint64_t *)(phdr + 8);
        uint64_t p_filesz = *(uint64_t *)(phdr + 32);

        if (p_type == PT_LOAD) {
            uint32_t extent = (uint32_t)(p_offset + p_filesz);
            if (extent > max_offset) {
                max_offset = extent;
            }
        }
    }

    if (max_offset == 0) {
        println("S2: No PT_LOAD segments found");
        return -1;
    }

    /* Step 4: Convert to sectors (round up) */
    uint64_t kernel_sectors = (max_offset + 511) / 512;

    if (kernel_sectors > MAX_KERNEL_SECTORS) {
        println("S2: Kernel too large");
        return -1;
    }

    /* Step 5: Copy first sector to destination */
    for (uint64_t i = 0; i < 128; i++) {
        ((uint64_t *)dest_buf)[i] = ((uint64_t *)temp_buf)[i];
    }

    /* Step 6: Load remaining sectors */
    uint64_t remaining = kernel_sectors - 1;
    uint64_t current_lba = kernel_lba + 1;
    uint8_t *dst = dest_buf + 512;

    while (remaining > 0) {
        uint64_t chunk = (remaining > 127) ? 127 : remaining;

        read = bios_read_disk_lba(temp_buf, current_lba, chunk);
        if ((int64_t)read < 0) {
            println("S2: Kernel data read failed");
            return -1;
        }

        /* Copy from temp to destination */
        for (uint64_t i = 0; i < chunk * 64; i++) {  /* sectors * 128 dwords */
            ((uint64_t *)dst)[i] = ((uint64_t *)temp_buf)[i];
        }

        dst += chunk * 512;
        current_lba += chunk;
        remaining -= chunk;
    }

    *addr = dest_buf;
    *size = kernel_sectors * 512;

    print("S2: Kernel loaded size=");
    serial_puthex(*size);
    println("");

    return 0;
}