/* SaltyOS Stage 3 Disk I/O Stub
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * TODO: Implement actual disk I/O via BIOS or EFI callbacks
 */

#include <types.h>

/* Read disk blocks - STUB IMPLEMENTATION
 * lba: Logical Block Address to read from
 * count: Number of blocks to read
 * buffer: Output buffer
 * Returns: 0 on success, negative on error
 */
int disk_read_blocks(uint64_t lba, uint32_t count, void *buffer) {
    /* TODO: Implement actual disk read via BIOS int 13h or EFI disk I/O */
    (void)lba;
    (void)count;
    (void)buffer;
    return -1;  /* Return error for now */
}
