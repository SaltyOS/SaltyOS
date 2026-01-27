/* SaltyOS Stage 2 - Loader
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Loads Stage 3 from disk and transfers control
 */

#include "../common/types.h"
#include "../common/print.h"

/* Stage 3 load address */
#define STAGE3_ADDR 0x100000  /* 1MB */

/* Simple disk read (placeholder - needs actual driver) */
static int disk_read(uint64_t lba, uint32_t count, void *buffer) {
    /* TODO: Implement actual disk read
     * For now, this is a stub that would be replaced with:
     * - ATA PIO driver
     * - Or AHCI driver
     */
    (void)lba;
    (void)count;
    (void)buffer;
    return 0;
}

/* Entry point from assembly */
void stage2_main(void) {
    serial_init();
    println("Stage 2: Long mode active");

    /* TODO: Load Stage 3 from disk */
    println("Loading Stage 3...");

    /* For now, just demonstrate we're running */
    print("Stage 3 address: ");
    serial_puthex(STAGE3_ADDR);
    println("");

    /* TODO: Jump to Stage 3 */
    /* void (*stage3_entry)(void) = (void (*)(void))STAGE3_ADDR; */
    /* stage3_entry(); */

    println("Stage 2 complete (Stage 3 not implemented yet)");

    /* Halt */
    for (;;) {
        __asm__ volatile("hlt");
    }
}
