/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - BTX Interface
 *
 * BTX (Boot Extender) provides BIOS services to protected mode code.
 * This is a compatibility layer over the V86 interface.
 *
 * For new code, prefer using v86.h directly with its BSD-style interface.
 */

#ifndef BOOT_COMMON_ARCH_X86_BIOS_BTX_H
#define BOOT_COMMON_ARCH_X86_BIOS_BTX_H

#include "v86.h"

/*
 * Initialize BTX/V86 subsystem
 *
 * Must be called from protected mode before any BIOS calls.
 */
#define btx_init(base, size) v86_init((base), (size))

/*
 * Convenience function: INT 13h extended read
 *
 * This wraps bios_disk_read from v86.c
 */
#define btx_disk_read(drive, lba, sectors, buffer) \
    bios_disk_read((drive), (lba), (sectors), (buffer))

/*
 * Convenience function: INT 15h E820 memory map
 */
#define btx_get_memory_map_entry(continuation, buffer) \
    bios_e820_get_entry((continuation), (buffer))

#endif /* BOOT_COMMON_ARCH_X86_BIOS_BTX_H */
