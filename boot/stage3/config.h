/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Stage 3 Configuration
 *
 * Build-time configuration options for Stage 3.
 */

#ifndef BOOT_STAGE3_CONFIG_H
#define BOOT_STAGE3_CONFIG_H

/* Enable debug output */
#define CONFIG_DEBUG            1

/* Enable verbose memory map printing */
#define CONFIG_DEBUG_MEMMAP     1

/* Enable ELF loading debug output */
#define CONFIG_DEBUG_ELF        1

/* Enable filesystem support (optional) */
#define CONFIG_FS_SUPPORT       0   /* Disabled - using raw extents only */

/* Enable FAT32 filesystem */
#define CONFIG_FS_FAT32         0

/* Enable SaltyFS filesystem */
#define CONFIG_FS_SALTYFS       0

/* Maximum number of memory regions to track */
#define CONFIG_MAX_MEM_REGIONS  128

/* Maximum kernel command line length */
#define CONFIG_MAX_CMDLINE      256

/* Enable framebuffer setup */
#define CONFIG_FRAMEBUFFER      0   /* Disabled for now */

/* Serial port for debug output */
#define CONFIG_SERIAL_PORT      0x3F8   /* COM1 */
#define CONFIG_SERIAL_BAUD      115200

#endif /* BOOT_STAGE3_CONFIG_H */
