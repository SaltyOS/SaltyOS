/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - A20 Line Enable
 *
 * The A20 line must be enabled to access memory above 1MB.
 * This is handled in entry.asm for the BIOS boot path.
 */

#ifndef BOOT_STAGE2_BIOS_A20_H
#define BOOT_STAGE2_BIOS_A20_H

#include "../../../../common/types.h"

/*
 * A20 enable methods:
 * 1. BIOS INT 15h, AX=2401h
 * 2. Keyboard controller (8042)
 * 3. Fast A20 (Port 0x92)
 */

/* Check if A20 is enabled */
bool a20_check(void);

/* Enable A20 line (tries all methods) */
bool a20_enable(void);

#endif /* BOOT_STAGE2_BIOS_A20_H */
