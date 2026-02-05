/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - V86 Mode Interface
 *
 * Provides Virtual 8086 mode support for calling BIOS services
 * from 32-bit protected mode C code. Inspired by FreeBSD BTX.
 *
 * Usage:
 *   v86.ctl = V86_FLAGS;
 *   v86.addr = 0x13;           // INT 13h
 *   v86.eax = 0x4200;          // Extended read
 *   v86.edx = drive;
 *   v86.ds = segment;
 *   v86.esi = offset;
 *   v86int();
 *   if (V86_CY(v86.efl)) { error... }
 */

#ifndef BOOT_COMMON_ARCH_X86_BIOS_V86_H
#define BOOT_COMMON_ARCH_X86_BIOS_V86_H

#include "../../../types.h"

/* V86 control flags */
#define V86_ADDR    0x0001      /* Segment:offset address valid */
#define V86_FLAGS   0x0002      /* Return flags */

/* V86 flag helpers */
#define V86_CY(flags)   ((flags) & 0x0001)  /* Carry flag */
#define V86_ZR(flags)   ((flags) & 0x0040)  /* Zero flag */

/*
 * V86 register structure
 *
 * This structure is used to pass register values to/from BIOS calls.
 * It mirrors the CPU register layout for easy access.
 */
struct V86Regs {
    /* Control */
    uint32_t ctl;       /* Control flags (V86_*) */
    uint32_t addr;      /* Interrupt number or address */

    /* General purpose registers */
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;       /* Not used for V86 calls */
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;

    /* Segment registers */
    uint32_t ds;
    uint32_t es;
    uint32_t fs;
    uint32_t gs;

    /* Flags (output) */
    uint32_t efl;
} PACKED;

/* Global V86 register structure */
extern struct V86Regs v86;

/*
 * Execute BIOS interrupt via V86 mode
 *
 * Reads parameters from global 'v86' structure,
 * executes the interrupt in V86 mode,
 * and stores results back in 'v86' structure.
 */
void v86int(void);

/*
 * Initialize V86/BTX subsystem
 *
 * Sets up TSS, IDT, and other structures needed for V86 mode.
 * Must be called once before any v86int() calls.
 */
void v86_init(void);

/* ========================================================================= */
/* Convenience macros for common BIOS calls                                  */
/* ========================================================================= */

/*
 * Convert linear address to segment:offset
 */
#define VTOPSEG(addr)   (((uint32_t)(addr) >> 4) & 0xF000)
#define VTOPOFF(addr)   ((uint32_t)(addr) & 0xFFFF)

/*
 * Convert segment:offset to linear address
 */
#define SEGOFF_TO_LINEAR(seg, off)  (((uint32_t)(seg) << 4) + (uint32_t)(off))

/* ========================================================================= */
/* High-level BIOS service wrappers                                          */
/* ========================================================================= */

/*
 * INT 13h - Disk Services
 */

/* Disk Address Packet for extended read/write */
struct DiskAddressPacket {
    uint8_t  size;          /* Size of packet (16 or 24) */
    uint8_t  reserved;      /* Reserved (0) */
    uint16_t count;         /* Number of sectors */
    uint16_t offset;        /* Buffer offset */
    uint16_t segment;       /* Buffer segment */
    uint64_t lba;           /* Starting LBA */
} PACKED;

/*
 * Extended disk read (INT 13h, AH=42h)
 *
 * @param drive: BIOS drive number (0x80 = first HDD)
 * @param lba: Starting logical block address
 * @param count: Number of sectors to read
 * @param buffer: Destination buffer (must be < 1MB)
 *
 * Returns: 0 on success, -1 on error
 */
int bios_disk_read(uint8_t drive, uint64_t lba, uint16_t count, void *buffer);

/*
 * Get disk parameters (INT 13h, AH=48h)
 *
 * @param drive: BIOS drive number
 * @param sectors: Output - total sectors
 * @param sector_size: Output - bytes per sector
 *
 * Returns: 0 on success, -1 on error
 */
int bios_disk_get_params(uint8_t drive, uint64_t *sectors, uint16_t *sector_size);

/*
 * INT 15h - System Services
 */

/* E820 memory map entry */
struct E820MemoryMap {
    uint64_t base;
    uint64_t length;
    uint32_t type;
    uint32_t acpi_attr;
} PACKED;

/* E820 memory types */
#define E820_USABLE         1
#define E820_RESERVED       2
#define E820_ACPI_RECLAIM   3
#define E820_ACPI_NVS       4
#define E820_BAD            5

/*
 * Get memory map entry (INT 15h, EAX=E820h)
 *
 * @param continuation: In/out continuation value (start with 0)
 * @param entry: Output memory map entry
 *
 * Returns: 0 on success and more entries available
 *          1 on success and this is last entry
 *         -1 on error
 */
int bios_e820_get_entry(uint32_t *continuation, struct E820MemoryMap *entry);

/*
 * Get extended memory size (INT 15h, AX=E801h)
 *
 * @param below_16mb: Output - KB between 1MB and 16MB
 * @param above_16mb: Output - 64KB blocks above 16MB
 *
 * Returns: 0 on success, -1 on error
 */
int bios_get_ext_memory(uint32_t *below_16mb, uint32_t *above_16mb);

/*
 * INT 10h - Video Services
 */

/*
 * Set video mode (INT 10h, AH=00h)
 *
 * @param mode: Video mode number
 *
 * Returns: 0 on success
 */
int bios_set_video_mode(uint8_t mode);

/*
 * Write character (INT 10h, AH=0Eh)
 *
 * @param ch: Character to write
 */
void bios_putchar(char ch);

/*
 * Print string via BIOS
 *
 * @param str: Null-terminated string
 */
void bios_puts(const char *str);

#endif /* BOOT_COMMON_ARCH_X86_BIOS_V86_H */
