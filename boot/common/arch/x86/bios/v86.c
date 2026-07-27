/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - V86 BIOS Service Wrappers
 *
 * Provides C functions for calling BIOS services via V86 mode.
 * These wrap the low-level v86int() interface.
 */

#include "v86.h"

/*
 * bios_disk_read - Extended disk read (INT 13h, AH=42h)
 */
int bios_disk_read(uint8_t drive, uint64_t lba, uint16_t count, void *buffer) {
  /* DAP must be in low memory (below 1MB) */
  volatile struct DiskAddressPacket *dap =
      (volatile struct DiskAddressPacket *)0x6E00;
  uintptr_t addr = (uintptr_t)buffer;

  dap->size = 16;
  dap->reserved = 0;
  dap->count = count;
  /*
   * Use canonical 16:4 real-mode addressing (segment = linear >> 4,
   * offset = linear & 0xF). This matches Stage 2 and avoids BIOS edge
   * cases with large offsets near 64K boundaries.
   */
  dap->offset = (uint16_t)(addr & 0xF);
  dap->segment = (uint16_t)((addr >> 4) & 0xFFFF);
  dap->lba = lba;

  v86.ctl = V86_FLAGS;
  v86.addr = 0x13;
  v86.eax = 0x4200;
  v86.edx = drive;
  v86.esi = 0x6E00;
  v86.ds = 0;

  v86int();

  if (V86_CY(v86.efl))
    return -1;

  return 0;
}

/*
 * bios_disk_get_params - Get disk parameters (INT 13h, AH=48h)
 */
int bios_disk_get_params(uint8_t drive, uint64_t *sectors,
                         uint16_t *sector_size) {
  /* Result buffer in low memory */
  struct {
    uint16_t size;
    uint16_t flags;
    uint32_t cylinders;
    uint32_t heads;
    uint32_t sectors_per_track;
    uint64_t total_sectors;
    uint16_t bytes_per_sector;
  } PACKED *result = (void *)0x6E00;

  result->size = 26; /* Minimum size for v1.x */

  v86.ctl = V86_FLAGS;
  v86.addr = 0x13;
  v86.eax = 0x4800;
  v86.edx = drive;
  v86.esi = 0x6E00;
  v86.ds = 0;

  v86int();

  if (V86_CY(v86.efl))
    return -1;

  if (sectors)
    *sectors = result->total_sectors;
  if (sector_size)
    *sector_size = result->bytes_per_sector;

  return 0;
}

/*
 * bios_e820_get_entry - Get E820 memory map entry (INT 15h, EAX=E820h)
 */
int bios_e820_get_entry(uint32_t *continuation, struct E820MemoryMap *entry) {
  /* E820 entry buffer in low memory */
  volatile struct E820MemoryMap *buf = (volatile struct E820MemoryMap *)0x6E00;

  v86.ctl = V86_FLAGS;
  v86.addr = 0x15;
  v86.eax = 0xE820;
  v86.ebx = *continuation;
  v86.ecx = 24;
  v86.edx = 0x534D4150; /* "SMAP" */
  v86.edi = 0x6E00;
  v86.es = 0;

  v86int();

  if (V86_CY(v86.efl))
    return -1;

  /* Verify signature */
  if ((v86.eax & 0xFFFFFFFF) != 0x534D4150)
    return -1;

  /* Copy result */
  entry->base = buf->base;
  entry->length = buf->length;
  entry->type = buf->type;
  entry->acpi_attr = buf->acpi_attr;

  /* Update continuation */
  *continuation = v86.ebx;

  /* Return 1 if this was the last entry */
  return (*continuation == 0) ? 1 : 0;
}

/*
 * bios_get_ext_memory - Get extended memory size (INT 15h, AX=E801h)
 */
int bios_get_ext_memory(uint32_t *below_16mb, uint32_t *above_16mb) {
  v86.ctl = V86_FLAGS;
  v86.addr = 0x15;
  v86.eax = 0xE801;
  v86.ebx = 0;
  v86.ecx = 0;
  v86.edx = 0;

  v86int();

  if (V86_CY(v86.efl))
    return -1;

  /* AX/CX = KB between 1MB and 16MB */
  /* BX/DX = 64KB blocks above 16MB */
  if (below_16mb)
    *below_16mb = v86.eax & 0xFFFF;
  if (above_16mb)
    *above_16mb = v86.ebx & 0xFFFF;

  return 0;
}

/*
 * bios_set_video_mode - Set video mode (INT 10h, AH=00h)
 */
int bios_set_video_mode(uint8_t mode) {
  v86.ctl = V86_FLAGS;
  v86.addr = 0x10;
  v86.eax = mode;

  v86int();

  return 0;
}

/*
 * bios_putchar - Write character (INT 10h, AH=0Eh)
 */
void bios_putchar(char ch) {
  v86.ctl = 0;
  v86.addr = 0x10;
  v86.eax = 0x0E00 | (uint8_t)ch;
  v86.ebx = 0x0007; /* Page 0, light gray on black */

  v86int();
}

/*
 * bios_puts - Print string via BIOS
 */
void bios_puts(const char *str) {
  while (*str)
    bios_putchar(*str++);
}
