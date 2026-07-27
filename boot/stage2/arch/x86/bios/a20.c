/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - A20 Line Enable (C implementation)
 *
 * Note: The primary A20 enable code is in entry.asm.
 * This C implementation is for reference and potential long mode use.
 */

#include "a20.h"

/* x86 I/O port operations */
static inline void outb(uint16_t port, uint8_t value) {
  __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
  uint8_t value;
  __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
  return value;
}

/* Wait for keyboard controller input buffer to be empty */
static void kbd_wait_input(void) {
  while (inb(0x64) & 0x02)
    ;
}

/* Wait for keyboard controller output buffer to have data */
static void kbd_wait_output(void) {
  while (!(inb(0x64) & 0x01))
    ;
}

bool a20_check(void) {
  /*
   * Check A20 by comparing addresses that differ only in bit 20.
   * If A20 is disabled, 0x100000 wraps to 0x000000.
   *
   * We use the BIOS data area (0x0000:0x0500) and its "wrap"
   * address (0xFFFF:0x0510 = 0x100500 with A20, 0x0500 without).
   */
  volatile uint8_t *low = (volatile uint8_t *)0x0500;
  volatile uint8_t *high = (volatile uint8_t *)0x100500;

  uint8_t old_low = *low;
  uint8_t old_high = *high;

  *low = 0x00;
  *high = 0xFF;

  bool enabled = (*low != 0xFF);

  *low = old_low;
  *high = old_high;

  return enabled;
}

bool a20_enable(void) {
  /* Check if already enabled */
  if (a20_check())
    return true;

  /* Method 1: Fast A20 (Port 0x92) */
  uint8_t val = inb(0x92);
  if (!(val & 0x02)) {
    val |= 0x02;
    val &= ~0x01; /* Don't reset CPU! */
    outb(0x92, val);
  }

  if (a20_check())
    return true;

  /* Method 2: Keyboard controller */
  kbd_wait_input();
  outb(0x64, 0xAD); /* Disable keyboard */

  kbd_wait_input();
  outb(0x64, 0xD0); /* Read output port */

  kbd_wait_output();
  val = inb(0x60);

  kbd_wait_input();
  outb(0x64, 0xD1); /* Write output port */

  kbd_wait_input();
  outb(0x60, val | 0x02); /* Set A20 bit */

  kbd_wait_input();
  outb(0x64, 0xAE); /* Enable keyboard */

  kbd_wait_input();

  if (a20_check())
    return true;

  return false;
}
