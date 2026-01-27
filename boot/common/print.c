/* SaltyOS Boot Print Utilities
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "types.h"

/* Serial port base address (COM1) */
#define SERIAL_PORT 0x3F8

/* Port I/O */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile ("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile ("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

/* Initialize serial port */
void serial_init(void) {
    outb(SERIAL_PORT + 1, 0x00);  /* Disable interrupts */
    outb(SERIAL_PORT + 3, 0x80);  /* Enable DLAB */
    outb(SERIAL_PORT + 0, 0x03);  /* Baud rate divisor low (38400) */
    outb(SERIAL_PORT + 1, 0x00);  /* Baud rate divisor high */
    outb(SERIAL_PORT + 3, 0x03);  /* 8 bits, no parity, 1 stop bit */
    outb(SERIAL_PORT + 2, 0xC7);  /* Enable FIFO */
    outb(SERIAL_PORT + 4, 0x0B);  /* IRQs enabled, RTS/DSR set */
}

/* Wait for transmit buffer to be empty */
static int serial_is_transmit_empty(void) {
    return inb(SERIAL_PORT + 5) & 0x20;
}

/* Write character to serial port */
void serial_putc(char c) {
    while (!serial_is_transmit_empty());
    outb(SERIAL_PORT, c);
}

/* Write string to serial port */
void serial_puts(const char *s) {
    while (*s) {
        if (*s == '\n') {
            serial_putc('\r');
        }
        serial_putc(*s++);
    }
}

/* Print hex number */
void serial_puthex(uint64_t value) {
    static const char hex[] = "0123456789ABCDEF";
    serial_puts("0x");
    for (int i = 60; i >= 0; i -= 4) {
        serial_putc(hex[(value >> i) & 0xF]);
    }
}

/* Simplified print function */
void print(const char *s) {
    serial_puts(s);
}

void println(const char *s) {
    serial_puts(s);
    serial_puts("\n");
}

/* String functions were moved to common/memory.c to avoid duplicates */
