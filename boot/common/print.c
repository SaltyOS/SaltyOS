/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - Print Functions Implementation
 */

#include "print.h"
#include "fb_console.h"
#include "string.h"

static uint32_t print_targets = 0;

/* x86 I/O port operations */
static inline void outb(uint16_t port, uint8_t value)
{
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port)
{
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

/* Serial port implementation */
void serial_init(void)
{
    /* Disable interrupts */
    outb(COM1_PORT + 1, 0x00);

    /* Set baud rate divisor (115200 baud) */
    outb(COM1_PORT + 3, 0x80);    /* Enable DLAB */
    outb(COM1_PORT + 0, 0x01);    /* Divisor low byte */
    outb(COM1_PORT + 1, 0x00);    /* Divisor high byte */

    /* 8 bits, no parity, one stop bit */
    outb(COM1_PORT + 3, 0x03);

    /* Enable FIFO, clear them, 14-byte threshold */
    outb(COM1_PORT + 2, 0xC7);

    /* Enable IRQs, RTS/DSR set */
    outb(COM1_PORT + 4, 0x0B);

    /* Set in loopback mode, test the serial chip */
    outb(COM1_PORT + 4, 0x1E);

    /* Test serial chip (send byte 0xAE and check if it returns same byte) */
    outb(COM1_PORT + 0, 0xAE);
    if (inb(COM1_PORT + 0) != 0xAE) {
        return; /* Serial port not working */
    }

    /* Set normal operation mode */
    outb(COM1_PORT + 4, 0x0F);
}

static int serial_is_transmit_empty(void)
{
    return inb(COM1_PORT + 5) & 0x20;
}

void serial_putc(char c)
{
    while (!serial_is_transmit_empty())
        ;
    outb(COM1_PORT, c);
}

/* VGA text mode implementation */
static uint16_t *vga_buffer = (uint16_t *)VGA_TEXT_BASE;
static int vga_row = 0;
static int vga_col = 0;
static uint8_t vga_color = 0x07; /* Light gray on black */

void vga_init(void)
{
    vga_buffer = (uint16_t *)VGA_TEXT_BASE;
    vga_row = 0;
    vga_col = 0;
    vga_color = 0x07;
}

static void vga_scroll(void)
{
    /* Move all lines up by one */
    for (int i = 0; i < (VGA_HEIGHT - 1) * VGA_WIDTH; i++) {
        vga_buffer[i] = vga_buffer[i + VGA_WIDTH];
    }

    /* Clear the last line */
    for (int i = 0; i < VGA_WIDTH; i++) {
        vga_buffer[(VGA_HEIGHT - 1) * VGA_WIDTH + i] = (vga_color << 8) | ' ';
    }

    vga_row = VGA_HEIGHT - 1;
}

void vga_putc(char c)
{
    if (c == '\n') {
        vga_col = 0;
        vga_row++;
    } else if (c == '\r') {
        vga_col = 0;
    } else if (c == '\t') {
        vga_col = (vga_col + 8) & ~7;
    } else {
        vga_buffer[vga_row * VGA_WIDTH + vga_col] = (vga_color << 8) | c;
        vga_col++;
    }

    if (vga_col >= VGA_WIDTH) {
        vga_col = 0;
        vga_row++;
    }

    if (vga_row >= VGA_HEIGHT) {
        vga_scroll();
    }
}

void vga_clear(void)
{
    for (int i = 0; i < VGA_WIDTH * VGA_HEIGHT; i++) {
        vga_buffer[i] = (vga_color << 8) | ' ';
    }
    vga_row = 0;
    vga_col = 0;
}

/* Print subsystem */
void print_init(uint32_t targets)
{
    print_targets = targets;

    if (targets & PRINT_TARGET_SERIAL) {
        serial_init();
    }

    if (targets & PRINT_TARGET_VGA) {
        vga_init();
        vga_clear();
    }
}

void print_add_target(uint32_t target)
{
    print_targets |= target;
}

void print_char(char c)
{
    if (print_targets & PRINT_TARGET_SERIAL) {
        if (c == '\n')
            serial_putc('\r');
        serial_putc(c);
    }

    if (print_targets & PRINT_TARGET_VGA) {
        vga_putc(c);
    }

    if (print_targets & PRINT_TARGET_FB) {
        fb_console_putc(c);
    }
}

void print_str(const char *s)
{
    while (*s) {
        print_char(*s++);
    }
}

void print_hex(uint64_t value, int width)
{
    static const char hex_chars[] = "0123456789ABCDEF";
    char buf[17];
    int i;

    /* Build hex string from right to left */
    buf[16] = '\0';
    for (i = 15; i >= 0; i--) {
        buf[i] = hex_chars[value & 0xF];
        value >>= 4;
    }

    /* Find start position based on width */
    int start = 16 - width;
    if (start < 0)
        start = 0;

    /* Skip leading zeros (but keep at least one digit) */
    while (start < 15 && buf[start] == '0')
        start++;

    /* Print "0x" prefix */
    print_str("0x");
    print_str(&buf[start]);
}

void print_hex64(uint64_t value)
{
    static const char hex_chars[] = "0123456789ABCDEF";
    char buf[17];
    buf[16] = '\0';
    for (int i = 15; i >= 0; i--) {
        buf[i] = hex_chars[value & 0xF];
        value >>= 4;
    }
    print_str("0x");
    print_str(buf);
}

void print_dec(uint64_t value)
{
    char buf[21];
    int i = 20;

    buf[i] = '\0';

    if (value == 0) {
        print_char('0');
        return;
    }

    while (value > 0) {
        buf[--i] = '0' + (value % 10);
        value /= 10;
    }

    print_str(&buf[i]);
}

void print_line(const char *s)
{
    print_str(s);
    print_char('\n');
}
