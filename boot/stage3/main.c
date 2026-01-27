/* SaltyOS Stage 3 - Kernel Loader
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Runs in 64-bit long mode
 * Parses kernel ELF, sets up boot info, jumps to kernel
 */

#include "../common/types.h"
#include "elf.h"

/* Addresses */
#define KERNEL_TEMP_ADDR    0x20000ULL          /* Kernel ELF loaded here by Stage 2 (temp) */
#define KERNEL_PHYS_ADDR    0x100000ULL         /* Kernel loaded here (1MB) after parsing */
#define KERNEL_VIRT_ADDR    0xFFFFFFFF80000000ULL

/* Serial port for debug output */
#define SERIAL_PORT 0x3F8

/* I/O functions */
static inline void outb(uint16_t port, uint8_t value) {
    __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    __asm__ volatile("inb %1, %0" : "=a"(value) : "Nd"(port));
    return value;
}

static void serial_init(void) {
    /* Disable interrupts */
    outb(SERIAL_PORT + 1, 0x00);
    /* Set baud rate divisor (115200) */
    outb(SERIAL_PORT + 3, 0x80);    /* Enable DLAB */
    outb(SERIAL_PORT + 0, 0x01);    /* Divisor low */
    outb(SERIAL_PORT + 1, 0x00);    /* Divisor high */
    /* 8 bits, no parity, one stop bit */
    outb(SERIAL_PORT + 3, 0x03);
    /* Enable FIFO */
    outb(SERIAL_PORT + 2, 0xC7);
    /* Enable IRQs, RTS/DSR set */
    outb(SERIAL_PORT + 4, 0x0B);
}

static void serial_putc(char c) {
    /* Wait for transmit buffer empty */
    while ((inb(SERIAL_PORT + 5) & 0x20) == 0);
    outb(SERIAL_PORT, c);
}

static void serial_puts(const char *s) {
    while (*s) {
        if (*s == '\n') serial_putc('\r');
        serial_putc(*s++);
    }
}

static void serial_puthex(uint64_t value) {
    const char *hex = "0123456789ABCDEF";
    serial_puts("0x");
    for (int i = 60; i >= 0; i -= 4) {
        serial_putc(hex[(value >> i) & 0xF]);
    }
}

/* Boot info - using struct from types.h */
static struct boot_info g_boot_info;

/* Simple memset */
static void *memset_local(void *s, int c, uint64_t n) {
    uint8_t *p = s;
    while (n--) *p++ = (uint8_t)c;
    return s;
}

/* Simple memcpy */
static void *memcpy_local(void *dest, const void *src, uint64_t n) {
    uint8_t *d = dest;
    const uint8_t *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

/* Parse ELF and get entry point */
static uint64_t parse_elf(void *elf_data) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_data;
    
    /* Verify ELF magic */
    if (ehdr->e_ident[0] != 0x7F || 
        ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L' ||
        ehdr->e_ident[3] != 'F') {
        serial_puts("Not an ELF file!\n");
        return 0;
    }
    
    serial_puts("ELF valid, entry: ");
    serial_puthex(ehdr->e_entry);
    serial_puts("\n");
    
    /* Load program headers */
    Elf64_Phdr *phdr = (Elf64_Phdr *)((uint8_t *)elf_data + ehdr->e_phoff);
    
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            serial_puts("  LOAD: vaddr=");
            serial_puthex(phdr[i].p_vaddr);
            serial_puts(" filesz=");
            serial_puthex(phdr[i].p_filesz);
            serial_puts("\n");
            
            /* Calculate physical address from virtual */
            uint64_t paddr;
            if (phdr[i].p_vaddr >= KERNEL_VIRT_ADDR) {
                paddr = phdr[i].p_vaddr - KERNEL_VIRT_ADDR + KERNEL_PHYS_ADDR;
            } else {
                paddr = phdr[i].p_vaddr;
            }
            
            /* Skip empty segments */
            if (phdr[i].p_memsz == 0) {
                continue;
            }
            
            /* Clear the segment (for .bss) */
            memset_local((void *)paddr, 0, phdr[i].p_memsz);
            
            /* Copy segment data */
            if (phdr[i].p_filesz > 0) {
                memcpy_local((void *)paddr,
                       (uint8_t *)elf_data + phdr[i].p_offset,
                       phdr[i].p_filesz);
            }
        }
    }
    
    return ehdr->e_entry;
}

/* Entry point - called from Stage 2 assembly */
void stage3_main(void) {
    serial_init();
    serial_puts("\nStage 3 loaded\n");
    
    /* Kernel ELF was loaded to KERNEL_TEMP_ADDR by Stage 2 */
    serial_puts("Parsing kernel ELF at ");
    serial_puthex(KERNEL_TEMP_ADDR);
    serial_puts("\n");
    
    uint64_t entry = parse_elf((void *)KERNEL_TEMP_ADDR);
    if (entry == 0) {
        serial_puts("Failed to parse kernel!\n");
        goto halt;
    }
    
    /* Set up boot info */
    memset_local(&g_boot_info, 0, sizeof(g_boot_info));
    g_boot_info.magic = BOOT_INFO_MAGIC;
    g_boot_info.memory_map = NULL;
    g_boot_info.memory_map_len = 0;
    
    serial_puts("Jumping to kernel at ");
    serial_puthex(entry);
    serial_puts("\n");
    
    /* Jump to kernel entry point */
    /* Kernel expects boot_info pointer in RDI */
    /* Flush TLB by reloading CR3, then use jmp */
    __asm__ volatile(
        "mov %%cr3, %%rax\n\t"
        "mov %%rax, %%cr3\n\t"  /* Flush TLB */
        "mov %0, %%rdi\n\t"
        "jmp *%1\n\t"
        :
        : "r"(&g_boot_info), "r"(entry)
        : "rax", "rdi"
    );
    
halt:
    serial_puts("HALT\n");
    for (;;) {
        __asm__ volatile("cli; hlt");
    }
}
