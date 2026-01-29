/* SaltyOS Stage 3 - Kernel Loader
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Runs in 64-bit long mode
 * Parses kernel ELF, sets up boot info, jumps to kernel
 */

#include "../common/types.h"
#include "elf.h"
#include "../common/print.h"

/* Addresses (defaults if BootInfo not set) */
#define KERNEL_PHYS_ADDR    0x100000ULL           /* Default kernel physical base */
#define KERNEL_VIRT_ADDR    0xFFFFFFFF80000000ULL /* Default kernel virtual base */
#define LEGACY_KERNEL_ADDR  0x20000ULL            /* BIOS temp load location */

/* Serial helpers come from common/print */

/* Boot info - using struct from types.h */
static struct boot_info g_boot_info;

/* Get kernel base addresses from BootInfo or use defaults */
static inline uint64_t get_kernel_phys_base(const struct boot_info *bi) {
    if (bi) {
        return bi->kernel_phys_base;
    }
    return KERNEL_PHYS_ADDR;
}

static inline uint64_t get_kernel_virt_base(const struct boot_info *bi) {
    if (bi && bi->kernel_virt_base != 0) {
        return bi->kernel_virt_base;
    }
    return KERNEL_VIRT_ADDR;
}

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

/* Initialize BootInfo defaults for BIOS fallback */
static void bootinfo_set_defaults(struct boot_info *bi) {
    memset_local(bi, 0, sizeof(*bi));
    bi->magic = BOOT_INFO_MAGIC;
    bi->kernel_phys_base = KERNEL_PHYS_ADDR;
    bi->kernel_virt_base = KERNEL_VIRT_ADDR;
    bi->initrd_addr = LEGACY_KERNEL_ADDR;
    bi->initrd_size = 0;
}

/* Parse ELF and get entry point */
static uint64_t parse_elf(void *elf_data, const struct boot_info *bi) {
    uint64_t kernel_phys_base = get_kernel_phys_base(bi);
    uint64_t kernel_virt_base = get_kernel_virt_base(bi);
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
            if (phdr[i].p_vaddr >= kernel_virt_base) {
                paddr = phdr[i].p_vaddr - kernel_virt_base + kernel_phys_base;
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
void stage3_main(struct boot_info *bi) {
    serial_init();
    serial_puts("\nStage 3 loaded\n");

    /* Validate BootInfo - MUST be provided by bootloader */
    if (!bi || bi->magic != BOOT_INFO_MAGIC) {
        serial_puts("ERROR: Invalid or missing BootInfo!\n");
        goto halt;
    }

    /* Store BootInfo for kernel access */
    g_boot_info = *bi;

    /* Kernel ELF buffer passed via initrd fields */
    serial_puts("Parsing kernel ELF at ");
    serial_puthex(g_boot_info.initrd_addr);
    serial_puts(" size ");
    serial_puthex(g_boot_info.initrd_size);
    serial_puts("\n");
    serial_puts("Kernel phys base: ");
    serial_puthex(g_boot_info.kernel_phys_base);
    serial_puts("\n");

    uint64_t entry = parse_elf((void *)g_boot_info.initrd_addr, &g_boot_info);
    if (entry == 0) {
        serial_puts("Failed to parse kernel!\n");
        goto halt;
    }

    /* Boot info already set up above, ensure magic is set */
    g_boot_info.magic = BOOT_INFO_MAGIC;

    /* Convert virtual entry point to physical address */
    uint64_t phys_entry;
    if (entry >= g_boot_info.kernel_virt_base) {
        phys_entry = entry - g_boot_info.kernel_virt_base + g_boot_info.kernel_phys_base;
    } else {
        phys_entry = entry;
    }

    /* Debug: Verify addresses before jump */
    serial_puts("Jump info:\n");
    serial_puts("  boot_info: ");
    serial_puthex((uint64_t)&g_boot_info);
    serial_puts("\n  kernel_phys_base: ");
    serial_puthex(g_boot_info.kernel_phys_base);
    serial_puts("\n  kernel_virt_base: ");
    serial_puthex(g_boot_info.kernel_virt_base);
    serial_puts("\n  virt_entry: ");
    serial_puthex(entry);
    serial_puts("\n  phys_entry: ");
    serial_puthex(phys_entry);
    serial_puts("\nJumping to kernel...\n");

/* Jump to kernel entry point with VIRTUAL address */
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
