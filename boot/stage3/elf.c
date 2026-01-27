/* SaltyOS ELF Parser
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "../common/types.h"
#include "elf.h"

/* Validate ELF header */
int elf_validate(const Elf64_Ehdr *ehdr) {
    /* Check magic */
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        return -1;
    }

    /* Check class (64-bit) */
    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        return -2;
    }

    /* Check type (executable) */
    if (ehdr->e_type != ET_EXEC) {
        return -3;
    }

    /* Check machine (x86_64) */
    if (ehdr->e_machine != EM_X86_64) {
        return -4;
    }

    return 0;
}

/* Load ELF program segments */
int elf_load(const void *elf_data, uint64_t *entry_point) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_data;

    if (elf_validate(ehdr) != 0) {
        return -1;
    }

    /* Get program headers */
    const Elf64_Phdr *phdr = (const Elf64_Phdr *)((uint8_t *)elf_data + ehdr->e_phoff);

    /* Load each loadable segment */
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            /* Source in ELF file */
            const uint8_t *src = (const uint8_t *)elf_data + phdr[i].p_offset;

            /* Destination in memory (physical address for now) */
            /* TODO: Handle virtual-to-physical mapping */
            uint8_t *dst = (uint8_t *)phdr[i].p_paddr;

            /* Copy segment data */
            for (uint64_t j = 0; j < phdr[i].p_filesz; j++) {
                dst[j] = src[j];
            }

            /* Zero BSS (memsz > filesz) */
            for (uint64_t j = phdr[i].p_filesz; j < phdr[i].p_memsz; j++) {
                dst[j] = 0;
            }
        }
    }

    *entry_point = ehdr->e_entry;
    return 0;
}
