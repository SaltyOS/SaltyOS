/* ELF Dynamic Linking Helpers
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Utilities for detecting dynamically-linked ELF binaries and extracting
 * PT_INTERP / program header info needed for rtld bootstrap.
 */

#ifndef LIBSALTY_ELF_DYNAMIC_H
#define LIBSALTY_ELF_DYNAMIC_H

#include <stdint.h>
#include <stddef.h>
#include "elf_loader.h"  /* elf64_ehdr, elf64_phdr, ELF constants */

#define PT_INTERP  3
#define PT_PHDR    6

/* Check whether an ELF binary has a PT_INTERP segment (i.e. needs rtld).
 * Returns 1 if PT_INTERP is present, 0 otherwise.
 */
static inline int elf_has_interp(const uint8_t *elf_data, size_t elf_size) {
    if (elf_size < sizeof(struct elf64_ehdr))
        return 0;

    const struct elf64_ehdr *ehdr = (const struct elf64_ehdr *)elf_data;
    size_t phoff = (size_t)ehdr->e_phoff;
    size_t phnum = ehdr->e_phnum;
    size_t phentsz = ehdr->e_phentsize;

    for (size_t i = 0; i < phnum; i++) {
        size_t off = phoff + i * phentsz;
        if (off + sizeof(struct elf64_phdr) > elf_size)
            break;
        const struct elf64_phdr *phdr =
            (const struct elf64_phdr *)(elf_data + off);
        if (phdr->p_type == PT_INTERP)
            return 1;
    }
    return 0;
}

/* Extract the PT_INTERP path string from an ELF binary.
 * Returns pointer to the NUL-terminated path, or NULL if not present.
 * The returned pointer points into the elf_data buffer.
 */
static inline const char *elf_get_interp(const uint8_t *elf_data,
                                          size_t elf_size) {
    if (elf_size < sizeof(struct elf64_ehdr))
        return NULL;

    const struct elf64_ehdr *ehdr = (const struct elf64_ehdr *)elf_data;
    size_t phoff = (size_t)ehdr->e_phoff;
    size_t phnum = ehdr->e_phnum;
    size_t phentsz = ehdr->e_phentsize;

    for (size_t i = 0; i < phnum; i++) {
        size_t off = phoff + i * phentsz;
        if (off + sizeof(struct elf64_phdr) > elf_size)
            break;
        const struct elf64_phdr *phdr =
            (const struct elf64_phdr *)(elf_data + off);
        if (phdr->p_type == PT_INTERP) {
            size_t interp_off = (size_t)phdr->p_offset;
            size_t interp_len = (size_t)phdr->p_filesz;
            if (interp_off + interp_len > elf_size)
                return NULL;
            return (const char *)(elf_data + interp_off);
        }
    }
    return NULL;
}

/* Extract program header info needed for constructing auxv.
 *
 * For a PIE loaded at load_base, the phdr virtual address in the loaded
 * image is: load_base + ehdr->e_phoff  (since phdrs are in the first
 * PT_LOAD segment).
 *
 * Outputs:
 *   *phdr_vaddr = load_base + e_phoff (relocated phdr address)
 *   *phent      = e_phentsize
 *   *phnum      = e_phnum
 *
 * Returns 0 on success, -1 on failure.
 */
static inline int elf_get_phdr_info(const uint8_t *elf_data, size_t elf_size,
                                     uint64_t load_base,
                                     uint64_t *phdr_vaddr, uint64_t *phent,
                                     uint64_t *phnum) {
    if (elf_size < sizeof(struct elf64_ehdr))
        return -1;

    const struct elf64_ehdr *ehdr = (const struct elf64_ehdr *)elf_data;
    *phdr_vaddr = load_base + ehdr->e_phoff;
    *phent = ehdr->e_phentsize;
    *phnum = ehdr->e_phnum;
    return 0;
}

#endif /* LIBSALTY_ELF_DYNAMIC_H */
