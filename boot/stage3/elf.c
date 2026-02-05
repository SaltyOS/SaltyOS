/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - ELF64 Loader Implementation
 *
 * Loads ET_DYN (PIE) ELF64 executables with RELA relocation support.
 */

#include "elf.h"
#include "../common/string.h"
#include "../common/print.h"
#include "config.h"

/* Forward declaration - defined below elf_load */
static int elf_apply_rela(uint64_t rela_addr, uint64_t rela_size,
                          uint64_t rela_ent, uint64_t virt_base,
                          int64_t delta_phys);

int elf_validate(const struct Elf64_Ehdr *ehdr)
{
    /* Check magic number */
    if (*(uint32_t *)ehdr->e_ident != ELF_MAGIC)
        return ELF_ERR_NOT_ELF;

    /* Check class (must be 64-bit) */
    if (ehdr->e_ident[4] != ELFCLASS64)
        return ELF_ERR_NOT_64BIT;

    /* Check endianness (must be little-endian) */
    if (ehdr->e_ident[5] != ELFDATA2LSB)
        return ELF_ERR_NOT_LE;

    /* Check type (must be ET_DYN for PIE) */
    if (ehdr->e_type != ET_DYN)
        return ELF_ERR_NOT_DYN;

    /* Check machine type */
    if (ehdr->e_machine != EM_X86_64)
        return ELF_ERR_BAD_ARCH;

    return ELF_OK;
}

int elf_calc_size(const void *data, uint64_t *min_vaddr, uint64_t *max_vaddr)
{
    const struct Elf64_Ehdr *ehdr = (const struct Elf64_Ehdr *)data;
    const struct Elf64_Phdr *phdr;
    uint64_t min_va = UINT64_MAX;
    uint64_t max_va = 0;
    bool found_load = false;

    /* Iterate program headers */
    for (uint16_t i = 0; i < ehdr->e_phnum; i++) {
        phdr = (const struct Elf64_Phdr *)((const uint8_t *)data +
                                           ehdr->e_phoff +
                                           i * ehdr->e_phentsize);

        if (phdr->p_type != PT_LOAD)
            continue;

        found_load = true;

        if (phdr->p_vaddr < min_va)
            min_va = phdr->p_vaddr;

        uint64_t end = phdr->p_vaddr + phdr->p_memsz;
        if (end > max_va)
            max_va = end;
    }

    if (!found_load)
        return ELF_ERR_NO_LOAD;

    *min_vaddr = min_va;
    *max_vaddr = max_va;

    return ELF_OK;
}

int elf_load(const void *data, size_t data_size, uint64_t phys_addr,
             uint64_t virt_base, struct ElfLoadResult *result)
{
    const struct Elf64_Ehdr *ehdr = (const struct Elf64_Ehdr *)data;
    const struct Elf64_Phdr *phdr;
    int err;

    (void)data_size;

    /* Validate ELF header */
    err = elf_validate(ehdr);
    if (err != ELF_OK) {
        result->error = err;
        return err;
    }

    /* Calculate size */
    uint64_t min_vaddr, max_vaddr;
    err = elf_calc_size(data, &min_vaddr, &max_vaddr);
    if (err != ELF_OK) {
        result->error = err;
        return err;
    }

    /*
     * Two separate deltas:
     * - delta_phys: for memcpy destinations (where segments go in physical RAM)
     * - delta_virt: for relocations (what addresses the kernel sees at runtime)
     */
    int64_t delta_phys = (int64_t)phys_addr - (int64_t)min_vaddr;
    int64_t delta_virt = (int64_t)virt_base - (int64_t)min_vaddr;

#if CONFIG_DEBUG_ELF
    print_str("ELF: min_vaddr=");
    print_hex(min_vaddr, 16);
    print_str(" max_vaddr=");
    print_hex(max_vaddr, 16);
    print_char('\n');
    print_str("ELF: phys_addr=");
    print_hex(phys_addr, 16);
    print_str(" virt_base=");
    print_hex(virt_base, 16);
    print_char('\n');
#endif

    /*
     * Pre-extract all metadata from the source buffer BEFORE copying segments.
     *
     * UEFI's AllocateAnyPages may place the raw ELF file buffer and the
     * segment destination in overlapping physical memory. The segment copy
     * loop below can overwrite the source buffer (including the ELF header,
     * program headers, and dynamic section). We must cache everything we
     * need from the source before that happens.
     */
    uint64_t saved_entry = ehdr->e_entry;
    uint16_t saved_phnum = ehdr->e_phnum;
    uint64_t saved_phoff = ehdr->e_phoff;
    uint16_t saved_phentsize = ehdr->e_phentsize;

    /* Pre-extract RELA relocation info from PT_DYNAMIC */
    uint64_t rela_addr = 0, rela_size = 0, rela_ent = 0;
    for (uint16_t i = 0; i < saved_phnum; i++) {
        phdr = (const struct Elf64_Phdr *)((const uint8_t *)data +
                                           saved_phoff +
                                           i * saved_phentsize);
        if (phdr->p_type == PT_DYNAMIC) {
            const struct Elf64_Dyn *dyn =
                (const struct Elf64_Dyn *)((const uint8_t *)data + phdr->p_offset);
            while (dyn->d_tag != DT_NULL) {
                switch (dyn->d_tag) {
                case DT_RELA:    rela_addr = dyn->d_val; break;
                case DT_RELASZ:  rela_size = dyn->d_val; break;
                case DT_RELAENT: rela_ent  = dyn->d_val; break;
                }
                dyn++;
            }
            break;
        }
    }

    /* Load PT_LOAD segments to physical memory */
    for (uint16_t i = 0; i < saved_phnum; i++) {
        phdr = (const struct Elf64_Phdr *)((const uint8_t *)data +
                                           saved_phoff +
                                           i * saved_phentsize);

        if (phdr->p_type != PT_LOAD)
            continue;

        /* Segments are copied to physical addresses */
        uint64_t dest = phdr->p_vaddr + delta_phys;
        const uint8_t *src = (const uint8_t *)data + phdr->p_offset;

#if CONFIG_DEBUG_ELF
        print_str("ELF: Loading segment to phys ");
        print_hex(dest, 16);
        print_str(" size=");
        print_hex(phdr->p_filesz, 8);
        print_str("/");
        print_hex(phdr->p_memsz, 8);
        print_char('\n');
#endif

        /* Copy file content */
        if (phdr->p_filesz > 0) {
            memcpy((void *)(uintptr_t)dest, src, phdr->p_filesz);
        }

        /* Zero BSS (p_memsz > p_filesz) */
        if (phdr->p_memsz > phdr->p_filesz) {
            memset((void *)(uintptr_t)(dest + phdr->p_filesz), 0,
                   phdr->p_memsz - phdr->p_filesz);
        }
    }

    /*
     * After this point, the source buffer (data) may be corrupted.
     * Use only pre-extracted values and the loaded image (at delta_phys).
     */

    /* Apply relocations using pre-extracted RELA info */
    err = elf_apply_rela(rela_addr, rela_size, rela_ent,
                         virt_base, delta_phys);
    if (err != ELF_OK) {
        result->error = err;
        return err;
    }

    /* Fill result using pre-extracted entry point */
    result->phys_base = phys_addr;
    result->virt_base = virt_base;
    result->mem_size = max_vaddr - min_vaddr;
    result->entry = saved_entry + delta_virt;
    result->error = ELF_OK;

#if CONFIG_DEBUG_ELF
    print_str("ELF: entry=");
    print_hex(result->entry, 16);
    print_char('\n');
#endif

    return ELF_OK;
}

/*
 * Apply RELA relocations using pre-extracted info.
 *
 * Called after segments have been copied to physical memory. The RELA table
 * is accessed from the loaded image (at rela_addr + delta_phys). This avoids
 * reading from the original source buffer which may have been overwritten
 * by overlapping segment copies.
 *
 * @param rela_addr:  Virtual address of RELA table (from DT_RELA)
 * @param rela_size:  Total size of RELA table in bytes (from DT_RELASZ)
 * @param rela_ent:   Size of each RELA entry (from DT_RELAENT)
 * @param virt_base:  Virtual base for relocation values
 * @param delta_phys: Physical delta for accessing loaded image
 */
static int elf_apply_rela(uint64_t rela_addr, uint64_t rela_size,
                          uint64_t rela_ent, uint64_t virt_base,
                          int64_t delta_phys)
{
    if (rela_addr == 0 || rela_size == 0)
        return ELF_OK;  /* No relocations */

    if (rela_ent == 0)
        rela_ent = sizeof(struct Elf64_Rela);

#if CONFIG_DEBUG_ELF
    print_str("ELF: Applying ");
    print_dec(rela_size / rela_ent);
    print_line(" relocations");
#endif

    /*
     * rela_addr is a virtual address from the ELF file.
     * The relocation table has been loaded at physical address rela_addr + delta_phys.
     * Relocation targets are written at their physical locations (delta_phys)
     * with values using the virtual base.
     */
    const struct Elf64_Rela *rela = (const struct Elf64_Rela *)((uintptr_t)(rela_addr + delta_phys));
    uint64_t count = rela_size / rela_ent;

    for (uint64_t i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        /* Target is in physical memory */
        uint64_t *target = (uint64_t *)(uintptr_t)(rela[i].r_offset + delta_phys);

        switch (type) {
        case R_X86_64_RELATIVE:
            /* *target = virt_base + addend (kernel sees virtual addresses) */
            *target = virt_base + rela[i].r_addend;
            break;

        case R_X86_64_64:
            /* For PIE without external symbols, this shouldn't happen */
            break;

        case R_X86_64_NONE:
            break;

        default:
#if CONFIG_DEBUG_ELF
            print_str("ELF: Unknown reloc type ");
            print_dec(type);
            print_char('\n');
#endif
            return ELF_ERR_RELOC;
        }
    }

    return ELF_OK;
}
