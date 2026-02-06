/* Userspace ELF64 Loader
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Loads PIE (ET_DYN) and static (ET_EXEC) ELF64 binaries into a child
 * process's VSpace. Uses capability invocations for memory management:
 *   - Retype Frames from Untyped
 *   - Map temporarily into loader's VSpace at SCRATCH_VADDR
 *   - Copy ELF segment data
 *   - Unmap from loader
 *   - Map into child VSpace
 *
 * Port of kernel/src/elf.rs to userspace C.
 */

#ifndef LIBSALTY_ELF_LOADER_H
#define LIBSALTY_ELF_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include "salty.h"

/* ELF64 header */
struct elf64_ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

/* ELF64 program header */
struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* ELF64 dynamic entry */
struct elf64_dyn {
    int64_t  d_tag;
    uint64_t d_val;
};

/* ELF64 RELA relocation entry */
struct elf64_rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

/* ELF constants */
#define ELFCLASS64       2
#define ELFDATA2LSB      1
#define ET_EXEC          2
#define ET_DYN           3
#define EM_X86_64        62
#define PT_LOAD          1
#define PT_DYNAMIC       2
#define PF_X             1
#define PF_W             2
#define PF_R             4
#define DT_NULL          0
#define DT_RELA          7
#define DT_RELASZ        8
#define DT_RELAENT       9
#define R_X86_64_RELATIVE 8

#define ELF_PAGE_SIZE    4096
#define ELF_MAX_PAGES    64

/* ELF load errors */
#define ELF_OK             0
#define ELF_NOT_ELF        1
#define ELF_NOT_64BIT      2
#define ELF_NOT_LE         3
#define ELF_BAD_TYPE       4
#define ELF_BAD_ARCH       5
#define ELF_NO_LOAD        6
#define ELF_RELOC_FAILED   7
#define ELF_OUT_OF_MEMORY  8
#define ELF_TOO_SMALL      9
#define ELF_TOO_MANY_PAGES 10
#define ELF_MAP_FAILED     11

/* Result of loading an ELF binary */
struct elf_load_result {
    uint64_t entry;  /* Virtual entry point (relocated for PIE) */
    uint64_t base;   /* Virtual base address */
    uint64_t brk;    /* Highest mapped virtual address */
};

/* Per-page tracking for loader */
struct elf_page_entry {
    uint64_t vaddr;      /* Virtual address in child VSpace */
    cap_t    frame_cap;  /* Cap slot of the Frame */
    uint64_t flags;      /* Current mapping flags in child VSpace */
};

/* Loader context: caller must provide cap slots and VSpace caps */
struct elf_loader_ctx {
    cap_t    untyped;          /* Untyped to retype frames from */
    cap_t    self_vspace;      /* Loader's own VSpace (for scratch mapping) */
    cap_t    child_vspace;     /* Child's VSpace (final mapping target) */
    uint64_t scratch_vaddr;    /* Temp VA in loader's VSpace for copying */
    cap_t    next_frame_slot;  /* Next free cap slot for new frames */
};

static inline uint64_t elf_page_align_down(uint64_t v) {
    return v & ~(uint64_t)(ELF_PAGE_SIZE - 1);
}

static inline uint64_t elf_page_align_up(uint64_t v) {
    return (v + ELF_PAGE_SIZE - 1) & ~(uint64_t)(ELF_PAGE_SIZE - 1);
}

/* Convert ELF p_flags to VSpace mapping flags */
static inline uint64_t elf_phdr_to_flags(uint32_t p_flags) {
    uint64_t flags = VSPACE_FLAG_USER;
    if (p_flags & PF_W) flags |= VSPACE_FLAG_WRITABLE;
    if (p_flags & PF_X) flags |= VSPACE_FLAG_EXECUTABLE;
    return flags;
}

/* Allocate a frame, map at scratch, copy data, unmap, map into child.
 * Returns the cap slot of the frame, or 0 on failure.
 */
static inline cap_t elf_alloc_and_map_page(
    struct elf_loader_ctx *ctx,
    uint64_t child_vaddr,
    uint64_t flags,
    const uint8_t *src_data,
    size_t src_offset,
    size_t copy_len
) {
    cap_t frame_slot = ctx->next_frame_slot++;
    int err;

    /* Retype a Frame from untyped */
    err = salty_untyped_retype(ctx->untyped, OBJ_FRAME, 0, frame_slot);
    if (err != 0) return 0;

    /* Map frame into our VSpace at scratch address */
    err = salty_vspace_map(ctx->self_vspace, frame_slot,
                           ctx->scratch_vaddr,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) return 0;

    /* Zero the page, then copy data */
    volatile uint8_t *scratch = (volatile uint8_t *)ctx->scratch_vaddr;
    for (size_t i = 0; i < ELF_PAGE_SIZE; i++)
        scratch[i] = 0;

    if (src_data && copy_len > 0) {
        const uint8_t *src = src_data + src_offset;
        for (size_t i = 0; i < copy_len; i++)
            scratch[i] = src[i];
    }

    /* Unmap from our VSpace */
    salty_vspace_unmap(ctx->self_vspace, ctx->scratch_vaddr);

    /* Map into child's VSpace */
    err = salty_vspace_map(ctx->child_vspace, frame_slot, child_vaddr, flags);
    if (err != 0) return 0;

    return frame_slot;
}

/* Write a uint64_t into a page that is already mapped in the child.
 * Re-maps it at scratch temporarily.
 */
static inline int elf_write_to_page(
    struct elf_loader_ctx *ctx,
    cap_t frame_cap,
    size_t page_offset,
    uint64_t value
) {
    /* Map frame at scratch for writing */
    int err = salty_vspace_map(ctx->self_vspace, frame_cap,
                                ctx->scratch_vaddr,
                                VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) return err;

    volatile uint64_t *ptr = (volatile uint64_t *)
        ((uint8_t *)ctx->scratch_vaddr + page_offset);
    *ptr = value;

    salty_vspace_unmap(ctx->self_vspace, ctx->scratch_vaddr);
    return 0;
}

/* Apply RELA relocations for PIE binaries */
static inline int elf_apply_relocations(
    const uint8_t *data, size_t data_len,
    uint64_t delta, uint64_t load_base,
    struct elf_page_entry *pages, size_t page_count,
    struct elf_loader_ctx *ctx
) {
    const struct elf64_ehdr *ehdr = (const struct elf64_ehdr *)data;
    size_t phdr_base = (size_t)ehdr->e_phoff;
    size_t phdr_count = ehdr->e_phnum;
    size_t phdr_size = ehdr->e_phentsize;

    /* Find PT_DYNAMIC segment */
    uint64_t dyn_offset = 0;
    uint64_t dyn_size = 0;

    for (size_t i = 0; i < phdr_count; i++) {
        size_t off = phdr_base + i * phdr_size;
        if (off + sizeof(struct elf64_phdr) > data_len) break;
        const struct elf64_phdr *phdr =
            (const struct elf64_phdr *)(data + off);
        if (phdr->p_type == PT_DYNAMIC) {
            dyn_offset = phdr->p_offset;
            dyn_size = phdr->p_filesz;
            break;
        }
    }

    if (dyn_offset == 0) return 0; /* No dynamic section */

    /* Parse .dynamic entries */
    uint64_t rela_offset = 0;
    uint64_t rela_size = 0;
    uint64_t rela_ent = 0;

    size_t pos = (size_t)dyn_offset;
    size_t dyn_end = pos + (size_t)dyn_size;

    while (pos + sizeof(struct elf64_dyn) <= dyn_end &&
           pos + sizeof(struct elf64_dyn) <= data_len) {
        const struct elf64_dyn *d = (const struct elf64_dyn *)(data + pos);
        if (d->d_tag == DT_NULL) break;
        if (d->d_tag == DT_RELA)    rela_offset = d->d_val;
        if (d->d_tag == DT_RELASZ)  rela_size = d->d_val;
        if (d->d_tag == DT_RELAENT) rela_ent = d->d_val;
        pos += sizeof(struct elf64_dyn);
    }

    if (rela_offset == 0 || rela_size == 0 || rela_ent == 0)
        return 0;

    size_t rela_file_offset = (size_t)rela_offset;
    uint64_t rela_count = rela_size / rela_ent;

    for (uint64_t i = 0; i < rela_count; i++) {
        size_t entry_off = rela_file_offset + (size_t)i * sizeof(struct elf64_rela);
        if (entry_off + sizeof(struct elf64_rela) > data_len)
            return ELF_RELOC_FAILED;

        const struct elf64_rela *rela =
            (const struct elf64_rela *)(data + entry_off);
        uint32_t reloc_type = (uint32_t)(rela->r_info & 0xFFFFFFFF);

        if (reloc_type == R_X86_64_RELATIVE) {
            uint64_t target_vaddr = rela->r_offset + delta;
            uint64_t value = load_base + (uint64_t)rela->r_addend;

            uint64_t target_page = elf_page_align_down(target_vaddr);
            size_t page_offset = (size_t)(target_vaddr - target_page);

            /* Find the page in our tracked pages */
            int found = 0;
            for (size_t j = 0; j < page_count; j++) {
                if (pages[j].vaddr == target_page) {
                    int err = elf_write_to_page(ctx, pages[j].frame_cap,
                                                 page_offset, value);
                    if (err != 0) return ELF_RELOC_FAILED;
                    found = 1;
                    break;
                }
            }
            if (!found) return ELF_RELOC_FAILED;
        }
    }

    return 0;
}

/* Load an ELF64 binary into a child VSpace.
 *
 * For PIE (ET_DYN): loads at load_base, applies RELA relocations.
 * For ET_EXEC: loads at fixed addresses from program headers.
 *
 * Each page of each PT_LOAD segment:
 *   1. Retype Frame from untyped
 *   2. Map at scratch in loader's VSpace
 *   3. Copy data (or zero for BSS)
 *   4. Unmap from loader
 *   5. Map into child VSpace
 */
static inline int elf_load(
    const uint8_t *data, size_t data_len,
    uint64_t load_base,
    struct elf_loader_ctx *ctx,
    struct elf_load_result *result
) {
    /* Validate minimum size */
    if (data_len < sizeof(struct elf64_ehdr))
        return ELF_TOO_SMALL;

    const struct elf64_ehdr *ehdr = (const struct elf64_ehdr *)data;

    /* Validate magic */
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F')
        return ELF_NOT_ELF;

    if (ehdr->e_ident[4] != ELFCLASS64)  return ELF_NOT_64BIT;
    if (ehdr->e_ident[5] != ELFDATA2LSB) return ELF_NOT_LE;
    if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) return ELF_BAD_TYPE;
    if (ehdr->e_machine != EM_X86_64) return ELF_BAD_ARCH;

    int is_pie = (ehdr->e_type == ET_DYN);

    /* Find min vaddr across all PT_LOAD segments */
    uint64_t min_vaddr = UINT64_MAX;
    int has_load = 0;

    size_t phdr_base = (size_t)ehdr->e_phoff;
    size_t phdr_count = ehdr->e_phnum;
    size_t phdr_size = ehdr->e_phentsize;

    for (size_t i = 0; i < phdr_count; i++) {
        size_t off = phdr_base + i * phdr_size;
        if (off + sizeof(struct elf64_phdr) > data_len) break;
        const struct elf64_phdr *phdr =
            (const struct elf64_phdr *)(data + off);
        if (phdr->p_type == PT_LOAD) {
            has_load = 1;
            if (phdr->p_vaddr < min_vaddr)
                min_vaddr = phdr->p_vaddr;
        }
    }

    if (!has_load) return ELF_NO_LOAD;

    /* Delta for PIE relocation */
    uint64_t delta = is_pie ? (load_base - min_vaddr) : 0;

    /* Track mapped pages */
    struct elf_page_entry pages[ELF_MAX_PAGES];
    size_t page_count = 0;
    uint64_t brk = 0;

    /* Load each PT_LOAD segment */
    for (size_t i = 0; i < phdr_count; i++) {
        size_t off = phdr_base + i * phdr_size;
        if (off + sizeof(struct elf64_phdr) > data_len) break;
        const struct elf64_phdr *phdr =
            (const struct elf64_phdr *)(data + off);
        if (phdr->p_type != PT_LOAD) continue;

        uint64_t seg_vaddr = phdr->p_vaddr + delta;
        uint64_t seg_start = elf_page_align_down(seg_vaddr);
        uint64_t seg_end = elf_page_align_up(seg_vaddr + phdr->p_memsz);
        uint64_t flags = elf_phdr_to_flags(phdr->p_flags);

        if (seg_end > brk) brk = seg_end;

        uint64_t page_vaddr = seg_start;
        while (page_vaddr < seg_end) {
            /* Check if page already mapped by previous segment */
            size_t existing_idx = page_count;
            for (size_t j = 0; j < page_count; j++) {
                if (pages[j].vaddr == page_vaddr) {
                    existing_idx = j;
                    break;
                }
            }

            /* Calculate file data overlap for this page */
            uint64_t file_start = seg_vaddr;
            uint64_t file_end = seg_vaddr + phdr->p_filesz;
            uint64_t copy_start = (page_vaddr > file_start) ? page_vaddr : file_start;
            uint64_t copy_end = ((page_vaddr + ELF_PAGE_SIZE) < file_end)
                ? (page_vaddr + ELF_PAGE_SIZE) : file_end;

            size_t src_offset = 0;
            size_t dst_offset = 0;
            size_t copy_len = 0;

            if (copy_start < copy_end) {
                src_offset = (size_t)(copy_start - delta - phdr->p_vaddr + phdr->p_offset);
                dst_offset = (size_t)(copy_start - page_vaddr);
                copy_len = (size_t)(copy_end - copy_start);
            }

            if (existing_idx < page_count) {
                cap_t existing = pages[existing_idx].frame_cap;
                /* Page exists; need to map at scratch, copy more data, unmap */
                if (copy_len > 0 && src_offset + copy_len <= data_len) {
                    int err = salty_vspace_map(ctx->self_vspace, existing,
                                               ctx->scratch_vaddr,
                                               VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
                    if (err == 0) {
                        volatile uint8_t *scratch =
                            (volatile uint8_t *)(ctx->scratch_vaddr + dst_offset);
                        for (size_t k = 0; k < copy_len; k++)
                            scratch[k] = data[src_offset + k];
                        salty_vspace_unmap(ctx->self_vspace, ctx->scratch_vaddr);
                    }
                }

                /* Merge permissions for overlapping PT_LOAD pages. */
                uint64_t merged_flags = pages[existing_idx].flags | flags;
                if (merged_flags != pages[existing_idx].flags) {
                    salty_vspace_unmap(ctx->child_vspace, page_vaddr);
                    int remap_err = salty_vspace_map(ctx->child_vspace, existing,
                                                     page_vaddr, merged_flags);
                    if (remap_err != 0) {
                        salty_serial_puts("[ELF] remap child failed err=");
                        salty_serial_hex((uint64_t)remap_err);
                        salty_serial_puts(" vaddr=");
                        salty_serial_hex(page_vaddr);
                        salty_serial_puts(" frame=");
                        salty_serial_hex((uint64_t)existing);
                        salty_serial_puts(" flags=");
                        salty_serial_hex(merged_flags);
                        salty_serial_puts("\n");
                        return ELF_MAP_FAILED;
                    }
                    pages[existing_idx].flags = merged_flags;
                }
            } else {
                /* New page */
                if (page_count >= ELF_MAX_PAGES) return ELF_TOO_MANY_PAGES;

                const uint8_t *src_ptr = NULL;
                size_t actual_offset = 0;
                size_t actual_len = 0;

                if (copy_len > 0 && src_offset + copy_len <= data_len) {
                    /* We need to handle dst_offset: zero page first,
                     * then copy at offset. elf_alloc_and_map_page zeros
                     * the whole page, so we just need to pass the right offset.
                     */
                    src_ptr = data;
                    actual_offset = src_offset;
                    actual_len = copy_len;
                }

                /* The alloc function zeros the page and copies data at offset 0.
                 * We need a version that copies at dst_offset. Let's do it inline.
                 */
                cap_t frame_slot = ctx->next_frame_slot++;
                int err;

                err = salty_untyped_retype(ctx->untyped, OBJ_FRAME, 0, frame_slot);
                if (err != 0) return ELF_OUT_OF_MEMORY;

                err = salty_vspace_map(ctx->self_vspace, frame_slot,
                                       ctx->scratch_vaddr,
                                       VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
                if (err != 0) {
                    salty_serial_puts("[ELF] map scratch failed err=");
                    salty_serial_hex((uint64_t)err);
                    salty_serial_puts(" vaddr=");
                    salty_serial_hex(ctx->scratch_vaddr);
                    salty_serial_puts(" frame=");
                    salty_serial_hex((uint64_t)frame_slot);
                    salty_serial_puts("\n");
                    return ELF_MAP_FAILED;
                }

                /* Zero the page */
                volatile uint8_t *scratch = (volatile uint8_t *)ctx->scratch_vaddr;
                for (size_t k = 0; k < ELF_PAGE_SIZE; k++)
                    scratch[k] = 0;

                /* Copy file data at the correct offset within the page */
                if (actual_len > 0) {
                    volatile uint8_t *dst = scratch + dst_offset;
                    for (size_t k = 0; k < actual_len; k++)
                        dst[k] = data[actual_offset + k];
                }

                salty_vspace_unmap(ctx->self_vspace, ctx->scratch_vaddr);

                err = salty_vspace_map(ctx->child_vspace, frame_slot,
                                       page_vaddr, flags);
                if (err != 0) {
                    salty_serial_puts("[ELF] map child failed err=");
                    salty_serial_hex((uint64_t)err);
                    salty_serial_puts(" vaddr=");
                    salty_serial_hex(page_vaddr);
                    salty_serial_puts(" frame=");
                    salty_serial_hex((uint64_t)frame_slot);
                    salty_serial_puts(" flags=");
                    salty_serial_hex(flags);
                    salty_serial_puts("\n");
                    return ELF_MAP_FAILED;
                }

                pages[page_count].vaddr = page_vaddr;
                pages[page_count].frame_cap = frame_slot;
                pages[page_count].flags = flags;
                page_count++;
            }

            page_vaddr += ELF_PAGE_SIZE;
        }
    }

    /* Apply RELA relocations for PIE */
    if (is_pie) {
        int err = elf_apply_relocations(data, data_len, delta, load_base,
                                         pages, page_count, ctx);
        if (err != 0) return err;
    }

    result->entry = ehdr->e_entry + delta;
    result->base = load_base;
    result->brk = brk;
    return ELF_OK;
}

#endif /* LIBSALTY_ELF_LOADER_H */
