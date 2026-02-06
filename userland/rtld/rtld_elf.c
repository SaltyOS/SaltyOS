/* SaltyOS Runtime Dynamic Linker - ELF Loading
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Parses .dynamic sections and loads shared libraries from the CPIO initrd
 * into the current process's VSpace using capability syscalls.
 */

#include "rtld_internal.h"

void parse_dynamic(struct link_map *map, Elf64_Dyn *dyn, uint64_t base) {
    map->base = base;
    map->symtab = NULL;
    map->strtab = NULL;
    map->gnu_hash = NULL;
    map->jmprel = NULL;
    map->jmprel_count = 0;
    map->pltgot = NULL;
    map->rela = NULL;
    map->rela_count = 0;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        switch (dyn[i].d_tag) {
        case DT_SYMTAB:
            map->symtab = (Elf64_Sym *)(base + dyn[i].d_val);
            break;
        case DT_STRTAB:
            map->strtab = (const char *)(base + dyn[i].d_val);
            break;
        case DT_GNU_HASH:
            map->gnu_hash = (uint32_t *)(base + dyn[i].d_val);
            break;
        case DT_JMPREL:
            map->jmprel = (Elf64_Rela *)(base + dyn[i].d_val);
            break;
        case DT_PLTRELSZ:
            map->jmprel_count = dyn[i].d_val / sizeof(Elf64_Rela);
            break;
        case DT_PLTGOT:
            map->pltgot = (uint64_t *)(base + dyn[i].d_val);
            break;
        case DT_RELA:
            map->rela = (Elf64_Rela *)(base + dyn[i].d_val);
            break;
        case DT_RELASZ:
            map->rela_count = dyn[i].d_val / sizeof(Elf64_Rela);
            break;
        }
    }
}

/* Allocate a frame, map at scratch, copy data, unmap from scratch, map at target.
 * Returns 0 on success, nonzero on failure.
 */
static int alloc_map_page(struct rtld_state *st, uint64_t vaddr, uint64_t flags,
                           const uint8_t *data, size_t data_offset,
                           size_t page_offset, size_t copy_len) {
    cap_t frame_slot = st->next_frame_slot++;
    uint64_t err;

    /* Retype a frame from untyped */
    err = rtld_retype_frame(st->untyped, frame_slot);
    if (err != 0) {
        rtld_puts("[RTLD] retype frame failed err=");
        rtld_hex(err);
        rtld_putc('\n');
        return -1;
    }

    /* Map at scratch for writing */
    err = rtld_vspace_map(st->vspace, frame_slot, st->scratch_vaddr,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        rtld_puts("[RTLD] map scratch failed err=");
        rtld_hex(err);
        rtld_putc('\n');
        return -2;
    }

    /* Zero the page */
    volatile uint8_t *scratch = (volatile uint8_t *)st->scratch_vaddr;
    for (size_t i = 0; i < PAGE_SIZE; i++)
        scratch[i] = 0;

    /* Copy file data at the correct offset within the page */
    if (data && copy_len > 0) {
        volatile uint8_t *dst = scratch + page_offset;
        const uint8_t *src = data + data_offset;
        for (size_t i = 0; i < copy_len; i++)
            dst[i] = src[i];
    }

    /* Unmap from scratch */
    rtld_vspace_unmap(st->vspace, st->scratch_vaddr);

    /* Map at target vaddr in our own VSpace */
    err = rtld_vspace_map(st->vspace, frame_slot, vaddr, flags);
    if (err != 0) {
        rtld_puts("[RTLD] map target failed vaddr=");
        rtld_hex(vaddr);
        rtld_puts(" err=");
        rtld_hex(err);
        rtld_putc('\n');
        return -3;
    }

    return 0;
}

#define RTLD_MAX_LIB_PAGES  256

struct rtld_lib_page {
    uint64_t vaddr;
    cap_t frame_slot;
    uint64_t flags;
};

/* Update bytes in an already-mapped target page by scratch-mapping its frame. */
static int patch_mapped_page(struct rtld_state *st, cap_t frame_slot,
                              const uint8_t *data, size_t data_offset,
                              size_t page_offset, size_t copy_len) {
    if (!data || copy_len == 0)
        return 0;

    uint64_t err = rtld_vspace_map(st->vspace, frame_slot, st->scratch_vaddr,
                                    VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        rtld_puts("[RTLD] patch map scratch failed err=");
        rtld_hex(err);
        rtld_putc('\n');
        return -1;
    }

    volatile uint8_t *dst = (volatile uint8_t *)(st->scratch_vaddr + page_offset);
    const uint8_t *src = data + data_offset;
    for (size_t i = 0; i < copy_len; i++)
        dst[i] = src[i];

    rtld_vspace_unmap(st->vspace, st->scratch_vaddr);
    return 0;
}

int load_shared_library(struct rtld_state *st, const char *name,
                         uint64_t load_addr) {
    rtld_puts("[RTLD] Loading ");
    rtld_puts(name);
    rtld_puts(" at ");
    rtld_hex(load_addr);
    rtld_putc('\n');

    if (st->nobjects >= RTLD_MAX_OBJECTS) {
        rtld_puts("[RTLD] too many loaded objects\n");
        return -1;
    }

    /* Find the .so in the CPIO initrd */
    struct rtld_cpio_entry cpio;
    if (!rtld_cpio_find((const uint8_t *)st->initrd_base, st->initrd_size,
                         name, &cpio)) {
        rtld_puts("[RTLD] not found in initrd: ");
        rtld_puts(name);
        rtld_putc('\n');
        return -2;
    }

    rtld_puts("[RTLD] Found in initrd, size=");
    rtld_hex(cpio.data_len);
    rtld_putc('\n');

    /* Validate ELF header */
    if (cpio.data_len < sizeof(Elf64_Ehdr))
        return -3;

    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)cpio.data;
    if (ehdr->e_ident[0] != 0x7F || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F')
        return -4;

    if (ehdr->e_type != ET_DYN)
        return -5;

    /* Find minimum vaddr across PT_LOAD segments */
    uint64_t min_vaddr = UINT64_MAX;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(cpio.data + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type == PT_LOAD && ph->p_vaddr < min_vaddr)
            min_vaddr = ph->p_vaddr;
    }

    uint64_t base = load_addr;
    uint64_t delta = base - min_vaddr;
    struct rtld_lib_page pages[RTLD_MAX_LIB_PAGES];
    size_t page_count = 0;

    /* Load each PT_LOAD segment */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD)
            continue;

        uint64_t seg_vaddr = ph->p_vaddr + delta;
        uint64_t seg_start = rtld_page_align_down(seg_vaddr);
        uint64_t seg_end = rtld_page_align_up(seg_vaddr + ph->p_memsz);
        uint64_t flags = rtld_elf_to_vspace_flags(ph->p_flags);

        rtld_puts("[RTLD]   LOAD ");
        rtld_hex(seg_start);
        rtld_puts("-");
        rtld_hex(seg_end);
        rtld_putc('\n');

        /* Map pages for this segment */
        for (uint64_t page = seg_start; page < seg_end; page += PAGE_SIZE) {
            /* Calculate how much file data overlaps this page */
            uint64_t file_start = seg_vaddr;
            uint64_t file_end = seg_vaddr + ph->p_filesz;
            uint64_t copy_start = (page > file_start) ? page : file_start;
            uint64_t copy_end = ((page + PAGE_SIZE) < file_end)
                                 ? (page + PAGE_SIZE) : file_end;

            size_t data_offset = 0;
            size_t page_offset = 0;
            size_t copy_len = 0;

            if (copy_start < copy_end) {
                /* data_offset: position in the ELF file to copy from */
                data_offset = (size_t)(copy_start - seg_vaddr + ph->p_offset);
                /* page_offset: position within the page to copy to */
                page_offset = (size_t)(copy_start - page);
                copy_len = (size_t)(copy_end - copy_start);

                /* Bounds check against CPIO data */
                if (data_offset + copy_len > cpio.data_len)
                    copy_len = 0;
            }

            size_t existing = SIZE_MAX;
            for (size_t j = 0; j < page_count; j++) {
                if (pages[j].vaddr == page) {
                    existing = j;
                    break;
                }
            }

            if (existing != SIZE_MAX) {
                int err = patch_mapped_page(st, pages[existing].frame_slot,
                                             cpio.data, data_offset,
                                             page_offset, copy_len);
                if (err != 0) {
                    rtld_puts("[RTLD] patch_mapped_page failed\n");
                    return -6;
                }

                uint64_t merged_flags = pages[existing].flags | flags;
                if (merged_flags != pages[existing].flags) {
                    rtld_vspace_unmap(st->vspace, page);
                    uint64_t remap_err = rtld_vspace_map(st->vspace,
                                                          pages[existing].frame_slot,
                                                          page, merged_flags);
                    if (remap_err != 0) {
                        rtld_puts("[RTLD] remap merged flags failed vaddr=");
                        rtld_hex(page);
                        rtld_puts(" err=");
                        rtld_hex(remap_err);
                        rtld_putc('\n');
                        return -6;
                    }
                    pages[existing].flags = merged_flags;
                }
                continue;
            }

            if (page_count >= RTLD_MAX_LIB_PAGES) {
                rtld_puts("[RTLD] too many pages in library\n");
                return -6;
            }

            cap_t frame_slot = st->next_frame_slot;
            int err = alloc_map_page(st, page, flags,
                                      cpio.data, data_offset,
                                      page_offset, copy_len);
            if (err != 0) {
                rtld_puts("[RTLD] alloc_map_page failed\n");
                return -6;
            }

            pages[page_count].vaddr = page;
            pages[page_count].frame_slot = frame_slot;
            pages[page_count].flags = flags;
            page_count++;
        }
    }

    /* Find PT_DYNAMIC and create link_map entry */
    Elf64_Dyn *lib_dyn = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC) {
            lib_dyn = (Elf64_Dyn *)(phdrs[i].p_vaddr + delta);
            break;
        }
    }

    struct link_map *map = &st->objects[st->nobjects];
    map->name = name;
    map->next = NULL;

    if (lib_dyn)
        parse_dynamic(map, lib_dyn, base);
    else
        map->base = base;

    /* Append to linked list */
    struct link_map *tail = st->head;
    while (tail->next)
        tail = tail->next;
    tail->next = map;

    st->nobjects++;

    rtld_puts("[RTLD] Loaded ");
    rtld_puts(name);
    rtld_puts(" base=");
    rtld_hex(base);
    rtld_putc('\n');

    return 0;
}
