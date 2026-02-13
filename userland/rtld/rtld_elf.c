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
    map->symtab_count = 0;
    map->sym_ent_size = sizeof(Elf64_Sym);
    map->strtab = NULL;
    map->strtab_size = 0;
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
        case DT_STRSZ:
            map->strtab_size = dyn[i].d_val;
            break;
        case DT_SYMENT:
            if (dyn[i].d_val != 0)
                map->sym_ent_size = dyn[i].d_val;
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

    /* Derive an upper bound for dynsym entries when symtab precedes strtab.
     * This holds for our userland link layout and enables safe bounds checks.
     */
    if (map->symtab && map->strtab
        && map->sym_ent_size != 0
        && (uintptr_t)map->strtab > (uintptr_t)map->symtab) {
        uint64_t bytes = (uint64_t)((uintptr_t)map->strtab - (uintptr_t)map->symtab);
        map->symtab_count = bytes / map->sym_ent_size;
    }
}

/* Allocate a frame, map at scratch, copy data, unmap from scratch, map at target.
 * Returns 0 on success, nonzero on failure.
 */
static uint64_t retype_frame_any(struct rtld_state *st, cap_t frame_slot) {
    uint64_t err = rtld_retype_frame(st->untyped, frame_slot);
    if (err == 0)
        return 0;

    uint64_t best_err = err;
    for (cap_t ut = CAP_UNTYPED_START; ut < CAP_UNTYPED_END; ut++) {
        if (ut == st->untyped)
            continue;
        err = rtld_retype_frame(ut, frame_slot);
        if (err == 0) {
            st->untyped = ut;
            return 0;
        }
        if (err != SALTY_INVALID_CAPABILITY
            && err != SALTY_INVALID_OPERATION
            && err != SALTY_NOT_FOUND) {
            best_err = err;
        }
    }

    return best_err;
}

static int alloc_map_page(struct rtld_state *st, uint64_t vaddr, uint64_t flags,
                           const uint8_t *data, size_t data_offset,
                           size_t page_offset, size_t copy_len) {
    cap_t frame_slot = st->next_frame_slot++;
    uint64_t err;

    /* Retype a frame from untyped */
    err = retype_frame_any(st, frame_slot);
    if (err != 0) {
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] retype frame failed err=");
          rtld_lb_hex(&lb, err); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
        return -1;
    }

    /* Map at scratch for writing */
    err = rtld_vspace_map(st->vspace, frame_slot, st->scratch_vaddr,
                           VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER);
    if (err != 0) {
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] map scratch failed err=");
          rtld_lb_hex(&lb, err); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
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
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] map target failed vaddr=");
          rtld_lb_hex(&lb, vaddr); rtld_lb_str(&lb, " err=");
          rtld_lb_hex(&lb, err); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
        return -3;
    }

    return 0;
}

#define RTLD_MAX_LIB_PAGES  256

struct rtld_lib_page {
    uint64_t vaddr;
    cap_t frame_slot;
    uint64_t flags;
    int is_device;
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
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] patch map scratch failed err=");
          rtld_lb_hex(&lb, err); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
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
    { struct rtld_linebuf lb; rtld_lb_init(&lb);
      rtld_lb_str(&lb, "[RTLD] Loading ");
      rtld_lb_str(&lb, name); rtld_lb_str(&lb, " at ");
      rtld_lb_hex(&lb, load_addr); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }

    if (st->nobjects >= RTLD_MAX_OBJECTS) {
        rtld_puts("[RTLD] too many loaded objects\n");
        return -1;
    }

    /* Find the .so in the CPIO initrd */
    struct rtld_cpio_entry cpio;
    if (!rtld_cpio_find((const uint8_t *)st->initrd_base, st->initrd_size,
                         name, &cpio)) {
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] not found in initrd: ");
          rtld_lb_str(&lb, name); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
        return -2;
    }

    { struct rtld_linebuf lb; rtld_lb_init(&lb);
      rtld_lb_str(&lb, "[RTLD] Found in initrd, size=");
      rtld_lb_hex(&lb, cpio.data_len); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }

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

    /* Check if this library was pre-mapped by procmgr */
    int is_premapped = (st->shared_lib_base != 0
                        && load_addr >= st->shared_lib_base);
    if (is_premapped) {
        rtld_puts("[RTLD] Using pre-mapped shared pages for ");
        rtld_puts(name);
        rtld_puts("\n");
    }

    /* Load each PT_LOAD segment */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD)
            continue;

        uint64_t seg_vaddr = ph->p_vaddr + delta;
        uint64_t seg_start = rtld_page_align_down(seg_vaddr);
        uint64_t seg_end = rtld_page_align_up(seg_vaddr + ph->p_memsz);
        uint64_t flags = rtld_elf_to_vspace_flags(ph->p_flags);

        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD]   LOAD ");
          rtld_lb_hex(&lb, seg_start); rtld_lb_str(&lb, "-");
          rtld_lb_hex(&lb, seg_end); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }

        /* RO segment already mapped by procmgr — record pages as device-mapped */
        if (is_premapped && (ph->p_flags & PF_W) == 0) {
            for (uint64_t page = seg_start; page < seg_end; page += PAGE_SIZE) {
                if (page_count >= RTLD_MAX_LIB_PAGES) return -6;
                pages[page_count].vaddr = page;
                pages[page_count].frame_slot = 0;
                pages[page_count].flags = flags;
                pages[page_count].is_device = 1;
                page_count++;
            }
            continue;
        }

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
                if (pages[existing].is_device) {
                    /* Device-mapped pages are expected to be final RO/RX mappings.
                     * If a later segment overlaps, fall back is not implemented. */
                    if (copy_len != 0 || (pages[existing].flags | flags) != pages[existing].flags) {
                        rtld_puts("[RTLD] overlapping device-mapped page unsupported\n");
                        return -6;
                    }
                    continue;
                }

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
                        { struct rtld_linebuf lb; rtld_lb_init(&lb);
                          rtld_lb_str(&lb, "[RTLD] remap merged flags failed vaddr=");
                          rtld_lb_hex(&lb, page); rtld_lb_str(&lb, " err=");
                          rtld_lb_hex(&lb, remap_err); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
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

            /* Prefer direct initrd device mapping for fully-covered RO/RX pages.
             * This avoids per-process frame allocation for immutable library code/data. */
            if ((flags & VSPACE_FLAG_WRITABLE) == 0
                && page_offset == 0
                && copy_len == PAGE_SIZE) {
                const uint8_t *src_page = cpio.data + data_offset;
                if ((((uintptr_t)src_page) & (PAGE_SIZE - 1)) == 0) {
                    uint64_t src_off = (uint64_t)((uintptr_t)src_page - (uintptr_t)st->initrd_base);
                    if (src_off + PAGE_SIZE <= st->initrd_size) {
                        uint64_t derr = rtld_vspace_map_device(
                            st->vspace, CAP_INITRD_UNTYPED, src_off, page, flags);
                        if (derr == 0) {
                            pages[page_count].vaddr = page;
                            pages[page_count].frame_slot = 0;
                            pages[page_count].flags = flags;
                            pages[page_count].is_device = 1;
                            page_count++;
                            continue;
                        }
                    }
                }
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
            pages[page_count].is_device = 0;
            page_count++;
        }
    }

    /* Compute actual page-aligned load footprint */
    uint64_t max_end = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type != PT_LOAD) continue;
        uint64_t seg_end = rtld_page_align_up(phdrs[i].p_vaddr + delta + phdrs[i].p_memsz);
        if (seg_end > max_end) max_end = seg_end;
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
    map->load_size = (max_end > load_addr) ? (max_end - load_addr) : 0;

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

    { struct rtld_linebuf lb; rtld_lb_init(&lb);
      rtld_lb_str(&lb, "[RTLD] Loaded ");
      rtld_lb_str(&lb, name); rtld_lb_str(&lb, " base=");
      rtld_lb_hex(&lb, base); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }

    return 0;
}
