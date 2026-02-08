/* SaltyOS POSIX Memory Management
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * In-process memory management library. Provides brk/sbrk, mmap, munmap,
 * mprotect using existing Untyped/VSpace kernel primitives.
 *
 * No kernel changes needed - uses UNTYPED_RETYPE + VSPACE_MAP/UNMAP.
 *
 * Requires salty.h to be included first.
 */

#ifndef LIBSALTY_POSIX_MM_H
#define LIBSALTY_POSIX_MM_H

#include <stdint.h>

/* POSIX mmap protection flags */
#define PROT_NONE   0x0
#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

/* POSIX mmap flags */
#define MAP_PRIVATE     0x02
#define MAP_ANONYMOUS   0x20
#define MAP_ANON        MAP_ANONYMOUS
#define MAP_FIXED       0x10
#define MAP_FAILED      ((void *)-1)

/* Region types */
#define MM_REGION_FREE    0
#define MM_REGION_HEAP    1
#define MM_REGION_MMAP    2

/* Limits */
#define MM_MAX_REGIONS       128
#define MM_MAX_FRAME_SLOTS   1024
#define MM_MAX_PAGES_PER_REGION 256

struct posix_mm_region {
    uint64_t base;
    uint64_t length;
    uint8_t  type;
    uint8_t  prot;
    uint16_t num_pages;
    cap_t    frame_slots[MM_MAX_PAGES_PER_REGION];
};

struct posix_mm_state {
    cap_t    untyped;
    cap_t    vspace;
    cap_t    cspace;
    cap_t    next_frame_slot;
    cap_t    max_frame_slot;
    uint64_t heap_base;
    uint64_t heap_current;
    uint64_t mmap_base;
    uint64_t mmap_next;
    struct posix_mm_region regions[MM_MAX_REGIONS];
    cap_t    heap_frame_slots[MM_MAX_PAGES_PER_REGION];
    int      initialized;
};

static struct posix_mm_state __posix_mm;

static inline void posix_mm_init(cap_t untyped, cap_t vspace, cap_t cspace,
                                  cap_t first_frame_slot,
                                  uint64_t heap_base, uint64_t mmap_base) {
    __posix_mm.untyped = untyped;
    __posix_mm.vspace = vspace;
    __posix_mm.cspace = cspace;
    __posix_mm.next_frame_slot = first_frame_slot;
    __posix_mm.max_frame_slot = first_frame_slot + MM_MAX_FRAME_SLOTS;
    __posix_mm.heap_base = heap_base;
    __posix_mm.heap_current = heap_base;
    __posix_mm.mmap_base = mmap_base;
    __posix_mm.mmap_next = mmap_base;
    for (int i = 0; i < MM_MAX_REGIONS; i++)
        __posix_mm.regions[i].type = MM_REGION_FREE;
    __posix_mm.initialized = 1;
}

/* Allocate a frame cap slot and retype a 4KB frame from untyped */
static inline cap_t __mm_alloc_frame(void) {
    if (__posix_mm.next_frame_slot >= __posix_mm.max_frame_slot)
        return (cap_t)-1;
    cap_t slot = __posix_mm.next_frame_slot++;
    int err = salty_untyped_retype(__posix_mm.untyped, OBJ_FRAME, 0, slot);
    if (err != 0)
        return (cap_t)-1;
    return slot;
}

/* Convert PROT_* to VSPACE_FLAG_* */
static inline uint64_t __mm_prot_to_flags(int prot) {
    uint64_t flags = VSPACE_FLAG_USER;
    if (prot & PROT_WRITE)
        flags |= VSPACE_FLAG_WRITABLE;
    if (prot & PROT_EXEC)
        flags |= VSPACE_FLAG_EXECUTABLE;
    return flags;
}

/* Map a frame at vaddr with given protection */
static inline int __mm_map_page(cap_t frame, uint64_t vaddr, int prot) {
    uint64_t flags = __mm_prot_to_flags(prot);
    return salty_vspace_map(__posix_mm.vspace, frame, vaddr, flags);
}

/* Find a free region slot */
static inline struct posix_mm_region *__mm_alloc_region(void) {
    for (int i = 0; i < MM_MAX_REGIONS; i++) {
        if (__posix_mm.regions[i].type == MM_REGION_FREE)
            return &__posix_mm.regions[i];
    }
    return (struct posix_mm_region *)0;
}

/* Find region containing addr */
static inline struct posix_mm_region *__mm_find_region(uint64_t addr) {
    for (int i = 0; i < MM_MAX_REGIONS; i++) {
        struct posix_mm_region *r = &__posix_mm.regions[i];
        if (r->type != MM_REGION_FREE &&
            addr >= r->base && addr < r->base + r->length)
            return r;
    }
    return (struct posix_mm_region *)0;
}

/* Set the program break. Returns 0 on success, -1 on error. */
static inline int posix_brk(uint64_t addr) {
    if (!__posix_mm.initialized)
        return -1;

    /* Cannot go below heap base */
    if (addr < __posix_mm.heap_base)
        return -1;

    uint64_t old_page = (__posix_mm.heap_current + 4095) & ~4095ULL;
    uint64_t new_page = (addr + 4095) & ~4095ULL;

    if (new_page > old_page) {
        /* Need to map new pages */
        for (uint64_t va = old_page; va < new_page; va += 4096) {
            cap_t frame = __mm_alloc_frame();
            if (frame == (cap_t)-1)
                return -1;
            int err = __mm_map_page(frame, va, PROT_READ | PROT_WRITE);
            if (err != 0)
                return -1;
            /* Record frame slot for later reclamation */
            uint64_t idx = (va - __posix_mm.heap_base) / 4096;
            if (idx < MM_MAX_PAGES_PER_REGION)
                __posix_mm.heap_frame_slots[idx] = frame;
            /* Zero the page by scratch-writing through it */
            volatile uint8_t *p = (volatile uint8_t *)va;
            for (int i = 0; i < 4096; i++)
                p[i] = 0;
        }
    } else if (new_page < old_page) {
        /* Shrink: unmap pages and reclaim frame caps */
        for (uint64_t va = new_page; va < old_page; va += 4096) {
            salty_vspace_unmap(__posix_mm.vspace, va);
            uint64_t idx = (va - __posix_mm.heap_base) / 4096;
            if (idx < MM_MAX_PAGES_PER_REGION && __posix_mm.heap_frame_slots[idx] != 0) {
                salty_cnode_delete(__posix_mm.cspace, __posix_mm.heap_frame_slots[idx]);
                __posix_mm.heap_frame_slots[idx] = 0;
            }
        }
    }

    __posix_mm.heap_current = addr;
    return 0;
}

/* Increment program break by increment bytes. Returns previous break, or
 * (void *)-1 on error. If increment is 0, returns current break. */
static inline void *posix_sbrk(long increment) {
    if (!__posix_mm.initialized)
        return (void *)-1;

    uint64_t old_break = __posix_mm.heap_current;

    if (increment == 0)
        return (void *)old_break;

    uint64_t new_break;
    if (increment > 0) {
        new_break = old_break + (uint64_t)increment;
    } else {
        uint64_t dec = (uint64_t)(-increment);
        if (dec > old_break - __posix_mm.heap_base)
            return (void *)-1;
        new_break = old_break - dec;
    }

    if (posix_brk(new_break) != 0)
        return (void *)-1;

    return (void *)old_break;
}

/* Forward declaration (needed by MAP_FIXED overlap handling in posix_mmap) */
static inline int posix_munmap(void *addr, unsigned long length);

/* Map anonymous memory. Returns pointer to mapped region or MAP_FAILED. */
static inline void *posix_mmap(void *addr, unsigned long length, int prot,
                                int flags, int fd, long offset) {
    (void)fd;
    (void)offset;

    if (!__posix_mm.initialized)
        return MAP_FAILED;

    /* Only anonymous mappings supported */
    if (!(flags & MAP_ANONYMOUS))
        return MAP_FAILED;

    if (length == 0)
        return MAP_FAILED;

    /* Round up to page boundary */
    uint64_t len = (length + 4095) & ~4095ULL;
    uint64_t num_pages = len / 4096;

    if (num_pages > MM_MAX_PAGES_PER_REGION)
        return MAP_FAILED;

    /* Find a region slot */
    struct posix_mm_region *region = __mm_alloc_region();
    if (!region)
        return MAP_FAILED;

    /* Choose base address */
    uint64_t base;
    if ((flags & MAP_FIXED) && addr) {
        base = (uint64_t)addr & ~4095ULL;
        /* Unmap any existing mmap region that overlaps the fixed address */
        struct posix_mm_region *existing = __mm_find_region(base);
        if (existing && existing->type == MM_REGION_MMAP) {
            posix_munmap((void *)existing->base, existing->length);
        }
    } else {
        base = __posix_mm.mmap_next;
        __posix_mm.mmap_next = base + len;
    }

    /* Allocate frames and map */
    region->base = base;
    region->length = len;
    region->type = MM_REGION_MMAP;
    region->prot = (uint8_t)prot;
    region->num_pages = (uint16_t)num_pages;

    for (uint64_t i = 0; i < num_pages; i++) {
        cap_t frame = __mm_alloc_frame();
        if (frame == (cap_t)-1) {
            /* Unmap already-mapped pages */
            for (uint64_t j = 0; j < i; j++)
                salty_vspace_unmap(__posix_mm.vspace, base + j * 4096);
            region->type = MM_REGION_FREE;
            return MAP_FAILED;
        }
        region->frame_slots[i] = frame;

        int err = __mm_map_page(frame, base + i * 4096, prot);
        if (err != 0) {
            for (uint64_t j = 0; j < i; j++)
                salty_vspace_unmap(__posix_mm.vspace, base + j * 4096);
            region->type = MM_REGION_FREE;
            return MAP_FAILED;
        }

        /* Zero the page */
        volatile uint8_t *p = (volatile uint8_t *)(base + i * 4096);
        for (int k = 0; k < 4096; k++)
            p[k] = 0;
    }

    return (void *)base;
}

/* Unmap a previously mapped region. Returns 0 on success, -1 on error. */
static inline int posix_munmap(void *addr, unsigned long length) {
    if (!__posix_mm.initialized)
        return -1;

    uint64_t base = (uint64_t)addr;
    struct posix_mm_region *region = __mm_find_region(base);
    if (!region || region->type != MM_REGION_MMAP)
        return -1;

    /* Intentional limitation: partial munmap not supported.
     * Only full-region unmap is allowed (base must match region start). */
    if (base != region->base)
        return -1;

    /* Unmap all pages and reclaim frame caps */
    for (uint16_t i = 0; i < region->num_pages; i++) {
        salty_vspace_unmap(__posix_mm.vspace, region->base + (uint64_t)i * 4096);
        if (region->frame_slots[i] != 0) {
            salty_cnode_delete(__posix_mm.cspace, region->frame_slots[i]);
            region->frame_slots[i] = 0;
        }
    }

    region->type = MM_REGION_FREE;
    (void)length;
    return 0;
}

/* Change protection on a mapped region.
 * Implementation: unmap + remap with new flags (kernel has no PROTECT op). */
static inline int posix_mprotect(void *addr, unsigned long length, int prot) {
    if (!__posix_mm.initialized)
        return -1;

    uint64_t base = (uint64_t)addr;
    struct posix_mm_region *region = __mm_find_region(base);
    if (!region || region->type != MM_REGION_MMAP)
        return -1;

    /* Unmap and remap each page with new flags */
    for (uint16_t i = 0; i < region->num_pages; i++) {
        uint64_t va = region->base + (uint64_t)i * 4096;
        salty_vspace_unmap(__posix_mm.vspace, va);
        int err = __mm_map_page(region->frame_slots[i], va, prot);
        if (err != 0)
            return -1;
    }

    region->prot = (uint8_t)prot;
    (void)length;
    return 0;
}

#endif /* LIBSALTY_POSIX_MM_H */
