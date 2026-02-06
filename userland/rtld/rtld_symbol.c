/* SaltyOS Runtime Dynamic Linker - Symbol Resolution
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * GNU hash lookup with bloom filter, and linear fallback.
 */

#include "rtld_internal.h"

/* Compute GNU hash for a symbol name */
static uint32_t gnu_hash(const char *name) {
    uint32_t h = 5381;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++)
        h = (h << 5) + h + *p;
    return h;
}

uint64_t gnu_hash_lookup(struct link_map *map, const char *name) {
    if (!map->gnu_hash || !map->symtab || !map->strtab)
        return 0;

    uint32_t *hashtab = map->gnu_hash;
    uint32_t nbuckets = hashtab[0];
    uint32_t symoffset = hashtab[1];
    uint32_t bloom_size = hashtab[2];
    uint32_t bloom_shift = hashtab[3];
    uint64_t *bloom = (uint64_t *)&hashtab[4];
    uint32_t *buckets = (uint32_t *)&bloom[bloom_size];
    uint32_t *chain = &buckets[nbuckets];

    uint32_t h = gnu_hash(name);

    /* Bloom filter check */
    uint64_t word = bloom[(h / 64) % bloom_size];
    uint64_t mask = (1ULL << (h % 64)) | (1ULL << ((h >> bloom_shift) % 64));
    if ((word & mask) != mask)
        return 0;

    /* Bucket lookup */
    uint32_t idx = buckets[h % nbuckets];
    if (idx < symoffset)
        return 0;

    /* Chain walk */
    for (;;) {
        uint32_t chain_hash = chain[idx - symoffset];
        /* Compare hashes (low bit is the end-of-chain marker, so mask it) */
        if ((h | 1) == (chain_hash | 1)) {
            Elf64_Sym *sym = &map->symtab[idx];
            if (rtld_strcmp(name, map->strtab + sym->st_name) == 0) {
                if (sym->st_shndx != SHN_UNDEF)
                    return map->base + sym->st_value;
            }
        }
        if (chain_hash & 1)
            break;  /* End of chain */
        idx++;
    }

    return 0;
}

uint64_t linear_lookup(struct link_map *map, const char *name) {
    if (!map->symtab || !map->strtab)
        return 0;

    /* Without DT_HASH we don't know symtab size exactly.
     * Use gnu_hash symoffset as a hint for the start of hashed symbols,
     * and scan a reasonable bound.
     */
    uint32_t start = 0;
    uint32_t limit = 4096;

    /* If gnu_hash is available, we know the structure but the name
     * wasn't found there. For linear fallback, scan from index 0.
     */
    for (uint32_t i = start; i < limit; i++) {
        Elf64_Sym *sym = &map->symtab[i];

        /* Heuristic end: if st_name points past reasonable bounds, stop */
        if (sym->st_name == 0 && sym->st_value == 0 && sym->st_size == 0 &&
            sym->st_info == 0 && i > 1)
            break;

        if (sym->st_name == 0)
            continue;
        if (sym->st_shndx == SHN_UNDEF)
            continue;

        uint8_t bind = ELF64_ST_BIND(sym->st_info);
        if (bind != STB_GLOBAL && bind != STB_WEAK)
            continue;

        if (rtld_strcmp(name, map->strtab + sym->st_name) == 0)
            return map->base + sym->st_value;
    }

    return 0;
}

uint64_t resolve_symbol_addr(struct rtld_state *st, const char *name) {
    /* Search all loaded objects in link order (exe first, then libs) */
    struct link_map *cur = st->head;
    while (cur) {
        uint64_t addr = gnu_hash_lookup(cur, name);
        if (addr)
            return addr;
        addr = linear_lookup(cur, name);
        if (addr)
            return addr;
        cur = cur->next;
    }
    return 0;
}
