/* SaltyOS Runtime Dynamic Linker - Relocation Processing
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Handles R_X86_64_RELATIVE, R_X86_64_64, R_X86_64_GLOB_DAT,
 * and R_X86_64_JUMP_SLOT relocations.
 */

#include "rtld_internal.h"

/* Resolve a symbol by index from a given object's symtab */
static uint64_t resolve_by_index(struct rtld_state *st, struct link_map *map,
                                  uint32_t sym_idx) {
    Elf64_Sym *sym = &map->symtab[sym_idx];
    const char *name = map->strtab + sym->st_name;

    /* Search all loaded objects in link order */
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

    /* Weak symbols can remain unresolved (return 0) */
    if (ELF64_ST_BIND(sym->st_info) == STB_WEAK)
        return 0;

    { struct rtld_linebuf lb; rtld_lb_init(&lb);
      rtld_lb_str(&lb, "[RTLD] WARN: unresolved symbol: ");
      rtld_lb_str(&lb, name); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
    return 0;
}

/* Apply a single relocation */
static void apply_rela(struct rtld_state *st, struct link_map *map,
                        Elf64_Rela *r) {
    uint64_t *target = (uint64_t *)(map->base + r->r_offset);
    uint32_t type = ELF64_R_TYPE(r->r_info);
    uint32_t sym_idx = ELF64_R_SYM(r->r_info);

    switch (type) {
    case R_X86_64_NONE:
        break;

    case R_X86_64_RELATIVE:
        /* B + A: base address + addend */
        *target = map->base + (uint64_t)r->r_addend;
        break;

    case R_X86_64_64: {
        /* S + A: symbol value + addend */
        uint64_t sym_addr = resolve_by_index(st, map, sym_idx);
        *target = sym_addr + (uint64_t)r->r_addend;
        break;
    }

    case R_X86_64_GLOB_DAT: {
        /* S: symbol value */
        uint64_t sym_addr = resolve_by_index(st, map, sym_idx);
        *target = sym_addr;
        break;
    }

    case R_X86_64_JUMP_SLOT: {
        /* For eager binding: resolve now */
        uint64_t sym_addr = resolve_by_index(st, map, sym_idx);
        *target = sym_addr;
        break;
    }

    default:
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] WARN: unknown reloc type ");
          rtld_lb_hex(&lb, type); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
        break;
    }
}

int process_relocations(struct rtld_state *st, struct link_map *map) {
    /* Process DT_RELA (non-PLT relocations) */
    for (uint64_t i = 0; i < map->rela_count; i++) {
        apply_rela(st, map, &map->rela[i]);
    }

    /* Process DT_JMPREL (PLT relocations) eagerly.
     * Even though we set up lazy binding via GOT[1]/GOT[2], we also
     * resolve eagerly here for reliability. The lazy resolver is a
     * fallback for any we missed or for PLT entries added later.
     */
    for (uint64_t i = 0; i < map->jmprel_count; i++) {
        apply_rela(st, map, &map->jmprel[i]);
    }

    return 0;
}

/* Lazy PLT resolver: called from _dl_runtime_resolve trampoline.
 * Resolves a single PLT slot by relocation index.
 */
uint64_t _dl_fixup(struct link_map *map, uint64_t reloc_index) {
    if (!map->jmprel || reloc_index >= map->jmprel_count) {
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] _dl_fixup: invalid reloc_index ");
          rtld_lb_hex(&lb, reloc_index); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
        return 0;
    }

    Elf64_Rela *rela = &map->jmprel[reloc_index];
    uint32_t sym_idx = ELF64_R_SYM(rela->r_info);
    Elf64_Sym *sym = &map->symtab[sym_idx];
    const char *name = map->strtab + sym->st_name;

    { struct rtld_linebuf lb; rtld_lb_init(&lb);
      rtld_lb_str(&lb, "[RTLD] Lazy resolve: ");
      rtld_lb_str(&lb, name); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }

    uint64_t addr = resolve_symbol_addr(&g_rtld, name);

    if (addr == 0) {
        { struct rtld_linebuf lb; rtld_lb_init(&lb);
          rtld_lb_str(&lb, "[RTLD] FATAL: lazy resolve failed for: ");
          rtld_lb_str(&lb, name); rtld_lb_str(&lb, "\n"); rtld_lb_flush(&lb); }
        for (;;) rtld_yield();
    }

    /* Patch the GOT entry so next call goes directly */
    uint64_t *got_entry = (uint64_t *)(map->base + rela->r_offset);
    *got_entry = addr;

    return addr;
}
