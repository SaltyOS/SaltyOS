/* SaltyOS Runtime Dynamic Linker - Entry Point
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Entry point for ld-besalt.so. Parses the initial stack (argc/argv/envp/auxv),
 * self-relocates, loads shared libraries from the CPIO initrd, applies
 * relocations, sets up PLT lazy binding, and jumps to the executable entry.
 */

#include "rtld_internal.h"

struct rtld_state g_rtld;

/* Exported so applications can continue allocating frame slots after rtld */
uint64_t __besalt_next_frame_slot = 0;

/* Exported per-process slot pool info for slot_alloc */
uint64_t __besalt_slot_base = 0;
uint64_t __besalt_slot_count = 0;
uint64_t __besalt_cspace_ntfn = 0;

/* Exported ELF TLS info so libbesalt can set up the TLS data area */
uint64_t __besalt_tls_template = 0;  /* Runtime address of .tdata template */
uint64_t __besalt_tls_filesz = 0;    /* Size of .tdata (initialized data) */
uint64_t __besalt_tls_memsz = 0;     /* Total static TLS block size */
uint64_t __besalt_tls_align = 1;     /* Maximum static TLS alignment */
uint64_t __besalt_tls_module_count = 0;
struct rtld_tls_module __besalt_tls_modules[RTLD_MAX_OBJECTS];

void __attribute__((naked, noreturn)) _start(void) {
#if defined(__x86_64__)
    __asm__ volatile(
        "mov %%rsp, %%rdi\n"
        "call rtld_main\n"
        : : : "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile(
        "mov x0, sp\n"
        "bl rtld_main\n"
        : : : "memory"
    );
#endif
}

/* Self-relocate the rtld's own R_RELATIVE entries.
 * Called before any global data can be accessed reliably.
 */
static void self_relocate(uint64_t base, Elf64_Dyn *dyn) {
    Elf64_Rela *rela = NULL;
    uint64_t rela_size = 0;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == DT_RELA)
            rela = (Elf64_Rela *)(base + dyn[i].d_val);
        else if (dyn[i].d_tag == DT_RELASZ)
            rela_size = dyn[i].d_val;
    }

    if (!rela || rela_size == 0)
        return;

    uint64_t count = rela_size / sizeof(Elf64_Rela);
    for (uint64_t i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        if (type == R_RELATIVE) {
            uint64_t *target = (uint64_t *)(base + rela[i].r_offset);
            *target = base + (uint64_t)rela[i].r_addend;
        }
    }
}

/* Find PT_DYNAMIC in program headers at a given base */
static Elf64_Dyn *find_dynamic(uint64_t base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC)
            return (Elf64_Dyn *)(base + phdrs[i].p_vaddr);
    }
    return NULL;
}

static void finalize_static_tls_layout(struct rtld_state *st) {
    uint64_t total = 0;
    uint64_t max_align = 1;
    uint64_t module_id = 1;

    for (struct link_map *map = st->head; map; map = map->next) {
        map->tls_module_id = 0;
        map->tls_tpoff = 0;
        if (map->tls_memsz == 0)
            continue;

        uint64_t align = map->tls_align ? map->tls_align : 1;
        uint64_t next_total = total + map->tls_memsz;
        if (align > 1)
            next_total = (next_total + align - 1) & ~(align - 1);
        total = next_total;
        if (align > max_align)
            max_align = align;

        map->tls_module_id = module_id++;
        map->tls_tpoff = -(int64_t)total;
    }

    st->tls_memsz = total;
    st->tls_align = max_align;
    st->tls_module_count = module_id - 1;
}

static void export_static_tls_layout(struct rtld_state *st) {
    __besalt_tls_template = st->exe_tls_vaddr;
    __besalt_tls_filesz = st->exe_tls_filesz;
    __besalt_tls_memsz = st->tls_memsz;
    __besalt_tls_align = st->tls_align;
    __besalt_tls_module_count = st->tls_module_count;
    rtld_memset(__besalt_tls_modules, 0, sizeof(__besalt_tls_modules));

    uint64_t tls_index = 0;
    for (struct link_map *map = st->head; map && tls_index < RTLD_MAX_OBJECTS; map = map->next) {
        if (map->tls_module_id == 0)
            continue;

        __besalt_tls_modules[tls_index].module_id = map->tls_module_id;
        __besalt_tls_modules[tls_index].template_addr = map->tls_template;
        __besalt_tls_modules[tls_index].filesz = map->tls_filesz;
        __besalt_tls_modules[tls_index].memsz = map->tls_memsz;
        __besalt_tls_modules[tls_index].tpoff = map->tls_tpoff;
        tls_index++;
    }

    uint64_t tmpl_addr = resolve_symbol_addr(&g_rtld, "__besalt_tls_template");
    if (tmpl_addr != 0)
        *(volatile uint64_t *)tmpl_addr = __besalt_tls_template;
    uint64_t fsz_addr = resolve_symbol_addr(&g_rtld, "__besalt_tls_filesz");
    if (fsz_addr != 0)
        *(volatile uint64_t *)fsz_addr = __besalt_tls_filesz;
    uint64_t msz_addr = resolve_symbol_addr(&g_rtld, "__besalt_tls_memsz");
    if (msz_addr != 0)
        *(volatile uint64_t *)msz_addr = __besalt_tls_memsz;
    uint64_t align_addr = resolve_symbol_addr(&g_rtld, "__besalt_tls_align");
    if (align_addr != 0)
        *(volatile uint64_t *)align_addr = __besalt_tls_align;
    uint64_t count_addr = resolve_symbol_addr(&g_rtld, "__besalt_tls_module_count");
    if (count_addr != 0)
        *(volatile uint64_t *)count_addr = __besalt_tls_module_count;
    uint64_t mods_addr = resolve_symbol_addr(&g_rtld, "__besalt_tls_modules");
    if (mods_addr != 0)
        rtld_memcpy((void *)(uintptr_t)mods_addr, __besalt_tls_modules,
                    sizeof(__besalt_tls_modules));
}

void __attribute__((noreturn)) rtld_main(uint64_t *sp) {
    /* 1. Parse initial stack: argc, argv[], NULL, envp[], NULL, auxv[] */
    uint64_t argc = sp[0];
    uint64_t *argv = &sp[1];

    /* Skip past argv (argc entries + NULL terminator) */
    uint64_t *p = argv + argc + 1;

    /* Skip past envp (entries until NULL) */
    while (*p != 0) p++;
    p++;  /* skip the NULL terminator */

    /* Now p points to auxv array (key/value pairs, terminated by AT_NULL) */
    uint64_t at_phdr = 0;
    uint64_t at_phent = 0;
    uint64_t at_phnum = 0;
    uint64_t at_entry = 0;
    uint64_t at_base = 0;

    for (; p[0] != AT_NULL; p += 2) {
        switch (p[0]) {
        case AT_PHDR:            at_phdr = p[1]; break;
        case AT_PHENT:           at_phent = p[1]; break;
        case AT_PHNUM:           at_phnum = p[1]; break;
        case AT_ENTRY:           at_entry = p[1]; break;
        case AT_BASE:            at_base = p[1]; break;
        case AT_BESALT_UNTYPED:   g_rtld.untyped = p[1]; break;
        case AT_BESALT_VSPACE:    g_rtld.vspace = p[1]; break;
        case AT_BESALT_SCRATCH:   g_rtld.scratch_vaddr = p[1]; break;
        case AT_BESALT_INITRD:    g_rtld.initrd_base = p[1]; break;
        case AT_BESALT_INITRD_SZ: g_rtld.initrd_size = p[1]; break;
        case AT_BESALT_FRAME_SLOT:g_rtld.next_frame_slot = p[1]; break;
        case AT_BESALT_SHARED_LIB_BASE: g_rtld.shared_lib_base = p[1]; break;
        case AT_BESALT_SLOT_BASE:  g_rtld.slot_base = p[1]; break;
        case AT_BESALT_SLOT_COUNT: g_rtld.slot_count = p[1]; break;
        case AT_BESALT_CSPACE_NTFN: g_rtld.cspace_ntfn = p[1]; break;
        }
    }

    /* 2. Self-relocate.
     * at_base is the load address of the rtld itself.
     * Find our own PT_DYNAMIC and apply R_RELATIVE.
     */
    g_rtld.rtld_base = at_base;
    if (at_base != 0) {
        Elf64_Dyn *own_dyn = find_dynamic(at_base);
        if (own_dyn)
            self_relocate(at_base, own_dyn);
    }

    /* Now global data is safe to use */
    rtld_puts("[RTLD] SaltyOS dynamic linker starting\n");

    g_rtld.exe_entry = at_entry;
    g_rtld.exe_phdr = at_phdr;
    g_rtld.exe_phent = at_phent;
    g_rtld.exe_phnum = at_phnum;

    /* 3. Parse executable's .dynamic section.
     * AT_PHDR points to the exe's program headers (already mapped).
     * Walk them to find PT_DYNAMIC.
     */
    Elf64_Phdr *exe_phdrs = (Elf64_Phdr *)at_phdr;
    Elf64_Dyn *exe_dyn = NULL;
    uint64_t exe_base = 0;

    /* Determine exe min vaddr and find PT_DYNAMIC/PT_PHDR.
     * Note: the in-memory phdrs contain original file vaddrs (not relocated),
     * so we need to compute the load delta from PT_PHDR.
     */
    uint64_t exe_min_vaddr = UINT64_MAX;
    uint64_t exe_phdr_vaddr = 0;
    int have_phdr = 0;
    for (uint64_t i = 0; i < at_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((uint8_t *)exe_phdrs + i * at_phent);
        if (ph->p_type == PT_LOAD && ph->p_vaddr < exe_min_vaddr)
            exe_min_vaddr = ph->p_vaddr;
        if (ph->p_type == PT_DYNAMIC)
            exe_dyn = (Elf64_Dyn *)ph->p_vaddr;
        if (ph->p_type == PT_PHDR) {
            exe_phdr_vaddr = ph->p_vaddr;
            have_phdr = 1;
        }
        if (ph->p_type == PT_TLS) {
            g_rtld.exe_tls_filesz = ph->p_filesz;
            g_rtld.exe_tls_memsz  = ph->p_memsz;
            g_rtld.exe_tls_align  = ph->p_align ? ph->p_align : 1;
            /* vaddr needs load delta applied — done below */
            g_rtld.exe_tls_vaddr  = ph->p_vaddr;
        }
    }

    /* Compute load delta: AT_PHDR is the actual runtime address of the phdrs,
     * while exe_phdr_vaddr is the file-level vaddr from the PT_PHDR entry.
     * The difference is the slide applied by the loader.
     */
    uint64_t exe_load_delta = 0;
    if (have_phdr) {
        exe_load_delta = at_phdr - exe_phdr_vaddr;
    } else if (at_phdr >= sizeof(Elf64_Ehdr)) {
        /* Fallback: if no PT_PHDR, try reading the ELF header which is
         * expected immediately before the phdrs (e_phoff == sizeof(Elf64_Ehdr)
         * for all standard ELF64 binaries). Verify via magic bytes.
         */
        Elf64_Ehdr *exe_ehdr = (Elf64_Ehdr *)(at_phdr - sizeof(Elf64_Ehdr));
        if (exe_ehdr->e_ident[0] == 0x7F && exe_ehdr->e_ident[1] == 'E' &&
            exe_ehdr->e_ident[2] == 'L'  && exe_ehdr->e_ident[3] == 'F') {
            exe_load_delta = at_phdr - exe_ehdr->e_phoff;
            rtld_dbg_puts("[RTLD] PT_PHDR missing, computed delta from ELF header\n");
        } else {
            rtld_puts("[RTLD] WARN: no PT_PHDR and ELF header not found\n");
        }
    }

    /* Apply delta to exe_dyn (which was set from the file-level vaddr) */
    if (exe_dyn)
        exe_dyn = (Elf64_Dyn *)((uint64_t)exe_dyn + exe_load_delta);
    exe_base = exe_min_vaddr + exe_load_delta;
    g_rtld.exe_phdr = at_phdr;

    /* Apply delta to TLS template address */
    if (g_rtld.exe_tls_memsz > 0)
        g_rtld.exe_tls_vaddr += exe_load_delta;

    /* Create link_map for executable */
    struct link_map *exe_map = &g_rtld.objects[0];
    exe_map->name = "executable";
    g_rtld.nobjects = 1;
    g_rtld.head = exe_map;

    if (exe_dyn) {
        parse_dynamic(exe_map, exe_dyn, exe_base);
    }
    exe_map->tls_template = g_rtld.exe_tls_vaddr;
    exe_map->tls_filesz = g_rtld.exe_tls_filesz;
    exe_map->tls_memsz = g_rtld.exe_tls_memsz;
    exe_map->tls_align = g_rtld.exe_tls_align ? g_rtld.exe_tls_align : 1;

    /* 4. Load shared libraries: walk exe's DT_NEEDED entries */
    uint64_t lib_load_addr;
    if (g_rtld.shared_lib_base != 0) {
        /* Pre-mapped path: procmgr computed the shared lib base address */
        lib_load_addr = g_rtld.shared_lib_base;
    } else {
        /* Self-loading fallback: compute lib base from RTLD's own load extent.
         * Walk RTLD's phdrs to find max_end, then start libs after a 1-page gap.
         */
        Elf64_Ehdr *rtld_ehdr = (Elf64_Ehdr *)g_rtld.rtld_base;
        Elf64_Phdr *rtld_phdrs = (Elf64_Phdr *)(g_rtld.rtld_base + rtld_ehdr->e_phoff);
        uint64_t rtld_min_vaddr = UINT64_MAX;
        for (int i = 0; i < rtld_ehdr->e_phnum; i++) {
            if (rtld_phdrs[i].p_type == PT_LOAD && rtld_phdrs[i].p_vaddr < rtld_min_vaddr)
                rtld_min_vaddr = rtld_phdrs[i].p_vaddr;
        }
        uint64_t rtld_delta = g_rtld.rtld_base - rtld_min_vaddr;
        uint64_t rtld_max_end = 0;
        for (int i = 0; i < rtld_ehdr->e_phnum; i++) {
            if (rtld_phdrs[i].p_type == PT_LOAD) {
                uint64_t mapped_end = rtld_page_align_up(
                    rtld_phdrs[i].p_vaddr + rtld_delta + rtld_phdrs[i].p_memsz
                );
                if (mapped_end > rtld_max_end) rtld_max_end = mapped_end;
            }
        }
        if (rtld_max_end == 0)
            rtld_max_end = g_rtld.rtld_base + 0x80000ULL; /* conservative fallback */
        lib_load_addr = rtld_max_end + PAGE_SIZE; /* 1-page gap */
    }

    if (exe_dyn) {
        for (int i = 0; exe_dyn[i].d_tag != DT_NULL; i++) {
            if (exe_dyn[i].d_tag == DT_NEEDED) {
                const char *lib_name = exe_map->strtab + exe_dyn[i].d_val;
                int err = load_shared_library(&g_rtld, lib_name, lib_load_addr);
                if (err != 0) {
                    struct rtld_linebuf lb;
                    rtld_lb_init(&lb);
                    rtld_lb_str(&lb, "[RTLD] FATAL: failed to load ");
                    rtld_lb_str(&lb, lib_name);
                    rtld_lb_str(&lb, " err=");
                    rtld_lb_hex(&lb, (uint64_t)err);
                    rtld_lb_str(&lb, "\n");
                    rtld_lb_flush(&lb);
                    rtld_exit(127);
                }

                /* Debug: log successful library load */
                {
                    struct rtld_linebuf dlb;
                    rtld_dbg_lb_init(&dlb);
                    rtld_dbg_lb_str(&dlb, "[RTLD] loaded ");
                    rtld_dbg_lb_str(&dlb, lib_name);
                    rtld_dbg_lb_str(&dlb, " at ");
                    rtld_dbg_lb_hex(&dlb, lib_load_addr);
                    rtld_dbg_lb_str(&dlb, "\n");
                    rtld_dbg_lb_flush(&dlb);
                }

                /* Advance load address by actual library footprint + 1-page gap */
                struct link_map *loaded_map = &g_rtld.objects[g_rtld.nobjects - 1];
                uint64_t advance = loaded_map->load_size;
                if (advance == 0) advance = 0x80000ULL; /* fallback */
                lib_load_addr += advance + PAGE_SIZE;
            }
        }
    }

    finalize_static_tls_layout(&g_rtld);

    /* 5. Process relocations for all loaded objects (libs first, then exe) */
    for (int i = g_rtld.nobjects - 1; i >= 0; i--) {
        struct link_map *map = &g_rtld.objects[i];
        process_relocations(&g_rtld, map);
    }

    /* 6. Setup PLT lazy binding for executable.
     * GOT[0] = address of .dynamic (already set by linker)
     * GOT[1] = pointer to this object's link_map
     * GOT[2] = address of _dl_runtime_resolve
     */
    if (exe_map->pltgot) {
        exe_map->pltgot[1] = (uint64_t)exe_map;
        exe_map->pltgot[2] = (uint64_t)_dl_runtime_resolve;
    }

    /* Also setup lazy binding for loaded libraries */
    for (int i = 1; i < g_rtld.nobjects; i++) {
        struct link_map *map = &g_rtld.objects[i];
        if (map->pltgot) {
            map->pltgot[1] = (uint64_t)map;
            map->pltgot[2] = (uint64_t)_dl_runtime_resolve;
        }
    }

    /* 7. Export frame slot so user code can allocate after rtld.
     * __besalt_next_frame_slot references in user code resolve to libbesalt,
     * so update that symbol explicitly if present. */
    __besalt_next_frame_slot = g_rtld.next_frame_slot;
    {
        uint64_t slot_addr = resolve_symbol_addr(&g_rtld, "__besalt_next_frame_slot");
        if (slot_addr != 0)
            *(volatile uint64_t *)slot_addr = g_rtld.next_frame_slot;
    }

    /* 7b. Export per-process slot pool info for slot_alloc.
     * Advance base/count past the slots already consumed by RTLD itself
     * (ld.so + DT_NEEDED library allocations), so user allocators start
     * from the first truly free slot.
     */
    uint64_t export_slot_base = g_rtld.slot_base;
    uint64_t export_slot_count = g_rtld.slot_count;
    if (export_slot_base != 0 && export_slot_count != 0 &&
        g_rtld.next_frame_slot >= export_slot_base) {
        uint64_t used = g_rtld.next_frame_slot - export_slot_base;
        if (used < export_slot_count) {
            export_slot_base = g_rtld.next_frame_slot;
            export_slot_count -= used;
        } else {
            export_slot_base = g_rtld.next_frame_slot;
            export_slot_count = 0;
        }
    }

    __besalt_slot_base = export_slot_base;
    __besalt_slot_count = export_slot_count;
    {
        uint64_t base_addr = resolve_symbol_addr(&g_rtld, "__besalt_slot_base");
        if (base_addr != 0)
            *(volatile uint64_t *)base_addr = export_slot_base;
        uint64_t count_addr = resolve_symbol_addr(&g_rtld, "__besalt_slot_count");
        if (count_addr != 0)
            *(volatile uint64_t *)count_addr = export_slot_count;
    }

    /* 7c. Export CSpace expansion notification cap for slot_alloc. */
    __besalt_cspace_ntfn = g_rtld.cspace_ntfn;
    {
        uint64_t ntfn_addr = resolve_symbol_addr(&g_rtld, "__besalt_cspace_ntfn");
        if (ntfn_addr != 0)
            *(volatile uint64_t *)ntfn_addr = g_rtld.cspace_ntfn;
    }

    /* 7d. Export combined static TLS layout for libbesalt. */
    export_static_tls_layout(&g_rtld);

    /* 7e. Call shared library constructors (DT_INIT + DT_INIT_ARRAY).
     * Skip index 0 (the executable) -- its .init_array is called by the CRT.
     * Forward order matches dependency order for flat DT_NEEDED loading.
     */
    for (int i = 1; i < g_rtld.nobjects; i++) {
        struct link_map *map = &g_rtld.objects[i];
        if (map->init_fn)
            map->init_fn();
        for (uint64_t j = 0; j < map->init_array_count; j++) {
            if (map->init_array[j])
                map->init_array[j]();
        }
    }

    /* 8. Jump to executable entry point.
     * Process-entry ABI in SaltyOS:
     *   - [RSP+0] = argc
     *   - RSP % 16 == 8 at entry
     * Startup code for both C and Rust relies on this contract.
     */
    rtld_jump_entry((uint64_t)(uintptr_t)sp, (void *)(uintptr_t)g_rtld.exe_entry);
}
