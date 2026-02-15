/* SaltyOS Runtime Dynamic Linker - Entry Point
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Entry point for ld-salty.so. Parses the initial stack (argc/argv/envp/auxv),
 * self-relocates, loads shared libraries from the CPIO initrd, applies
 * relocations, sets up PLT lazy binding, and jumps to the executable entry.
 */

#include "rtld_internal.h"

struct rtld_state g_rtld;

/* Exported so applications can continue allocating frame slots after rtld */
uint64_t __salty_next_frame_slot = 0;

/* Exported per-process slot pool info for slot_alloc */
uint64_t __salty_slot_base = 0;
uint64_t __salty_slot_count = 0;
uint64_t __salty_expand_ep = 0;

void __attribute__((naked, noreturn)) _start(void) {
    __asm__ volatile(
        "mov %%rsp, %%rdi\n"
        "call rtld_main\n"
        : : : "memory"
    );
}

/* Self-relocate the rtld's own R_X86_64_RELATIVE entries.
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
        if (type == R_X86_64_RELATIVE) {
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
        case AT_SALTY_UNTYPED:   g_rtld.untyped = p[1]; break;
        case AT_SALTY_VSPACE:    g_rtld.vspace = p[1]; break;
        case AT_SALTY_SCRATCH:   g_rtld.scratch_vaddr = p[1]; break;
        case AT_SALTY_INITRD:    g_rtld.initrd_base = p[1]; break;
        case AT_SALTY_INITRD_SZ: g_rtld.initrd_size = p[1]; break;
        case AT_SALTY_FRAME_SLOT:g_rtld.next_frame_slot = p[1]; break;
        case AT_SALTY_SHARED_LIB_BASE: g_rtld.shared_lib_base = p[1]; break;
        case AT_SALTY_SLOT_BASE:  g_rtld.slot_base = p[1]; break;
        case AT_SALTY_SLOT_COUNT: g_rtld.slot_count = p[1]; break;
        case AT_SALTY_EXPAND_EP:  g_rtld.expand_ep = p[1]; break;
        }
    }

    /* 2. Self-relocate.
     * at_base is the load address of the rtld itself.
     * Find our own PT_DYNAMIC and apply R_X86_64_RELATIVE.
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
            rtld_puts("[RTLD] PT_PHDR missing, computed delta from ELF header\n");
        } else {
            rtld_puts("[RTLD] WARN: no PT_PHDR and ELF header not found\n");
        }
    }

    /* Apply delta to exe_dyn (which was set from the file-level vaddr) */
    if (exe_dyn)
        exe_dyn = (Elf64_Dyn *)((uint64_t)exe_dyn + exe_load_delta);
    exe_base = exe_min_vaddr + exe_load_delta;
    g_rtld.exe_phdr = at_phdr;

    /* Create link_map for executable */
    struct link_map *exe_map = &g_rtld.objects[0];
    exe_map->name = "executable";
    g_rtld.nobjects = 1;
    g_rtld.head = exe_map;

    if (exe_dyn) {
        parse_dynamic(exe_map, exe_dyn, exe_base);
    }

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

                /* Advance load address by actual library footprint + 1-page gap */
                struct link_map *loaded_map = &g_rtld.objects[g_rtld.nobjects - 1];
                uint64_t advance = loaded_map->load_size;
                if (advance == 0) advance = 0x80000ULL; /* fallback */
                lib_load_addr += advance + PAGE_SIZE;
            }
        }
    }

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
     * __salty_next_frame_slot references in user code resolve to libsalty,
     * so update that symbol explicitly if present. */
    __salty_next_frame_slot = g_rtld.next_frame_slot;
    {
        uint64_t slot_addr = resolve_symbol_addr(&g_rtld, "__salty_next_frame_slot");
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

    __salty_slot_base = export_slot_base;
    __salty_slot_count = export_slot_count;
    {
        uint64_t base_addr = resolve_symbol_addr(&g_rtld, "__salty_slot_base");
        if (base_addr != 0)
            *(volatile uint64_t *)base_addr = export_slot_base;
        uint64_t count_addr = resolve_symbol_addr(&g_rtld, "__salty_slot_count");
        if (count_addr != 0)
            *(volatile uint64_t *)count_addr = export_slot_count;
    }

    /* 7c. Export procmgr expansion EP slot for slot_alloc async expansion. */
    __salty_expand_ep = g_rtld.expand_ep;
    {
        uint64_t ep_addr = resolve_symbol_addr(&g_rtld, "__salty_expand_ep");
        if (ep_addr != 0)
            *(volatile uint64_t *)ep_addr = g_rtld.expand_ep;
    }

    /* 8. Jump to executable entry point.
     * Restore RSP to the original stack (argc/argv/envp/auxv from procmgr)
     * and jump (not call) to the executable entry point.
     * C programs expect standard stack layout at _start; a plain C call
     * would push a return address and clobber the stack pointer.
     */
    __asm__ volatile(
        "mov %0, %%rsp\n"
        "xor %%rbp, %%rbp\n"
        "jmp *%1\n"
        : : "r"(sp), "r"((void *)(uintptr_t)g_rtld.exe_entry)
        : "memory"
    );
    __builtin_unreachable();
}
