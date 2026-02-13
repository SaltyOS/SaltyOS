/* SaltyOS Runtime Dynamic Linker (ld-salty.so) - Internal Header
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Self-contained header: rtld has NO external dependencies.
 * All string functions, syscall stubs, ELF types, and CPIO parsing
 * are defined inline here.
 */

#ifndef RTLD_INTERNAL_H
#define RTLD_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * Debug output (via DebugPutStr batch syscall)
 * ============================================================ */

#define SYS_DEBUG_PUTCHAR  10
#define SYS_DEBUG_PUTBUF   15

static inline void rtld_putc(char c) {
    register uint64_t r10 __asm__("r10") = 0;
    register uint64_t r8  __asm__("r8")  = 0;
    register uint64_t r9  __asm__("r9")  = 0;
    __asm__ volatile("syscall"
        : : "a"((uint64_t)SYS_DEBUG_PUTCHAR), "D"((uint64_t)(unsigned char)c),
            "S"((uint64_t)0), "d"((uint64_t)0),
            "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
}

/* Write a string atomically via DebugPutBuf (pointer + length, up to 256 bytes).
 * The kernel copies from user memory and outputs under SERIAL_LOCK. */
static inline void rtld_puts(const char *s) {
    size_t len = 0;
    const char *p = s;
    while (*p++) len++;

    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;

        register uint64_t r10 __asm__("r10") = 0;
        register uint64_t r8  __asm__("r8")  = 0;
        register uint64_t r9  __asm__("r9")  = 0;
        __asm__ volatile("syscall"
            : : "a"((uint64_t)SYS_DEBUG_PUTBUF),
                "D"((uint64_t)(uintptr_t)(s + off)),
                "S"((uint64_t)chunk), "d"((uint64_t)0),
                "r"(r10), "r"(r8), "r"(r9)
            : "rcx", "r11", "memory");
        off += chunk;
    }
}

/* Write hex number atomically via a single rtld_puts call */
static inline void rtld_hex(uint64_t val) {
    static const char hextab[] = "0123456789abcdef";
    char buf[18]; /* "0x" + up to 16 digits */
    buf[0] = '0';
    buf[1] = 'x';
    if (val == 0) {
        buf[2] = '0';
        buf[3] = '\0';
        rtld_puts(buf);
        return;
    }
    char tmp[16];
    int pos = 15;
    while (val > 0 && pos >= 0) {
        tmp[pos--] = hextab[val & 0xF];
        val >>= 4;
    }
    int idx = 2;
    for (int i = pos + 1; i < 16; i++)
        buf[idx++] = tmp[i];
    buf[idx] = '\0';
    rtld_puts(buf);
}

/* Line buffer for compound output (build a full line, flush atomically) */
struct rtld_linebuf {
    char buf[128];
    int pos;
};

static inline void rtld_lb_init(struct rtld_linebuf *lb) {
    lb->pos = 0;
}

static inline void rtld_lb_str(struct rtld_linebuf *lb, const char *s) {
    while (*s && lb->pos < (int)sizeof(lb->buf) - 1)
        lb->buf[lb->pos++] = *s++;
}

static inline void rtld_lb_hex(struct rtld_linebuf *lb, uint64_t val) {
    static const char ht[] = "0123456789abcdef";
    rtld_lb_str(lb, "0x");
    if (val == 0) {
        if (lb->pos < (int)sizeof(lb->buf) - 1) lb->buf[lb->pos++] = '0';
        return;
    }
    char tmp[16];
    int p = 15;
    while (val > 0 && p >= 0) {
        tmp[p--] = ht[val & 0xF];
        val >>= 4;
    }
    for (int i = p + 1; i < 16 && lb->pos < (int)sizeof(lb->buf) - 1; i++)
        lb->buf[lb->pos++] = tmp[i];
}

static inline void rtld_lb_flush(struct rtld_linebuf *lb) {
    lb->buf[lb->pos] = '\0';
    rtld_puts(lb->buf);
    lb->pos = 0;
}

/* ============================================================
 * String functions (self-contained)
 * ============================================================ */

static inline size_t rtld_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static inline int rtld_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *(unsigned char *)a - *(unsigned char *)b;
}

static inline int rtld_strncmp(const char *a, const char *b, size_t n) {
    while (n && *a && *a == *b) { a++; b++; n--; }
    if (n == 0) return 0;
    return *(unsigned char *)a - *(unsigned char *)b;
}

static inline void *rtld_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void *rtld_memset(void *dst, int c, size_t n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

/* ============================================================
 * SaltyOS Syscall ABI (from salty.h)
 * ============================================================ */

#define SYS_SEND        0
#define SYS_RECV        1
#define SYS_CALL        2
#define SYS_REPLY_RECV  3
#define SYS_NBSEND      4
#define SYS_SIGNAL      5
#define SYS_WAIT        6
#define SYS_POLL        7
#define SYS_YIELD       8
#define SYS_INVOKE      9

/* Invocation labels */
#define UNTYPED_RETYPE      0x20
#define VSPACE_MAP          0x50
#define VSPACE_UNMAP        0x51
#define VSPACE_MAP_DEVICE   0x55

/* Object types */
#define OBJ_FRAME  7

/* Frame size */
#define FRAME_SIZE_BITS  12
#define PAGE_SIZE        4096

/* VSpace map flags */
#define VSPACE_FLAG_WRITABLE      (1 << 0)
#define VSPACE_FLAG_USER          (1 << 1)
#define VSPACE_FLAG_EXECUTABLE    (1 << 2)

typedef uint64_t cap_t;
/* Well-known child cap slot for initrd pseudo-device untyped */
#define CAP_INITRD_UNTYPED  12
#define CAP_UNTYPED_START   16
#define CAP_UNTYPED_END     24

/* Salty error codes used for fallback filtering */
#define SALTY_INVALID_CAPABILITY  1
#define SALTY_INVALID_OPERATION   2
#define SALTY_OUT_OF_MEMORY       5
#define SALTY_NOT_FOUND           6

struct rtld_syscall_result {
    uint64_t error;
    uint64_t value;
};

static inline struct rtld_syscall_result rtld_syscall(
    uint64_t syscall_num, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5
) {
    struct rtld_syscall_result result;
    register uint64_t r10 __asm__("r10") = a3;
    register uint64_t r8  __asm__("r8")  = a4;
    register uint64_t r9  __asm__("r9")  = a5;
    __asm__ volatile("syscall"
        : "=a"(result.error), "=d"(result.value)
        : "a"(syscall_num), "D"(a0), "S"(a1), "d"(a2),
          "r"(r10), "r"(r8), "r"(r9)
        : "rcx", "r11", "memory");
    return result;
}

static inline uint64_t rtld_invoke(cap_t cap, uint64_t label,
                                    uint64_t a0, uint64_t a1,
                                    uint64_t a2, uint64_t a3) {
    struct rtld_syscall_result r = rtld_syscall(SYS_INVOKE, cap, label,
                                                 a0, a1, a2, a3);
    return r.error;
}

static inline uint64_t rtld_retype_frame(cap_t untyped, uint64_t dest_slot) {
    return rtld_invoke(untyped, UNTYPED_RETYPE, OBJ_FRAME, 0, dest_slot, 0);
}

static inline uint64_t rtld_vspace_map(cap_t vspace, cap_t frame,
                                        uint64_t vaddr, uint64_t flags) {
    return rtld_invoke(vspace, VSPACE_MAP, frame, vaddr, flags, 0);
}

static inline uint64_t rtld_vspace_unmap(cap_t vspace, uint64_t vaddr) {
    return rtld_invoke(vspace, VSPACE_UNMAP, vaddr, 0, 0, 0);
}

static inline uint64_t rtld_vspace_map_device(cap_t vspace, cap_t dev_ut,
                                               uint64_t page_offset,
                                               uint64_t vaddr, uint64_t flags) {
    return rtld_invoke(vspace, VSPACE_MAP_DEVICE, dev_ut, page_offset, vaddr, flags);
}

static inline void rtld_yield(void) {
    rtld_syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
}

/* ============================================================
 * ELF64 Types
 * ============================================================ */

typedef struct {
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
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} Elf64_Dyn;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
} Elf64_Sym;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

/* ELF segment types */
#define PT_NULL     0
#define PT_LOAD     1
#define PT_DYNAMIC  2
#define PT_INTERP   3
#define PT_PHDR     6

/* ELF permission flags */
#define PF_X  0x1
#define PF_W  0x2
#define PF_R  0x4

/* ELF types */
#define ET_EXEC  2
#define ET_DYN   3

/* ELF machine */
#define EM_X86_64  62

/* Dynamic tags */
#define DT_NULL       0
#define DT_NEEDED     1
#define DT_PLTRELSZ   2
#define DT_PLTGOT     3
#define DT_HASH       4
#define DT_STRTAB     5
#define DT_SYMTAB     6
#define DT_RELA       7
#define DT_RELASZ     8
#define DT_RELAENT    9
#define DT_STRSZ      10
#define DT_SYMENT     11
#define DT_INIT       12
#define DT_FINI       13
#define DT_SONAME     14
#define DT_SYMBOLIC   16
#define DT_REL        17
#define DT_JMPREL     23
#define DT_GNU_HASH   0x6ffffef5

/* Relocation types */
#define R_X86_64_NONE       0
#define R_X86_64_64         1
#define R_X86_64_GLOB_DAT   6
#define R_X86_64_JUMP_SLOT  7
#define R_X86_64_RELATIVE   8

/* ELF macros */
#define ELF64_R_TYPE(info) ((uint32_t)((info) & 0xFFFFFFFF))
#define ELF64_R_SYM(info)  ((uint32_t)((info) >> 32))

#define ELF64_ST_BIND(info) ((info) >> 4)
#define ELF64_ST_TYPE(info) ((info) & 0xF)

#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2

#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2

#define SHN_UNDEF  0

/* ============================================================
 * Auxiliary vector types
 * ============================================================ */

#define AT_NULL    0
#define AT_PHDR    3
#define AT_PHENT   4
#define AT_PHNUM   5
#define AT_PAGESZ  6
#define AT_BASE    7
#define AT_ENTRY   9

/* SaltyOS custom auxv types */
#define AT_SALTY_UNTYPED     0x1000
#define AT_SALTY_VSPACE      0x1001
#define AT_SALTY_SCRATCH     0x1002
#define AT_SALTY_INITRD      0x1003
#define AT_SALTY_INITRD_SZ   0x1004
#define AT_SALTY_FRAME_SLOT  0x1005
#define AT_SALTY_SHARED_LIB_BASE  0x1006

/* ============================================================
 * CPIO parser (inline, self-contained)
 * ============================================================ */

#define CPIO_HEADER_SIZE  110

struct rtld_cpio_entry {
    const char *name;
    size_t name_len;
    const uint8_t *data;
    size_t data_len;
};

static inline size_t rtld_cpio_parse_hex8(const uint8_t *bytes) {
    size_t val = 0;
    for (int i = 0; i < 8; i++) {
        uint8_t b = bytes[i];
        size_t digit;
        if (b >= '0' && b <= '9')      digit = b - '0';
        else if (b >= 'a' && b <= 'f') digit = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') digit = b - 'A' + 10;
        else return 0;
        val = (val << 4) | digit;
    }
    return val;
}

static inline size_t rtld_cpio_align4(size_t n) {
    return (n + 3) & ~(size_t)3;
}

static inline int rtld_cpio_find(const uint8_t *archive, size_t archive_len,
                                  const char *name, struct rtld_cpio_entry *entry) {
    size_t name_len = rtld_strlen(name);
    size_t offset = 0;

    for (;;) {
        if (offset + CPIO_HEADER_SIZE > archive_len)
            return 0;

        const uint8_t *header = archive + offset;

        /* Verify magic "070701" */
        if (header[0] != '0' || header[1] != '7' || header[2] != '0' ||
            header[3] != '7' || header[4] != '0' || header[5] != '1')
            return 0;

        size_t namesize = rtld_cpio_parse_hex8(header + 94);
        size_t filesize = rtld_cpio_parse_hex8(header + 54);

        size_t name_start = offset + CPIO_HEADER_SIZE;
        if (name_start + namesize > archive_len)
            return 0;

        const uint8_t *entry_name = archive + name_start;
        size_t entry_name_len = namesize;
        if (entry_name_len > 0 && entry_name[entry_name_len - 1] == 0)
            entry_name_len--;

        /* Check for TRAILER!!! */
        if (entry_name_len == 10 &&
            entry_name[0] == 'T' && entry_name[1] == 'R' &&
            entry_name[2] == 'A' && entry_name[3] == 'I' &&
            entry_name[4] == 'L' && entry_name[5] == 'E' &&
            entry_name[6] == 'R' && entry_name[7] == '!' &&
            entry_name[8] == '!' && entry_name[9] == '!')
            return 0;

        size_t data_start = rtld_cpio_align4(offset + CPIO_HEADER_SIZE + namesize);
        size_t data_end = data_start + filesize;

        if (data_end > archive_len)
            return 0;

        /* Compare names */
        if (entry_name_len == name_len) {
            int match = 1;
            for (size_t i = 0; i < name_len; i++) {
                if (entry_name[i] != (uint8_t)name[i]) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                entry->name = (const char *)entry_name;
                entry->name_len = entry_name_len;
                entry->data = archive + data_start;
                entry->data_len = filesize;
                return 1;
            }
        }

        offset = rtld_cpio_align4(data_end);
    }
}

/* ============================================================
 * link_map -- one per loaded ELF object
 * ============================================================ */

struct link_map {
    uint64_t    base;       /* Load base address */
    const char *name;       /* Object name */
    Elf64_Sym  *symtab;     /* DT_SYMTAB */
    uint64_t    symtab_count;
    uint64_t    sym_ent_size;
    const char *strtab;     /* DT_STRTAB */
    uint64_t    strtab_size;
    uint32_t   *gnu_hash;   /* DT_GNU_HASH */
    Elf64_Rela *jmprel;     /* DT_JMPREL (PLT relocations) */
    uint64_t    jmprel_count;
    uint64_t   *pltgot;     /* DT_PLTGOT */
    Elf64_Rela *rela;       /* DT_RELA (non-PLT relocations) */
    uint64_t    rela_count;
    uint64_t    load_size;  /* Page-aligned total footprint in VA */
    struct link_map *next;
};

/* ============================================================
 * rtld_state -- global dynamic linker state
 * ============================================================ */

#define RTLD_MAX_OBJECTS  8

struct rtld_state {
    struct link_map objects[RTLD_MAX_OBJECTS];
    int nobjects;
    struct link_map *head;  /* Linked list head (exe first) */

    /* Caps from auxv */
    cap_t    untyped;
    cap_t    vspace;
    uint64_t scratch_vaddr;
    uint64_t initrd_base;
    uint64_t initrd_size;
    uint64_t next_frame_slot;

    /* Exe info from auxv */
    uint64_t exe_entry;
    uint64_t exe_phdr;
    uint64_t exe_phent;
    uint64_t exe_phnum;
    uint64_t rtld_base;

    /* Shared library pre-mapping (0 if not pre-mapped) */
    uint64_t shared_lib_base;
};

extern struct rtld_state g_rtld;

/* ============================================================
 * Function declarations
 * ============================================================ */

void parse_dynamic(struct link_map *map, Elf64_Dyn *dyn, uint64_t base);
int load_shared_library(struct rtld_state *st, const char *name, uint64_t load_addr);
uint64_t resolve_symbol_addr(struct rtld_state *st, const char *name);
uint64_t gnu_hash_lookup(struct link_map *map, const char *name);
uint64_t linear_lookup(struct link_map *map, const char *name);
int process_relocations(struct rtld_state *st, struct link_map *map);
uint64_t _dl_fixup(struct link_map *map, uint64_t reloc_index);

/* Defined in rtld_resolve.S */
extern void _dl_runtime_resolve(void);

/* Page alignment helpers */
static inline uint64_t rtld_page_align_down(uint64_t v) {
    return v & ~(uint64_t)(PAGE_SIZE - 1);
}

static inline uint64_t rtld_page_align_up(uint64_t v) {
    return (v + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
}

/* Convert ELF p_flags to VSpace mapping flags */
static inline uint64_t rtld_elf_to_vspace_flags(uint32_t p_flags) {
    uint64_t flags = VSPACE_FLAG_USER;
    if (p_flags & PF_W) flags |= VSPACE_FLAG_WRITABLE;
    if (p_flags & PF_X) flags |= VSPACE_FLAG_EXECUTABLE;
    return flags;
}

#endif /* RTLD_INTERNAL_H */
