/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SaltyOS Bootloader - ELF64 Loader
 *
 * Loads ET_DYN (PIE) ELF64 executables with RELA relocation support.
 */

#ifndef BOOT_STAGE3_ELF_H
#define BOOT_STAGE3_ELF_H

#include "../common/types.h"

/* ELF magic */
#define ELF_MAGIC       0x464C457F  /* "\x7FELF" */

/* ELF class */
#define ELFCLASS32      1
#define ELFCLASS64      2

/* ELF data encoding */
#define ELFDATA2LSB     1   /* Little endian */
#define ELFDATA2MSB     2   /* Big endian */

/* ELF type */
#define ET_NONE         0   /* No file type */
#define ET_REL          1   /* Relocatable file */
#define ET_EXEC         2   /* Executable file */
#define ET_DYN          3   /* Shared object / PIE */
#define ET_CORE         4   /* Core file */

/* ELF machine types */
#define EM_X86_64       62
#define EM_AARCH64      183
#define EM_RISCV        243

/* Program header types */
#define PT_NULL         0   /* Unused */
#define PT_LOAD         1   /* Loadable segment */
#define PT_DYNAMIC      2   /* Dynamic linking info */
#define PT_INTERP       3   /* Interpreter path */
#define PT_NOTE         4   /* Note section */
#define PT_PHDR         6   /* Program header table */
#define PT_GNU_RELRO    0x6474E552
#define PT_GNU_STACK    0x6474E551

/* Program header flags */
#define PF_X            (1 << 0)    /* Executable */
#define PF_W            (1 << 1)    /* Writable */
#define PF_R            (1 << 2)    /* Readable */

/* Section header types */
#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOTE        7
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_DYNSYM      11

/* Dynamic section tags */
#define DT_NULL         0
#define DT_RELA         7
#define DT_RELASZ       8
#define DT_RELAENT      9

/* x86_64 relocation types */
#define R_X86_64_NONE       0
#define R_X86_64_64         1
#define R_X86_64_RELATIVE   8

/* ELF64 header */
struct Elf64_Ehdr {
    uint8_t  e_ident[16];   /* ELF identification */
    uint16_t e_type;        /* Object file type */
    uint16_t e_machine;     /* Machine type */
    uint32_t e_version;     /* Object file version */
    uint64_t e_entry;       /* Entry point address */
    uint64_t e_phoff;       /* Program header offset */
    uint64_t e_shoff;       /* Section header offset */
    uint32_t e_flags;       /* Processor-specific flags */
    uint16_t e_ehsize;      /* ELF header size */
    uint16_t e_phentsize;   /* Program header entry size */
    uint16_t e_phnum;       /* Number of program headers */
    uint16_t e_shentsize;   /* Section header entry size */
    uint16_t e_shnum;       /* Number of section headers */
    uint16_t e_shstrndx;    /* Section name string table index */
} PACKED;

/* ELF64 program header */
struct Elf64_Phdr {
    uint32_t p_type;        /* Segment type */
    uint32_t p_flags;       /* Segment flags */
    uint64_t p_offset;      /* Segment file offset */
    uint64_t p_vaddr;       /* Segment virtual address */
    uint64_t p_paddr;       /* Segment physical address */
    uint64_t p_filesz;      /* Segment size in file */
    uint64_t p_memsz;       /* Segment size in memory */
    uint64_t p_align;       /* Segment alignment */
} PACKED;

/* ELF64 section header */
struct Elf64_Shdr {
    uint32_t sh_name;       /* Section name offset */
    uint32_t sh_type;       /* Section type */
    uint64_t sh_flags;      /* Section flags */
    uint64_t sh_addr;       /* Section virtual address */
    uint64_t sh_offset;     /* Section file offset */
    uint64_t sh_size;       /* Section size */
    uint32_t sh_link;       /* Link to another section */
    uint32_t sh_info;       /* Additional info */
    uint64_t sh_addralign;  /* Section alignment */
    uint64_t sh_entsize;    /* Entry size if table */
} PACKED;

/* ELF64 dynamic entry */
struct Elf64_Dyn {
    int64_t  d_tag;         /* Dynamic entry type */
    uint64_t d_val;         /* Value */
} PACKED;

/* ELF64 relocation entry (RELA) */
struct Elf64_Rela {
    uint64_t r_offset;      /* Address */
    uint64_t r_info;        /* Relocation type and symbol index */
    int64_t  r_addend;      /* Addend */
} PACKED;

/* Relocation info macros */
#define ELF64_R_TYPE(info)  ((uint32_t)(info))
#define ELF64_R_SYM(info)   ((info) >> 32)

/* ELF loading result */
struct ElfLoadResult {
    uint64_t phys_base;     /* Physical load address */
    uint64_t virt_base;     /* Virtual base (min p_vaddr) */
    uint64_t mem_size;      /* Total memory size */
    uint64_t entry;         /* Entry point (relocated) */
    int      error;         /* Error code (0 = success) */
};

/* Error codes */
#define ELF_OK              0
#define ELF_ERR_NOT_ELF     1
#define ELF_ERR_NOT_64BIT   2
#define ELF_ERR_NOT_LE      3
#define ELF_ERR_NOT_DYN     4
#define ELF_ERR_BAD_ARCH    5
#define ELF_ERR_NO_LOAD     6
#define ELF_ERR_RELOC       7
#define ELF_ERR_MEMORY      8

/*
 * Validate ELF header
 *
 * @param ehdr: ELF header to validate
 *
 * Returns: 0 on success, error code otherwise
 */
int elf_validate(const struct Elf64_Ehdr *ehdr);

/*
 * Calculate memory requirements for ELF
 *
 * @param data: ELF file data
 * @param min_vaddr: Output - minimum virtual address
 * @param max_vaddr: Output - maximum virtual address
 *
 * Returns: 0 on success, error code otherwise
 */
int elf_calc_size(const void *data, uint64_t *min_vaddr, uint64_t *max_vaddr);

/*
 * Load ELF file into memory
 *
 * Supports split physical/virtual addressing: segments are copied to
 * physical memory at phys_addr, but relocations are applied using
 * virt_base so the kernel runs correctly in higher-half virtual space.
 *
 * @param data: ELF file data
 * @param data_size: Size of ELF file
 * @param phys_addr: Physical address to copy segments to
 * @param virt_base: Virtual base address for relocations (e.g. KERNEL_VIRT_BASE)
 * @param result: Output - load result
 *
 * Returns: 0 on success, error code otherwise
 */
int elf_load(const void *data, size_t data_size, uint64_t phys_addr,
             uint64_t virt_base, struct ElfLoadResult *result);

#endif /* BOOT_STAGE3_ELF_H */
