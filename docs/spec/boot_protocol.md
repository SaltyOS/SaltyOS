# SaltyOS Boot Protocol & Bootloader Specification

## 1. Scope and Design Goals

This document defines the **complete boot protocol** for SaltyOS, covering:

* Stage 1 → Stage 2 handoff
* Stage 2 → Stage 3 handoff
* Stage 3 → Kernel handoff
* Boot storage model (Boot Reserved Area + Boot Manifest)
* Kernel loading and relocation rules
* BootInfo ABI

### Design Goals (Normative)

* Preserve a **3-stage boot model** across BIOS and UEFI
* Support **MBR, GPT, and raw media** without mandatory partition parsing
* Provide a **filesystem-free mandatory boot path**
* Support **ET_DYN (PIE) kernels** with runtime relocation
* Operate on systems with as little as **~4 MB RAM**
* Be **multi-architecture aware by construction**
* Keep early stages small, deterministic, and auditable

---

## 2. Boot Storage Model (Mandatory)

### 2.1 Boot Reserved Area (BRA)

All boot-critical components reside in a **Boot Reserved Area (BRA)**:

* Located at a **fixed absolute disk offset**
* Outside all partitions
* Identical layout for MBR, GPT, and raw media

Recommended default:

```
BRA_START_LBA = 2048   // 1 MiB offset
```

BRA may contain:

* Stage 2 image
* Stage 3 image
* Boot Manifest
* Kernel image (raw extents)
* Optional initrd image

No filesystem metadata is required to locate these components.

---

### 2.2 Boot Manifest (Mandatory)

The **Boot Manifest** is the single source of truth for boot contents.

* Always present
* Binary, versioned format
* Architecture-independent
* Describes boot images via **raw block extents**

If booting via the manifest fails, the system is considered non-bootable.

---

## 3. Boot Manifest Format (v1)

### 3.1 Manifest Header

```c
#define BOOT_MANIFEST_MAGIC   0x53414C54594D414EULL  // "SALTYMAN"
#define BOOT_MANIFEST_VERSION 1

struct BootManifestHeader {
    uint64_t magic;
    uint16_t version;
    uint16_t header_size;
    uint32_t manifest_size;

    uint32_t flags;
    uint16_t arch;             // ARCH_*
    uint16_t entry_count;

    uint64_t entry_table_off;
    uint64_t checksum;         // CRC64 (checksum field zeroed)
};
```

Validation of this header is **mandatory**.

---

### 3.2 Manifest Entries

```c
#define MAX_EXTENTS 8

struct ManifestExtent {
    uint64_t lba;
    uint32_t sector_count;
    uint32_t reserved;
};

enum ManifestEntryType {
    MANIFEST_ENTRY_KERNEL = 1,
    MANIFEST_ENTRY_INITRD = 2,
    MANIFEST_ENTRY_STAGE3 = 3,
    MANIFEST_ENTRY_CONFIG = 4,
};

struct BootManifestEntry {
    uint16_t type;
    uint16_t flags;
    uint32_t id;

    uint64_t size_bytes;
    uint64_t load_align;

    uint32_t extent_count;
    uint32_t reserved;

    struct ManifestExtent extents[MAX_EXTENTS];
};
```

#### Entry Rules

* Exactly **one kernel entry MUST exist**
* Kernel entry MUST be `ET_DYN (PIE)`
* initrd and config entries are optional
* Extents are read sequentially and concatenated

---

## 4. Boot Stages

### 4.1 Stage 1 → Stage 2

#### BIOS

* CPU in Real Mode
* `DL` contains boot drive
* Stage 2 loaded at `0x0000:0x8000`
* Interrupts may be enabled

Stage 1 responsibilities:

* Minimal setup
* Load Stage 2 via raw LBA
* Jump to Stage 2

Stage 1 MUST NOT parse filesystems or ELF.

#### UEFI

* Stage 1 is an EFI application
* Stage 2 is loaded as a payload
* Boot Services remain available
* Stage 1 MUST NOT exit Boot Services

---

### 4.2 Stage 2 → Stage 3

Stage 2 performs platform bring-up and block I/O setup.

Stage 2 MUST:

* Enable full address space
* Establish required CPU mode
* Provide raw block read capability
* Load Stage 3
* Pass `Stage2Info` to Stage 3

Stage 2 MUST NOT:

* Load the kernel
* Parse ELF
* Perform relocations

#### Stage2Info

```c
#define STAGE2_MAGIC 0x53544147u  // "STAG"

struct Stage2Info {
    uint32_t magic;
    uint16_t version;
    uint16_t arch;

    uint32_t boot_mode;         // BIOS / UEFI
    uint32_t flags;

    uint64_t manifest_lba;

    uint64_t memmap_addr;
    uint32_t memmap_count;
    uint16_t memmap_entry_size;
    uint8_t  memmap_format;
    uint8_t  reserved;

    uint64_t rsdp_addr;
    uint64_t dtb_addr;
    uint64_t smbios_addr;

    uint64_t framebuffer_addr;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_bpp;
};
```

---

## 5. Stage 3 Responsibilities

Stage 3 is the **policy loader**.

Stage 3 MUST:

1. Read and validate the Boot Manifest
2. Select a physical load base at runtime
3. Load kernel and initrd via raw extents
4. Perform ELF relocations
5. Build BootInfo
6. Transfer control to the kernel

Filesystem support is optional and layered on top.

---

## 6. Kernel Loading Model

### 6.1 Kernel Requirements

* ELF64
* `ET_DYN` (PIE)
* RELA relocations
* No dynamic interpreter

### 6.2 Load Base Selection

* Chosen from usable memory
* Prefer ≥ 2 MiB alignment
* Avoid bootloader regions
* Streaming load only (no full buffering)

### 6.3 Relocation Rules

```
delta = load_base - min(p_vaddr)
```

* Load PT_LOAD segments at `p_vaddr + delta`
* Entry point = `e_entry + delta`
* `R_*_RELATIVE` resolves to `base + addend`

---

## 7. Stage 3 → Kernel Handoff

### Entry State (x86_64)

* Long Mode
* Interrupts disabled
* `RDI` = physical pointer to BootInfo
* `RSP` = initial kernel stack

Paging guarantees are minimal; the kernel must rebuild its own address space.

---

## 8. BootInfo ABI (v1)

BootInfo is a **stable ABI contract**.

### Header

```c
#define BOOTINFO_MAGIC 0x53414C5459424F4FULL  // "SALTYBOO"

struct BootInfoHeader {
    uint64_t magic;
    uint16_t version;
    uint16_t arch;
    uint32_t total_size;
    uint32_t flags;
    uint32_t reserved;
};
```

### TLV Records

```c
struct BootInfoTLV {
    uint16_t type;
    uint16_t reserved;
    uint32_t length;
};
```

### Required TLVs

* `TLV_MEMMAP`
* `TLV_KERNEL_IMAGE`

### Optional TLVs

* `TLV_INITRD`
* `TLV_CMDLINE`
* `TLV_FRAMEBUFFER`
* `TLV_ACPI_RSDP`
* `TLV_DTB`

All addresses are physical.

---

## 9. Memory Constraints

Target system: **~4 MB RAM**

| Component     | Budget   |
| ------------- | -------- |
| Stage 2       | ≤ 256 KB |
| Stage 3       | ≤ 512 KB |
| Debug buffers | ≤ 16 KB  |

Unbounded allocation is forbidden.

---

## 10. Multi-Architecture Policy

Architecture-specific code is limited to:

* CPU mode transitions
* MMU setup
* Cache/barrier operations
* Final kernel entry

All other logic is architecture-neutral.

---

## 11. Non-Goals

* Secure Boot
* Network boot
* Interactive boot menus
* Mandatory filesystem dependency

---

## 12. Summary (Normative Guarantees)

This specification guarantees:

* Deterministic 3-stage boot
* MBR/GPT/raw compatibility
* Filesystem-free mandatory boot path
* PIE kernel support with relocation
* Stable, extensible boot ABI
* Operation under tight memory constraints
