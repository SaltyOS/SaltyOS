# Boot Protocol Specification

This document defines the protocol between the bootloader stages and the kernel.

## Overview

The boot protocol defines:
1. How Stage 1 transfers to Stage 2
2. How Stage 2 transfers to Stage 3
3. How Stage 3 transfers to the kernel
4. The BootInfo structure passed to the kernel

## Stage Transitions

### Stage 1 → Stage 2 (BIOS)

**Entry State:**
- CPU in Real Mode (16-bit)
- `DL` = Boot drive number
- `CS:IP` = 0x0000:0x8000 (Stage 2 load address)
- A20 line may or may not be enabled
- Interrupts enabled

**Memory Layout:**
```
0x00000 - 0x00500  BIOS Data Area
0x00500 - 0x07BFF  Free (Stack)
0x07C00 - 0x07DFF  Stage 1 (MBR)
0x07E00 - 0x07FFF  Free
0x08000 - 0x17FFF  Stage 2 (64 KB)
0x18000 - 0x9FFFF  Free (Extended)
0xA0000 - 0xFFFFF  BIOS/Video Memory
```

### Stage 1 → Stage 2 (UEFI)

For UEFI, Stage 1 and Stage 2 are typically combined into a single EFI application.

**Entry State:**
- CPU in Long Mode (64-bit)
- UEFI Boot Services available
- Memory map available via GetMemoryMap()

### Stage 2 → Stage 3

**Entry State:**
- CPU in Long Mode (64-bit)
- Paging enabled (identity mapping for first 4GB minimum)
- A20 enabled
- Interrupts disabled
- `RDI` = Pointer to Stage2Info structure

**Stage2Info Structure:**

```c
#define STAGE2_MAGIC 0x53544147  // "STAG"

struct Stage2Info {
    uint32_t magic;             // STAGE2_MAGIC
    uint32_t version;           // Protocol version (1)
    
    // Boot mode
    uint32_t boot_mode;         // 0=BIOS, 1=UEFI
    uint32_t reserved1;
    
    // Memory map
    uint64_t memory_map_addr;   // Pointer to memory map
    uint64_t memory_map_size;   // Size in bytes
    uint64_t memory_map_entry_size;
    uint32_t memory_map_version;
    uint32_t reserved2;
    
    // Stage 3 location (if loaded by Stage 2)
    uint64_t stage3_addr;       // 0 if not applicable
    uint64_t stage3_size;
    
    // Boot drive info
    uint8_t  boot_drive;        // BIOS drive number
    uint8_t  reserved3[7];
    
    // Partition info
    uint64_t root_partition_lba;
    uint64_t root_partition_size;
    
    // UEFI specific
    uint64_t efi_system_table;  // EFI_SYSTEM_TABLE pointer (UEFI only)
    
    // ACPI
    uint64_t rsdp_addr;         // ACPI RSDP address
    
    // Framebuffer (optional)
    uint64_t framebuffer_addr;
    uint32_t framebuffer_width;
    uint32_t framebuffer_height;
    uint32_t framebuffer_pitch;
    uint32_t framebuffer_bpp;
    uint32_t framebuffer_type;  // 0=none, 1=RGB, 2=indexed
    uint32_t reserved4;
};
```

### Stage 3 → Kernel

**Entry State:**
- CPU in Long Mode (64-bit)
- Paging enabled with kernel mapped at higher half
- Interrupts disabled
- `RDI` = Physical address of BootInfo structure
- `RSP` = Initial kernel stack pointer

**Memory Layout at Kernel Entry:**
```
Virtual Address              Physical Address
────────────────────────────────────────────────
0xFFFFFFFF80000000+         Kernel .text/.rodata/.data/.bss
                            (loaded from ELF)

0xFFFF800000000000+         All physical memory
                            (direct mapping)

0x0000000000000000+         Identity mapping (first 4GB)
                            (temporary, kernel removes)
```

## BootInfo Structure

The BootInfo structure is passed to the kernel in physical memory. The kernel must copy it to a safe location before reclaiming bootloader memory.

### Definition

```c
#define BOOTINFO_MAGIC 0x53414C5459424F4F  // "SALTYBOOT"
#define BOOTINFO_VERSION 1

struct BootInfo {
    // Header (offset 0x000)
    uint64_t magic;             // BOOTINFO_MAGIC
    uint32_t version;           // BOOTINFO_VERSION
    uint32_t size;              // Total size of BootInfo
    uint32_t flags;             // Feature flags
    uint32_t reserved;
    
    // Memory map (offset 0x018)
    uint64_t memory_map_addr;   // Physical address of memory map
    uint32_t memory_map_entries;// Number of entries
    uint32_t memory_map_entry_size;
    
    // Kernel location (offset 0x028)
    uint64_t kernel_phys_start; // Kernel physical start
    uint64_t kernel_phys_end;   // Kernel physical end
    uint64_t kernel_virt_start; // Kernel virtual base (0xFFFFFFFF80000000)
    uint64_t kernel_entry;      // Kernel entry point
    
    // initrd (offset 0x048)
    uint64_t initrd_phys_start; // initrd physical address
    uint64_t initrd_size;       // initrd size in bytes
    
    // Page tables (offset 0x058)
    uint64_t pml4_phys;         // PML4 table physical address
    
    // ACPI (offset 0x060)
    uint64_t rsdp_addr;         // ACPI RSDP physical address
    
    // Framebuffer (offset 0x068)
    struct FramebufferInfo framebuffer;
    
    // SMBIOS (offset 0x090)
    uint64_t smbios_addr;       // SMBIOS entry point (0 if not found)
    
    // Command line (offset 0x098)
    uint64_t cmdline_addr;      // Physical address of command line
    uint32_t cmdline_size;      // Command line length
    uint32_t reserved2;
    
    // Boot device (offset 0x0A8)
    struct BootDevice boot_device;
    
    // Timestamps (offset 0x0C8)
    uint64_t boot_timestamp;    // TSC at boot
    uint64_t tsc_frequency;     // TSC frequency (if known)
    
    // Reserved for future use (offset 0x0D8)
    uint64_t reserved3[5];
};
```

### Flags

```c
#define BOOTINFO_FLAG_UEFI          (1 << 0)  // Booted via UEFI
#define BOOTINFO_FLAG_FRAMEBUFFER   (1 << 1)  // Framebuffer available
#define BOOTINFO_FLAG_INITRD        (1 << 2)  // initrd present
#define BOOTINFO_FLAG_ACPI          (1 << 3)  // ACPI available
#define BOOTINFO_FLAG_SMBIOS        (1 << 4)  // SMBIOS available
```

### Memory Map Entry

```c
struct MemoryMapEntry {
    uint64_t base;              // Physical base address
    uint64_t size;              // Size in bytes
    uint32_t type;              // Memory type
    uint32_t attributes;        // Memory attributes
};

// Memory types (compatible with E820 and UEFI)
#define MEMORY_TYPE_USABLE              1
#define MEMORY_TYPE_RESERVED            2
#define MEMORY_TYPE_ACPI_RECLAIMABLE    3
#define MEMORY_TYPE_ACPI_NVS            4
#define MEMORY_TYPE_BAD                 5
#define MEMORY_TYPE_BOOTLOADER          0x1000  // Bootloader code/data
#define MEMORY_TYPE_KERNEL              0x1001  // Kernel code/data
#define MEMORY_TYPE_INITRD              0x1002  // initrd
#define MEMORY_TYPE_PAGE_TABLES         0x1003  // Boot page tables
#define MEMORY_TYPE_FRAMEBUFFER         0x1004  // Framebuffer

// Attributes
#define MEMORY_ATTR_UNCACHEABLE         (1 << 0)
#define MEMORY_ATTR_WRITE_COMBINING     (1 << 1)
#define MEMORY_ATTR_WRITE_THROUGH       (1 << 2)
#define MEMORY_ATTR_WRITE_BACK          (1 << 3)
```

### Framebuffer Info

```c
struct FramebufferInfo {
    uint64_t addr;              // Framebuffer physical address
    uint32_t width;             // Width in pixels
    uint32_t height;            // Height in pixels
    uint32_t pitch;             // Bytes per scanline
    uint32_t bpp;               // Bits per pixel
    uint8_t  red_mask_size;
    uint8_t  red_mask_shift;
    uint8_t  green_mask_size;
    uint8_t  green_mask_shift;
    uint8_t  blue_mask_size;
    uint8_t  blue_mask_shift;
    uint16_t reserved;
};
```

### Boot Device

```c
struct BootDevice {
    uint8_t  type;              // Device type
    uint8_t  reserved[3];
    uint32_t partition;         // Partition number
    uint64_t partition_lba;     // Partition start LBA
    uint64_t partition_size;    // Partition size in sectors
    uint8_t  uuid[16];          // Partition UUID (if GPT)
};

// Device types
#define BOOT_DEVICE_BIOS_DISK   0
#define BOOT_DEVICE_AHCI        1
#define BOOT_DEVICE_NVME        2
#define BOOT_DEVICE_VIRTIO      3
#define BOOT_DEVICE_USB         4
```

## Configuration File Format

Stage 3 reads `/boot/saltyos.cfg` from SaltyFS:

```ini
# SaltyOS Boot Configuration

# Default entry to boot
default = main

# Timeout in seconds (0 = no timeout, -1 = wait forever)
timeout = 5

# Main entry
[main]
title = SaltyOS
kernel = /boot/kernel.elf
initrd = /boot/initrd.img
cmdline = console=serial0 loglevel=info

# Debug entry
[debug]
title = SaltyOS (Debug)
kernel = /boot/kernel.elf
initrd = /boot/initrd.img
cmdline = console=serial0 loglevel=debug debug_shell

# Recovery from snapshot
[recovery]
title = SaltyOS (Recovery)
snapshot = last
kernel = /boot/kernel.elf
initrd = /boot/initrd-recovery.img
cmdline = console=serial0 single
```

### Configuration Keys

| Key | Description |
|-----|-------------|
| `default` | Name of default entry |
| `timeout` | Seconds to wait (global) |
| `title` | Display name (per entry) |
| `kernel` | Path to kernel ELF |
| `initrd` | Path to initial ramdisk |
| `cmdline` | Kernel command line |
| `snapshot` | Snapshot ID or "last" |

## Command Line Parameters

The kernel parses the command line for boot options:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `console=X` | Console device (serial0, fb) | serial0 |
| `loglevel=X` | Log level (error,warn,info,debug,trace) | info |
| `mem=X` | Limit memory to X MB | all |
| `maxcpus=X` | Limit CPUs | all |
| `init=X` | Init program path | /sbin/init |
| `root=X` | Root device | boot device |
| `single` | Single-user mode | no |
| `debug_shell` | Drop to debug shell early | no |
| `noacpi` | Disable ACPI | no |
| `nolapic` | Disable local APIC | no |

## Kernel ELF Requirements

The kernel ELF must:

1. Be a 64-bit ELF (`EI_CLASS = ELFCLASS64`)
2. Be statically linked (no dynamic sections)
3. Have virtual addresses in higher half (`>= 0xFFFFFFFF80000000`)
4. Have a valid entry point
5. Not exceed available physical memory

### Typical Memory Layout

```
┌───────────────────────────────────────────────────────────────┐
│  .text                     0xFFFFFFFF80100000                 │
│  (Executable code)                                            │
├───────────────────────────────────────────────────────────────┤
│  .rodata                   0xFFFFFFFF80200000                 │
│  (Read-only data)                                             │
├───────────────────────────────────────────────────────────────┤
│  .data                     0xFFFFFFFF80300000                 │
│  (Initialized data)                                           │
├───────────────────────────────────────────────────────────────┤
│  .bss                      0xFFFFFFFF80400000                 │
│  (Uninitialized data)                                         │
└───────────────────────────────────────────────────────────────┘
```

## initrd Format

The initial ramdisk is a simple archive containing initial userspace:

### Header

```c
struct InitrdHeader {
    uint8_t  magic[8];          // "SALTYRD\0"
    uint32_t version;
    uint32_t num_files;
    uint64_t total_size;
};

struct InitrdFileEntry {
    char     name[256];         // Null-terminated path
    uint64_t offset;            // Offset from initrd start
    uint64_t size;              // File size
    uint32_t mode;              // File mode
    uint32_t reserved;
};
```

### Contents

Typical initrd contains:
```
/init                   # Init process
/sbin/procmgr           # Process manager
/sbin/vfs               # VFS server
/sbin/console           # Console driver
/lib/libsalty.so        # System library
```

## Bootloader Memory Allocation

The bootloader must track which memory regions it uses:

| Region | Purpose | Memory Type |
|--------|---------|-------------|
| 0x8000-0x17FFF | Stage 2 code | BOOTLOADER |
| 0x100000-0x1FFFFF | Stage 3 code/data | BOOTLOADER |
| 0x200000-0x3FFFFF | Page tables | PAGE_TABLES |
| varies | Kernel image | KERNEL |
| varies | initrd | INITRD |
| varies | BootInfo | BOOTLOADER |
| varies | Memory map | BOOTLOADER |

After kernel init, BOOTLOADER and PAGE_TABLES regions can be reclaimed as usable memory.

## Error Handling

### Stage 2 Errors

Stage 2 displays errors via BIOS INT 10h or UEFI ConOut:

```
SaltyOS Stage 2 Error
──────────────────────
E01: Cannot read Stage 3
E02: Stage 3 checksum mismatch
E03: Not enough memory
E04: CPU does not support long mode
E05: A20 line cannot be enabled
```

### Stage 3 Errors

```
SaltyOS Stage 3 Error
──────────────────────
E10: Cannot mount filesystem
E11: Configuration file not found
E12: Kernel not found
E13: Kernel is not a valid ELF
E14: initrd not found
E15: Out of memory
E16: Cannot create page tables
```

### Recovery

On error, Stage 3 should:
1. Display error message
2. Wait for keypress
3. Attempt to reboot or halt
