# Bootloader Design

SaltyOS uses a custom **three-stage bootloader** designed to operate on constrained systems (≈4 MB RAM), support multiple architectures, and maintain full control over the boot process while allowing optional filesystem-based booting.

The design is inspired by **BSD-style loaders** and **microkernel systems such as seL4**, emphasizing a small trusted computing base, explicit boot contracts, and clear stage responsibilities.

---

## Overview

### Why 3 Stages?

| Stage   | Size Constraint           | Filesystem Access    | Purpose                                    |
| ------- | ------------------------- | -------------------- | ------------------------------------------ |
| Stage 1 | 446 bytes (MBR) / EFI app | None                 | Minimal platform entry, load Stage 2       |
| Stage 2 | ~64 KB                    | None (raw block I/O) | CPU mode setup, block access, load Stage 3 |
| Stage 3 | Bounded (≤ 512 KB target) | Optional             | Load kernel, build BootInfo, handoff       |

The three-stage design exists to satisfy the following constraints:

1. **Firmware limits**

   * BIOS MBR provides only 446 bytes of executable code.
2. **Memory constraints**

   * The bootloader must operate on systems with as little as ~4 MB RAM.
3. **Separation of mechanism and policy**

   * Early stages perform only mechanical setup.
   * Policy (load address selection, relocations, configuration) is isolated to Stage 3.
4. **Optional filesystem support**

   * Filesystems are supported for convenience, not required for correctness.

---

## Boot Flow

```mermaid
graph TD
    A[Power On] --> B{BIOS or UEFI?}
    B -->|BIOS| C[Stage 1: MBR]
    B -->|UEFI| D[Stage 1: EFI Entry]
    
    C --> E[Stage 2]
    D --> E
    
    E --> F[Stage 2: CPU & Block Setup]
    F --> G[Stage 3: Policy Loader]
    
    G --> H[Read Boot Manifest]
    H --> I[Load Kernel (raw extents)]
    I --> J[Optional: FS-based load]
    J --> K[Relocate ET_DYN Kernel]
    K --> L[Build BootInfo]
    L --> M[Jump to Kernel]
```

---

## Boot Storage Model

### Boot Reserved Area (BRA)

All mandatory boot components reside in a **Boot Reserved Area** (BRA):

* Located at a **fixed absolute disk offset**
* Outside all partitions
* Identical for MBR, GPT, and raw media

Recommended default:

```
BRA_START_LBA = 2048  (1 MiB offset)
```

The BRA contains:

* Stage 2
* Stage 3
* Boot Manifest
* Kernel image (raw extents)
* Optional initrd

This avoids dependency on partition parsing and filesystem code in early stages.

---

## Boot Manifest

The **Boot Manifest** is mandatory and always present.

### Purpose

* Acts as the single source of truth for boot contents
* Describes kernel and initrd locations using **raw block extents**
* Eliminates filesystem dependency in the critical boot path

### Properties

* Fixed absolute LBA within the BRA
* Binary, versioned format
* Architecture-independent
* Parsable with minimal memory usage

Filesystem-based booting, if enabled, is layered on top of the manifest rather than replacing it.

---

## Stage 1: Initial Loader

### BIOS Path (MBR)

Stage 1 for BIOS resides in the MBR boot sector.

**Responsibilities:**

1. Establish minimal real-mode environment
2. Load Stage 2 from a fixed LBA via INT 13h
3. Transfer control to Stage 2

Stage 1 contains:

* No filesystem code
* No ELF parsing
* No policy decisions

---

### UEFI Path

Under UEFI, Stage 1 is implemented as an EFI application.

**Responsibilities:**

1. Locate and load Stage 2
2. Preserve firmware state
3. Transfer control to Stage 2

UEFI services are not exited until Stage 3 determines it is safe to do so.

---

## Stage 2: Platform and Block Setup

Stage 2 is responsible for **mechanical platform initialization**.

### Responsibilities

* Enable full address space (A20 or equivalent)
* Establish initial CPU execution mode
* Perform minimal paging setup if required
* Provide a uniform **block device abstraction**
* Load Stage 3 using raw block reads

### Non-Responsibilities

* No filesystem parsing
* No kernel loading
* No relocation logic
* No configuration parsing

Stage 2 must operate within a small, fixed memory budget and avoid dynamic allocation.

---

## Stage 3: Policy Loader

Stage 3 performs all policy-heavy boot logic.

### Responsibilities

1. Read and validate the Boot Manifest
2. Select a physical load address for the kernel
3. Load kernel and initrd via raw extents
4. Perform ELF relocation
5. Construct the BootInfo structure
6. Transfer control to the kernel

Stage 3 is the **only stage** that understands kernel format and boot ABI.

---

## Kernel Loading Model

### Kernel Format

* ELF64
* **ET_DYN (Position Independent Executable)**
* RELA relocations supported
* At minimum, `R_*_RELATIVE` relocations required

This applies uniformly across architectures.

---

### Load Address Selection

* The kernel load address is chosen **at runtime**
* Stage 3 selects a suitable region from the firmware-provided memory map
* No fixed physical address is assumed

Requirements:

* Streaming load (no full-image buffering)
* Alignment preference ≥ 2 MiB
* Avoid low-memory and bootloader-used regions
* Fallback to alternate regions if necessary

---

### Relocation Rules

Let:

```
base      = chosen physical load base
min_vaddr = minimum p_vaddr of PT_LOAD segments
delta     = base - min_vaddr
```

Then:

* Each PT_LOAD segment is loaded at `p_vaddr + delta`
* Entry point becomes `e_entry + delta`
* `R_*_RELATIVE` relocations resolve to `base + addend`

---

## Filesystem Support

Filesystem support is **optional**.

### Mandatory Path

* Kernel loading via **Boot Manifest + raw extents** MUST always work
* No filesystem is required to boot

### Optional Path

* Stage 3 may include filesystem drivers (e.g., SaltyFS, FAT32)
* Filesystems may be used for:

  * Configuration files
  * Snapshot selection
  * Development convenience
* Filesystem failure must not prevent boot via raw extents

Filesystem code must not increase the mandatory memory footprint.

---

## Boot Configuration

If filesystem support is enabled, configuration may be loaded from the filesystem.

Example:

```ini
[default]
entry = main

[main]
kernel = /boot/kernel.elf
initrd = /boot/initrd.img
cmdline = console=serial0
```

Configuration is **non-essential** and ignored if unavailable.

---

## BootInfo Handoff

### Design Principles

* BootInfo is a **stable ABI contract**
* Architecture-neutral
* Extensible without breaking compatibility

### Structure

* Fixed header:

  * Magic
  * Version
  * Architecture ID
  * Pointer width
  * Endianness
* Followed by TLV records

TLVs may include:

* Memory map (filtered)
* Framebuffer info
* ACPI RSDP or device tree
* initrd location
* Command line

All addresses are physical unless specified otherwise.

---

## Memory Constraints

The bootloader must function on systems with approximately **4 MB RAM**.

### Target Budgets

| Component         | Target   |
| ----------------- | -------- |
| Stage 2 workspace | ≤ 256 KB |
| Stage 3 workspace | ≤ 512 KB |
| Debug buffers     | ≤ 16 KB  |

### Prohibited Patterns

* Loading full images into temporary buffers
* Unbounded logging
* Retaining full firmware memory maps verbatim

---

## Multi-Architecture Considerations

Architecture-specific code is limited to:

* CPU mode transitions
* MMU and page table setup
* Cache and barrier operations
* Final kernel entry jump

All other logic (manifest parsing, ELF loading, relocation, BootInfo construction) is architecture-independent.

---

## Non-Goals

The following are explicitly out of scope:

* Secure Boot
* Network boot
* Interactive boot menus
* Mandatory filesystem dependency
* Firmware-specific policy logic

---

## Summary

The SaltyOS bootloader guarantees:

* A consistent three-stage model across BIOS and UEFI
* MBR and GPT compatibility without partition parsing
* ET_DYN kernel support with runtime relocation
* Operation under ~4 MB RAM
* Filesystem-free mandatory boot path
* A stable, extensible BootInfo ABI
