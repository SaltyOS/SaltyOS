/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Boot info handoff.
 *
 * The bootloader hands the kernel a TLV-encoded BootInfo block; the
 * kernel walks the tags during `kmain` to discover memory layout,
 * framebuffer, ACPI / DTB pointers, and the initrd payload.
 *
 * Tag values are stable ABI between the bootloader and kernel within
 * a single KERNITE_ABI_VERSION; userland never sees these directly,
 * so they live in the UAPI header only because the bootloader is a
 * separate codebase that links against the same surface.
 */

#ifndef KERNITE_UAPI_BOOT_H
#define KERNITE_UAPI_BOOT_H

#include <stdint.h>

#define KERNITE_BOOTINFO_MAGIC 0x4B45524E49544532ULL /* "KERNITE2" */

/* Init-visible mapping of the bootinfo page.
 *
 * The kernel maps a single read-only page of the BootInfo block at this
 * fixed virtual address during PID1 bootstrap. Normal services receive
 * curated startup metadata through AT_SALTYOS_STARTUP instead of reading
 * this page directly. Walking the TLV structure starts at offset 0; the
 * first 8 bytes are the magic above. */
#define KERNITE_BOOTINFO_VADDR 0x00000000001FF000ULL

#define KERNITE_BOOTINFO_TAG_END         0u
#define KERNITE_BOOTINFO_TAG_MEMORY_MAP  1u
#define KERNITE_BOOTINFO_TAG_FRAMEBUFFER 2u
#define KERNITE_BOOTINFO_TAG_RSDP        3u
#define KERNITE_BOOTINFO_TAG_DTB         4u
#define KERNITE_BOOTINFO_TAG_INITRD      5u
#define KERNITE_BOOTINFO_TAG_CMDLINE     6u
#define KERNITE_BOOTINFO_TAG_KERNEL_BASE 7u
#define KERNITE_BOOTINFO_TAG_HHDM        8u

/* Memory map entry kinds. */
#define KERNITE_MEM_KIND_RESERVED     0u
#define KERNITE_MEM_KIND_USABLE       1u
#define KERNITE_MEM_KIND_BOOTLOADER   2u
#define KERNITE_MEM_KIND_KERNEL       3u
#define KERNITE_MEM_KIND_INITRD       4u
#define KERNITE_MEM_KIND_FRAMEBUFFER  5u
#define KERNITE_MEM_KIND_ACPI_NVS     6u
#define KERNITE_MEM_KIND_ACPI_RECLAIM 7u
#define KERNITE_MEM_KIND_MMIO         8u

/* ---- TLV record format (kernel → userland). ----
 *
 * The userland-visible bootinfo page begins with the magic above,
 * immediately followed by a stream of TLV records terminated by a
 * record with `tag == KERNITE_BOOTINFO_TAG_END`. Each record consists
 * of a `kernite_bootinfo_tlv` header and a tag-specific payload. The
 * total record (header + payload) is padded out to an 8-byte
 * boundary, so a walker advances by
 * `((sizeof(header) + tlv.length) + 7) & ~7u`.
 *
 * Payload structures below are addressable via natural alignment when
 * the walker dereferences `((uint8_t*)tlv) + sizeof(*tlv)`. Records
 * with no payload (e.g. END) carry `length == 0`.
 */
struct kernite_bootinfo_tlv {
    uint16_t tag;       /* KERNITE_BOOTINFO_TAG_* */
    uint16_t reserved;  /* must be zero */
    uint32_t length;    /* payload length in bytes (excludes this header) */
};

/* TAG_MEMORY_MAP payload: array of `count` entries. The TLV record's
 * `length` divided by `sizeof(struct kernite_bootinfo_memory_entry)`
 * gives the entry count. */
struct kernite_bootinfo_memory_entry {
    uint64_t base;
    uint64_t length;
    uint32_t kind;      /* KERNITE_MEM_KIND_* */
    uint32_t reserved;
};

/* TAG_FRAMEBUFFER payload. `phys_addr` is the bootloader-handed
 * physical address; userland that wants to draw must obtain a frame
 * for that range from a privileged source (the framebuffer untyped). */
struct kernite_bootinfo_framebuffer {
    uint64_t phys_addr;
    uint32_t width;
    uint32_t height;
    uint32_t pitch;
    uint8_t  bpp;
    uint8_t  red_pos;
    uint8_t  red_size;
    uint8_t  green_pos;
    uint8_t  green_size;
    uint8_t  blue_pos;
    uint8_t  blue_size;
    uint8_t  reserved;
};

/* TAG_RSDP payload — the ACPI Root System Description Pointer. */
struct kernite_bootinfo_rsdp {
    uint64_t rsdp_addr;
    uint8_t  revision;
    uint8_t  reserved[7];
};

/* TAG_DTB payload — Device Tree Blob (aarch64 / non-ACPI platforms). */
struct kernite_bootinfo_dtb {
    uint64_t phys_addr;
    uint64_t length;
};

/* TAG_INITRD payload — userland-visible initrd image location.
 *
 * `user_va` is the virtual address inside the userland process where
 * the initrd CPIO archive is mapped (read-only). `length` is the byte
 * size of the image. The kernel maps the initrd into init's VSpace
 * during bootstrap; subsequent processes that need the same image
 * must obtain it through a service (no automatic per-process mapping). */
struct kernite_bootinfo_initrd {
    uint64_t user_va;
    uint64_t length;
};

/* TAG_KERNEL_BASE payload — kernel image self-description. */
struct kernite_bootinfo_kernel_base {
    uint64_t phys_base;
    uint64_t virt_base;
    uint64_t size;
    uint64_t entry_point;
};

/* TAG_HHDM payload — higher-half direct map base offset. Userland
 * normally never sees this, but `init` uses it to translate the
 * kernel-handed physical address ranges. */
struct kernite_bootinfo_hhdm {
    uint64_t offset;
};

/* TAG_CMDLINE payload — bootloader command line. The TLV header's
 * `length` carries the byte count; the payload is a raw byte string
 * (NUL-terminated by convention but not required). No struct here
 * because the payload is variable-length opaque bytes. */

#endif /* KERNITE_UAPI_BOOT_H */
