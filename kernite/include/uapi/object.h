/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Kernel object types and fixed sizes.
 *
 * KERNITE_OBJ_* values are passed userland → kernel as the
 * UNTYPED_RETYPE target type. Discriminants are stable ABI; the
 * KernelObject header (8 bytes obj_type/size_bits + ref_count + reaper
 * + parent_ut + sibling links) prefixes every concrete object struct
 * so the kernel can dispatch by type from a generic pointer.
 *
 * The KERNITE_*_BYTES constants record the exact size carved from
 * untyped memory for each fixed-layout type. They are arch-conditional
 * where struct contents include arch-sized atomics or pointers; the
 * kernel asserts size_of::<T>() == KERNITE_*_BYTES at compile time.
 */

#ifndef KERNITE_UAPI_OBJECT_H
#define KERNITE_UAPI_OBJECT_H

/* ---- Object type IDs (ABI-stable; retired IDs are not reused). ---- */

#define KERNITE_OBJ_NULL           0ULL
#define KERNITE_OBJ_UNTYPED        1ULL
#define KERNITE_OBJ_TCB            2ULL
#define KERNITE_OBJ_CNODE          3ULL
#define KERNITE_OBJ_VSPACE         4ULL
#define KERNITE_OBJ_FRAME          5ULL
#define KERNITE_OBJ_IRQ_HANDLER    6ULL
#define KERNITE_OBJ_IO_PORT        7ULL
#define KERNITE_OBJ_SCHED_CONTEXT  8ULL
#define KERNITE_OBJ_MEMORY_OBJECT  9ULL
#define KERNITE_OBJ_EVENT_QUEUE    10ULL
#define KERNITE_OBJ_WATCH          11ULL
#define KERNITE_OBJ_MESSAGE_PIPE   12ULL
#define KERNITE_OBJ_DATA_PIPE      13ULL
#define KERNITE_OBJ_TIMER          14ULL
#define KERNITE_OBJ_KERNEL_RNG          15ULL
#define KERNITE_OBJ_SYSTEM_CONTROL      16ULL
#define KERNITE_OBJ_CLOCK               17ULL
#define KERNITE_OBJ_SYSTEM_INFO         18ULL
#define KERNITE_OBJ_KERNEL_DEBUG        19ULL
#define KERNITE_OBJ_MESSAGE_PIPE_CORE   20ULL
#define KERNITE_OBJ_DATA_PIPE_CORE      21ULL
#define KERNITE_OBJ_PAGER               23ULL
#define KERNITE_OBJ_DEVICE_CONTROL      24ULL
#define KERNITE_OBJ_VM_HIERARCHY_STATE  25ULL
#define KERNITE_OBJ_EXEC_AUTHORITY      26ULL
/* A hardware page table provided by userland for VSPACE_MAP_PT. Distinct from
 * FRAME so the same object can never be data-mapped (which would let userland
 * forge PTEs); the 4 KiB page holds 512 PTEs and its metadata is out-of-band
 * (like FRAME), so the fixed byte size is one page granule. */
#define KERNITE_OBJ_PAGE_TABLE          27ULL

/* ---- Page granule. ---- */

#define KERNITE_PAGE_BYTES         4096ULL
#define KERNITE_PAGE_TABLE_BYTES   KERNITE_PAGE_BYTES

/* ---- CNode bounds. ---- */

#define KERNITE_CNODE_DEFAULT_SIZE_BITS 10ULL
#define KERNITE_CNODE_MIN_SIZE_BITS     4ULL
#define KERNITE_CNODE_MAX_SIZE_BITS     16ULL
#define KERNITE_CNODE_HEADER_BYTES      56ULL
#define KERNITE_CNODE_SLOT_BYTES        8ULL

/* ---- VSpace composite (PML4 page + tracking). ---- */

#define KERNITE_VSPACE_TRACKING_BYTES 384ULL
#define KERNITE_VSPACE_BYTES          (KERNITE_PAGE_BYTES + KERNITE_VSPACE_TRACKING_BYTES)

/* ---- MemoryObject header (page-aligned alloc). ---- */

#define KERNITE_MO_HEADER_BYTES 640ULL

/*
 * Fixed sizes for concrete kernel-object structs. Each value is
 * mechanically verified against size_of::<T>() in the kernel build;
 * a drift fires a compile-time error pointing at this header.
 *
 * TCB carries arch-specific FPU save-area alignment so its byte size
 * differs between x86_64 and aarch64; other types are arch-agnostic.
 */

#if defined(__x86_64__)
#define KERNITE_TCB_BYTES 2560ULL
#elif defined(__aarch64__)
#define KERNITE_TCB_BYTES 2304ULL
#else
#error "kernite UAPI: unsupported target architecture"
#endif

#define KERNITE_SCHED_CONTEXT_BYTES 96ULL
#define KERNITE_IRQ_HANDLER_BYTES   184ULL
#define KERNITE_IO_PORT_BYTES       48ULL

/*
 * Edge object set (MessagePipe / DataPipe / EventQueue / Watch /
 * Timer / system caps). Each value matches the concrete struct's
 * `size_of::<T>()` exactly; `object_alloc_bytes` carves precisely
 * this many bytes out of the parent untyped. The kernel-side asserts
 * in `cap/object_size_assert.rs` confirm the Rust struct size matches
 * every constant below.
 */

#define KERNITE_EVENT_QUEUE_BYTES       8448ULL
#define KERNITE_WATCH_BYTES             112ULL
#define KERNITE_MESSAGE_PIPE_BYTES      56ULL
#define KERNITE_MESSAGE_PIPE_CORE_BYTES 12448ULL
#define KERNITE_DATA_PIPE_BYTES         56ULL
#define KERNITE_DATA_PIPE_CORE_BYTES    8608ULL
#define KERNITE_TIMER_BYTES             304ULL
#define KERNITE_KERNEL_RNG_BYTES        40ULL
#define KERNITE_SYSTEM_CONTROL_BYTES    40ULL
#define KERNITE_CLOCK_BYTES             40ULL
#define KERNITE_SYSTEM_INFO_BYTES       40ULL
#define KERNITE_KERNEL_DEBUG_BYTES      40ULL
#define KERNITE_PAGER_BYTES             160ULL
#define KERNITE_DEVICE_CONTROL_BYTES    40ULL

/*
 * VmHierarchyState — per-COW-tree serialization lock object. Header +
 * SpinLock + one-shot bound flag + the bounded TLB range-change accumulator
 * (RangeChangeList). Verified against size_of::<VmHierarchyState>() by the
 * kernel asserts.
 */
#define KERNITE_VM_HIERARCHY_STATE_BYTES 376ULL

/*
 * ExecAuthority — capability token authorizing mo_mark_executable. A
 * bare KernelObject header; possession of the cap is the authority.
 */
#define KERNITE_EXEC_AUTHORITY_BYTES 40ULL

/* ---- Well-known capability slots. ----
 *
 * Every thread starts with these three slots preinstalled in its
 * CSpace at fixed indices. All other capabilities reach the thread
 * via the SaltyOS startup descriptor (`AT_SALTYOS_STARTUP`) and are
 * placed at spawner-chosen indices. yield / exit / get_state /
 * get_abi_version / set_invoke_depths invoke labels run against
 * `CAP_SELF_TCB`; futex labels run against `CAP_SELF_VSPACE`;
 * cspace mutation labels run against `CAP_SELF_CSPACE`.
 */

#define KERNITE_CAP_SELF_TCB    0ULL
#define KERNITE_CAP_SELF_VSPACE 1ULL
#define KERNITE_CAP_SELF_CSPACE 2ULL

#endif /* KERNITE_UAPI_OBJECT_H */
