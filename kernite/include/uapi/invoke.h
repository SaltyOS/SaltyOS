/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Capability invocation labels.
 *
 * Layout: 0x20-byte blocks per object type, lower nibbles allocated
 * sequentially per op. Dispatch keys on (cap.obj_type, label) so two
 * object types may reuse the same hex slot — the leading 0x20 stride
 * is a readability convention, not a uniqueness guarantee.
 *
 * Block map (v0):
 *   0x000 — reserved (ABI-version handshake / no-op)
 *   0x020 CNode
 *   0x040 Untyped
 *   0x060 TCB
 *   0x080 VSpace
 *   0x0A0 SchedContext
 *   0x0C0 IoPort
 *   0x0E0 IrqHandler
 *   0x100 MemoryObject
 *   0x120 EventQueue
 *   0x140 Watch
 *   0x160 MessagePipe
 *   0x180 DataPipe
 *   0x1A0 Timer
 *   0x1C0 KernelRng
 *   0x1E0 SystemControl
 *   0x200 Clock
 *   0x220 SystemInfo
 *   0x240 KernelDebug
 *   0x2A0 retired
 *   0x2C0 Pager
 *   0x2E0 DeviceControl
 */

#ifndef KERNITE_UAPI_INVOKE_H
#define KERNITE_UAPI_INVOKE_H

/* ---- CNode (0x020). ---- */

#define KERNITE_INV_CNODE_COPY      0x020ULL
#define KERNITE_INV_CNODE_MINT      0x021ULL
#define KERNITE_INV_CNODE_MOVE      0x022ULL
#define KERNITE_INV_CNODE_MUTATE    0x023ULL
#define KERNITE_INV_CNODE_DELETE    0x024ULL
#define KERNITE_INV_CNODE_REVOKE    0x025ULL
#define KERNITE_INV_CNODE_SET_GUARD 0x026ULL
#define KERNITE_INV_CNODE_GET_INFO  0x027ULL

/* ---- Untyped (0x040). ---- */

#define KERNITE_INV_UNTYPED_RETYPE    0x040ULL
#define KERNITE_INV_UNTYPED_RESET     0x041ULL
#define KERNITE_INV_UNTYPED_GET_STATS 0x042ULL

/* ---- TCB (0x060). ---- */

#define KERNITE_INV_TCB_CONFIGURE         0x060ULL
#define KERNITE_INV_TCB_START             0x061ULL
#define KERNITE_INV_TCB_STOP              0x062ULL
#define KERNITE_INV_TCB_KILL              0x063ULL
#define KERNITE_INV_TCB_YIELD             0x064ULL
#define KERNITE_INV_TCB_GET_STATE         0x065ULL
#define KERNITE_INV_TCB_GET_ABI_VERSION   0x066ULL
#define KERNITE_INV_TCB_SET_INVOKE_DEPTHS 0x067ULL
#define KERNITE_INV_TCB_SET_SPACE         0x068ULL
#define KERNITE_INV_TCB_SET_AFFINITY      0x069ULL
#define KERNITE_INV_TCB_READ_REGISTERS    0x06AULL
#define KERNITE_INV_TCB_WRITE_REGISTERS   0x06BULL
#define KERNITE_INV_TCB_SET_PRIORITY      0x06CULL
#define KERNITE_INV_TCB_SET_IPC_BUFFER        0x06DULL
#define KERNITE_INV_TCB_SET_FAULT_PIPE        0x06EULL
#define KERNITE_INV_TCB_COPY_FPU              0x070ULL
#define KERNITE_INV_TCB_SET_TLS_BASE          0x071ULL
#define KERNITE_INV_TCB_SET_STACK_BOUNDS      0x072ULL
#define KERNITE_INV_TCB_SET_SCHED_CLASS       0x073ULL
#define KERNITE_INV_TCB_GET_SPACE_INFO        0x074ULL
#define KERNITE_INV_TCB_GET_CPU_TIMES         0x075ULL
#define KERNITE_INV_TCB_GET_TRACE_ID          0x076ULL
#define KERNITE_INV_TCB_SET_ABI_TP            0x077ULL
#define KERNITE_INV_TCB_EXIT_SELF             0x078ULL

/* ---- VSpace (0x080). ---- */

#define KERNITE_INV_VSPACE_MAP                0x080ULL
#define KERNITE_INV_VSPACE_UNMAP              0x081ULL
#define KERNITE_INV_VSPACE_MAP_PT             0x082ULL
#define KERNITE_INV_VSPACE_WALK               0x083ULL
#define KERNITE_INV_VSPACE_COPY_PAGE          0x084ULL
#define KERNITE_INV_VSPACE_MAP_DEVICE         0x085ULL
#define KERNITE_INV_VSPACE_MAP_DEVICE_RANGE   0x086ULL
#define KERNITE_INV_VSPACE_PROTECT            0x087ULL
#define KERNITE_INV_VSPACE_PROTECT_RANGE      0x088ULL
#define KERNITE_INV_VSPACE_MAP_DEMAND         0x089ULL
#define KERNITE_INV_VSPACE_MAP_DEMAND_RANGE   0x08AULL
#define KERNITE_INV_VSPACE_SET_COW_POOL       0x08DULL
#define KERNITE_INV_VSPACE_REPLENISH_COW_POOL 0x08EULL
#define KERNITE_INV_VSPACE_MAP_MO             0x08FULL
#define KERNITE_INV_VSPACE_SHARE_RO_PAGE      0x090ULL
#define KERNITE_INV_VSPACE_FORK_RANGE         0x091ULL
#define KERNITE_INV_VSPACE_UNDO_FORK_RANGE    0x092ULL
#define KERNITE_INV_VSPACE_GET_MEM_STATS      0x093ULL
#define KERNITE_INV_VSPACE_GET_RANGE_STATS    0x094ULL
#define KERNITE_INV_VSPACE_GET_TRACE_ID       0x095ULL
#define KERNITE_INV_VSPACE_FUTEX_WAIT         0x096ULL
#define KERNITE_INV_VSPACE_FUTEX_WAKE         0x097ULL
#define KERNITE_INV_VSPACE_RESOLVE_PAGE       0x098ULL
#define KERNITE_INV_VSPACE_FUTEX_REQUEUE      0x099ULL

/* ---- SchedContext (0x0A0). ---- */

#define KERNITE_INV_SC_CONFIGURE 0x0A0ULL
#define KERNITE_INV_SC_BIND      0x0A1ULL

/* ---- IoPort (0x0C0). ----
 *
 * MMIO mapping is intentionally NOT here — VSpace::MAP_DEVICE owns
 * the address-space side of device wiring (`KERNITE_INV_VSPACE_MAP_DEVICE`).
 * IoPort is exclusively for the x86 port-mapped I/O surface.
 */

#define KERNITE_INV_IOPORT_READ_8   0x0C0ULL
#define KERNITE_INV_IOPORT_READ_16  0x0C1ULL
#define KERNITE_INV_IOPORT_READ_32  0x0C2ULL
#define KERNITE_INV_IOPORT_WRITE_8  0x0C3ULL
#define KERNITE_INV_IOPORT_WRITE_16 0x0C4ULL
#define KERNITE_INV_IOPORT_WRITE_32 0x0C5ULL

/* ---- IrqHandler (0x0E0). ---- */

#define KERNITE_INV_IRQ_BIND_EQ   0x0E0ULL
#define KERNITE_INV_IRQ_UNBIND_EQ 0x0E1ULL
#define KERNITE_INV_IRQ_ACK       0x0E2ULL

/* ---- MemoryObject (0x100). ---- */

#define KERNITE_INV_MO_COMMIT            0x100ULL
#define KERNITE_INV_MO_DECOMMIT          0x101ULL
#define KERNITE_INV_MO_GET_SIZE          0x102ULL
#define KERNITE_INV_MO_CLONE             0x103ULL
#define KERNITE_INV_MO_RESIZE            0x104ULL
#define KERNITE_INV_MO_READ              0x105ULL
#define KERNITE_INV_MO_WRITE             0x106ULL
#define KERNITE_INV_MO_HAS_PAGE          0x107ULL
#define KERNITE_INV_MO_GET_MAP_COUNT     0x108ULL
#define KERNITE_INV_MO_UPDATE_PAGE_FLAGS 0x109ULL
#define KERNITE_INV_MO_ATTACH_PAGER      0x10AULL
#define KERNITE_INV_MO_SNAPSHOT          0x10BULL
#define KERNITE_INV_MO_CLONE_RANGE       0x10CULL
/* Dispatched against an ExecAuthority cap (not a MemoryObject): confers
 * READ|EXECUTE on the named MemoryObject. Shares the 0x100 block per the
 * (obj_type, label) dispatch convention. */
#define KERNITE_INV_MO_MARK_EXECUTABLE   0x10DULL
/* Populate a pristine MemoryObject as a borrowed-frames view over a run of the
 * initrd device-untyped (zero-copy, immutable, never PMM-owned or freed). */
#define KERNITE_INV_MO_POPULATE_BORROWED 0x10EULL

/* ---- EventQueue (0x120). ---- */

#define KERNITE_INV_EQ_WAIT   0x120ULL
#define KERNITE_INV_EQ_POLL   0x121ULL
#define KERNITE_INV_EQ_CANCEL 0x122ULL

/* ---- Watch (0x140). ---- */

#define KERNITE_INV_WATCH_REGISTER 0x140ULL
#define KERNITE_INV_WATCH_DISARM   0x141ULL
#define KERNITE_INV_WATCH_CANCEL   0x142ULL

/* ---- MessagePipe side (0x160). ---- */

#define KERNITE_INV_MP_WRITE 0x160ULL
#define KERNITE_INV_MP_READ  0x161ULL
#define KERNITE_INV_MP_CLOSE 0x162ULL
#define KERNITE_INV_MP_CALL  0x163ULL
/* 0x164 retired; replies are reply-marked MP_WRITE records. */

/* ---- DataPipe side (0x180). ----
 *
 * No MAP op — DataPipe is a kernel-managed byte stream; userland
 * goes through `produce` / `consume` (with kernel staging). A
 * shared-memory zero-copy variant is a future, distinct kernel
 * object (`MemoryObject` mapped via `VSPACE_MAP_MO`) rather than a
 * mode of `DataPipe`.
 */

#define KERNITE_INV_DP_PRODUCE 0x180ULL
#define KERNITE_INV_DP_CONSUME 0x181ULL
#define KERNITE_INV_DP_QUERY   0x182ULL
#define KERNITE_INV_DP_CLOSE   0x183ULL
#define KERNITE_INV_DP_SET_RX_THRESHOLD 0x184ULL
#define KERNITE_INV_DP_SET_TX_THRESHOLD 0x185ULL
#define KERNITE_INV_DP_SHUTDOWN         0x186ULL /* half-close: disable this side's writes */

/* ---- MessagePipeCore (0x260). ---- */

#define KERNITE_INV_MP_CORE_PAIR 0x260ULL

/* ---- DataPipeCore (0x280). ---- */

#define KERNITE_INV_DP_CORE_PAIR 0x280ULL

/* ---- Timer (0x1A0). ---- */

#define KERNITE_INV_TIMER_SET    0x1A0ULL
#define KERNITE_INV_TIMER_CANCEL 0x1A1ULL
#define KERNITE_INV_TIMER_QUERY  0x1A2ULL

/* ---- KernelRng (0x1C0). ---- */

#define KERNITE_INV_RNG_READ 0x1C0ULL

/* ---- SystemControl (0x1E0). ---- */

#define KERNITE_INV_SYSTEM_SHUTDOWN 0x1E0ULL
#define KERNITE_INV_SYSTEM_REBOOT   0x1E1ULL

/* ---- Clock (0x200). ---- */

#define KERNITE_INV_CLOCK_READ 0x200ULL

/* Clock-id arg for KERNITE_INV_CLOCK_READ. */
#define KERNITE_CLOCK_ID_REALTIME  0ULL
#define KERNITE_CLOCK_ID_MONOTONIC 1ULL

/* ---- SystemInfo (0x220). ---- */

#define KERNITE_INV_SYSINFO_GET_INFO    0x220ULL
#define KERNITE_INV_SYSINFO_GET_MEMINFO 0x221ULL

/* ---- KernelDebug (0x240). ---- */

#define KERNITE_INV_KDEBUG_PUTCHAR         0x240ULL
#define KERNITE_INV_KDEBUG_PUTSTR          0x241ULL
#define KERNITE_INV_KDEBUG_PUTBUF          0x242ULL
#define KERNITE_INV_KDEBUG_DUMP_STATE      0x243ULL
#define KERNITE_INV_KDEBUG_CONSOLE_CONTROL 0x244ULL

/* ---- Pager (0x2C0). ----
 * File-backed MO supplier. The pager cap is held by vfs (or whichever
 * userspace task owns the file → page-cache translation). mmsrv attaches
 * it to a file-backed MO at MM_FILE_MMAP time; the kernel then routes
 * page-absent faults through the pager's bound EventQueue as
 * `KERNITE_EVENT_TYPE_PAGER_REQUEST`. The faulting thread blocks until
 * `PAGER_SUPPLY_PAGE` (donates a Frame cap into the MO at the offset)
 * or `PAGER_FAIL` (surfaces SIGBUS-equivalent). */

#define KERNITE_INV_PAGER_BIND_EQ         0x2C0ULL
#define KERNITE_INV_PAGER_SUPPLY_PAGE     0x2C1ULL
#define KERNITE_INV_PAGER_FAIL            0x2C2ULL
#define KERNITE_INV_PAGER_DETACH          0x2C3ULL
#define KERNITE_INV_PAGER_BEGIN_WRITEBACK 0x2C4ULL
#define KERNITE_INV_PAGER_WRITEBACK_DONE  0x2C5ULL
/* Reclaim a clean resident MO page: unmap it from every mapping and free the
 * frame. Refuses (Busy) if the page is dirty so the pager writes it back
 * first. A later access re-faults via PAGER_REQUEST. */
#define KERNITE_INV_PAGER_EVICT_PAGE      0x2C6ULL
/* Page-cache supply: the kernel sources the page from global PMM, copies
 * `bytes_read` bytes from the pager's `src_va` into it, and commits it into
 * the MO. Unlike PAGER_SUPPLY_PAGE the pager donates no Frame cap — the page
 * is kernel-owned page-cache memory, so it never charges the pager's untyped
 * quota and returns to the global PMM on MO release. */
#define KERNITE_INV_PAGER_SUPPLY_COPY     0x2C7ULL

/* ---- DeviceControl (0x2E0). ----
 *
 * Privileged hardware-resource broker. Holders can mint narrower
 * device-resource caps into a destination CSpace:
 *
 *   CREATE_IOPORT:         arg0=base_port, arg1=num_ports,
 *                          arg2=dest_cspace, arg3=dest_slot
 *   CREATE_DEVICE_UNTYPED: arg0=phys_addr, arg1=size_bits,
 *                          arg2=dest_cspace, arg3=dest_slot
 *   CREATE_IRQ_HANDLER:    arg0=irq, arg1=dest_cspace,
 *                          arg2=dest_slot, arg3=flags
 *
 * The destination slot depth is supplied through
 * TCB_SET_INVOKE_DEPTHS depth0, matching other CSpace-writing
 * invocations.
 */

#define KERNITE_INV_DEVICE_CONTROL_CREATE_IOPORT         0x2E0ULL
#define KERNITE_INV_DEVICE_CONTROL_CREATE_DEVICE_UNTYPED 0x2E1ULL
#define KERNITE_INV_DEVICE_CONTROL_CREATE_IRQ_HANDLER    0x2E2ULL

#endif /* KERNITE_UAPI_INVOKE_H */
