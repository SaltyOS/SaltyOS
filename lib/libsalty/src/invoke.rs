//! Capability invocation wrappers
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Invoke is the universal capability operation: `SYS_INVOKE(cap, label, args...)`
//! dispatches to the kernel handler for the capability type at `cap`, using
//! `label` to select the specific operation (e.g. `CNODE_COPY`, `VSPACE_MAP`).
//!
//! This module provides typed wrappers for every invoke label, grouped by
//! capability type: CNode, Untyped, TCB, SchedContext, VSpace, IRQ, IoPort.
//! Each wrapper encodes the arguments into the correct register positions
//! and returns the error code (0 = success).

use crate::consts::*;
use crate::syscall::syscall;
use crate::types::*;

/// Raw capability invocation: `SYS_INVOKE(cap, label, arg0..arg3)`.
/// Returns the full `SaltyResult` (error + value).
#[inline(always)]
pub fn invoke(cap: Cap, label: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> SaltyResult {
    syscall(SYS_INVOKE, cap, label, arg0, arg1, arg2, arg3)
}

// ---- Untyped operations ----

/// Retype raw memory from `untyped` into a new kernel object of `new_type`
/// with `size_bits` (0 = default), placing the resulting cap at `dest_slot`.
pub fn untyped_retype(untyped: Cap, new_type: u64, size_bits: u64, dest_slot: u64) -> i32 {
    invoke(untyped, UNTYPED_RETYPE, new_type, size_bits, dest_slot, 0).error as i32
}

/// Retype with explicit CNode depth (for expanded CSpace hierarchy).
pub fn untyped_retype_depth(
    untyped: Cap,
    new_type: u64,
    size_bits: u64,
    dest_slot: u64,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(dest_depth, 0);
    invoke(untyped, UNTYPED_RETYPE, new_type, size_bits, dest_slot, 0).error as i32
}

// ---- TCB operations ----

/// Configure a TCB's instruction pointer, stack pointer, and IPC buffer address.
pub fn tcb_configure(tcb: Cap, rip: u64, rsp: u64, ipc_buf: u64) -> i32 {
    invoke(tcb, TCB_CONFIGURE, rip, rsp, ipc_buf, 0).error as i32
}

/// Resume a suspended TCB (make it schedulable).
pub fn tcb_resume(tcb: Cap) -> i32 {
    invoke(tcb, TCB_RESUME, 0, 0, 0, 0).error as i32
}

/// Set a TCB's CSpace and VSpace root capabilities.
pub fn tcb_set_space(tcb: Cap, cspace: Cap, vspace: Cap) -> i32 {
    invoke(tcb, TCB_SET_SPACE, cspace, vspace, 0, 0).error as i32
}

/// Set a TCB's CSpace and VSpace with explicit CNode depth.
pub fn tcb_set_space_with_depth(tcb: Cap, cspace: Cap, vspace: Cap, depth: u64) -> i32 {
    invoke(tcb, TCB_SET_SPACE, cspace, vspace, depth, 0).error as i32
}

/// Set the fault endpoint for a TCB. Page faults and exceptions are
/// delivered as IPC messages to this endpoint.
pub fn tcb_set_fault_handler(tcb: Cap, fault_ep: Cap) -> i32 {
    invoke(tcb, TCB_SET_FAULT_HANDLER, fault_ep, 0, 0, 0).error as i32
}

/// Set the IPC buffer virtual address for a TCB.
pub fn tcb_set_ipc_buffer(tcb: Cap, addr: u64) -> i32 {
    invoke(tcb, TCB_SET_IPC_BUFFER, addr, 0, 0, 0).error as i32
}

/// Write a TCB's instruction pointer and stack pointer. `flags` controls
/// whether the thread is resumed after writing (bit 0 = resume).
pub fn tcb_write_registers(tcb: Cap, flags: u64, rip: u64, rsp: u64) -> i32 {
    invoke(tcb, TCB_WRITE_REGISTERS, flags, rip, rsp, 0).error as i32
}

/// Suspend a TCB (remove from scheduler ready queue).
pub fn tcb_suspend(tcb: Cap) -> i32 {
    invoke(tcb, TCB_SUSPEND, 0, 0, 0, 0).error as i32
}

/// Suspend a thread, retrying on Busy (cross-CPU contention).
/// Yields between retries to give the target CPU time to context-switch.
/// Returns 0 on success, or the last error code after max retries.
pub fn tcb_suspend_retry(tcb: Cap, max_retries: u32) -> i32 {
    for _ in 0..max_retries {
        let err = tcb_suspend(tcb);
        if err != crate::consts::SALTY_BUSY as i32 {
            return err;
        }
        crate::syscall::syscall(crate::consts::SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
    tcb_suspend(tcb)
}

/// Bind a notification object to a TCB. Signals on the notification
/// will wake the thread if it is blocked on Recv.
pub fn tcb_bind_notification(tcb: Cap, ntfn: Cap) -> i32 {
    invoke(tcb, TCB_BIND_NOTIFICATION, ntfn, 0, 0, 0).error as i32
}

/// Copy FPU/SSE state from source TCB to destination TCB.
/// Used during fork to preserve the parent's floating-point state.
pub fn tcb_copy_fpu(dest_tcb: Cap, src_tcb: Cap) -> i32 {
    invoke(dest_tcb, TCB_COPY_FPU, src_tcb, 0, 0, 0).error as i32
}

/// Set the TLS base address (FS_BASE) for a TCB.
/// If the target is the current thread, applies immediately.
pub fn tcb_set_tls_base(tcb: Cap, tls_base: u64) -> i32 {
    invoke(tcb, TCB_SET_TLS_BASE, tls_base, 0, 0, 0).error as i32
}

// ---- SchedContext operations ----

/// Configure a scheduling context with budget and period (microseconds).
pub fn sc_configure(sc: Cap, budget_us: u64, period_us: u64) -> i32 {
    invoke(sc, SC_CONFIGURE, budget_us, period_us, 0, 0).error as i32
}

/// Bind a scheduling context to a TCB.
pub fn sc_bind(sc: Cap, tcb: Cap) -> i32 {
    invoke(sc, SC_BIND, tcb, 0, 0, 0).error as i32
}

// ---- VSpace operations ----

/// Map a frame capability at `vaddr` in the given VSpace with `flags`
/// (VSPACE_FLAG_WRITABLE, _USER, _EXECUTABLE, etc.).
pub fn vspace_map(vspace: Cap, frame: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke(vspace, VSPACE_MAP, frame, vaddr, flags, 0).error as i32
}

/// Unmap the page at `vaddr` from the given VSpace.
pub fn vspace_unmap(vspace: Cap, vaddr: u64) -> i32 {
    invoke(vspace, VSPACE_UNMAP, vaddr, 0, 0, 0).error as i32
}

/// Change protection flags on the page at `vaddr` in the given VSpace.
pub fn vspace_protect(vspace: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke(vspace, VSPACE_PROTECT, vaddr, flags, 0, 0).error as i32
}

/// Map an intermediate page table at the given level for `vaddr`.
pub fn vspace_map_pt(vspace: Cap, frame: Cap, vaddr: u64, level: u64) -> i32 {
    invoke(vspace, VSPACE_MAP_PT, frame, vaddr, level, 0).error as i32
}

/// Walk the page table starting at `start_vaddr`, returning up to
/// `max_entries` mapping entries via the IPC buffer.
pub fn vspace_walk(vspace: Cap, start_vaddr: u64, max_entries: u64) -> i32 {
    invoke(vspace, VSPACE_WALK, start_vaddr, max_entries, 0, 0).error as i32
}

/// Start word offset in IPC buffer page for `VSPACE_WALK` tuples (new ABI).
pub const VSPACE_WALK_ENTRY_BASE_WORD: usize = 30;
/// Tuple width in u64 words: `(vaddr, phys, flags)`.
pub const VSPACE_WALK_ENTRY_WORDS: usize = 3;

/// Read `(count, next_vaddr)` from the latest `VSPACE_WALK` result.
#[inline]
pub fn vspace_walk_result_header() -> Option<(u64, u64)> {
    unsafe {
        let ipc_words = walk_ipc_words()?;
        Some((
            core::ptr::read_volatile(ipc_words),
            core::ptr::read_volatile(ipc_words.add(1)),
        ))
    }
}

/// Read one `(vaddr, phys, flags)` tuple from the latest `VSPACE_WALK` result.
pub fn vspace_walk_result_entry(index: usize) -> Option<(u64, u64, u64)> {
    unsafe {
        let ipc_words = walk_ipc_words()?;
        let offset = VSPACE_WALK_ENTRY_BASE_WORD
            .checked_add(index.checked_mul(VSPACE_WALK_ENTRY_WORDS)?)?;
        let ipc_words_total = core::mem::size_of::<IpcBuffer>() / core::mem::size_of::<u64>();
        if offset + 2 >= ipc_words_total {
            return None;
        }

        Some((
            core::ptr::read_volatile(ipc_words.add(offset)),
            core::ptr::read_volatile(ipc_words.add(offset + 1)),
            core::ptr::read_volatile(ipc_words.add(offset + 2)),
        ))
    }
}

#[inline]
unsafe fn walk_ipc_words() -> Option<*const u64> {
    let ctx = crate::tls::current_ipc_ctx();
    let ipc_buffer = unsafe { (*ctx).ipc_buffer };
    if ipc_buffer.is_null() {
        return None;
    }
    Some(ipc_buffer as *const u64)
}

/// Copy page contents from `src_vaddr` in `src_vspace` into `dst_frame`.
pub fn vspace_copy_page(src_vspace: Cap, src_vaddr: u64, dst_frame: Cap) -> i32 {
    invoke(src_vspace, VSPACE_COPY_PAGE, src_vaddr, dst_frame, 0, 0).error as i32
}

/// Map a single 4K page from a device untyped region into a VSpace.
pub fn vspace_map_device(
    vspace: Cap,
    device_untyped: Cap,
    page_offset: u64,
    vaddr: u64,
    flags: u64,
) -> i32 {
    invoke(
        vspace,
        VSPACE_MAP_DEVICE,
        device_untyped,
        page_offset,
        vaddr,
        flags,
    )
    .error as i32
}

/// Batch-map contiguous 4K pages from a device untyped region.
///
/// Returns (error, pages_mapped). On success error==0 and pages_mapped==num_pages.
/// On partial failure error==0 and pages_mapped < num_pages.
pub fn vspace_map_device_range(
    vspace: Cap,
    device_untyped: Cap,
    offset_start: u64,
    vaddr_start: u64,
    num_pages: u64,
    flags: u64,
) -> (i32, u64) {
    let count_and_flags = (num_pages << 32) | (flags & 0xFFFF_FFFF);
    let result = invoke(
        vspace,
        VSPACE_MAP_DEVICE_RANGE,
        device_untyped,
        offset_start,
        vaddr_start,
        count_and_flags,
    );
    (result.error as i32, result.value)
}

/// Clone a page from src to dst VSpace with copy-on-write semantics.
pub fn vspace_clone_cow_page(
    src_vspace: Cap,
    src_vaddr: u64,
    dst_vspace: Cap,
    dst_vaddr: u64,
) -> i32 {
    invoke(
        src_vspace,
        VSPACE_CLONE_COW_PAGE,
        src_vaddr,
        dst_vspace,
        dst_vaddr,
        0,
    )
    .error as i32
}

/// Install a demand-page PTE at `vaddr` in the given VSpace.
///
/// On first user access, the kernel allocates a zero-fill frame directly
/// (no IPC to mmsrv), making the page present.
pub fn vspace_map_demand(vspace: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke(vspace, VSPACE_MAP_DEMAND, vaddr, flags, 0, 0).error as i32
}

/// Resolve a COW fault using a caller-provided frame.
///
/// Called by mmsrv when a VMFault indicates a COW page (write to present page).
/// The kernel copies the old page contents to `new_frame` and updates the PTE.
///
/// Returns SALTY_OK on success, SALTY_ALREADY_EXISTS if already resolved (race),
/// SALTY_NOT_FOUND if page not present, SALTY_OUT_OF_MEMORY on failure.
pub fn vspace_cow_resolve(vspace: Cap, vaddr: u64, new_frame: Cap, flags: u64) -> i32 {
    invoke(vspace, VSPACE_COW_RESOLVE, vaddr, new_frame, flags, 0).error as i32
}

/// Configure a pre-allocated frame pool for kernel-side COW fast-path.
///
/// The kernel walks `src_cnode` slots 0..count-1, extracts physical addresses
/// from each Frame cap, and writes them to the pool page. This avoids exposing
/// physical addresses to userland.
pub fn vspace_set_cow_pool(vspace: Cap, pool_frame: Cap, src_cnode: Cap, count: u64) -> i32 {
    invoke(vspace, VSPACE_SET_COW_POOL, pool_frame, src_cnode, count, 0).error as i32
}

/// Configure the notification ring for COW fast-path feedback.
///
/// When the kernel consumes a pool entry, it writes to the ring page and
/// signals the notification, allowing mmsrv to update tracking and replenish.
pub fn vspace_set_cow_notif(vspace: Cap, ring_frame: Cap, notif: Cap) -> i32 {
    invoke(vspace, VSPACE_SET_COW_NOTIF, ring_frame, notif, 0, 0).error as i32
}

/// Replenish consumed pool entries with new Frame caps.
///
/// The kernel walks `src_cnode` slots start_slot..start_slot+count, extracts
/// physical addresses, and appends them to the pool page.
pub fn vspace_replenish_cow_pool(vspace: Cap, src_cnode: Cap, start_slot: u64, count: u64) -> i32 {
    invoke(vspace, VSPACE_REPLENISH_COW_POOL, src_cnode, start_slot, count, 0).error as i32
}

/// Install demand-page PTEs for a contiguous range.
///
/// Returns (error, pages_mapped). On success error==0 and pages_mapped==count.
pub fn vspace_map_demand_range(
    vspace: Cap,
    vaddr_start: u64,
    count: u64,
    flags: u64,
) -> (i32, u64) {
    let result = invoke(
        vspace,
        VSPACE_MAP_DEMAND_RANGE,
        vaddr_start,
        count,
        flags,
        0,
    );
    (result.error as i32, result.value)
}

// ---- CNode operations ----

/// Copy a capability from `src_cnode[src_slot]` to `dest_cnode[dest_slot]`
/// with the given `rights` mask.
pub fn cnode_copy(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    rights: u64,
) -> i32 {
    invoke(src_cnode, CNODE_COPY, src_slot, dest_cnode, dest_slot, rights).error as i32
}

/// Copy a capability with a badge applied (mint = copy + badge).
pub fn cnode_mint(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    badge: u64,
) -> i32 {
    invoke(src_cnode, CNODE_MINT, src_slot, dest_cnode, dest_slot, badge).error as i32
}

/// Move a capability (src slot becomes empty).
pub fn cnode_move(dest_cnode: Cap, dest_slot: u64, src_cnode: Cap, src_slot: u64) -> i32 {
    invoke(dest_cnode, CNODE_MOVE, dest_slot, src_cnode, src_slot, 0).error as i32
}

/// Move a capability with a badge change (mutate = move + rebadge).
pub fn cnode_mutate(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
    badge: u64,
) -> i32 {
    invoke(dest_cnode, CNODE_MUTATE, dest_slot, src_cnode, src_slot, badge).error as i32
}

/// Save the reply capability from the last Call into a CNode slot.
pub fn cnode_save_caller(cnode: Cap, slot: u64) -> i32 {
    invoke(cnode, CNODE_SAVE_CALLER, slot, 0, 0, 0).error as i32
}

/// Delete (clear) a capability slot.
pub fn cnode_delete(cnode: Cap, slot: u64) -> i32 {
    invoke(cnode, CNODE_DELETE, slot, 0, 0, 0).error as i32
}

/// Revoke a capability and all its CDT children.
pub fn cnode_revoke(cnode: Cap, slot: u64) -> i32 {
    invoke(cnode, CNODE_REVOKE, slot, 0, 0, 0).error as i32
}

/// Set the guard value and guard bits on a CNode.
pub fn cnode_set_guard(cnode: Cap, guard: u64, guard_bits: u64) -> i32 {
    invoke(cnode, CNODE_SET_GUARD, guard, guard_bits, 0, 0).error as i32
}

/// Query CNode metadata (size_bits, num_slots, etc.) via IPC buffer.
pub fn cnode_get_info(cnode: Cap) -> SaltyResult {
    invoke(cnode, CNODE_GET_INFO, 0, 0, 0, 0)
}

// ---- IRQ operations ----

/// Acknowledge an IRQ (re-enable it in the interrupt controller).
pub fn irq_handler_ack(irq_handler: Cap) -> i32 {
    invoke(irq_handler, IRQ_HANDLER_ACK, 0, 0, 0, 0).error as i32
}

/// Bind an IRQ handler to a notification object. Interrupts will signal
/// the notification rather than blocking on an endpoint.
pub fn irq_handler_set_notification(irq_handler: Cap, ntfn: Cap) -> i32 {
    invoke(irq_handler, IRQ_HANDLER_SET_NOTIFICATION, ntfn, 0, 0, 0).error as i32
}

// ---- I/O port operations ----

/// Read an 8-bit value from an I/O port at the given offset.
pub fn ioport_in8(ioport: Cap, offset: u64) -> u8 {
    invoke(ioport, IOPORT_IN8, offset, 0, 0, 0).value as u8
}

/// Write an 8-bit value to an I/O port at the given offset.
pub fn ioport_out8(ioport: Cap, offset: u64, value: u8) {
    invoke(ioport, IOPORT_OUT8, offset, value as u64, 0, 0);
}

/// Read a 16-bit value from an I/O port at the given offset.
pub fn ioport_in16(ioport: Cap, offset: u64) -> u16 {
    invoke(ioport, IOPORT_IN16, offset, 0, 0, 0).value as u16
}

/// Write a 16-bit value to an I/O port at the given offset.
pub fn ioport_out16(ioport: Cap, offset: u64, value: u16) {
    invoke(ioport, IOPORT_OUT16, offset, value as u64, 0, 0);
}

/// Read a 32-bit value from an I/O port at the given offset.
pub fn ioport_in32(ioport: Cap, offset: u64) -> u32 {
    invoke(ioport, IOPORT_IN32, offset, 0, 0, 0).value as u32
}

/// Write a 32-bit value to an I/O port at the given offset.
pub fn ioport_out32(ioport: Cap, offset: u64, value: u32) {
    invoke(ioport, IOPORT_OUT32, offset, value as u64, 0, 0);
}

/// Configure base port and count on a freshly retyped IoPort (one-shot).
pub fn ioport_configure(ioport: Cap, base_port: u64, num_ports: u64) -> i32 {
    invoke(ioport, IOPORT_CONFIGURE, base_port, num_ports, 0, 0).error as i32
}

/// Create an IoPort capability from a physical I/O port range.
/// Requires IrqControl cap (IrqHandler type with CONFIGURE rights).
pub fn ioport_create(
    irq_ctrl: Cap,
    base_port: u64,
    num_ports: u64,
    dest_cnode: Cap,
    dest_slot: u64,
) -> i32 {
    invoke(irq_ctrl, IOPORT_CREATE, base_port, num_ports, dest_cnode, dest_slot).error as i32
}

// ---- IRQ control operations ----

/// Acquire an IRQ handler capability. Allocates a new IrqHandler object
/// from the kernel's dynamic pool, registers it for the given IRQ number,
/// auto-unmasks the IOAPIC, and places the resulting cap at `dest_slot`
/// in `dest_cnode`.
///
/// The IrqHandler cap at `irq_ctrl` must have CONFIGURE rights (IrqControl).
pub fn irq_control_get(irq_ctrl: Cap, irq_num: u64, dest_cnode: Cap, dest_slot: u64) -> i32 {
    invoke(irq_ctrl, IRQ_CONTROL_GET, irq_num, dest_cnode, dest_slot, 0).error as i32
}

/// Clear (unbind notification + unregister) an IRQ handler.
pub fn irq_handler_clear(irq_handler: Cap) -> i32 {
    invoke(irq_handler, IRQ_HANDLER_CLEAR, 0, 0, 0, 0).error as i32
}

/// Create a device untyped capability from a physical MMIO address.
/// Requires IrqControl cap (slot with CONFIGURE rights, IrqHandler type).
pub fn device_untyped_create(
    irq_ctrl: Cap,
    phys_addr: u64,
    size_bits: u64,
    dest_cnode: Cap,
    dest_slot: u64,
) -> i32 {
    invoke(irq_ctrl, DEVICE_UNTYPED_CREATE, phys_addr, size_bits, dest_cnode, dest_slot).error as i32
}

// ===========================================================================
// Depth-aware helpers for CNode hierarchy (expanded CSpace)
// ===========================================================================

/// Write per-thread invoke depths for the next depth-aware invoke call.
/// depth=0 means flat mode.
fn write_invoke_depth(d0: u8, d1: u8) {
    let _ = syscall(SYS_SET_INVOKE_DEPTHS, d0 as u64, d1 as u64, 0, 0, 0, 0);
}

pub fn cnode_copy_depth(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    rights: u64,
    src_depth: u8,
    dest_depth: u8,
) -> i32 {
    write_invoke_depth(src_depth, dest_depth);
    invoke(src_cnode, CNODE_COPY, src_slot, dest_cnode, dest_slot, rights).error as i32
}

pub fn cnode_delete_depth(cnode: Cap, slot: u64, depth: u8) -> i32 {
    write_invoke_depth(depth, 0);
    invoke(cnode, CNODE_DELETE, slot, 0, 0, 0).error as i32
}

pub fn cnode_revoke_depth(cnode: Cap, slot: u64, depth: u8) -> i32 {
    write_invoke_depth(depth, 0);
    invoke(cnode, CNODE_REVOKE, slot, 0, 0, 0).error as i32
}
