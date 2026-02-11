//! Capability invocation wrappers
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::syscall::syscall;
use crate::types::*;

#[inline(always)]
pub fn invoke(cap: Cap, label: u64, arg0: u64, arg1: u64, arg2: u64, arg3: u64) -> SaltyResult {
    syscall(SYS_INVOKE, cap, label, arg0, arg1, arg2, arg3)
}

pub fn untyped_retype(untyped: Cap, new_type: u64, size_bits: u64, dest_slot: u64) -> i32 {
    invoke(untyped, UNTYPED_RETYPE, new_type, size_bits, dest_slot, 0).error as i32
}

pub fn tcb_configure(tcb: Cap, rip: u64, rsp: u64, ipc_buf: u64) -> i32 {
    invoke(tcb, TCB_CONFIGURE, rip, rsp, ipc_buf, 0).error as i32
}

pub fn tcb_resume(tcb: Cap) -> i32 {
    invoke(tcb, TCB_RESUME, 0, 0, 0, 0).error as i32
}

pub fn tcb_set_space(tcb: Cap, cspace: Cap, vspace: Cap) -> i32 {
    invoke(tcb, TCB_SET_SPACE, cspace, vspace, 0, 0).error as i32
}

pub fn tcb_set_fault_handler(tcb: Cap, fault_ep: Cap) -> i32 {
    invoke(tcb, TCB_SET_FAULT_HANDLER, fault_ep, 0, 0, 0).error as i32
}

pub fn tcb_set_ipc_buffer(tcb: Cap, addr: u64) -> i32 {
    invoke(tcb, TCB_SET_IPC_BUFFER, addr, 0, 0, 0).error as i32
}

pub fn tcb_write_registers(tcb: Cap, flags: u64, rip: u64, rsp: u64) -> i32 {
    invoke(tcb, TCB_WRITE_REGISTERS, flags, rip, rsp, 0).error as i32
}

pub fn tcb_suspend(tcb: Cap) -> i32 {
    invoke(tcb, TCB_SUSPEND, 0, 0, 0, 0).error as i32
}

pub fn tcb_bind_notification(tcb: Cap, ntfn: Cap) -> i32 {
    invoke(tcb, TCB_BIND_NOTIFICATION, ntfn, 0, 0, 0).error as i32
}

pub fn sc_configure(sc: Cap, budget_us: u64, period_us: u64) -> i32 {
    invoke(sc, SC_CONFIGURE, budget_us, period_us, 0, 0).error as i32
}

pub fn sc_bind(sc: Cap, tcb: Cap) -> i32 {
    invoke(sc, SC_BIND, tcb, 0, 0, 0).error as i32
}

pub fn vspace_map(vspace: Cap, frame: Cap, vaddr: u64, flags: u64) -> i32 {
    invoke(vspace, VSPACE_MAP, frame, vaddr, flags, 0).error as i32
}

pub fn vspace_unmap(vspace: Cap, vaddr: u64) -> i32 {
    invoke(vspace, VSPACE_UNMAP, vaddr, 0, 0, 0).error as i32
}

pub fn vspace_map_pt(vspace: Cap, frame: Cap, vaddr: u64, level: u64) -> i32 {
    invoke(vspace, VSPACE_MAP_PT, frame, vaddr, level, 0).error as i32
}

pub fn vspace_walk(vspace: Cap, start_vaddr: u64, max_entries: u64) -> i32 {
    invoke(vspace, VSPACE_WALK, start_vaddr, max_entries, 0, 0).error as i32
}

pub fn vspace_copy_page(src_vspace: Cap, src_vaddr: u64, dst_frame: Cap) -> i32 {
    invoke(src_vspace, VSPACE_COPY_PAGE, src_vaddr, dst_frame, 0, 0).error as i32
}

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

pub fn cnode_copy(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    rights: u64,
) -> i32 {
    invoke(src_cnode, CNODE_COPY, src_slot, dest_cnode, dest_slot, rights).error as i32
}

pub fn cnode_mint(
    src_cnode: Cap,
    src_slot: u64,
    dest_cnode: Cap,
    dest_slot: u64,
    badge: u64,
) -> i32 {
    invoke(src_cnode, CNODE_MINT, src_slot, dest_cnode, dest_slot, badge).error as i32
}

pub fn cnode_move(dest_cnode: Cap, dest_slot: u64, src_cnode: Cap, src_slot: u64) -> i32 {
    invoke(dest_cnode, CNODE_MOVE, dest_slot, src_cnode, src_slot, 0).error as i32
}

pub fn cnode_mutate(
    dest_cnode: Cap,
    dest_slot: u64,
    src_cnode: Cap,
    src_slot: u64,
    badge: u64,
) -> i32 {
    invoke(dest_cnode, CNODE_MUTATE, dest_slot, src_cnode, src_slot, badge).error as i32
}

pub fn cnode_save_caller(cnode: Cap, slot: u64) -> i32 {
    invoke(cnode, CNODE_SAVE_CALLER, slot, 0, 0, 0).error as i32
}

pub fn cnode_delete(cnode: Cap, slot: u64) -> i32 {
    invoke(cnode, CNODE_DELETE, slot, 0, 0, 0).error as i32
}

pub fn cnode_revoke(cnode: Cap, slot: u64) -> i32 {
    invoke(cnode, CNODE_REVOKE, slot, 0, 0, 0).error as i32
}

pub fn irq_handler_ack(irq_handler: Cap) -> i32 {
    invoke(irq_handler, IRQ_HANDLER_ACK, 0, 0, 0, 0).error as i32
}

pub fn irq_handler_set_notification(irq_handler: Cap, ntfn: Cap) -> i32 {
    invoke(irq_handler, IRQ_HANDLER_SET_NOTIFICATION, ntfn, 0, 0, 0).error as i32
}

pub fn ioport_in8(ioport: Cap, offset: u64) -> u8 {
    invoke(ioport, IOPORT_IN8, offset, 0, 0, 0).value as u8
}

pub fn ioport_out8(ioport: Cap, offset: u64, value: u8) {
    invoke(ioport, IOPORT_OUT8, offset, value as u64, 0, 0);
}

pub fn ioport_in16(ioport: Cap, offset: u64) -> u16 {
    invoke(ioport, IOPORT_IN16, offset, 0, 0, 0).value as u16
}

pub fn ioport_out16(ioport: Cap, offset: u64, value: u16) {
    invoke(ioport, IOPORT_OUT16, offset, value as u64, 0, 0);
}
