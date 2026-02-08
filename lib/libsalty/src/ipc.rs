//! IPC operations (send, recv, call, reply_recv, etc.)
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::syscall::syscall;
use crate::types::*;

// Message info encoding
#[inline(always)]
pub fn msginfo(label: u64, length: u64, caps: u64) -> u64 {
    (label << 12) | (caps << 7) | (length & 0x7F)
}

#[inline(always)]
pub fn msginfo_label(info: u64) -> u64 {
    (info >> 12) & 0xFF_FFFF_FFFF
}

#[inline(always)]
pub fn msginfo_length(info: u64) -> u64 {
    info & 0x7F
}

#[inline(always)]
pub fn msginfo_extracaps(info: u64) -> u64 {
    (info >> 7) & 0x1F
}

// Context initialization
pub unsafe fn ipc_context_init(ctx: *mut IpcContext, ipc_buffer_vaddr: *mut IpcBuffer) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        (*ctx).ipc_buffer = ipc_buffer_vaddr;
        (*ctx).send_cap_count = 0;
    }
}

pub unsafe fn clear_send_caps_ctx(ctx: *mut IpcContext) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if !c.ipc_buffer.is_null() {
            for i in 0..4 {
                (*c.ipc_buffer).caps[i] = 0;
            }
        }
        c.send_cap_count = 0;
    }
}

pub unsafe fn set_send_cap_ctx(ctx: *mut IpcContext, slot_index: i32, cap_slot: u64) {
    if ctx.is_null() || slot_index < 0 || slot_index >= 4 {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        (*c.ipc_buffer).caps[slot_index as usize] = cap_slot;
        if c.send_cap_count < slot_index + 1 {
            c.send_cap_count = slot_index + 1;
        }
    }
}

pub unsafe fn set_receive_slot_ctx(ctx: *mut IpcContext, cnode: Cap, index: u64, depth: u64) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        let c = &mut *ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        (*c.ipc_buffer).receive_cnode = cnode;
        (*c.ipc_buffer).receive_index = index;
        (*c.ipc_buffer).receive_depth = depth;
    }
}

unsafe fn write_overflow_ctx(ctx: *mut IpcContext, msg: *const SaltyMsg) {
    unsafe {
        let len = (*msg).length as u32;
        let len = if len > 20 { 20 } else { len };
        if ctx.is_null() || len <= 4 {
            return;
        }
        let c = &*ctx;
        if c.ipc_buffer.is_null() {
            return;
        }
        let n = core::cmp::min(len as i32 - 4, 16);
        for i in 0..n as usize {
            (*c.ipc_buffer).msg[6 + i] = (*msg).regs[4 + i];
        }
    }
}

// Per-context IPC operations
pub unsafe fn send_ctx(ctx: *mut IpcContext, ep: Cap, msg: *const SaltyMsg) -> i32 {
    unsafe {
        let caps = if ctx.is_null() { 0 } else { (*ctx).send_cap_count };
        let info = msginfo((*msg).label, (*msg).length, caps as u64);
        write_overflow_ctx(ctx, msg);
        let r = syscall(
            SYS_SEND,
            ep,
            info,
            (*msg).regs[0],
            (*msg).regs[1],
            (*msg).regs[2],
            (*msg).regs[3],
        );
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        r.error as i32
    }
}

pub unsafe fn recv_ctx(
    ctx: *mut IpcContext,
    ep: Cap,
    msg: *mut SaltyMsg,
    badge: *mut u64,
) -> i32 {
    let r = syscall(SYS_RECV, ep, 0, 0, 0, 0, 0);
    if r.error == 0 {
        unsafe {
            if !badge.is_null() {
                *badge = r.value;
            }
            if !msg.is_null() && !ctx.is_null() && !(*ctx).ipc_buffer.is_null() {
                let buf = (*ctx).ipc_buffer as *const SaltyMsg;
                *msg = *buf;
            }
        }
    }
    r.error as i32
}

pub unsafe fn call_ctx(
    ctx: *mut IpcContext,
    ep: Cap,
    msg: *const SaltyMsg,
    reply: *mut SaltyMsg,
) -> i32 {
    unsafe {
        let caps = if ctx.is_null() { 0 } else { (*ctx).send_cap_count };
        let info = msginfo((*msg).label, (*msg).length, caps as u64);
        write_overflow_ctx(ctx, msg);
        let r = syscall(
            SYS_CALL,
            ep,
            info,
            (*msg).regs[0],
            (*msg).regs[1],
            (*msg).regs[2],
            (*msg).regs[3],
        );
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        if r.error == 0 && !reply.is_null() && !ctx.is_null() && !(*ctx).ipc_buffer.is_null() {
            let buf = (*ctx).ipc_buffer as *const SaltyMsg;
            *reply = *buf;
        }
        r.error as i32
    }
}

pub unsafe fn reply_recv_ctx(
    ctx: *mut IpcContext,
    ep: Cap,
    reply: *const SaltyMsg,
    out_msg: *mut SaltyMsg,
    badge: *mut u64,
) -> i32 {
    unsafe {
        let caps = if ctx.is_null() { 0 } else { (*ctx).send_cap_count };
        let info = msginfo((*reply).label, (*reply).length, caps as u64);
        write_overflow_ctx(ctx, reply);
        let r = syscall(
            SYS_REPLY_RECV,
            ep,
            info,
            (*reply).regs[0],
            (*reply).regs[1],
            (*reply).regs[2],
            (*reply).regs[3],
        );
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        if r.error == 0 {
            if !badge.is_null() {
                *badge = r.value;
            }
            if !out_msg.is_null() && !ctx.is_null() && !(*ctx).ipc_buffer.is_null() {
                let buf = (*ctx).ipc_buffer as *const SaltyMsg;
                *out_msg = *buf;
            }
        }
        r.error as i32
    }
}

pub unsafe fn nbsend_ctx(ctx: *mut IpcContext, ep: Cap, msg: *const SaltyMsg) -> i32 {
    unsafe {
        let caps = if ctx.is_null() { 0 } else { (*ctx).send_cap_count };
        let info = msginfo((*msg).label, (*msg).length, caps as u64);
        write_overflow_ctx(ctx, msg);
        let r = syscall(
            SYS_NBSEND,
            ep,
            info,
            (*msg).regs[0],
            (*msg).regs[1],
            (*msg).regs[2],
            (*msg).regs[3],
        );
        if caps > 0 && !ctx.is_null() {
            clear_send_caps_ctx(ctx);
        }
        r.error as i32
    }
}
