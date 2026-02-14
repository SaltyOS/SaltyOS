//! IPC operations: send, recv, call, reply_recv, nbsend
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! All IPC goes through a shared per-thread IPC buffer page. The kernel copies
//! the first 4 message registers from CPU registers (rdi, rsi, rdx, r10);
//! registers 4-19 overflow through the IPC buffer (`msg[6..21]`).
//!
//! # Message info encoding (seL4-style)
//!
//! A 64-bit `msginfo` word packs three fields:
//! - bits 6:0 = length (0-127 message registers)
//! - bits 11:7 = extra_caps (0-31 capability slots to transfer)
//! - bits 51:12 = label (operation identifier)
//!
//! # Capability transfer
//!
//! Before a send, stage caps in `ipc_buffer.caps[0..3]` and set `send_cap_count`.
//! Before a receive, configure `receive_cnode/index/depth` to designate where
//! incoming caps should be placed. Caps are automatically cleared after each send.

use crate::consts::*;
use crate::syscall::syscall;
use crate::types::*;

/// Encode label, length, and extra_caps into a 64-bit message info word.
#[inline(always)]
pub fn msginfo(label: u64, length: u64, caps: u64) -> u64 {
    (label << 12) | (caps << 7) | (length & 0x7F)
}

/// Extract the label field from a message info word (bits 51:12).
#[inline(always)]
pub fn msginfo_label(info: u64) -> u64 {
    (info >> 12) & 0xFF_FFFF_FFFF
}

/// Extract the message length from a message info word (bits 6:0).
#[inline(always)]
pub fn msginfo_length(info: u64) -> u64 {
    info & 0x7F
}

/// Extract the extra_caps count from a message info word (bits 11:7).
#[inline(always)]
pub fn msginfo_extracaps(info: u64) -> u64 {
    (info >> 7) & 0x1F
}

/// Initialize an IPC context with the given IPC buffer page address.
///
/// # Safety
/// `ctx` must be a valid pointer. `ipc_buffer_vaddr` must point to a
/// mapped IPC buffer page (or be null to defer initialization).
pub unsafe fn ipc_context_init(ctx: *mut IpcContext, ipc_buffer_vaddr: *mut IpcBuffer) {
    if ctx.is_null() {
        return;
    }
    unsafe {
        (*ctx).ipc_buffer = ipc_buffer_vaddr;
        (*ctx).send_cap_count = 0;
    }
}

/// Clear all staged send capabilities and reset the send_cap_count to 0.
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

/// Stage a capability for transfer on the next send. `slot_index` (0-3)
/// selects the position in `ipc_buffer.caps[]`.
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

/// Configure the receive slot for incoming capability transfers.
/// The kernel will place received caps at `cnode[index]` with the given `depth`.
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

/// Write overflow message registers (regs[4..19]) into the IPC buffer.
/// Called before send/call/reply_recv when the message exceeds 4 registers.
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

/// Blocking send on an endpoint. Blocks until a receiver is ready.
/// Transfers `msg` and any staged capabilities. Returns 0 on success.
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

/// Blocking receive on an endpoint. Blocks until a sender arrives.
/// On success, copies the received message into `*msg` and writes the
/// sender's badge to `*badge`. Returns 0 on success.
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

/// Blocking call (send + receive): sends `msg` on `ep`, then blocks
/// waiting for the server's reply. The reply message is written to `*reply`.
/// This is the standard client RPC pattern. Returns 0 on success.
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

/// Reply to the current caller and wait for the next request (server loop).
///
/// Atomically sends `reply` to the caller that invoked Call, then blocks
/// on `ep` waiting for the next incoming message. The next message is
/// written to `*out_msg` and the sender's badge to `*badge`.
/// Returns 0 on success.
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

/// Non-blocking send: delivers `msg` to a waiting receiver if one exists,
/// otherwise returns immediately with an error (no blocking).
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
