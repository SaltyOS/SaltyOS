// SPDX-License-Identifier: GPL-2.0-only
//
//! Wire handlers for the adopt (private) and resolve (public) labels, plus the
//! reply paths. Adoption populates the cache from PID 1's trusted handoff;
//! resolution answers from the cache, falling back to a VFS open for a
//! `DT_NEEDED` miss or conferring `EXECUTE` on a `RESOLVE_MAIN` backing.

use trona_kernel::core_types::{CapRef, IpcContext, TronaMsg};
use trona_kernel::invoke;
use trona_kernel::ipc;
use trona_protocol::common::TRONA_OK;
use trona_protocol::ldsrv::{
    LDSRV_ADOPT_AUTHORITY, LDSRV_ADOPT_NAME_BASE, LDSRV_ADOPT_OBJECT, LDSRV_ADOPT_REG_ENTRY,
    LDSRV_ADOPT_REG_FORMAT, LDSRV_ADOPT_REG_IDENTITY_HI, LDSRV_ADOPT_REG_IDENTITY_LO,
    LDSRV_ADOPT_REG_MO_SIZE, LDSRV_ADOPT_REG_NAME_LEN, LDSRV_ADOPT_REG_PHNUM,
    LDSRV_ADOPT_REG_PHOFF, LDSRV_ADOPT_SEAL, LDSRV_RESOLVE_LIBRARY, LDSRV_RESOLVE_MAIN,
    LDSRV_RESOLVE_MAIN_REQ_REG_OFFSET, LDSRV_RESOLVE_MAIN_REQ_REG_SIZE,
    LDSRV_RESOLVE_REPLY_REG_COUNT, LDSRV_RESOLVE_REPLY_REG_ENTRY, LDSRV_RESOLVE_REPLY_REG_FORMAT,
    LDSRV_RESOLVE_REPLY_REG_IDENTITY, LDSRV_RESOLVE_REPLY_REG_MO_SIZE,
    LDSRV_RESOLVE_REPLY_REG_PHNUM, LDSRV_RESOLVE_REPLY_REG_PHOFF, LDSRV_RESOLVE_REQ_NAME_BASE,
    LDSRV_RESOLVE_REQ_REG_NAME_LEN,
};
use trona_runtime::core::slot_alloc::{dup_for_transfer, resolved_cap_ref, slot_invoke_depth};
use trona_server::recv_slot::{RecvSlotArena, capture_transferred_cap};

use crate::cache::{Cache, CodeObject, Identity, MAX_SONAME_BYTES};
use crate::resolve;

const SELF_CSPACE: u64 = uapi::KERNITE_CAP_SELF_CSPACE as u64;

/// Copy a packed soname (`len_idx` byte count, `base_idx..` bytes) out of a
/// request's register block into `out`, returning the byte length actually
/// copied (bounded by `out` and the registers available).
fn copy_name(regs: &[u64; 32], len_idx: usize, base_idx: usize, out: &mut [u8]) -> usize {
    let avail = (regs.len() - base_idx) * 8;
    let len = (regs[len_idx] as usize).min(out.len()).min(avail);
    let src = &regs[base_idx] as *const u64 as *const u8;
    for i in 0..len {
        out[i] = unsafe { *src.add(i) };
    }
    len
}

/// Handle one message on the private adopt MP. Returns `true` once the seal
/// arrives, ending the adopt phase.
///
/// # Safety
/// `ctx` is the current IPC context; the most recent `mp_read` on it produced
/// `msg`. `exec_authority_slot` points at the static holding the moved
/// authority slot.
pub unsafe fn handle_adopt(
    ctx: *mut IpcContext,
    msg: &TronaMsg,
    txid: u64,
    mp: u64,
    cache: &mut Cache,
    arena: &mut RecvSlotArena,
    exec_authority_slot: *mut u64,
) -> bool {
    match msg.label {
        LDSRV_ADOPT_OBJECT => {
            let Some(slot) = (unsafe { capture_transferred_cap(ctx, arena) }) else {
                unsafe { reply_err(ctx, mp, txid, uapi::KERNITE_ERR_INVALID_ARGUMENT as u64) };
                return false;
            };
            let identity = Identity {
                lo: msg.regs[LDSRV_ADOPT_REG_IDENTITY_LO],
                hi: msg.regs[LDSRV_ADOPT_REG_IDENTITY_HI],
            };
            let obj = CodeObject::new(
                identity,
                slot,
                msg.regs[LDSRV_ADOPT_REG_MO_SIZE],
                msg.regs[LDSRV_ADOPT_REG_FORMAT],
                msg.regs[LDSRV_ADOPT_REG_ENTRY],
                msg.regs[LDSRV_ADOPT_REG_PHOFF],
                msg.regs[LDSRV_ADOPT_REG_PHNUM],
            );
            if cache.find_object(identity).is_some() {
                let depth = slot_invoke_depth(slot);
                let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), slot, depth);
            } else if cache.insert_object(obj).is_none() {
                let depth = slot_invoke_depth(slot);
                let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), slot, depth);
                unsafe { reply_err(ctx, mp, txid, uapi::KERNITE_ERR_OUT_OF_MEMORY as u64) };
                return false;
            }
            let mut namebuf = [0u8; MAX_SONAME_BYTES];
            let nlen = copy_name(
                &msg.regs,
                LDSRV_ADOPT_REG_NAME_LEN,
                LDSRV_ADOPT_NAME_BASE,
                &mut namebuf,
            );
            if nlen == 0 || !cache.bind_soname(&namebuf[..nlen], identity) {
                unsafe { reply_err(ctx, mp, txid, uapi::KERNITE_ERR_OUT_OF_MEMORY as u64) };
                return false;
            }
            unsafe { reply_ok(ctx, mp, txid) };
            false
        }
        LDSRV_ADOPT_AUTHORITY => {
            let Some(slot) = (unsafe { capture_transferred_cap(ctx, arena) }) else {
                unsafe { reply_err(ctx, mp, txid, uapi::KERNITE_ERR_INVALID_ARGUMENT as u64) };
                return false;
            };
            unsafe { core::ptr::write_volatile(exec_authority_slot, slot) };
            unsafe { reply_ok(ctx, mp, txid) };
            false
        }
        LDSRV_ADOPT_SEAL => {
            unsafe { reply_ok(ctx, mp, txid) };
            true
        }
        _ => {
            unsafe { reply_err(ctx, mp, txid, uapi::KERNITE_ERR_INVALID_OPERATION as u64) };
            false
        }
    }
}

/// Answer one `resolve_*` request. `allow_main` gates `RESOLVE_MAIN` to the
/// private exec-control MP (init only): on the public service endpoint
/// (`allow_main == false`) a `RESOLVE_MAIN` is refused, so no client can ask
/// ldsrv to confer EXECUTE on a backing it supplied. `RESOLVE_LIBRARY` is
/// served on either source.
///
/// # Safety
/// `ctx` is the current IPC context; the most recent `mp_read` produced `msg`.
pub unsafe fn handle_resolve(
    ctx: *mut IpcContext,
    msg: &TronaMsg,
    txid: u64,
    ep: u64,
    cache: &mut Cache,
    arena: &mut RecvSlotArena,
    exec_authority: u64,
    allow_main: bool,
) {
    match msg.label {
        LDSRV_RESOLVE_LIBRARY => {
            let mut namebuf = [0u8; MAX_SONAME_BYTES];
            let nlen = copy_name(
                &msg.regs,
                LDSRV_RESOLVE_REQ_REG_NAME_LEN,
                LDSRV_RESOLVE_REQ_NAME_BASE,
                &mut namebuf,
            );
            if nlen == 0 {
                unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_INVALID_ARGUMENT as u64) };
                return;
            }
            let soname = &namebuf[..nlen];
            if soname.iter().any(|&b| b == b'/') {
                unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_INVALID_ARGUMENT as u64) };
                return;
            }
            let idx = cache
                .find_soname(soname)
                .or_else(|| unsafe { resolve::from_vfs(soname, exec_authority, cache) });
            match idx.and_then(|i| cache.object(i).copied()) {
                Some(obj) => unsafe { reply_code_mo(ctx, ep, txid, &obj) },
                None => unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_NOT_FOUND as u64) },
            }
        }
        LDSRV_RESOLVE_MAIN => {
            if !allow_main {
                // `resolve_main` confers EXECUTE on a caller-supplied backing,
                // so it is gated to the private exec-control MP (init). On the
                // public endpoint, capture and drop any transferred backing so
                // it does not linger in the receive slot, then refuse.
                if let Some(backing) = unsafe { capture_transferred_cap(ctx, arena) } {
                    let depth = slot_invoke_depth(backing);
                    let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), backing, depth);
                }
                unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_INVALID_OPERATION as u64) };
                return;
            }
            let Some(backing) = (unsafe { capture_transferred_cap(ctx, arena) }) else {
                unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_INVALID_ARGUMENT as u64) };
                return;
            };
            let size = msg.regs[LDSRV_RESOLVE_MAIN_REQ_REG_SIZE];
            let offset = msg.regs[LDSRV_RESOLVE_MAIN_REQ_REG_OFFSET];
            if size == 0 || offset.checked_add(size).is_none() {
                let depth = slot_invoke_depth(backing);
                let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), backing, depth);
                unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_INVALID_ARGUMENT as u64) };
                return;
            }
            let idx =
                unsafe { resolve::confer_and_cache(backing, offset, size, exec_authority, cache) };
            // The captured non-exec backing is redundant once the code MO is
            // minted (a hit reuses the cached MO; a miss minted an independent
            // CDT child) — release it.
            let depth = slot_invoke_depth(backing);
            let _ = invoke::cnode_delete_depth(CapRef::flat(SELF_CSPACE), backing, depth);
            match idx.and_then(|i| cache.object(i).copied()) {
                Some(obj) => unsafe { reply_code_mo(ctx, ep, txid, &obj) },
                None => unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_OUT_OF_MEMORY as u64) },
            }
        }
        _ => unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_INVALID_OPERATION as u64) },
    }
}

/// Reply with a transfer copy of a cached code MO plus its advisory header
/// summary. The pinned cache slot is left intact (`dup_for_transfer` copies,
/// preserving `READ|EXECUTE|GRANT|TRANSFER`); the copy is moved to the caller.
unsafe fn reply_code_mo(ctx: *mut IpcContext, ep: u64, txid: u64, obj: &CodeObject) {
    let Some(tc) = dup_for_transfer(resolved_cap_ref(obj.mo_slot)) else {
        unsafe { reply_err(ctx, ep, txid, uapi::KERNITE_ERR_OUT_OF_MEMORY as u64) };
        return;
    };
    let mut reply = TronaMsg::zeroed();
    reply.label = TRONA_OK;
    reply.regs[LDSRV_RESOLVE_REPLY_REG_MO_SIZE] = obj.mo_size;
    reply.regs[LDSRV_RESOLVE_REPLY_REG_IDENTITY] = obj.identity.lo;
    reply.regs[LDSRV_RESOLVE_REPLY_REG_FORMAT] = obj.format;
    reply.regs[LDSRV_RESOLVE_REPLY_REG_ENTRY] = obj.entry;
    reply.regs[LDSRV_RESOLVE_REPLY_REG_PHOFF] = obj.phoff;
    reply.regs[LDSRV_RESOLVE_REPLY_REG_PHNUM] = obj.phnum;
    reply.length = LDSRV_RESOLVE_REPLY_REG_COUNT;
    unsafe {
        ipc::set_send_cap_ctx(ctx, 0, tc.slot());
        let _ = ipc::mp_write_reply_to_ctx(ctx, ep, txid, &raw const reply);
    }
    drop(tc);
}

unsafe fn reply_ok(ctx: *mut IpcContext, ep: u64, txid: u64) {
    let mut reply = TronaMsg::zeroed();
    reply.label = TRONA_OK;
    reply.length = 0;
    unsafe {
        let _ = ipc::mp_write_reply_to_ctx(ctx, ep, txid, &raw const reply);
    }
}

unsafe fn reply_err(ctx: *mut IpcContext, ep: u64, txid: u64, err: u64) {
    let mut reply = TronaMsg::zeroed();
    reply.label = err;
    reply.length = 0;
    unsafe {
        let _ = ipc::mp_write_reply_to_ctx(ctx, ep, txid, &raw const reply);
    }
}
