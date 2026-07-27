// SPDX-License-Identifier: GPL-2.0-only

//! Per-label handlers. The reactor enters this dispatch table after
//! reading one `MpRecord` from the master MP. Each handler validates
//! authorisation, mutates `ServerState`, and replies via `reply-marked MP_WRITE`
//! on the master MessagePipe endpoint.

use core::sync::atomic::{AtomicU64, Ordering};
use trona_kernel::syscall;
use uapi::{
    KERNITE_ERR_INSUFFICIENT_RESOURCES, KERNITE_ERR_INSUFFICIENT_RIGHTS,
    KERNITE_ERR_INVALID_ARGUMENT, KERNITE_ERR_INVALID_CAPABILITY, KERNITE_ERR_NOT_FOUND,
    KERNITE_ERR_NOT_SUPPORTED, KERNITE_ERR_OUT_OF_MEMORY, KERNITE_INV_CNODE_COPY,
    KERNITE_INV_CNODE_DELETE, KERNITE_INV_CNODE_MINT, KERNITE_INV_CNODE_MOVE,
    KERNITE_INV_CNODE_REVOKE, KERNITE_OBJ_DATA_PIPE, KERNITE_OBJ_DATA_PIPE_CORE,
    KERNITE_OBJ_MESSAGE_PIPE, KERNITE_OBJ_MESSAGE_PIPE_CORE, KERNITE_RIGHT_ALL, kernite_ipc_buffer,
};

use crate::authz::{BadgeClass, BadgeFields};
use crate::caps::{
    CAP_SELF_CSPACE, object_back_ref_base, object_back_ref_len, recv_payload0_slot, recv_user_slot,
};
use crate::labels::{
    LABEL_ADOPT_UNTYPED, LABEL_ALLOC, LABEL_ALLOC_DP_PAIR, LABEL_ALLOC_MP_PAIR, LABEL_BATCH_ALLOC,
    LABEL_DUMP_STATS, LABEL_FREE, LABEL_GET_QUOTA, LABEL_OWNER_EXITED, LABEL_PROVISION_CLIENT,
    LABEL_REBIND_FAULT_PIPE, LABEL_SET_QUOTA, REPLY_RECORD_ID_WORD, REQ_BATCH_COUNT_WORD,
    REQ_BATCH_SIZE_BITS_BASE, REQ_BATCH_TYPES_BASE, REQ_FLAGS_WORD, REQ_FREE_RECORD_ID_WORD,
    REQ_SIZE_BITS_WORD, REQ_TYPE_WORD, RSRC_TYPE_AGGREGATE,
};
use crate::main_loop::ServerState;
use crate::objects::{
    MAX_OBJECTS, NUM_OBJ_CLASSES, class_cost_bytes, class_of, class_size_bits_default,
    unpack_record_id,
};
use crate::pairs;
use trona_server::MpReplyTarget;
use trona_server::badge::client_id_of;

const TRONA_OK: u64 = 0;
static CURRENT_REPLY_MP: AtomicU64 = AtomicU64::new(0);
static CURRENT_REPLY_TXID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_current_reply_target(buf: *const kernite_ipc_buffer, slot: u64) {
    let target = unsafe { MpReplyTarget::from_ipc_buffer(buf, slot) };
    CURRENT_REPLY_MP.store(target.mp_slot, Ordering::Relaxed);
    CURRENT_REPLY_TXID.store(target.txid, Ordering::Relaxed);
}

pub(crate) fn current_reply_target() -> MpReplyTarget {
    MpReplyTarget::new(
        CURRENT_REPLY_MP.load(Ordering::Relaxed),
        CURRENT_REPLY_TXID.load(Ordering::Relaxed),
    )
}

fn set_self_cnode_depths(src_slot: u64, dest_slot: u64) {
    let src_depth = trona_runtime::core::slot_alloc::slot_invoke_depth(src_slot) as u64;
    let dest_depth = trona_runtime::core::slot_alloc::slot_invoke_depth(dest_slot) as u64;
    let _ = syscall::invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_SET_INVOKE_DEPTHS as u64,
        src_depth,
        dest_depth,
        0,
        0,
    );
}

fn cnode_mint_self(src_slot: u64, dest_slot: u64, badge: u64) -> i32 {
    set_self_cnode_depths(src_slot, dest_slot);
    syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_MINT as u64,
        src_slot,
        CAP_SELF_CSPACE,
        dest_slot,
        badge,
    )
    .error as i32
}

fn cnode_copy_self(src_slot: u64, dest_slot: u64) -> i32 {
    set_self_cnode_depths(src_slot, dest_slot);
    syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_COPY as u64,
        src_slot,
        CAP_SELF_CSPACE,
        dest_slot,
        KERNITE_RIGHT_ALL as u64,
    )
    .error as i32
}

fn cnode_delete_self(slot: u64) -> i32 {
    set_self_cnode_depths(slot, 0);
    syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_DELETE as u64,
        slot,
        0,
        0,
        0,
    )
    .error as i32
}

fn cnode_move_self(src_slot: u64, dest_slot: u64) -> i32 {
    let dest_depth = trona_runtime::core::slot_alloc::slot_invoke_depth(dest_slot) as u64;
    let src_depth = trona_runtime::core::slot_alloc::slot_invoke_depth(src_slot) as u64;
    let _ = syscall::invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_SET_INVOKE_DEPTHS as u64,
        dest_depth,
        src_depth,
        0,
        0,
    );
    syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_MOVE as u64,
        dest_slot,
        CAP_SELF_CSPACE,
        src_slot,
        0,
    )
    .error as i32
}

pub(crate) fn cnode_revoke_self(slot: u64) -> i32 {
    set_self_cnode_depths(slot, 0);
    syscall::invoke(
        CAP_SELF_CSPACE,
        KERNITE_INV_CNODE_REVOKE as u64,
        slot,
        0,
        0,
        0,
    )
    .error as i32
}

pub(crate) fn send_reply(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) -> i32 {
    if buf.is_null() {
        return KERNITE_ERR_INVALID_ARGUMENT as i32;
    }
    let target = current_reply_target();
    unsafe { trona_server::mp_write_reply_to(buf, target, label, regs, cap_count) }
}

fn send_reply_if_requested(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) -> i32 {
    if current_reply_target().has_txid() {
        send_reply(buf, label, regs, cap_count)
    } else {
        0
    }
}

pub(crate) fn alloc_reply_temp(src_slot: u64, badge: u64) -> Result<u64, i32> {
    let Some(temp) = trona_runtime::core::slot_alloc::alloc_slot_no_expand() else {
        return Err(KERNITE_ERR_INSUFFICIENT_RESOURCES as i32);
    };
    // Unbadged allocator replies are authority-bearing object caps:
    // init may need to copy/mint them onward into child CSpaces or
    // transfer duplicates to mmsrv. Only true badged replies use mint,
    // since the kernel deliberately strips Grant from minted caps.
    let r = if badge == 0 {
        cnode_copy_self(src_slot, temp.addr())
    } else {
        cnode_mint_self(src_slot, temp.addr(), badge)
    };
    if r != 0 {
        // copy/mint failed: `temp` (OwnedSlot) Drop frees the empty slot.
        return Err(r);
    }
    Ok(temp.into_raw())
}

pub(crate) fn finish_reply_with_caps(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64],
    temps: &[u64],
) -> i32 {
    if buf.is_null() {
        return KERNITE_ERR_INVALID_ARGUMENT as i32;
    }
    unsafe {
        for (i, slot) in temps
            .iter()
            .enumerate()
            .take(uapi::KERNITE_IPC_MAX_CAPS as usize)
        {
            (*buf).caps[i] = *slot;
        }
    }
    let result = unsafe {
        trona_server::mp_write_reply_to_with_error_fallback(
            buf,
            current_reply_target(),
            label,
            regs,
            temps.len() as u64,
        )
    };
    let err = result.primary_error;
    // SAFETY: `temps` are this reply's temp slots, solely owned here; on failure
    // they still hold caps (deleted), on success they were emptied (reclaimed).
    unsafe { release_reply_temps(temps, err != 0) };
    if err != 0 && result.fallback_error != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[RSRCSRV] cap reply fallback failed primary=");
            _lb.dec(err as u64);
            _lb.str(b" fallback=");
            _lb.dec(result.fallback_error as u64);
            _lb.putc(b'\n');
        });
    }
    err
}

/// # Safety
/// `temps` are reply-temp slots the caller solely owns. With `delete_caps`, each
/// still holds its cap (reply failed) and is torn down and freed; without it,
/// each was emptied by a successful reply and only its index is reclaimed.
pub(crate) unsafe fn release_reply_temps(temps: &[u64], delete_caps: bool) {
    for slot in temps {
        if delete_caps {
            // SAFETY: caller-owned reply-temp slot, cap still present (the reply
            // failed) per this fn's `# Safety`.
            unsafe { trona_runtime::core::slot_alloc::delete_and_free(*slot) };
        } else {
            // The reply transferred the cap out, leaving the slot empty.
            // SAFETY: on a successful reply the cap was moved out of `*slot`, so
            // it is empty; it was allocated for this reply temp and freed once.
            unsafe {
                trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(*slot);
            }
        }
    }
}

fn discard_payload_caps(buf: *mut kernite_ipc_buffer) {
    if buf.is_null() {
        return;
    }
    let cap_count = unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf) };
    for idx in 0..cap_count {
        let _ = cnode_delete_self(recv_user_slot(idx));
    }
}

fn require_admin(buf: *mut kernite_ipc_buffer, fields: &BadgeFields) -> bool {
    if matches!(fields.class, BadgeClass::Admin) {
        return true;
    }
    send_reply(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
    false
}

/// Pick a back-reference slot from the rsrcsrv-private object-cap zone.
/// Slots are paired 1:1 with `ObjectTable` indices — record idx N owns
/// slot `object_back_ref_base + N`. Caller asserts the index is within
/// the reserved range.
fn back_ref_slot_for(idx: usize) -> u64 {
    object_back_ref_base() + idx as u64
}
fn handle_alloc(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    let owner_id = fields.client_id;
    let obj_type = regs[REQ_TYPE_WORD];
    let size_bits = regs[REQ_SIZE_BITS_WORD];
    let flags = regs[REQ_FLAGS_WORD];

    if flags != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let Some(class) = class_of(obj_type) else {
        send_reply(buf, KERNITE_ERR_NOT_SUPPORTED as u64, &[], 0);
        return;
    };

    if obj_type == KERNITE_OBJ_MESSAGE_PIPE_CORE
        || obj_type == KERNITE_OBJ_MESSAGE_PIPE
        || obj_type == KERNITE_OBJ_DATA_PIPE_CORE
        || obj_type == KERNITE_OBJ_DATA_PIPE
    {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let bytes = class_cost_bytes(class, size_bits);
    if state.quotas.admit(owner_id, class, bytes).is_err() {
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    }

    let Some(rec_idx) = state.objects.alloc() else {
        state.quotas.release(owner_id, class, bytes);
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    };
    if rec_idx as u64 >= object_back_ref_len() {
        state.quotas.release(owner_id, class, bytes);
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    }
    let back_ref = back_ref_slot_for(rec_idx);
    let kernel_size_bits = class_size_bits_default(class, size_bits);

    let chunk_idx = match state
        .untyped
        .try_retype_detailed(obj_type, kernel_size_bits, back_ref)
    {
        Ok(idx) => idx,
        Err(failure) => {
            state.quotas.release(owner_id, class, bytes);
            send_reply(buf, failure.reply_error(), &[], 0);
            return;
        }
    };

    let reply_cap = match alloc_reply_temp(back_ref, 0) {
        Ok(slot) => slot,
        Err(_) => {
            let _ = cnode_revoke_self(back_ref);
            state.untyped.release_one(chunk_idx);
            state.untyped.drain_and_reset();
            state.quotas.release(owner_id, class, bytes);
            send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
            return;
        }
    };

    let record_id = state.objects.install(
        rec_idx,
        obj_type,
        size_bits as u8,
        class,
        u32::MAX,
        owner_id,
        back_ref,
        chunk_idx,
        bytes as u32,
    );
    let mut reply = [0u64; 1];
    reply[REPLY_RECORD_ID_WORD] = record_id;
    let err = finish_reply_with_caps(buf, TRONA_OK, &reply, &[reply_cap]);
    if err != 0 {
        let _ = cnode_revoke_self(back_ref);
        state.untyped.release_one(chunk_idx);
        state.untyped.drain_and_reset();
        state.quotas.release(owner_id, class, bytes);
        let _ = state.objects.vacate(rec_idx);
        return;
    }
}

fn handle_free(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    let owner_id = fields.client_id;
    let record_id = regs[REQ_FREE_RECORD_ID_WORD];
    let (epoch, idx) = unpack_record_id(record_id);
    let Some(record) = state.objects.record(idx as usize) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    if record.epoch != epoch {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    }
    if record.owner_id != owner_id {
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
        return;
    }
    let pair_group = record.pair_group;

    let mut indices = [idx as usize; 3];
    let mut indices_n = 1usize;
    if pair_group != u32::MAX {
        indices_n = 0;
        for candidate in 0..MAX_OBJECTS {
            let Some(r) = state.objects.record(candidate) else {
                continue;
            };
            if r.owner_id == owner_id && r.pair_group == pair_group {
                if indices_n >= indices.len() {
                    send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
                    return;
                }
                indices[indices_n] = candidate;
                indices_n += 1;
            }
        }
        if indices_n == 0 {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        }
    }

    let mut back_refs = [(0u64, 0usize, 0u64, 0usize); 3];
    for i in 0..indices_n {
        let r = state
            .objects
            .record(indices[i])
            .expect("free target stable");
        back_refs[i] = (
            r.back_ref_slot,
            r.class as usize,
            r.bytes as u64,
            r.parent_chunk_idx as usize,
        );
    }
    for i in 0..indices_n {
        let (back_ref, class, bytes, chunk_idx) = back_refs[i];
        let _ = cnode_revoke_self(back_ref);
        state.untyped.release_one(chunk_idx);
        state.quotas.release(owner_id, class, bytes);
    }
    for idx in indices.iter().copied().take(indices_n) {
        state.objects.vacate(idx);
    }
    // Reclaim drained chunks after every revoke in the group has landed,
    // so a freed MP-pair's three sides reset together rather than one
    // side's reset being refused while a sibling is still bound.
    state.untyped.drain_and_reset();
    send_reply(buf, TRONA_OK, &[], 0);
}

fn rollback_batch_allocs(
    state: &mut ServerState,
    allocated: &[(usize, usize, u64); 8],
    allocated_n: usize,
    admitted: &[(u32, usize, u64); 8],
    admitted_n: usize,
) {
    for (rec_idx, chunk_idx, back_ref) in allocated.iter().copied().take(allocated_n) {
        let _ = cnode_revoke_self(back_ref);
        state.untyped.release_one(chunk_idx);
        let _ = state.objects.vacate(rec_idx);
    }
    for (owner_id, class, bytes) in admitted.iter().copied().take(admitted_n) {
        state.quotas.release(owner_id, class, bytes);
    }
    state.untyped.drain_and_reset();
}

fn handle_batch_alloc(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    let owner_id = fields.client_id;
    let count = regs[REQ_BATCH_COUNT_WORD] as usize;
    let max_reply_caps = uapi::KERNITE_IPC_MAX_CAPS as usize;
    if count == 0 || count > max_reply_caps || count > 8 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let mut results = [0u64; 8];
    let mut admitted: [(u32, usize, u64); 8] = [(0, 0, 0); 8];
    let mut admitted_n = 0usize;
    let mut allocated: [(usize, usize, u64); 8] = [(0, 0, 0); 8];
    let mut allocated_n = 0usize;
    let mut reply_caps = [0u64; 8];
    let mut reply_caps_n = 0usize;
    for i in 0..count {
        let obj_type = regs[REQ_BATCH_TYPES_BASE + i];
        let size_bits = regs[REQ_BATCH_SIZE_BITS_BASE + i];
        let Some(class) = class_of(obj_type) else {
            // SAFETY: reply_caps[..reply_caps_n] are this batch's reply temps
            // allocated so far, solely owned here; caps still present (deleted).
            unsafe { release_reply_temps(&reply_caps[..reply_caps_n], true) };
            rollback_batch_allocs(state, &allocated, allocated_n, &admitted, admitted_n);
            send_reply(buf, KERNITE_ERR_NOT_SUPPORTED as u64, &[], 0);
            return;
        };
        let bytes = class_cost_bytes(class, size_bits);
        if state.quotas.admit(owner_id, class, bytes).is_err() {
            // SAFETY: reply_caps[..reply_caps_n] are this batch's reply temps
            // allocated so far, solely owned here; caps still present (deleted).
            unsafe { release_reply_temps(&reply_caps[..reply_caps_n], true) };
            rollback_batch_allocs(state, &allocated, allocated_n, &admitted, admitted_n);
            send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
            return;
        }
        admitted[admitted_n] = (owner_id, class, bytes);
        admitted_n += 1;
        let Some(rec_idx) = state.objects.alloc() else {
            // SAFETY: reply_caps[..reply_caps_n] are this batch's reply temps
            // allocated so far, solely owned here; caps still present (deleted).
            unsafe { release_reply_temps(&reply_caps[..reply_caps_n], true) };
            rollback_batch_allocs(state, &allocated, allocated_n, &admitted, admitted_n);
            send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
            return;
        };
        let back_ref = back_ref_slot_for(rec_idx);
        let kernel_size_bits = class_size_bits_default(class, size_bits);
        let chunk_idx =
            match state
                .untyped
                .try_retype_detailed(obj_type, kernel_size_bits, back_ref)
            {
                Ok(idx) => idx,
                Err(failure) => {
                    // SAFETY: reply_caps[..reply_caps_n] are this batch's reply temps
                    // allocated so far, solely owned here; caps still present (deleted).
                    unsafe { release_reply_temps(&reply_caps[..reply_caps_n], true) };
                    rollback_batch_allocs(state, &allocated, allocated_n, &admitted, admitted_n);
                    send_reply(buf, failure.reply_error(), &[], 0);
                    return;
                }
            };
        allocated[allocated_n] = (rec_idx, chunk_idx, back_ref);
        allocated_n += 1;
        let reply_cap = match alloc_reply_temp(back_ref, 0) {
            Ok(slot) => slot,
            Err(_) => {
                // SAFETY: reply_caps[..reply_caps_n] are this batch's reply temps
                // allocated so far, solely owned here; caps still present (deleted).
                unsafe { release_reply_temps(&reply_caps[..reply_caps_n], true) };
                rollback_batch_allocs(state, &allocated, allocated_n, &admitted, admitted_n);
                send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
                return;
            }
        };
        reply_caps[reply_caps_n] = reply_cap;
        reply_caps_n += 1;
        let record_id = state.objects.install(
            rec_idx,
            obj_type,
            size_bits as u8,
            class,
            u32::MAX,
            owner_id,
            back_ref,
            chunk_idx,
            bytes as u32,
        );
        results[i] = record_id;
    }
    let mut reply = [0u64; 9];
    reply[0] = count as u64;
    for i in 0..count {
        reply[i + 1] = results[i];
    }
    let err = finish_reply_with_caps(buf, TRONA_OK, &reply[..1 + count], &reply_caps[..count]);
    if err != 0 {
        rollback_batch_allocs(state, &allocated, allocated_n, &admitted, admitted_n);
    }
}

fn handle_get_quota(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &ServerState,
) {
    let target = regs[0];
    let target_id = if target == 0 {
        fields.client_id
    } else if matches!(fields.class, BadgeClass::Admin) {
        client_id_of(target)
    } else {
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
        return;
    };
    let Some(entry) = state.quotas.find(target_id) else {
        send_reply(buf, TRONA_OK, &[0u64, 0, 0], 0);
        return;
    };
    let mut reply = [0u64; 1 + 1 + 1 + NUM_OBJ_CLASSES + NUM_OBJ_CLASSES];
    reply[0] = entry.bytes_used;
    reply[1] = entry.bytes_max;
    let mut idx = 2;
    for v in entry.per_class_used.iter() {
        reply[idx] = *v as u64;
        idx += 1;
    }
    for v in entry.per_class_max.iter() {
        reply[idx] = *v as u64;
        idx += 1;
    }
    send_reply(buf, TRONA_OK, &reply, 0);
}

fn handle_set_quota(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    if !require_admin(buf, fields) {
        discard_payload_caps(buf);
        return;
    }
    let target_id = client_id_of(regs[0]);
    let class_or_aggregate = regs[1];
    let limit = regs[2];
    if class_or_aggregate == RSRC_TYPE_AGGREGATE {
        let mut zero = [0u32; NUM_OBJ_CLASSES];
        if let Some(existing) = state.quotas.find(target_id) {
            zero = existing.per_class_max;
        }
        let _ = state.quotas.set_quota(target_id, limit, zero, false);
    } else {
        let class = class_or_aggregate as usize;
        if class >= NUM_OBJ_CLASSES {
            send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
            return;
        }
        let mut new_caps = [0u32; NUM_OBJ_CLASSES];
        let mut bytes_max = 0u64;
        if let Some(existing) = state.quotas.find(target_id) {
            new_caps = existing.per_class_max;
            bytes_max = existing.bytes_max;
        }
        new_caps[class] = limit as u32;
        let _ = state
            .quotas
            .set_quota(target_id, bytes_max, new_caps, false);
    }
    send_reply(buf, TRONA_OK, &[], 0);
}

fn handle_owner_exited(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    if !matches!(fields.class, BadgeClass::Admin) {
        let _ = send_reply_if_requested(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
        return;
    }
    let exited = client_id_of(regs[0]);
    // Revoke every object this owner still holds, then reclaim the drained
    // chunks in one pass. Revoking all back_refs *before* resetting is
    // load-bearing: a bound MP-pair side stays alive (its chunk un-resettable,
    // refused HasChildren) until its core's back_ref is also revoked, so a
    // per-object reset mid-loop would be refused and strand the chunk. The
    // whole owned set is processed — no fixed truncation.
    let mut freed = 0u64;
    for idx in 0..MAX_OBJECTS {
        let Some(record) = state.objects.record(idx).copied() else {
            continue;
        };
        if record.owner_id != exited {
            continue;
        }
        let _ = cnode_revoke_self(record.back_ref_slot);
        state.untyped.release_one(record.parent_chunk_idx as usize);
        state
            .quotas
            .release(exited, record.class as usize, record.bytes as u64);
        state.objects.vacate(idx);
        freed += 1;
    }
    state.untyped.drain_and_reset();
    state.quotas.drop_owner(exited);
    let _ = send_reply_if_requested(buf, TRONA_OK, &[freed], 0);
}

fn handle_dump_stats(buf: *mut kernite_ipc_buffer, fields: &BadgeFields, state: &ServerState) {
    if !require_admin(buf, fields) {
        return;
    }
    let used = state.objects.used() as u64;
    let chunks = state.untyped.used() as u64;
    let owners = state.quotas.iter_used().count() as u64;
    let self_storage_high = crate::selfmem::current_high_watermark();
    send_reply(buf, TRONA_OK, &[used, chunks, owners, self_storage_high], 0);
}

fn handle_adopt_untyped(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    if !require_admin(buf, fields) {
        discard_payload_caps(buf);
        return;
    }
    let size_bits = regs[0] as u8;
    let payload_slot = recv_payload0_slot();
    let Some(stable) = trona_runtime::core::slot_alloc::alloc_slot_no_expand() else {
        let _ = cnode_delete_self(payload_slot);
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    };
    let move_err = cnode_move_self(payload_slot, stable.addr());
    if move_err != 0 {
        let _ = cnode_delete_self(payload_slot);
        // move failed: `stable` (OwnedSlot, empty) Drop frees the slot.
        send_reply(buf, KERNITE_ERR_INVALID_CAPABILITY as u64, &[], 0);
        return;
    }
    let stable_slot = stable.into_raw();
    if !state.untyped.adopt(stable_slot, size_bits) {
        // SAFETY: stable_slot holds the payload cap cnode_move'd in and into_raw'd
        // above; solely owned here, torn down + freed once on this failure path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(stable_slot) };
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    }
    send_reply(buf, TRONA_OK, &[], 0);
}

fn handle_provision_client(
    buf: *mut kernite_ipc_buffer,
    _regs: &[u64; 32],
    fields: &BadgeFields,
    _state: &mut ServerState,
) {
    if !require_admin(buf, fields) {
        return;
    }
    discard_payload_caps(buf);
    send_reply(buf, KERNITE_ERR_NOT_SUPPORTED as u64, &[], 0);
}

fn handle_rebind_fault_pipe(
    buf: *mut kernite_ipc_buffer,
    fields: &BadgeFields,
    state: &mut ServerState,
) {
    if !require_admin(buf, fields) {
        discard_payload_caps(buf);
        return;
    }
    let payload_slot = recv_payload0_slot();
    let Some(stable) = trona_runtime::core::slot_alloc::alloc_slot_no_expand() else {
        let _ = cnode_delete_self(payload_slot);
        send_reply(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    };
    let move_err = cnode_move_self(payload_slot, stable.addr());
    if move_err != 0 {
        let _ = cnode_delete_self(payload_slot);
        // move failed: `stable` (OwnedSlot, empty) Drop frees the slot.
        send_reply(buf, KERNITE_ERR_INVALID_CAPABILITY as u64, &[], 0);
        return;
    }
    let stable_slot = stable.into_raw();
    let old_fault_pipe = state.startup.fault_pipe_send;
    state.startup.fault_pipe_send = stable_slot;
    let r = syscall::invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_SET_FAULT_PIPE as u64,
        state.startup.fault_pipe_send,
        0,
        0,
        0,
    );
    if r.error != 0 {
        state.startup.fault_pipe_send = old_fault_pipe;
        // SAFETY: stable_slot holds the payload cap cnode_move'd in and into_raw'd
        // above; solely owned here, torn down + freed once on this failure path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(stable_slot) };
        send_reply(buf, KERNITE_ERR_INVALID_CAPABILITY as u64, &[], 0);
        return;
    }
    if old_fault_pipe != 0 {
        // SAFETY: old_fault_pipe is the previous fault-pipe send cap rsrcsrv owns,
        // now superseded; torn down + freed once here.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(old_fault_pipe) };
    }
    send_reply(buf, TRONA_OK, &[], 0);
}

pub fn dispatch(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) -> bool {
    let Some(fields) = BadgeFields::parse(badge) else {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return true;
    };
    if fields.policy_id != 0 {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return true;
    }
    let owner_id = fields.client_id;
    match label {
        LABEL_ALLOC => handle_alloc(buf, regs, &fields, state),
        LABEL_FREE => handle_free(buf, regs, &fields, state),
        LABEL_BATCH_ALLOC => handle_batch_alloc(buf, regs, &fields, state),
        LABEL_GET_QUOTA => handle_get_quota(buf, regs, &fields, state),
        LABEL_SET_QUOTA => handle_set_quota(buf, regs, &fields, state),
        LABEL_OWNER_EXITED => handle_owner_exited(buf, regs, &fields, state),
        LABEL_DUMP_STATS => handle_dump_stats(buf, &fields, state),
        LABEL_ADOPT_UNTYPED => handle_adopt_untyped(buf, regs, &fields, state),
        LABEL_PROVISION_CLIENT => handle_provision_client(buf, regs, &fields, state),
        LABEL_REBIND_FAULT_PIPE => handle_rebind_fault_pipe(buf, &fields, state),
        LABEL_ALLOC_MP_PAIR => pairs::handle_alloc_mp_pair(buf, regs, owner_id, state),
        LABEL_ALLOC_DP_PAIR => pairs::handle_alloc_dp_pair(buf, regs, owner_id, state),
        _ => return false,
    }
    true
}
