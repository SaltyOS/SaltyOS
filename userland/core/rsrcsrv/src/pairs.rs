// SPDX-License-Identifier: GPL-2.0-only
//
//! MP / DP pair retype. A pair is one Core object plus two side
//! handles bound via `KERNITE_INV_MP_CORE_PAIR` (or DP equivalent).
//! Quota is charged once for the whole group; the three records share
//! a `pair_group` so OWNER_EXITED tears them down atomically.

use core::sync::atomic::{AtomicU32, Ordering};

use trona_kernel::syscall;
use uapi::{
    KERNITE_DATA_PIPE_BYTES, KERNITE_DATA_PIPE_CORE_BYTES, KERNITE_ERR_INSUFFICIENT_RESOURCES,
    KERNITE_ERR_INVALID_CAPABILITY, KERNITE_ERR_OUT_OF_MEMORY, KERNITE_INV_DP_CORE_PAIR,
    KERNITE_INV_MP_CORE_PAIR, KERNITE_MESSAGE_PIPE_BYTES, KERNITE_MESSAGE_PIPE_CORE_BYTES,
    KERNITE_OBJ_DATA_PIPE, KERNITE_OBJ_DATA_PIPE_CORE, KERNITE_OBJ_MESSAGE_PIPE,
    KERNITE_OBJ_MESSAGE_PIPE_CORE, kernite_ipc_buffer,
};

use crate::caps::{object_back_ref_base, object_back_ref_len};
use crate::main_loop::ServerState;
use crate::objects::{CLASS_DP_PAIR, CLASS_MP_PAIR, MAX_OBJECTS};

const TRONA_OK: u64 = 0;

static PAIR_GROUP_NEXT: AtomicU32 = AtomicU32::new(1);

fn next_pair_group() -> u32 {
    PAIR_GROUP_NEXT.fetch_add(1, Ordering::Relaxed)
}

fn back_ref_slot_for(idx: usize) -> u64 {
    object_back_ref_base() + idx as u64
}

fn revoke_back_ref(slot: u64) {
    let _ = crate::dispatch::cnode_revoke_self(slot);
}

fn alloc_pair_records(state: &mut ServerState) -> Option<(usize, usize, usize)> {
    let mut out = [0usize; 3];
    let mut found = 0usize;
    for idx in 0..MAX_OBJECTS {
        if state.objects.record(idx).is_none() {
            out[found] = idx;
            found += 1;
            if found == out.len() {
                return Some((out[0], out[1], out[2]));
            }
        }
    }
    None
}

fn install_record(
    state: &mut ServerState,
    rec_idx: usize,
    obj_type: u64,
    class: usize,
    pair_group: u32,
    owner_id: u32,
    back_ref: u64,
    chunk_idx: usize,
    bytes: u64,
) -> u64 {
    state.objects.install(
        rec_idx,
        obj_type,
        0,
        class,
        pair_group,
        owner_id,
        back_ref,
        chunk_idx,
        bytes as u32,
    )
}

/// Common pair retype — split between MP and DP only by the type
/// constants and the bind invocation label.
fn handle_pair(
    buf: *mut kernite_ipc_buffer,
    owner_id: u32,
    state: &mut ServerState,
    core_type: u64,
    side_type: u64,
    bind_label: u64,
    class: usize,
    bytes: u64,
) {
    if state.quotas.admit(owner_id, class, bytes).is_err() {
        super_consume(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[]);
        return;
    }
    let Some((core_idx, a_idx, b_idx)) = alloc_pair_records(state) else {
        state.quotas.release(owner_id, class, bytes);
        super_consume(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[]);
        return;
    };
    if (core_idx as u64) >= object_back_ref_len()
        || (a_idx as u64) >= object_back_ref_len()
        || (b_idx as u64) >= object_back_ref_len()
    {
        state.quotas.release(owner_id, class, bytes);
        super_consume(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[]);
        return;
    }
    let core_back = back_ref_slot_for(core_idx);
    let Some(core_chunk) = state.untyped.try_retype(core_type, 0, core_back) else {
        state.quotas.release(owner_id, class, bytes);
        super_consume(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[]);
        return;
    };
    let a_back = back_ref_slot_for(a_idx);
    let Some(a_chunk) = state.untyped.try_retype(side_type, 0, a_back) else {
        revoke_back_ref(core_back);
        state.untyped.release_one(core_chunk);
        state.quotas.release(owner_id, class, bytes);
        super_consume(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[]);
        return;
    };
    let b_back = back_ref_slot_for(b_idx);
    let Some(b_chunk) = state.untyped.try_retype(side_type, 0, b_back) else {
        revoke_back_ref(a_back);
        revoke_back_ref(core_back);
        state.untyped.release_one(a_chunk);
        state.untyped.release_one(core_chunk);
        state.quotas.release(owner_id, class, bytes);
        super_consume(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[]);
        return;
    };
    let bind = syscall::invoke(core_back, bind_label, a_back, b_back, 0, 0);
    if bind.error != 0 {
        revoke_back_ref(b_back);
        revoke_back_ref(a_back);
        revoke_back_ref(core_back);
        state.untyped.release_one(b_chunk);
        state.untyped.release_one(a_chunk);
        state.untyped.release_one(core_chunk);
        state.quotas.release(owner_id, class, bytes);
        super_consume(buf, KERNITE_ERR_INVALID_CAPABILITY as u64, &[]);
        return;
    }
    let reply_a = match crate::dispatch::alloc_reply_temp(a_back, 0) {
        Ok(slot) => slot,
        Err(_) => {
            revoke_back_ref(b_back);
            revoke_back_ref(a_back);
            revoke_back_ref(core_back);
            state.untyped.release_one(b_chunk);
            state.untyped.release_one(a_chunk);
            state.untyped.release_one(core_chunk);
            state.quotas.release(owner_id, class, bytes);
            super_consume(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[]);
            return;
        }
    };
    let reply_b = match crate::dispatch::alloc_reply_temp(b_back, 0) {
        Ok(slot) => slot,
        Err(_) => {
            // SAFETY: reply_a is this pair's first reply temp, solely owned here;
            // its cap is still present (deleted) on this failure path.
            unsafe { crate::dispatch::release_reply_temps(&[reply_a], true) };
            revoke_back_ref(b_back);
            revoke_back_ref(a_back);
            revoke_back_ref(core_back);
            state.untyped.release_one(b_chunk);
            state.untyped.release_one(a_chunk);
            state.untyped.release_one(core_chunk);
            state.quotas.release(owner_id, class, bytes);
            super_consume(buf, KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[]);
            return;
        }
    };
    let reply_caps = [reply_a, reply_b];
    let group = next_pair_group();
    let core_id = install_record(
        state, core_idx, core_type, class, group, owner_id, core_back, core_chunk, bytes,
    );
    let a_id = install_record(
        state, a_idx, side_type, class, group, owner_id, a_back, a_chunk, 0,
    );
    let b_id = install_record(
        state, b_idx, side_type, class, group, owner_id, b_back, b_chunk, 0,
    );
    let err =
        crate::dispatch::finish_reply_with_caps(buf, TRONA_OK, &[core_id, a_id, b_id], &reply_caps);
    if err != 0 {
        revoke_back_ref(b_back);
        revoke_back_ref(a_back);
        revoke_back_ref(core_back);
        state.untyped.release_one(b_chunk);
        state.untyped.release_one(a_chunk);
        state.untyped.release_one(core_chunk);
        state.quotas.release(owner_id, class, bytes);
        let _ = state.objects.vacate(b_idx);
        let _ = state.objects.vacate(a_idx);
        let _ = state.objects.vacate(core_idx);
    }
}

fn super_consume(buf: *mut kernite_ipc_buffer, label: u64, regs: &[u64]) {
    super_consume_with_caps(buf, label, regs, 0);
}

fn super_consume_with_caps(buf: *mut kernite_ipc_buffer, label: u64, regs: &[u64], cap_count: u64) {
    if buf.is_null() {
        return;
    }
    unsafe {
        let _ = trona_server::mp_write_reply_to(
            buf,
            crate::dispatch::current_reply_target(),
            label,
            regs,
            cap_count,
        );
    }
}

pub fn handle_alloc_mp_pair(
    buf: *mut kernite_ipc_buffer,
    _regs: &[u64; 32],
    owner_id: u32,
    state: &mut ServerState,
) {
    let bytes = KERNITE_MESSAGE_PIPE_CORE_BYTES + 2 * KERNITE_MESSAGE_PIPE_BYTES;
    handle_pair(
        buf,
        owner_id,
        state,
        KERNITE_OBJ_MESSAGE_PIPE_CORE,
        KERNITE_OBJ_MESSAGE_PIPE,
        KERNITE_INV_MP_CORE_PAIR as u64,
        CLASS_MP_PAIR,
        bytes,
    );
}

pub fn handle_alloc_dp_pair(
    buf: *mut kernite_ipc_buffer,
    _regs: &[u64; 32],
    owner_id: u32,
    state: &mut ServerState,
) {
    let bytes = KERNITE_DATA_PIPE_CORE_BYTES + 2 * KERNITE_DATA_PIPE_BYTES;
    handle_pair(
        buf,
        owner_id,
        state,
        KERNITE_OBJ_DATA_PIPE_CORE,
        KERNITE_OBJ_DATA_PIPE,
        KERNITE_INV_DP_CORE_PAIR as u64,
        CLASS_DP_PAIR,
        bytes,
    );
}
