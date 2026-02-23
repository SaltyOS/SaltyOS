//! CSpace expansion handlers
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use salty::serial::LineBuf;
use salty::types::*;

use crate::proc_table::{alloc_proc, find_by_badge, proctab, proctab_cap, NEXT_PID, PROC_RUNNING};

/// Handle EXPAND_CSPACE request from a child process.
///
/// The child requests more capability slots. We retype a new sub-CNode from
/// the child's untyped, set a guard on it, and insert it into an empty root
/// CNode slot so the child's address space grows.
///
/// msg.regs[0] = requested size_bits for the new sub-CNode (4..16)
///
/// reply.regs[0] = base address of the new slot range (on success)
/// reply.regs[1] = number of new slots (on success)
pub(crate) unsafe fn handle_expand_cspace(msg: &SaltyMsg, reply: &mut SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        }
    };

    let child_cn = unsafe { proctab(ci).cnode_cap };

    // Requested sub-CNode size_bits (default to 10 = 1024 slots if 0)
    let req_bits = msg.regs[0];
    let size_bits = if req_bits == 0 { 10u64 } else { req_bits };
    if size_bits < 4 || size_bits > 16 {
        reply.label = super::SALTY_INVALID_ARGUMENT;
        return;
    }

    // Use cnode_get_info to know the root CNode size.
    let info = salty::invoke::cnode_get_info(child_cn);
    if info.error != 0 {
        reply.label = super::SALTY_INVALID_OPERATION;
        return;
    }
    let (root_num_slots, _root_size_bits) = unsafe {
        let ctx = &*super::ipc_ctx();
        let buf = &*ctx.ipc_buffer;
        (buf.msg[3], buf.msg[2])
    };

    // We will probe root slots from 64 upward and attach the new sub-CNode
    // at the first free one.
    let mut target_slot: u64 = u64::MAX;

    // Retype a new sub-CNode into a procmgr-local temp slot.
    // Use allocator-wide untyped sources instead of a per-child dedicated
    // untyped so expansion keeps working after child-local UT depletion.
    let temp_slot = match unsafe { (&mut *(&raw mut super::ALLOCATOR)).alloc_single_slot() } {
        Some(s) => s,
        None => {
            reply.label = super::SALTY_OUT_OF_MEMORY;
            return;
        }
    };

    let err = unsafe {
        (&mut *(&raw mut super::ALLOCATOR)).retype_core_object(
            super::OBJ_CNODE,
            size_bits,
            temp_slot,
        )
    };
    if err != 0 {
        unsafe { (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = super::SALTY_OUT_OF_MEMORY;
        return;
    }

    // Set guard and attempt insertion into each candidate root slot.
    // The first successful copy becomes the new sub-CNode anchor.
    // Sub-CNode gets guard=0, guard_bits=0. The seL4 resolver uses
    // root_bits to index the root CNode, then sub_bits to index the sub-CNode.
    // Address encoding: (root_idx << sub_bits) | sub_idx.
    let err = salty::invoke::cnode_set_guard(temp_slot, 0, 0);
    if err != 0 {
        let mut lb = LineBuf::new();
        lb.str(b"[PROCMGR] set_guard failed err=");
        lb.hex(err as u64);
        lb.str(b"\n");
        lb.flush();
        salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
        unsafe { (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = super::SALTY_INVALID_OPERATION;
        return;
    }

    for slot in 64..root_num_slots {
        let err = salty::invoke::cnode_copy(
            super::CAP_SELF_CSPACE,
            temp_slot,
            child_cn,
            slot,
            super::CAP_RIGHTS_ALL,
        );
        if err == 0 {
            target_slot = slot;
            break;
        }
    }

    if target_slot == u64::MAX {
        salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
        unsafe { (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot) };
        reply.label = super::SALTY_OUT_OF_MEMORY;
        return;
    }

    // Clean up temp slot
    salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
    unsafe { (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot) };

    let new_slots = 1u64 << size_bits;
    let base_addr = target_slot << size_bits;

    reply.label = super::SALTY_OK;
    reply.length = 2;
    reply.regs[0] = base_addr;
    reply.regs[1] = new_slots;
}

/// Handle PM_EXPAND_CSPACE_ASYNC (NBSend): perform the expansion work and
/// store the result. No reply is sent (NBSend has no reply cap).
pub(crate) unsafe fn handle_expand_cspace_async(msg: &SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => return, // NBSend: no reply, just drop
    };

    unsafe {
        let child_cn = proctab(ci).cnode_cap;

        let req_bits = msg.regs[0];
        let size_bits = if req_bits == 0 { 10u64 } else { req_bits };
        if size_bits < 4 || size_bits > 16 {
            return;
        }

        let info = salty::invoke::cnode_get_info(child_cn);
        if info.error != 0 {
            return;
        }
        let (root_num_slots, _root_size_bits) = {
            let ctx = &*super::ipc_ctx();
            let buf = &*ctx.ipc_buffer;
            (buf.msg[3], buf.msg[2])
        };

        let temp_slot = match (&mut *(&raw mut super::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => return,
        };

        let err = (&mut *(&raw mut super::ALLOCATOR)).retype_core_object(
            super::OBJ_CNODE,
            size_bits,
            temp_slot,
        );
        if err != 0 {
            (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot);
            return;
        }

        // Sub-CNode gets guard=0, guard_bits=0 (same as blocking path).
        let err = salty::invoke::cnode_set_guard(temp_slot, 0, 0);
        if err != 0 {
            salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
            (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot);
            return;
        }

        let mut target_slot: u64 = u64::MAX;
        for slot in 64..root_num_slots {
            let err = salty::invoke::cnode_copy(
                super::CAP_SELF_CSPACE,
                temp_slot,
                child_cn,
                slot,
                super::CAP_RIGHTS_ALL,
            );
            if err == 0 {
                target_slot = slot;
                break;
            }
        }

        salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_slot);
        (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(temp_slot);

        if target_slot == u64::MAX {
            return;
        }

        let new_slots = 1u64 << size_bits;
        let base_addr = target_slot << size_bits;

        proctab(ci).expand_pending = true;
        proctab(ci).expand_result_base = base_addr;
        proctab(ci).expand_result_count = new_slots;
    }
}

/// Handle PM_EXPAND_COLLECT (Call): return the stored expansion result.
pub(crate) unsafe fn handle_expand_collect(reply: &mut SaltyMsg, badge: u64) {
    let ci = match find_by_badge(badge) {
        Some(i) => i,
        None => {
            reply.label = super::SALTY_NOT_FOUND;
            return;
        }
    };

    unsafe {
        if proctab(ci).expand_pending {
            reply.label = super::SALTY_OK;
            reply.length = 2;
            reply.regs[0] = proctab(ci).expand_result_base;
            reply.regs[1] = proctab(ci).expand_result_count;
            proctab(ci).expand_pending = false;
        } else {
            reply.label = super::SALTY_PENDING;
        }
    }
}

/// Handle CSpace expansion requests delivered via bound notification (upper 16 bits).
///
/// Each bit i (0-15) in `bits` corresponds to proctab(i). When a child signals
/// the procmgr's bound notification with badge = 1 << (16 + idx), the kernel ORs
/// the badge bits. We retype a sub-CNode and copy it into the child's root CNode
/// at deterministic slots [CSPACE_EXPAND_BASE .. CSPACE_EXPAND_BASE + count).
pub(crate) unsafe fn handle_cspace_expand_ntfn(bits: u64) {
    unsafe {
        let alloc = &mut *(&raw mut super::ALLOCATOR);
        for i in 0..proctab_cap() {
            if bits & (1u64 << i) == 0 {
                continue;
            }
            if proctab(i).state != PROC_RUNNING {
                continue;
            }

            let n = proctab(i).cspace_expand_count as u64;
            if n >= super::MAX_CSPACE_EXPANSIONS as u64 {
                continue;
            }

            let child_cn = proctab(i).cnode_cap;
            if child_cn == 0 {
                continue;
            }

            let dest_child_slot = super::CSPACE_EXPAND_BASE + n;

            // Allocate temp slot and retype sub-CNode from procmgr's pool
            let pm_slot = match alloc.alloc_single_slot() {
                Some(s) => s,
                None => continue,
            };

            let err =
                alloc.retype_core_object(super::OBJ_CNODE, super::CSPACE_EXPAND_BITS, pm_slot);
            if err != 0 {
                alloc.free_single_slot(pm_slot);
                continue;
            }

            // Sub-CNode: guard=0, guard_bits=0 (flat two-level addressing)
            let err = salty::invoke::cnode_set_guard(pm_slot, 0, 0);
            if err != 0 {
                salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, pm_slot);
                alloc.free_single_slot(pm_slot);
                continue;
            }

            // Move into child's root CNode at the deterministic slot.
            // cnode_move transfers atomically without creating a CDT parent->child
            // relationship, so the source slot becomes empty and can be freed.
            let move_err = salty::invoke::cnode_move(
                child_cn,
                dest_child_slot,
                super::CAP_SELF_CSPACE,
                pm_slot,
            );
            if move_err == 0 {
                alloc.free_single_slot(pm_slot);
            }

            if move_err != 0 {
                continue;
            }

            proctab(i).cspace_expand_count += 1;

            {
                let mut lb = LineBuf::new();
                lb.str(b"[PROCMGR] cspace-expand: granted ");
                lb.hex(1u64 << super::CSPACE_EXPAND_BITS);
                lb.str(b" slots to idx=");
                lb.hex(i as u64);
                lb.str(b" root_slot=");
                lb.hex(dest_child_slot);
                lb.str(b"\n");
                lb.flush();
            }
        }
    }
}

/// Handle PM_REGISTER (Call): register an init-spawned service in the proc table.
/// msg.regs[0] = badge used for this child
/// IPC buffer caps[0] = child's CNode cap (transferred via cap slot)
pub(crate) unsafe fn handle_register(msg: &SaltyMsg, reply: &mut SaltyMsg, _badge: u64) {
    let reg_badge = msg.regs[0];

    unsafe {
        // The CNode cap was transferred to CAP_RECV_SCRATCH by cap transfer
        let child_cn_scratch = super::CAP_RECV_SCRATCH;

        // Verify we received a cap by probing it
        let cn_info = salty::invoke::cnode_get_info(child_cn_scratch);
        if cn_info.error != 0 {
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        // Move CNode cap from scratch to a permanent allocator-managed slot.
        // Must use cnode_move (not cnode_copy) to avoid creating a CDT child,
        // which would prevent cnode_delete(scratch) from clearing the slot.
        let cn_perm = match (&mut *(&raw mut super::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return;
            }
        };
        let err = salty::invoke::cnode_move(
            super::CAP_SELF_CSPACE,
            cn_perm,
            super::CAP_SELF_CSPACE,
            child_cn_scratch,
        );
        if err != 0 {
            (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(cn_perm);
            reply.label = super::SALTY_INVALID_ARGUMENT;
            return;
        }

        let ci = match alloc_proc() {
            Some(i) => i,
            None => {
                salty::invoke::cnode_delete(super::CAP_SELF_CSPACE, cn_perm);
                (&mut *(&raw mut super::ALLOCATOR)).free_single_slot(cn_perm);
                reply.label = super::SALTY_OUT_OF_MEMORY;
                return;
            }
        };

        proctab(ci).pid = NEXT_PID;
        NEXT_PID += 1;
        proctab(ci).sid = proctab(ci).pid;
        proctab(ci).pgid = proctab(ci).pid;
        proctab(ci).badge = reg_badge;
        proctab(ci).state = PROC_RUNNING;
        proctab(ci).cnode_cap = cn_perm;

        // Mint CSpace expansion notification (upper 16 bits badge)
        let pm_ntfn = *(&raw const super::PM_BOUND_NTFN);
        if pm_ntfn != 0 {
            let cs_badge = 1u64 << (16 + ci);
            let _ = salty::invoke::cnode_mint(
                super::CAP_SELF_CSPACE,
                pm_ntfn,
                cn_perm,
                super::CHILD_CAP_CSPACE_NTFN,
                cs_badge,
            );
        }

        {
            let mut lb = LineBuf::new();
            lb.str(b"[PROCMGR] PM_REGISTER badge=");
            lb.hex(reg_badge);
            lb.str(b" pid=");
            lb.hex(proctab(ci).pid as u64);
            lb.str(b"\n");
            lb.flush();
        }

        reply.label = super::SALTY_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ci).pid as u64;
    }
}
