//! CSpace and process registration handlers.
//! Extracted from main.rs for separation of concerns.
//! SPDX-License-Identifier: GPL-2.0-only

use trona::consts::server::{CSPACE_EXPAND_BASE, MAX_CSPACE_EXPANSIONS};
use trona::types::core::*;

use crate::personality::PersonalityKind;
use crate::base::proc_table::{
    alloc_proc, find_by_badge, monotonic_now_ns, proctab, NEXT_PID, ProcessState,
};

// ---------------------------------------------------------------------------
// CSpace expansion clients
// ---------------------------------------------------------------------------

/// Number of distinct child slots that can have an outstanding CSpace
/// expansion subscription. Constrained by the badge encoding: each client
/// gets bit `1 << (16 + idx)` so the index range is `0..48` (badges fit in
/// `u64`). 48 is plenty for the active service set.
pub const MAX_EXPAND_CLIENTS: usize = 48;

/// Sub-CNode size used per CSpace expansion grant. 10 bits = 1024 slots —
/// keeps the on-wire CSpace layout for child processes stable.
const CSPACE_EXPAND_BITS: u64 = 10;

#[derive(Clone, Copy)]
struct ExpandClient {
    badge: u64,
    cnode_cap: Cap,
    expand_count: u16,
    active: bool,
}

impl ExpandClient {
    const fn empty() -> Self {
        ExpandClient {
            badge: 0,
            cnode_cap: 0,
            expand_count: 0,
            active: false,
        }
    }
}

static mut EXPAND_CLIENTS: [ExpandClient; MAX_EXPAND_CLIENTS] =
    [ExpandClient::empty(); MAX_EXPAND_CLIENTS];

unsafe fn alloc_client_slot() -> Option<usize> {
    unsafe {
        let table = &*(&raw const EXPAND_CLIENTS);
        for i in 0..MAX_EXPAND_CLIENTS {
            if !table[i].active {
                return Some(i);
            }
        }
        None
    }
}

unsafe fn find_client_by_badge(badge: u64) -> Option<usize> {
    unsafe {
        let table = &*(&raw const EXPAND_CLIENTS);
        for i in 0..MAX_EXPAND_CLIENTS {
            if table[i].active && table[i].badge == badge {
                return Some(i);
            }
        }
        None
    }
}

/// Drop a child from the CSpace expansion table on process exit. The
/// child's CNode cap is *not* deleted here — it's owned by the proctab
/// entry and revoked along with the rest of the process resources.
pub(crate) unsafe fn deregister_client(badge: u64) {
    unsafe {
        if let Some(i) = find_client_by_badge(badge) {
            let table = &raw mut EXPAND_CLIENTS;
            (*table)[i] = ExpandClient::empty();
        }
    }
}

/// Handle PM_REGISTER (Call): register an init-spawned service in the proc table.
/// msg.regs[0] = badge used for this child
/// msg.regs[1] = parent pid (0 if unknown)
/// IPC buffer caps[0] = child's CNode cap (transferred via cap slot)
pub(crate) unsafe fn handle_register(msg: &TronaMsg, reply: &mut TronaMsg, _badge: u64) {
    let reg_badge = msg.regs[0];
    let parent_pid = if msg.length >= 2 {
        msg.regs[1] as u32
    } else {
        0
    };
    // Child's chosen signaling slot for the CSpace-expand bound notification.
    // 0 = do not mint (used by early init-spawned services that do not need
    // runtime cspace expansion yet).
    let ntfn_slot = if msg.length >= 3 { msg.regs[2] } else { 0 };

    unsafe {
        if parent_pid != 0 && find_by_badge(parent_pid as u64).is_none() {
            if let Some(parent_idx) = alloc_proc() {
                proctab(parent_idx).set_personality_kind(PersonalityKind::Posix);
                proctab(parent_idx).pid = parent_pid;
                proctab(parent_idx).badge = parent_pid as u64;
                proctab(parent_idx).state = ProcessState::Running;
                proctab(parent_idx).start_time_ns = monotonic_now_ns();
            }
        }

        // The CNode cap was transferred to CAP_RECV_SCRATCH by cap transfer
        let child_cn_scratch = crate::CAP_RECV_SCRATCH;

        // Verify we received a cap by probing it
        let cn_info = trona::invoke::cnode_get_info(child_cn_scratch);
        if cn_info.error != 0 {
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        // Move CNode cap from scratch to a permanent allocator-managed slot.
        // Must use cnode_move (not cnode_copy) to avoid creating a CDT child,
        // which would prevent cnode_delete(scratch) from clearing the slot.
        let cn_perm = match (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        let err = trona::invoke::cnode_move(
            crate::CAP_SELF_CSPACE,
            cn_perm,
            crate::CAP_SELF_CSPACE,
            child_cn_scratch,
        );
        if err != 0 {
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(cn_perm);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let ci = match alloc_proc() {
            Some(i) => i,
            None => {
                trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, cn_perm);
                (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(cn_perm);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        proctab(ci).set_personality_kind(PersonalityKind::Posix);
        proctab(ci).pid = NEXT_PID;
        NEXT_PID += 1;
        let new_pid = proctab(ci).pid;
        proctab(ci).ppid = parent_pid;
        proctab(ci).sid = new_pid;
        proctab(ci).pgid = new_pid;
        proctab(ci).badge = reg_badge;
        proctab(ci).state = ProcessState::Running;
        proctab(ci).cnode_cap = cn_perm;

        // CSpace expansion is handled by procmgr's own bound-notification
        // path — children are registered in the CLIENTS table at register time.
        register_client(reg_badge, cn_perm, ntfn_slot);

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] PM_REGISTER badge=");
            _lb.hex(reg_badge);
            _lb.str(b" pid=");
            _lb.hex(proctab(ci).pid as u64);
            _lb.str(b"\n");
        });

        reply.label = crate::TRONA_OK;
        reply.length = 1;
        reply.regs[0] = proctab(ci).pid as u64;
    }
}

/// Register a child for procmgr's CSpace expansion path.
///
/// procmgr holds a TCB-bound notification (`crate::BOUND_NTFN`) and mints a
/// per-client badged copy of it into the child's root CNode at the child-
/// chosen `ntfn_slot`. When the child's `slot_alloc` runs out of segments
/// it signals that cap; the kernel ORs the badge into the notification word
/// and procmgr's main loop receives `(label=0, badge=N)` where badge bit
/// `16+idx` identifies which client needs an expansion.
///
/// `ntfn_slot == 0` is a sentinel meaning "do not mint" — used by early
/// init-spawned services that register before they need runtime CSpace
/// expansion.
pub(crate) fn register_client(badge: u64, cnode_cap: Cap, ntfn_slot: u64) {
    unsafe {
        if find_client_by_badge(badge).is_some() {
            return;
        }
        let Some(idx) = alloc_client_slot() else {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] expand client table full, badge=");
                _lb.hex(badge);
                _lb.str(b"\n");
            });
            return;
        };

        let table = &raw mut EXPAND_CLIENTS;
        (*table)[idx] = ExpandClient {
            badge,
            cnode_cap,
            expand_count: 0,
            active: true,
        };

        // Mint the bound notification with badge `1 << (16 + idx)` into the
        // child's CNode at the child-chosen signaling slot.
        let bound = *(&raw const crate::BOUND_NTFN);
        if ntfn_slot != 0 && bound != 0 {
            let signal_badge = 1u64 << (16 + idx as u64);
            let merr = trona::invoke::cnode_mint(
                crate::CAP_SELF_CSPACE,
                bound,
                cnode_cap,
                ntfn_slot,
                signal_badge,
            );
            if merr != 0 {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] mint cspace ntfn into child failed err=");
                    _lb.hex(merr as u64);
                    _lb.str(b"\n");
                });
            }
        }
    }
}

/// Process the badge bits delivered by a bound-notification recv from the
/// `slot_alloc` clients. Each set bit in `bits[16..64]` identifies an
/// `ExpandClient` index whose child needs another sub-CNode grafted into
/// its root CNode.
pub(crate) unsafe fn handle_cspace_expand_request(badge: u64) {
    unsafe {
        let bits = badge >> 16;
        if bits == 0 {
            return;
        }
        for i in 0..MAX_EXPAND_CLIENTS {
            if bits & (1u64 << i) == 0 {
                continue;
            }
            handle_one_expansion(i);
        }
    }
}

unsafe fn handle_one_expansion(idx: usize) {
    unsafe {
        let table = &raw mut EXPAND_CLIENTS;
        if !(*table)[idx].active {
            return;
        }
        let n = (*table)[idx].expand_count as u64;
        if n >= MAX_CSPACE_EXPANSIONS as u64 {
            return;
        }
        let child_cn = (*table)[idx].cnode_cap;
        if child_cn == 0 {
            return;
        }

        // Allocate a sub-CNode via rsrcsrv. owner_id=0 → procmgr's own
        // badge so the handle is accounted to procmgr; on child exit the
        // child's reclaim will not free this — the sub-CNode is folded into
        // the child's root CNode and shares its lifetime instead.
        let (cnode_slot, cnode_handle) = match crate::base::alloc::alloc_single(
            trona::caps::rsrcsrv_ep(),
            0,
            trona::OBJ_CNODE,
            CSPACE_EXPAND_BITS,
        ) {
            Ok(t) => t,
            Err(e) => {
                trona::uwarn!(|_lb| {
                    _lb.str(b"[PROCMGR] cspace expand: alloc CNode failed err=");
                    _lb.hex(e as u64);
                    _lb.str(b"\n");
                });
                return;
            }
        };

        let err = trona::invoke::cnode_set_guard(cnode_slot, 0, 0);
        if err != 0 {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] cspace expand: set_guard failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            let _ = crate::base::alloc::free_handle(trona::caps::rsrcsrv_ep(), 0, cnode_handle);
            return;
        }

        let dest_child_slot = CSPACE_EXPAND_BASE + n;
        let move_err = trona::invoke::cnode_move(
            child_cn,
            dest_child_slot,
            crate::CAP_SELF_CSPACE,
            cnode_slot,
        );
        if move_err != 0 {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] cspace expand: cnode_move failed err=");
                _lb.hex(move_err as u64);
                _lb.str(b"\n");
            });
            let _ = crate::base::alloc::free_handle(trona::caps::rsrcsrv_ep(), 0, cnode_handle);
            return;
        }

        // The cap has been moved out of procmgr's slot — free that slot
        // back into the slot allocator. The rsrcsrv handle is now backed
        // by a cap that lives in the child's CNode; the child's eventual
        // process exit will revoke it through proctab cleanup.
        trona::slot_alloc::slot_free(cnode_slot);

        (*table)[idx].expand_count += 1;

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] cspace expand granted ");
            _lb.hex(1u64 << CSPACE_EXPAND_BITS);
            _lb.str(b" slots to idx=");
            _lb.dec(idx as u64);
            _lb.str(b" root_slot=");
            _lb.hex(dest_child_slot);
            _lb.str(b"\n");
        });

        let _ = cnode_handle; // ownership transferred — handle stays for accounting
    }
}
