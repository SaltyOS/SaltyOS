//! Thread lifecycle handlers (PM_THREAD_*).
//!
//! procmgr owns the entire thread lifecycle for userland processes:
//! per-process auxiliary thread tables, kernel object allocation through
//! rsrcsrv, configuration of new TCBs against the caller's CSpace/VSpace,
//! join/detach/exit synchronization, and per-thread reaping.
//!
//! The main thread of each process is *not* tracked here — its kernel
//! objects already live on the Process struct. Auxiliary threads created
//! via PM_THREAD_CREATE start at tid=1.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona::invoke;
use trona::ipc;
use trona::types::core::Cap;
use trona::types::TronaMsg;

use crate::base::proc_table::{
    find_by_badge, proctab, ThreadEntry, ThreadState, MAX_THREADS_PER_PROC,
};
use crate::{
    ipc_ctx, ALLOCATOR, CAP_SELF_CSPACE, OBJ_SCHED_CONTEXT, OBJ_TCB, TRONA_INVALID_ARGUMENT,
    TRONA_NOT_FOUND, TRONA_OK, TRONA_OUT_OF_MEMORY,
};
use crate::base::alloc;
use crate::base::cap_helpers as procmgr_caps;

const OBJ_FRAME: u64 = trona::OBJ_FRAME;
const VSPACE_FLAG_WRITABLE: u64 = trona::VSPACE_FLAG_WRITABLE;
const VSPACE_FLAG_USER: u64 = trona::VSPACE_FLAG_USER;

/// Default scheduling parameters for libpthread-spawned threads.
/// Match libpthread's previous direct-retype values to preserve behavior.
const DEFAULT_THREAD_BUDGET_US: u64 = 10_000;
const DEFAULT_THREAD_PERIOD_US: u64 = 100_000;

/// Bit 0 of attr_flags = detached on creation.
const PTHREAD_CREATE_DETACHED: u64 = 1;

// ===========================================================================
// Internal helpers
// ===========================================================================

/// Locate the caller's process table index from its IPC badge.
unsafe fn caller_process(badge: u64) -> Option<usize> {
    find_by_badge(badge)
}

/// Find a free auxiliary thread slot in the given process's table.
/// Returns the array index, not the tid (use `assign_tid` to derive the tid).
unsafe fn alloc_thread_slot(proc_idx: usize) -> Option<usize> {
    unsafe {
        let p = proctab(proc_idx);
        for i in 0..MAX_THREADS_PER_PROC {
            if p.threads.entries[i].state == ThreadState::Unused {
                return Some(i);
            }
        }
        None
    }
}

/// Allocate the next per-process tid (monotonically increasing, never 0).
unsafe fn assign_tid(proc_idx: usize) -> u32 {
    unsafe {
        let p = proctab(proc_idx);
        let tid = p.threads.next_tid;
        let next = if tid == u32::MAX { 1 } else { tid + 1 };
        p.threads.next_tid = next;
        tid
    }
}

/// Look up an auxiliary thread by tid in the given process's table.
unsafe fn find_thread_by_tid(proc_idx: usize, tid: u32) -> Option<usize> {
    unsafe {
        let p = proctab(proc_idx);
        for i in 0..MAX_THREADS_PER_PROC {
            let entry = &p.threads.entries[i];
            if entry.state != ThreadState::Unused && entry.tid == tid {
                return Some(i);
            }
        }
        None
    }
}

/// Free the rsrcsrv-side handles + procmgr-side CSpace slots backing one
/// auxiliary thread, unmap its IPC buffer from the child's vspace, and
/// reset the slot to ThreadState::Unused.
unsafe fn reap_thread(proc_idx: usize, slot: usize) {
    unsafe {
        let p = proctab(proc_idx);
        let owner = p.badge;
        let vspace_cap = p.vspace_cap;
        let entry = p.threads.entries[slot];

        // Unmap the IPC buffer from the child's vspace before revoking
        // the frame. The frame revoke that follows would also tear down
        // the mapping, but vspace_unmap clears the page-table entry so
        // the address can be reused later.
        if entry.ipc_buf_vaddr != 0 && vspace_cap != 0 {
            let _ = invoke::vspace_unmap(vspace_cap, entry.ipc_buf_vaddr);
        }

        // Free the kernel objects via rsrcsrv (revokes derived caps too).
        for h in entry.rsrcsrv_handles.iter() {
            if *h != 0 {
                let _ = alloc::free_handle(trona::caps::rsrcsrv_ep(), owner, *h);
            }
        }

        // Drop the (now revoked) caps from procmgr's local CSpace.
        for &local_slot in &[entry.tcb_cap, entry.sc_cap, entry.frame_cap] {
            if local_slot != 0 {
                let _ = invoke::cnode_delete(CAP_SELF_CSPACE, local_slot);
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(local_slot);
            }
        }

        // If a joiner saved its reply cap but never woke up, drop it now
        // so we do not leak a procmgr CSpace slot. The joiner is dead by
        // construction (we only reach here from the same proc's exit
        // sweep or from a join that already replied).
        if entry.joiner_reply_cap != 0 {
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, entry.joiner_reply_cap);
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(entry.joiner_reply_cap);
        }

        let p = proctab(proc_idx);
        p.threads.entries[slot] = ThreadEntry::zeroed();
        if p.threads.count > 0 {
            p.threads.count -= 1;
        }
    }
}

/// Push a `(slot, handle)` pair onto a temporary rollback record so that an
/// abort partway through PM_THREAD_CREATE setup can revoke everything that
/// was allocated. Used in lieu of the spawn-style Reservation because thread
/// creation does not need a contiguous slot range.
struct CreateScratch {
    slots: [Cap; 3],
    handles: [u64; 3],
    filled: usize,
}

impl CreateScratch {
    const fn new() -> Self {
        CreateScratch {
            slots: [0; 3],
            handles: [0; 3],
            filled: 0,
        }
    }

    fn push(&mut self, slot: Cap, handle: u64) {
        if self.filled < 3 {
            self.slots[self.filled] = slot;
            self.handles[self.filled] = handle;
            self.filled += 1;
        }
    }

    /// Free everything we managed to allocate, then return.
    unsafe fn rollback(&self, owner_id: u64) {
        unsafe {
            for i in (0..self.filled).rev() {
                let h = self.handles[i];
                if h != 0 {
                    let _ = alloc::free_handle(trona::caps::rsrcsrv_ep(), owner_id, h);
                }
                let s = self.slots[i];
                if s != 0 {
                    let _ = invoke::cnode_delete(CAP_SELF_CSPACE, s);
                    (&mut *(&raw mut ALLOCATOR)).free_single_slot(s);
                }
            }
        }
    }
}

// ===========================================================================
// PM_THREAD_CREATE
// ===========================================================================

/// Inputs:
///   regs[0] = entry_pc            (caller-prepared trampoline)
///   regs[1] = stack_top           (with start_fn / arg already pushed)
///   regs[2] = tls_base            (architecture thread pointer)
///   regs[3] = ipc_buf_vaddr       (where to map the new IPC frame in child vspace)
///   regs[4] = attr_flags          (bit 0 = detached)
///
/// Reply:
///   regs[0] = tid (per-process, >= 1)
///   cap[0]  = derived TCB cap (cap_transfer)
pub(crate) unsafe fn handle_thread_create(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let entry_pc = msg.regs[0];
        let stack_top = msg.regs[1];
        let tls_base = msg.regs[2];
        let ipc_buf_vaddr = msg.regs[3];
        let attr_flags = msg.regs[4];

        // 1. Resolve the calling process.
        let Some(proc_idx) = caller_process(badge) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let owner = proctab(proc_idx).badge;
        let child_cnode = proctab(proc_idx).cnode_cap;
        let child_vspace = proctab(proc_idx).vspace_cap;
        if child_cnode == 0 || child_vspace == 0 {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        if ipc_buf_vaddr == 0 || (ipc_buf_vaddr & 0xFFF) != 0 {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }

        // 2. Reserve an auxiliary thread slot in the per-process table.
        let Some(slot_idx) = alloc_thread_slot(proc_idx) else {
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        };

        // 3. Allocate TCB / SchedContext / IPC frame from rsrcsrv (charged
        //    to the child pid via owner_id, which only privileged callers
        //    may set; procmgr is privileged via FLAG_PROMOTE_PRIVILEGED).
        let mut scratch = CreateScratch::new();

        let (tcb_slot, tcb_handle) =
            match alloc::alloc_single(trona::caps::rsrcsrv_ep(), owner, OBJ_TCB, 0) {
                Ok(v) => v,
                Err(e) => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] PM_THREAD_CREATE alloc TCB failed err=");
                        _lb.hex(e as u64);
                        _lb.str(b"\n");
                    });
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
        scratch.push(tcb_slot, tcb_handle);

        let (sc_slot, sc_handle) =
            match alloc::alloc_single(trona::caps::rsrcsrv_ep(), owner, OBJ_SCHED_CONTEXT, 0) {
                Ok(v) => v,
                Err(e) => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] PM_THREAD_CREATE alloc SC failed err=");
                        _lb.hex(e as u64);
                        _lb.str(b"\n");
                    });
                    scratch.rollback(owner);
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
        scratch.push(sc_slot, sc_handle);

        let (frame_slot, frame_handle) =
            match alloc::alloc_single(trona::caps::rsrcsrv_ep(), owner, OBJ_FRAME, 12) {
                Ok(v) => v,
                Err(e) => {
                    trona::uerror!(|_lb| {
                        _lb.str(b"[PROCMGR] PM_THREAD_CREATE alloc Frame failed err=");
                        _lb.hex(e as u64);
                        _lb.str(b"\n");
                    });
                    scratch.rollback(owner);
                    reply.label = TRONA_OUT_OF_MEMORY;
                    return;
                }
            };
        scratch.push(frame_slot, frame_handle);

        // 4. Configure the TCB to share the caller's CSpace + VSpace.
        let depth = invoke::tcb_get_space_info(crate::CAP_SELF_TCB).unwrap_or(0);
        let err = if depth > 0 {
            invoke::tcb_set_space_with_depth(tcb_slot, child_cnode, child_vspace, depth as u64)
        } else {
            invoke::tcb_set_space(tcb_slot, child_cnode, child_vspace)
        };
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PM_THREAD_CREATE tcb_set_space failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // 5. Route VMFaults through a per-process badged mmsrv endpoint.
        // Using procmgr's own client cap here would fault into the wrong
        // mmsrv client record, so auxiliary thread stack/TLS demand faults
        // would look up the wrong address space and segfault.
        let fault_ep_slot = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                scratch.rollback(owner);
                reply.label = TRONA_OUT_OF_MEMORY;
                return;
            }
        };
        let fault_ep_err = invoke::cnode_mint(
            CAP_SELF_CSPACE,
            procmgr_caps::mmsrv_authority_raw(),
            CAP_SELF_CSPACE,
            fault_ep_slot,
            owner,
        );
        if fault_ep_err != 0 {
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(fault_ep_slot);
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PM_THREAD_CREATE fault EP mint failed err=");
                _lb.hex(fault_ep_err as u64);
                _lb.str(b"\n");
            });
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }
        let err = invoke::tcb_set_fault_handler(tcb_slot, fault_ep_slot);
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, fault_ep_slot);
        (&mut *(&raw mut ALLOCATOR)).free_single_slot(fault_ep_slot);
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PM_THREAD_CREATE tcb_set_fault_handler failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // 6. Map the new IPC buffer frame into the child's vspace at the
        //    address the caller picked.
        let err = invoke::vspace_map(
            child_vspace,
            frame_slot,
            ipc_buf_vaddr,
            VSPACE_FLAG_WRITABLE | VSPACE_FLAG_USER,
        );
        if err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] PM_THREAD_CREATE vspace_map ipc failed err=");
                _lb.hex(err as u64);
                _lb.str(b"\n");
            });
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // 7. Bind IPC buffer / TLS base / entry point.
        let err = invoke::tcb_set_ipc_buffer(tcb_slot, ipc_buf_vaddr);
        if err != 0 {
            let _ = invoke::vspace_unmap(child_vspace, ipc_buf_vaddr);
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let err = invoke::tcb_set_tls_base(tcb_slot, tls_base);
        if err != 0 {
            let _ = invoke::vspace_unmap(child_vspace, ipc_buf_vaddr);
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        let err = invoke::tcb_configure(tcb_slot, entry_pc, stack_top, ipc_buf_vaddr);
        if err != 0 {
            let _ = invoke::vspace_unmap(child_vspace, ipc_buf_vaddr);
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // 8. Configure the SchedContext and bind it to the new TCB.
        let err = invoke::sc_configure(sc_slot, DEFAULT_THREAD_BUDGET_US, DEFAULT_THREAD_PERIOD_US);
        if err != 0 {
            let _ = invoke::vspace_unmap(child_vspace, ipc_buf_vaddr);
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }
        let err = invoke::sc_bind(sc_slot, tcb_slot);
        if err != 0 {
            let _ = invoke::vspace_unmap(child_vspace, ipc_buf_vaddr);
            scratch.rollback(owner);
            reply.label = TRONA_OUT_OF_MEMORY;
            return;
        }

        // 9. Commit the ThreadEntry into the per-process table before the new
        //    thread is allowed to run.
        let tid = assign_tid(proc_idx);
        let detached = (attr_flags & PTHREAD_CREATE_DETACHED) != 0;
        let p = proctab(proc_idx);
        p.threads.entries[slot_idx] = ThreadEntry {
            state: ThreadState::Running,
            detached,
            tid,
            tcb_cap: tcb_slot,
            sc_cap: sc_slot,
            frame_cap: frame_slot,
            rsrcsrv_handles: [tcb_handle, sc_handle, frame_handle],
            retval: 0,
            joiner_reply_cap: 0,
            ipc_buf_vaddr,
        };
        p.threads.count += 1;

        // 10. Resume the thread only after the create reply path has had a
        //     chance to publish the assigned thread metadata in userland.
        if !crate::server::enqueue_post_reply_resume(tcb_slot) {
            trona::uwarn!(|_lb| {
                _lb.str(b"[PROCMGR] WARN: post-reply resume queue full for PM_THREAD_CREATE, resuming immediately\n");
            });
            let err = invoke::tcb_resume(tcb_slot);
            if err != 0 {
                let _ = invoke::vspace_unmap(child_vspace, ipc_buf_vaddr);
                reap_thread(proc_idx, slot_idx);
                reply.label = TRONA_OUT_OF_MEMORY;
                return;
            }
        }

        // 11. Reply with the tid and a derived TCB cap (cap_transfer).
        ipc::set_send_cap_ctx(ipc_ctx(), 0, tcb_slot);
        reply.label = TRONA_OK;
        reply.length = 1;
        reply.regs[0] = tid as u64;
    }
}

// ===========================================================================
// PM_THREAD_EXIT
// ===========================================================================

/// Inputs:
///   regs[0] = tid (per-process, >= 1)
///   regs[1] = retval
///
/// Caller is expected to use Send (not NBSend) so that delivery is
/// guaranteed; once procmgr has consumed the message it returns to the
/// main loop without replying. procmgr suspends the auxiliary TCB using
/// its direct local cap before waking joiners / reaping resources.
pub(crate) unsafe fn handle_thread_exit(msg: &TronaMsg, badge: u64) {
    unsafe {
        let tid = msg.regs[0] as u32;
        let retval = msg.regs[1];

        let Some(proc_idx) = caller_process(badge) else {
            return;
        };
        let Some(slot) = find_thread_by_tid(proc_idx, tid) else {
            return;
        };

        let p = proctab(proc_idx);
        let entry = &mut p.threads.entries[slot];
        if entry.state != ThreadState::Running {
            return;
        }

        // Auxiliary threads share the process CSpace, so the child-side slot 0
        // always names the process main TCB rather than the exiting helper
        // thread. Suspend from procmgr while we still own a direct cap.
        let _ = invoke::tcb_suspend(entry.tcb_cap);

        entry.retval = retval;
        entry.state = ThreadState::Zombie;

        let detached = entry.detached;
        let joiner_reply = entry.joiner_reply_cap;
        entry.joiner_reply_cap = 0;

        // Wake any pending joiner first — they need the retval before we
        // tear the thread down.
        if joiner_reply != 0 {
            let mut wake = TronaMsg::zeroed();
            wake.label = TRONA_OK;
            wake.length = 1;
            wake.regs[0] = retval;
            let _ = ipc::send_ctx(ipc_ctx(), joiner_reply, &raw const wake);
            let _ = invoke::cnode_delete(CAP_SELF_CSPACE, joiner_reply);
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(joiner_reply);
            // The join wake doubles as a reap acknowledgement: once the
            // joiner has the retval, the kernel objects can go.
            reap_thread(proc_idx, slot);
        } else if detached {
            reap_thread(proc_idx, slot);
        }
    }
}

// ===========================================================================
// PM_THREAD_JOIN
// ===========================================================================

/// Inputs:
///   regs[0] = tid (per-process, >= 1)
///
/// Reply (when target already exited):
///   regs[0] = retval
///
/// If the target is still running, returns true so the main loop skips
/// the standard reply path; the joiner is woken later from
/// `handle_thread_exit` via the saved reply cap.
pub(crate) unsafe fn handle_thread_join(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) -> bool {
    unsafe {
        let tid = msg.regs[0] as u32;

        let Some(proc_idx) = caller_process(badge) else {
            reply.label = TRONA_NOT_FOUND;
            return false;
        };
        let Some(slot) = find_thread_by_tid(proc_idx, tid) else {
            reply.label = TRONA_NOT_FOUND;
            return false;
        };

        let p = proctab(proc_idx);
        let entry = &mut p.threads.entries[slot];

        // Joining a detached thread is a programmer error.
        if entry.detached {
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // Joining a thread that already has a parked joiner is a
        // programmer error — POSIX says only one join per thread.
        if entry.joiner_reply_cap != 0 {
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        if entry.state == ThreadState::Zombie {
            // Fast path: target already exited.
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = entry.retval;
            reap_thread(proc_idx, slot);
            return false;
        }

        if entry.state != ThreadState::Running {
            reply.label = TRONA_INVALID_ARGUMENT;
            return false;
        }

        // Slow path: park the joiner. Save its reply cap and let the main
        // loop continue receiving — `handle_thread_exit` will deliver the
        // reply when the target eventually exits.
        let reply_slot = match (&mut *(&raw mut ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = TRONA_OUT_OF_MEMORY;
                return false;
            }
        };
        let err = invoke::cnode_save_caller(CAP_SELF_CSPACE, reply_slot);
        if err != 0 {
            (&mut *(&raw mut ALLOCATOR)).free_single_slot(reply_slot);
            reply.label = TRONA_OUT_OF_MEMORY;
            return false;
        }
        entry.joiner_reply_cap = reply_slot;
        true
    }
}

// ===========================================================================
// PM_THREAD_DETACH
// ===========================================================================

/// Inputs:
///   regs[0] = tid
pub(crate) unsafe fn handle_thread_detach(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        let tid = msg.regs[0] as u32;

        let Some(proc_idx) = caller_process(badge) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let Some(slot) = find_thread_by_tid(proc_idx, tid) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };

        let p = proctab(proc_idx);
        let entry = &mut p.threads.entries[slot];

        if entry.detached {
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }
        if entry.joiner_reply_cap != 0 {
            // Already has a parked joiner — POSIX considers this an error.
            reply.label = TRONA_INVALID_ARGUMENT;
            return;
        }
        entry.detached = true;

        if entry.state == ThreadState::Zombie {
            reap_thread(proc_idx, slot);
        }

        reply.label = TRONA_OK;
    }
}

// ===========================================================================
// PM_THREAD_LIST
// ===========================================================================

/// Paginated tid list of the caller's process. Inputs:
///   regs[0] = offset (number of leading entries to skip)
///
/// Reply:
///   regs[0] = count returned in this batch
///   regs[1..1+count] = tids
///
/// The main thread is reported as tid=0 in the first entry of every
/// batch where offset==0, so a single batch is sufficient for processes
/// with up to MAX_PER_BATCH-1 auxiliary threads.
pub(crate) unsafe fn handle_thread_list(msg: &TronaMsg, reply: &mut TronaMsg, badge: u64) {
    unsafe {
        const MAX_PER_BATCH: usize = 16;

        let offset = msg.regs[0] as usize;
        let Some(proc_idx) = caller_process(badge) else {
            reply.label = TRONA_NOT_FOUND;
            return;
        };
        let p = proctab(proc_idx);

        // Build a flat list of tids: [0, aux_tids...] where 0 is main.
        let mut all = [0u32; 1 + MAX_THREADS_PER_PROC];
        let mut total = 0usize;
        all[total] = 0;
        total += 1;
        for i in 0..MAX_THREADS_PER_PROC {
            let entry = &p.threads.entries[i];
            if entry.state != ThreadState::Unused {
                all[total] = entry.tid;
                total += 1;
            }
        }

        let mut count = 0usize;
        if offset < total {
            let remaining = total - offset;
            let batch = if remaining > MAX_PER_BATCH {
                MAX_PER_BATCH
            } else {
                remaining
            };
            for i in 0..batch {
                reply.regs[1 + i] = all[offset + i] as u64;
            }
            count = batch;
        }
        reply.regs[0] = count as u64;
        reply.label = TRONA_OK;
        reply.length = (1 + count) as u64;
    }
}

// ===========================================================================
// Process exit sweep
// ===========================================================================

/// Drop all auxiliary threads of a process during teardown.
///
/// rsrcsrv-side handles are reclaimed by the bulk RES_RECLAIM_OWNER call
/// already issued by `personality::teardown_client_common`, so we only
/// need to drop the procmgr-side CSpace slots and zero the table.
pub(crate) unsafe fn drop_all_threads(proc_idx: usize) {
    unsafe {
        let p = proctab(proc_idx);
        for i in 0..MAX_THREADS_PER_PROC {
            let entry = p.threads.entries[i];
            if entry.state == ThreadState::Unused {
                continue;
            }
            for &local_slot in &[entry.tcb_cap, entry.sc_cap, entry.frame_cap] {
                if local_slot != 0 {
                    let _ = invoke::cnode_delete(CAP_SELF_CSPACE, local_slot);
                    (&mut *(&raw mut ALLOCATOR)).free_single_slot(local_slot);
                }
            }
            if entry.joiner_reply_cap != 0 {
                let _ = invoke::cnode_delete(CAP_SELF_CSPACE, entry.joiner_reply_cap);
                (&mut *(&raw mut ALLOCATOR)).free_single_slot(entry.joiner_reply_cap);
            }
            p.threads.entries[i] = ThreadEntry::zeroed();
        }
        p.threads.count = 0;
        p.threads.next_tid = 1;
    }
}
