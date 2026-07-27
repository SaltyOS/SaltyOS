// SPDX-License-Identifier: GPL-2.0-only
//
//! Dispatch table — bridges the master service-EP (init-only labels)
//! and the per-client request MPs (self-only labels) onto the
//! handlers in `mmap` and `client`.

use core::sync::atomic::{AtomicU64, Ordering};
use trona_protocol::common::{TRONA_OK, TRONA_PERMISSION_DENIED};
use uapi::{
    KERNITE_ERR_ALREADY_EXISTS, KERNITE_ERR_INSUFFICIENT_RIGHTS, KERNITE_ERR_INVALID_ARGUMENT,
    KERNITE_ERR_INVALID_OPERATION, KERNITE_ERR_NOT_FOUND, KERNITE_ERR_NOT_SUPPORTED,
    KERNITE_ERR_OUT_OF_MEMORY, KERNITE_ERR_OUT_OF_RANGE, KERNITE_INV_MO_READ, KERNITE_INV_MO_WRITE,
    KERNITE_INV_VSPACE_MAP_MO, KERNITE_INV_VSPACE_UNMAP,
    KERNITE_PAGE_BYTES as KERNITE_PAGE_BYTES_U32, KERNITE_PAGE_FLAG_EXECUTABLE,
    KERNITE_PAGE_FLAG_USER, KERNITE_PAGE_FLAG_WRITABLE, KERNITE_RIGHT_ALL, KERNITE_RIGHT_EXECUTE,
    KERNITE_RIGHT_GRANT, KERNITE_RIGHT_READ, KERNITE_RIGHT_TRANSFER, kernite_ipc_buffer,
};

use crate::caps::{CAP_SELF_CSPACE, recv_user_slot};
use crate::client::ClientVm;
use crate::labels::{
    LABEL_ABORT_EXEC_REPLACE, LABEL_ALLOC_RANGE, LABEL_BEGIN_EXEC_REPLACE, LABEL_BIND_CLIENT_SELF,
    LABEL_BRK, LABEL_COMMIT_EXEC_REPLACE, LABEL_DEREGISTER_CLIENT, LABEL_FILE_MMAP,
    LABEL_FORK_SET_PARTNER, LABEL_FORK_VSPACE, LABEL_GET_CLIENT_VM_STATS, LABEL_GET_COMMIT_AS,
    LABEL_GET_SYSTEM_MEMINFO, LABEL_LIST_RESERVATIONS, LABEL_LIST_VMAS, LABEL_MMAP,
    LABEL_MO_CREATE, LABEL_MPROTECT, LABEL_MSYNC, LABEL_MUNMAP, LABEL_PREFAULT_RANGE,
    LABEL_REGISTER_CLIENT, LABEL_REGISTER_FAULT_PIPE, LABEL_REGISTER_VFS_PAGER,
    LABEL_RESERVE_IMAGE, LABEL_RESERVE_RANGE, LABEL_SBRK, LABEL_SHM_CREATE, LABEL_SHM_DESTROY,
    LABEL_SHM_MAP, LABEL_SHM_UNMAP, LABEL_STAGE_IMAGE_REGION, LABEL_STAGE_SET_SOURCE,
    LABEL_UNMAP_IMAGE, LABEL_UNRESERVE_RANGE, LABEL_VFS_WRITEBACK_DONE,
    STAGE_FLAG_EXEC_MATERIALIZE, STAGE_FLAG_EXEC_MO_SRC, STAGE_FLAG_EXEC_TXN,
    STAGE_FLAG_PROVIDED_MO, STAGE_FLAG_STACK, STAGE_FLAG_TXN_ID_SHIFT, STAGE_GUARD_PAGES_MASK,
    STAGE_GUARD_PAGES_SHIFT, STAGE_IMAGE_KIND_BSS, STAGE_IMAGE_KIND_DATA, STAGE_IMAGE_KIND_NONE,
    STAGE_IMAGE_KIND_RODATA, STAGE_IMAGE_KIND_TEXT,
};
use crate::main_loop::ServerState;
use crate::mmap;
use crate::mo_registry::{MoKind, MoRegistry};
use crate::region::max_prot_for_region_type;
use crate::region::{
    BackingDescriptor, ForkPolicy, ImageKind, MappedRegion, MoHandle, REGION_IMAGE_BSS,
    REGION_IMAGE_DATA, REGION_IMAGE_TEXT, REGION_MMAP, REGION_SHARED_LIB, REGION_STACK, RegionId,
    ReservedRange, kernel_region_kind, reservation_kind_inherits_on_fork,
};
use crate::watch_pool;
use trona_kernel::core_types::CapRef;
use trona_protocol::control;
use trona_runtime::core::slot_alloc::resolved_cap_ref;
use trona_runtime::spawn::layout::{LayoutError, VmClientLayout};
use trona_server::frame_alloc::FrameAllocator;

const KERNITE_PAGE_BYTES: u64 = KERNITE_PAGE_BYTES_U32 as u64;
static CURRENT_REPLY_MP: AtomicU64 = AtomicU64::new(0);
static CURRENT_REPLY_TXID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_current_reply_target(buf: *const kernite_ipc_buffer, slot: u64) {
    let target = unsafe { trona_server::MpReplyTarget::from_ipc_buffer(buf, slot) };
    CURRENT_REPLY_MP.store(target.mp_slot, Ordering::Relaxed);
    CURRENT_REPLY_TXID.store(target.txid, Ordering::Relaxed);
}

pub(crate) fn current_reply_target() -> trona_server::MpReplyTarget {
    trona_server::MpReplyTarget::new(
        CURRENT_REPLY_MP.load(Ordering::Relaxed),
        CURRENT_REPLY_TXID.load(Ordering::Relaxed),
    )
}

/// Reply to the current caller on the MessagePipe endpoint that
/// produced the request. `cap_count` is the number of caps the reply
/// itself ships back.
fn send_reply(buf: *mut kernite_ipc_buffer, label: u64, regs: &[u64], cap_count: u64) {
    if buf.is_null() {
        return;
    }
    let target = current_reply_target();
    let result = unsafe {
        trona_server::mp_write_reply_to_with_error_fallback(buf, target, label, regs, cap_count)
    };
    if result.primary_error != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] mp_write_reply failed label=");
            _lb.hex(label);
            _lb.str(b" primary=");
            _lb.dec(result.primary_error as u64);
            _lb.str(b" fallback=");
            _lb.dec(result.fallback_error as u64);
            _lb.str(b" caps=");
            _lb.dec(cap_count);
            _lb.putc(b'\n');
        });
    }
}

fn send_reply_if_requested(buf: *mut kernite_ipc_buffer, label: u64, regs: &[u64], cap_count: u64) {
    if current_reply_target().has_txid() {
        send_reply(buf, label, regs, cap_count);
    }
}

fn copy_cap_for_reply(src_slot: u64, label: &[u8]) -> Result<u64, u64> {
    let Some(temp) = trona_runtime::core::slot_alloc::alloc_slot() else {
        let _ = label;
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let err = crate::kernel_vm::cnode_copy_ref(
        CAP_SELF_CSPACE,
        resolved_cap_ref(src_slot),
        CAP_SELF_CSPACE,
        resolved_cap_ref(temp.addr()),
        // Client-facing reply caps never carry EXECUTE: executable memory is
        // conferred only via mo_mark_executable, never through an mmsrv reply.
        (KERNITE_RIGHT_ALL & !KERNITE_RIGHT_EXECUTE) as u64,
    );
    if err != 0 {
        // copy failed: `temp` (OwnedSlot) Drop frees the empty slot.
        return Err(err as u64);
    }
    Ok(temp.into_raw())
}

/// # Safety
/// `slot` is a transient cap slot the caller solely owns (0 = no-op); torn down
/// and its index freed once here.
unsafe fn delete_and_free_temp_cap(slot: u64) {
    if slot == 0 {
        return;
    }
    // SAFETY: exclusive ownership of `slot` per this fn's `# Safety`.
    unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
}

fn send_reply_with_cap_copy(
    buf: *mut kernite_ipc_buffer,
    src_slot: u64,
    label: u64,
    regs: &[u64],
    copy_label: &[u8],
) {
    let temp = match copy_cap_for_reply(src_slot, copy_label) {
        Ok(slot) => slot,
        Err(err) => {
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    unsafe {
        (*buf).caps[0] = temp;
    }
    let result = unsafe {
        trona_server::mp_write_reply_to_with_error_fallback(
            buf,
            current_reply_target(),
            label,
            regs,
            1,
        )
    };
    if result.primary_error == 0 {
        // The reply transfer moved the cap out of `temp`, leaving it empty.
        // SAFETY: `temp` came from copy_cap_for_reply and the successful reply
        // moved its cap out, so the slot is empty and is reclaimed once here.
        unsafe {
            trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(temp);
        }
        return;
    }
    // SAFETY: the reply failed so `temp` (from copy_cap_for_reply) still holds
    // its cap and is solely owned here; tear down + free once.
    unsafe { delete_and_free_temp_cap(temp) };
    let _ = result.fallback_error;
}

/// Authorize the per-server ROOT control cap — the only authority for
/// `REGISTER_CLIENT` (the one verb with no per-client cap yet). On any
/// other badge, delete received caps and reply INSUFFICIENT_RIGHTS.
fn require_root(buf: *mut kernite_ipc_buffer, badge: u64) -> bool {
    if control::is_root(badge) {
        return true;
    }
    delete_recv_user_caps(received_user_cap_count(buf));
    send_reply(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
    false
}

/// Resolve the invoked per-client control cap to its client slot. On any
/// failure (wrong tag, ROOT cap, dead slot, epoch mismatch) delete received
/// caps, reply INSUFFICIENT_RIGHTS, and return `None`. The returned slot is
/// both the authorization and the target identity — there is no trusted
/// `client_id` argument.
fn resolve_control_or_reject(
    buf: *mut kernite_ipc_buffer,
    badge: u64,
    state: &ServerState,
) -> Option<usize> {
    if let Some(idx) = state.clients.resolve_control(badge) {
        return Some(idx);
    }
    delete_recv_user_caps(received_user_cap_count(buf));
    send_reply(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
    None
}

/// Mint a per-client control cap — a badged copy of mmsrv's own master-EP
/// send (`startup.master_service_mp_send`) — into a transient slot. The
/// kernel strips GRANT, leaving an invocable `READ|WRITE|TRANSFER` leaf that
/// the reply moves into init's receive window. Returns the temp slot or an
/// error code.
fn mint_control_cap_for_reply(master_send: u64, badge: u64) -> Result<u64, u64> {
    if master_send == 0 {
        return Err(KERNITE_ERR_INVALID_OPERATION as u64);
    }
    let Some(temp) = trona_runtime::core::slot_alloc::alloc_slot() else {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let err = trona_kernel::invoke::cnode_mint_ref(
        CapRef::flat(CAP_SELF_CSPACE),
        resolved_cap_ref(master_send),
        CapRef::flat(CAP_SELF_CSPACE),
        resolved_cap_ref(temp.addr()),
        badge,
    );
    if err != 0 {
        // mint failed: `temp` (OwnedSlot) Drop frees the empty slot.
        return Err(err as u64);
    }
    Ok(temp.into_raw())
}

/// Roll back a just-installed client slot when register fails after install
/// (control-cap mint or reply error). A freshly-registered client owns no
/// regions or pending exec, so teardown is the Watch cancel + `vacate`.
fn rollback_fresh_register(idx: usize, state: &mut ServerState) {
    let Some(saved) = (unsafe { state.clients.vacate(idx, &mut state.self_vm) }) else {
        return;
    };
    if saved.watch_cap != 0 {
        let (_kind, slot, _gen) = trona_server::event_loop::decode_cookie(saved.watch_cookie);
        let _ = state
            .main_cookie_table
            .cancel(crate::main_loop::MMSRV_KIND_PER_CLIENT, slot);
        let _ = trona_kernel::invoke::watch_cancel(resolved_cap_ref(saved.watch_cap));
        state.watches.free(saved.watch_cap);
    }
    // saved caps drop here (OwnedCap Drop deletes the kernel objects).
}

fn received_user_cap_count(buf: *mut kernite_ipc_buffer) -> u64 {
    unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf as *const _) }
}

fn delete_recv_user_caps(user_cap_count: u64) {
    let limit = core::cmp::min(user_cap_count, crate::caps::RECV_WINDOW_LEN);
    for idx in 0..limit {
        let _ =
            trona_kernel::invoke::cnode_delete(CapRef::flat(CAP_SELF_CSPACE), recv_user_slot(idx));
    }
}

fn move_recv_user_cap_to_stable(
    idx: u64,
    label: &[u8],
) -> Result<trona_runtime::core::slot_alloc::OwnedCap, u64> {
    let Some(stable) = trona_runtime::core::slot_alloc::alloc_slot() else {
        let _ = label;
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    // The stable slot comes from the slot allocator and may live in an
    // expansion sub-CNode (invoke depth > 0). `cnode_move` (flat, depth 0)
    // would resolve the destination at the root width and silently land the
    // cap at the wrong slot, while the `assume_filled` OwnedCap below points at
    // the correct deep slot — leaving mmsrv holding an empty/wrong cap (e.g. a
    // client's VSpace). Carry the depth via `cnode_move_ref`. The receive
    // window base is a flat root reservation, so the source stays depth 0.
    let err = trona_kernel::invoke::cnode_move_ref(
        CapRef::flat(CAP_SELF_CSPACE),
        stable.borrow(),
        CapRef::flat(CAP_SELF_CSPACE),
        CapRef::flat(recv_user_slot(idx)),
    );
    if err != 0 {
        // move failed: `stable` (OwnedSlot) Drop frees the empty slot.
        return Err(err as u64);
    }
    // The cap was just moved into the slot; adopt it as an OwnedCap.
    Ok(stable.assume_filled())
}

/// `MM_REGISTER_CLIENT(client_id, pid, layout; caps=[vspace,
/// request_mp_recv?, request_mp_send?])`. The 12-field `VmClientLayout`
/// (heap_base/limit, mmap_base/limit, dso_base/limit, elf_code_base/limit,
/// interpreter_base/limit, preloaded_base/limit) is unpacked into
/// `regs[2..14]`. mmsrv stamps the per-client entry, arms a Watch over
/// `request_mp_recv`'s STATE_READABLE on its service EQ with cookie =
/// `client_id`, retains the send-side cap as the reply source for
/// `MM_BIND_CLIENT_SELF`, and echoes the id back to the caller.
///
/// The image windows (`elf_code`, `interpreter`, `preloaded_dsos`) are
/// required so mmsrv can validate subsequent staging runs against the same
/// plan the loader used; exec-txn staging rejects any `dst_va` outside the
/// registered image windows.
///
/// `caps[2]` (request_mp_send) may be 0 — core servers self-register
/// without a self-tier send because they never call
/// `MM_BIND_CLIENT_SELF` against their own master.
fn handle_register_client(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    if !require_root(buf, badge) {
        return;
    }
    let client_id = regs[0] as u32;
    let pid = regs[1] as u32;
    let layout = VmClientLayout {
        heap_base: regs[2],
        heap_limit: regs[3],
        mmap_base: regs[4],
        mmap_limit: regs[5],
        dso_base: regs[6],
        dso_limit: regs[7],
        elf_code_base: regs[8],
        elf_code_limit: regs[9],
        interpreter_base: regs[10],
        interpreter_limit: regs[11],
        preloaded_base: regs[12],
        preloaded_limit: regs[13],
    };
    if let Err(err) = layout.validate() {
        send_reply(buf, err.wire_code(), &[], 0);
        return;
    }
    let user_cap_count = received_user_cap_count(buf);
    if user_cap_count == 0 || user_cap_count > 3 {
        delete_recv_user_caps(user_cap_count);
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let vspace_cap = match move_recv_user_cap_to_stable(0, b"mmsrv client vspace") {
        Ok(cap) => cap,
        Err(err) => {
            delete_recv_user_caps(user_cap_count);
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    // OwnedCap error paths: dropping vspace_cap / request_mp_recv /
    // request_mp_send on early return is handled by their Drops.
    let request_mp_recv = if user_cap_count >= 2 {
        match move_recv_user_cap_to_stable(1, b"mmsrv client mp recv") {
            Ok(cap) => cap,
            Err(err) => {
                delete_recv_user_caps(user_cap_count);
                send_reply(buf, err, &[], 0);
                return; // vspace_cap drops here
            }
        }
    } else {
        trona_runtime::core::slot_alloc::OwnedCap::null()
    };
    let request_mp_send = if user_cap_count >= 3 {
        match move_recv_user_cap_to_stable(2, b"mmsrv client mp send") {
            Ok(cap) => cap,
            Err(err) => {
                delete_recv_user_caps(user_cap_count);
                send_reply(buf, err, &[], 0);
                return; // request_mp_recv + vspace_cap drop here
            }
        }
    } else {
        trona_runtime::core::slot_alloc::OwnedCap::null()
    };

    let Some(idx) = state.clients.alloc() else {
        // request_mp_send, request_mp_recv, vspace_cap all drop here.
        send_reply(buf, uapi::KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };

    // A null `request_mp_recv` means the caller does not need an
    // event-driven self-tier path. Pre-self-tier core service
    // registrations use this; init's own self-registration passes both
    // recv/send once it has allocated its request MP pair.
    let recv_raw = request_mp_recv.as_raw();
    let (watch_cap, watch_cookie) = if recv_raw != 0 {
        let cap = state.watches.alloc();
        if cap == 0 {
            send_reply(buf, uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
            return; // OwnedCaps drop here
        }
        // Register the per-client request MP in the main reactor's
        // cookie table; the cookie returned identifies this Watch's
        // (kind, slot, live_gen) and is what the kernel publishes
        // back through EventRecord.cookie when the Watch fires.
        let cookie = match unsafe {
            state.main_cookie_table.arm(
                &mut state.segment_allocator,
                crate::main_loop::MMSRV_KIND_PER_CLIENT,
                recv_raw,
                cap,
                crate::main_loop::MmsrvMainTarget::Client { idx: idx as u32 },
            )
        } {
            Ok(c) => c,
            Err(_) => {
                state.watches.free(cap);
                send_reply(buf, uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
                return; // OwnedCaps drop here
            }
        };
        let arm_err = watch_pool::arm(cap, recv_raw, state.startup.service_eq, cookie);
        if arm_err != 0 {
            // Roll back the cookie-table slot — the Watch was never
            // armed kernel-side, so no WATCH_CANCEL is needed.
            let (_kind, slot, _gen) = trona_server::event_loop::decode_cookie(cookie);
            let _ = state
                .main_cookie_table
                .cancel(crate::main_loop::MMSRV_KIND_PER_CLIENT, slot);
            state.watches.free(cap);
            send_reply(buf, arm_err as u64, &[], 0);
            return; // OwnedCaps drop here
        }
        (cap, cookie)
    } else {
        (0, 0)
    };

    let recv_log = recv_raw;
    let send_log = request_mp_send.as_raw();
    state.clients.install(
        idx,
        client_id,
        pid,
        vspace_cap,
        request_mp_recv,
        request_mp_send,
        watch_cap,
        watch_cookie,
        layout,
    );
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] client registered id=");
        _lb.hex(client_id as u64);
        _lb.str(b" pid=");
        _lb.dec(pid as u64);
        _lb.str(b" idx=");
        _lb.dec(idx as u64);
        _lb.str(b" recv=");
        _lb.hex(recv_log);
        _lb.str(b" send=");
        _lb.hex(send_log);
        _lb.str(b" watch=");
        _lb.hex(watch_cap);
        _lb.str(b" cookie=");
        _lb.hex(watch_cookie);
        _lb.str(b" heap=");
        _lb.hex(layout.heap_base);
        _lb.str(b"..");
        _lb.hex(layout.heap_limit);
        _lb.str(b" mmap=");
        _lb.hex(layout.mmap_base);
        _lb.str(b"..");
        _lb.hex(layout.mmap_limit);
        _lb.str(b" dso=");
        _lb.hex(layout.dso_base);
        _lb.str(b"..");
        _lb.hex(layout.dso_limit);
        _lb.putc(b'\n');
    });
    // Mint the per-client control cap (badge = slot + current epoch) and
    // return it to init. Register is atomic: any failure after install rolls
    // the slot back so mmsrv never holds an orphaned client init cannot drive.
    let epoch = state.clients.epoch_of(idx).unwrap_or(0);
    let control_badge = control::encode(idx as u16, epoch);
    let control_temp =
        match mint_control_cap_for_reply(state.startup.master_service_mp_send, control_badge) {
            Ok(slot) => slot,
            Err(err) => {
                rollback_fresh_register(idx, state);
                send_reply(buf, err, &[], 0);
                return;
            }
        };
    unsafe {
        (*buf).caps[0] = control_temp;
    }
    let result = unsafe {
        trona_server::mp_write_reply_to_with_error_fallback(
            buf,
            current_reply_target(),
            TRONA_OK,
            &[client_id as u64],
            1,
        )
    };
    if result.primary_error == 0 {
        // The reply moved the control cap into init's window; reclaim the
        // emptied temp slot.
        unsafe {
            trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(control_temp);
        }
    } else {
        // Reply failed: the cap is still in temp. Free it and roll the
        // registration back so mmsrv holds no orphaned client.
        unsafe { delete_and_free_temp_cap(control_temp) };
        rollback_fresh_register(idx, state);
        let _ = result.fallback_error;
    }
}

fn handle_deregister_client(
    buf: *mut kernite_ipc_buffer,
    _regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    let Some(idx) = state.clients.resolve_control(badge) else {
        delete_recv_user_caps(received_user_cap_count(buf));
        send_reply_if_requested(buf, KERNITE_ERR_INSUFFICIENT_RIGHTS as u64, &[], 0);
        return;
    };
    let Some(entry) = state.clients.entry(idx) else {
        send_reply_if_requested(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let vspace_raw = entry.vspace_cap.as_raw();
    let pending_vspace_raw = state
        .clients
        .pending_exec(idx)
        .map(|p| p.pending_vspace_cap.as_raw());

    // Tear down the kernel backing (VSpace unmaps + MO / cap drops) of
    // every live region, then of any staged exec image, before the slab
    // bookkeeping is released by `vacate`. `ClientVm` is non-`Copy`, so
    // teardown reads the live VM in place rather than snapshotting it.
    if let Some(vm) = state.clients.vm(idx) {
        teardown_regions(vm, vspace_raw, &mut state.mo_registry, &mut state.frames);
    }
    if let Some(p) = state.clients.pending_exec(idx) {
        teardown_regions(
            &p.staged_vm,
            pending_vspace_raw.unwrap_or(0),
            &mut state.mo_registry,
            &mut state.frames,
        );
    }

    let Some(saved) = (unsafe { state.clients.vacate(idx, &mut state.self_vm) }) else {
        send_reply_if_requested(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    // saved.pending_vspace_cap and saved.vspace_cap are OwnedCap — they
    // drop automatically at the end of this function; no explicit free needed.
    if saved.watch_cap != 0 {
        // Tombstone the cookie-table slot so any in-flight stale
        // EventRecord with this cookie fails the live_gen check on
        // dispatch. WATCH_CANCEL detaches the Watch from the bound EQ
        // and purges any queued record with the same cookie (the
        // kernite WATCH_CANCEL hygiene primitive).
        let (_kind, slot, _gen) = trona_server::event_loop::decode_cookie(saved.watch_cookie);
        let _ = state
            .main_cookie_table
            .cancel(crate::main_loop::MMSRV_KIND_PER_CLIENT, slot);
        let _ = trona_kernel::invoke::watch_cancel(resolved_cap_ref(saved.watch_cap));
        state.watches.free(saved.watch_cap);
    }
    // saved.request_mp_send is OwnedCap — drops automatically when saved
    // is dropped at end of scope. No explicit free needed.
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[MMSRV] client deregistered id=");
        _lb.hex(saved.client_id as u64);
        _lb.str(b" pid=");
        _lb.dec(saved.pid_for_diagnostics as u64);
        _lb.str(b" idx=");
        _lb.dec(idx as u64);
        _lb.str(b" recv=");
        _lb.hex(saved.request_mp_recv.as_raw());
        _lb.str(b" send=");
        _lb.hex(saved.request_mp_send.as_raw());
        _lb.str(b" watch=");
        _lb.hex(saved.watch_cap);
        _lb.str(b" cookie=");
        _lb.hex(saved.watch_cookie);
        _lb.putc(b'\n');
    });
    // saved.request_mp_recv, saved.vspace_cap, saved.pending_vspace_cap
    // all drop here (OwnedCap Drop handles delete-and-free).
    // Disarm + free every fault-MP Watch this client owned. The helper
    // tombstones each fault-cookie-table slot and fires WATCH_CANCEL
    // before returning the Watch cap to the pool.
    state.fault.evict_by_client(
        saved.client_id,
        &mut state.watches,
        &mut state.fault_cookie_table,
    );
    // Self-heal any two-step transaction that named this slot as its pending
    // secondary, so a later operate step cannot consume a dead operand.
    state.clients.clear_partner_naming(idx);
    send_reply_if_requested(buf, TRONA_OK, &[], 0);
}

/// `MM_BIND_CLIENT_SELF` — bootstrap-bind exception within the 0x40x
/// admin range. dispatched to non-admin callers iff the caller's
/// badge `client_id` matches a registered `ClientState`. mmsrv
/// `cnode_copy`s `ClientState.request_mp_send` into the caller's
/// receive slot and replies with the client_id in `regs[0]`. Used by
/// the lazy `caps::mmsrv_ep()` resolver to obtain the per-client
/// send after `NAMESRV_LOOKUP("mmsrv")`.
fn handle_bind_client_self(buf: *mut kernite_ipc_buffer, badge: u64, state: &mut ServerState) {
    let client_id = (badge & 0xFFFF_FFFF) as u32;
    if client_id == 0 {
        send_reply(buf, TRONA_PERMISSION_DENIED, &[], 0);
        return;
    }
    let Some(idx) = state.clients.find_by_client_id(client_id) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let Some(entry) = state.clients.entry(idx) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    };
    let send_slot = entry.request_mp_send.as_raw();
    if send_slot == 0 {
        send_reply(buf, uapi::KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    }
    send_reply_with_cap_copy(
        buf,
        send_slot,
        TRONA_OK,
        &[client_id as u64],
        b"mmsrv bind self send",
    );
}

/// `MM_FORK_VSPACE(parent_client_id, child_client_id)` — clone the
/// parent's anon regions into the child via per-region
/// `KERNITE_INV_VSPACE_FORK_RANGE`. Both clients must already be
/// registered (init runs `MM_REGISTER_CLIENT` for the child before
/// fork). For each parent region mmsrv retypes a fresh
/// `parent_shadow_mo` and `child_mo` from its MO pool; the fork
/// primitive replaces parent's VmArea with `parent_shadow_mo` and
/// installs `child_mo` in the child VSpace at the same VA.
fn handle_fork_vspace(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    // Primary operand (parent): authorized + identified by the invoked
    // control cap. Secondary operand (child): the consumed pending partner
    // recorded by a prior `MM_FORK_SET_PARTNER` on the child's control cap.
    let nonce = regs[0];
    let Some(parent_idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    let Some(child_idx) = state.clients.consume_partner(nonce) else {
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    };
    // Recover the client_ids for the owner badge stamped into the child's
    // inherited regions / reservations and the fork bookkeeping.
    let parent_id = state
        .clients
        .entry(parent_idx)
        .map(|e| e.client_id)
        .unwrap_or(0);
    let child_id = state
        .clients
        .entry(child_idx)
        .map(|e| e.client_id)
        .unwrap_or(0);

    // Optional `exclude_vas` list: parent regions whose `va_base`
    // matches any entry are skipped during fork. init uses this to
    // preserve the cap-table region in the child's VSpace so it can
    // re-stage a fresh cap-table frame at the same VA without
    // colliding with a COW'd inherit.
    const MAX_EXCLUDE: usize = 8;
    let exclude_count = (regs[1] as usize).min(MAX_EXCLUDE);
    let mut exclude_vas: [u64; MAX_EXCLUDE] = [0; MAX_EXCLUDE];
    for i in 0..exclude_count {
        // regs[2..2+count] hold the exclude addresses.
        let reg_idx = 2 + i;
        if reg_idx >= regs.len() {
            break;
        }
        exclude_vas[i] = regs[reg_idx];
    }
    let exclude_slice = &exclude_vas[..exclude_count];
    let parent_vspace = state
        .clients
        .entry(parent_idx)
        .expect("parent")
        .vspace_cap
        .as_raw();
    let child_vspace = state
        .clients
        .entry(child_idx)
        .expect("child")
        .vspace_cap
        .as_raw();

    let mut rollback: [u8; 1056] = [0; 1056];

    // Walk the parent's regions by base-sorted index position. fork only
    // updates parent regions in place (rebinding them onto a shadow MO)
    // and installs child regions into the *child* VM, so the parent
    // index is structurally stable across the walk and a positional
    // cursor stays valid. `region_snapshot_at` returns owned copies, so
    // no borrow on the client table is held across the per-region
    // mutations below.
    let parent_region_total = state
        .clients
        .vm(parent_idx)
        .map(|vm| vm.regions_index().count())
        .unwrap_or(0);
    for pos in 0..parent_region_total {
        let Some((parent_region_id, parent_region)) = (unsafe {
            match state.clients.vm(parent_idx) {
                Some(vm) => vm.region_snapshot_at(pos),
                None => None,
            }
        }) else {
            continue;
        };

        // Skip excluded VA bases — these regions stay private to the
        // parent and the child's VSpace receives no inherit.
        if exclude_slice.contains(&parent_region.base) {
            continue;
        }
        let region_pages = parent_region.length / KERNITE_PAGE_BYTES;
        if region_pages == 0 {
            continue;
        }
        if region_pages > 8192 {
            send_reply(buf, uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
            return;
        }
        let region_size = region_pages * KERNITE_PAGE_BYTES;

        // Dispatch on the region's stored fork policy. `Exclude` (device,
        // VA-excluded) regions are dropped; `InheritShare` regions map the
        // same backing object into the child (no copy — read-only for image
        // text/rodata, writable for SHM / MAP_SHARED anon / shared file);
        // `InheritCow` regions fall through to the shadow-MO copy-on-write
        // fork below.
        match parent_region.fork_policy {
            ForkPolicy::Exclude => continue,
            ForkPolicy::InheritShare => {
                // Extract the LIVE backing's Copy fields: `snapshot()`
                // tombstones FileBacked/Shm (they hold an OwnedCap), so the
                // snapshot is unusable for them. Drop the borrow before
                // retaining a registry ref or dup'ing a cap.
                enum ShareSrc {
                    Registry {
                        mo_idx: usize,
                        mo_offset: u32,
                        image_kind: Option<ImageKind>,
                    },
                    FileBacked {
                        cap_raw: u64,
                        mo_offset: u32,
                        file_id0: u64,
                        file_id1: u64,
                        file_offset: u64,
                        file_size: u64,
                        backing_kind: u8,
                        writeback: bool,
                    },
                    Shm {
                        cap_raw: u64,
                        shm_idx: u32,
                        mo_offset: u32,
                    },
                }
                let src = match unsafe {
                    match state.clients.vm(parent_idx) {
                        Some(vm) => vm.region(parent_region_id),
                        None => None,
                    }
                } {
                    Some(r) => match &r.backing {
                        BackingDescriptor::Anon {
                            mo_handle,
                            mo_offset,
                        } => ShareSrc::Registry {
                            mo_idx: mo_handle.0 as usize,
                            mo_offset: *mo_offset,
                            image_kind: None,
                        },
                        BackingDescriptor::Image {
                            mo_handle,
                            mo_offset,
                            image_kind,
                        } => ShareSrc::Registry {
                            mo_idx: mo_handle.0 as usize,
                            mo_offset: *mo_offset,
                            image_kind: Some(*image_kind),
                        },
                        BackingDescriptor::FileBacked {
                            mo_cap,
                            mo_offset,
                            file_id0,
                            file_id1,
                            file_offset,
                            file_size,
                            backing_kind,
                            writeback,
                        } => ShareSrc::FileBacked {
                            cap_raw: mo_cap.as_raw(),
                            mo_offset: *mo_offset,
                            file_id0: *file_id0,
                            file_id1: *file_id1,
                            file_offset: *file_offset,
                            file_size: *file_size,
                            backing_kind: *backing_kind,
                            writeback: *writeback,
                        },
                        BackingDescriptor::Shm {
                            mo_cap,
                            shm_idx,
                            mo_offset,
                        } => ShareSrc::Shm {
                            cap_raw: mo_cap.as_raw(),
                            shm_idx: *shm_idx,
                            mo_offset: *mo_offset,
                        },
                        // CowChild / Device can never be InheritShare (the
                        // validator forbids it); skip defensively.
                        _ => continue,
                    },
                    None => continue,
                };

                // Reserve the child's slab slot before the kernel map so the
                // post-map publish cannot fail and strand a mapped VmArea.
                let reserved = unsafe {
                    match state.clients.vm_mut(child_idx) {
                        Some(vm) => vm.reserve_region_capacity(1, &mut state.self_vm),
                        None => false,
                    }
                };
                if !reserved {
                    send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
                    return;
                }

                // Build an independent reference to the same backing object
                // (registry retain, or a fresh cap copy) plus the raw cap to
                // map the child with.
                let (child_backing, map_cap_raw, share_offset_pages) = match src {
                    ShareSrc::Registry {
                        mo_idx,
                        mo_offset,
                        image_kind,
                    } => {
                        if !state.mo_registry.retain_by_handle(mo_idx) {
                            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                            return;
                        }
                        let cap_raw = match state.mo_registry.entry(mo_idx) {
                            Some(e) => e.mo_cap.as_raw(),
                            None => {
                                let _ = state
                                    .mo_registry
                                    .release_by_handle(mo_idx, &mut state.frames);
                                send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                                return;
                            }
                        };
                        let backing = match image_kind {
                            Some(image_kind) => BackingDescriptor::Image {
                                mo_handle: MoHandle(mo_idx as u32),
                                mo_offset,
                                image_kind,
                            },
                            None => BackingDescriptor::Anon {
                                mo_handle: MoHandle(mo_idx as u32),
                                mo_offset,
                            },
                        };
                        (backing, cap_raw, mo_offset)
                    }
                    ShareSrc::FileBacked {
                        cap_raw,
                        mo_offset,
                        file_id0,
                        file_id1,
                        file_offset,
                        file_size,
                        backing_kind,
                        writeback,
                    } => {
                        let Some(dup) = crate::txn::dup_cap(cap_raw) else {
                            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
                            return;
                        };
                        // SAFETY: dup_cap minted a fresh copy into a new slot;
                        // this OwnedCap is its sole owner.
                        let owned = unsafe {
                            trona_runtime::core::slot_alloc::OwnedCap::adopt_received(dup)
                        };
                        let raw = owned.as_raw();
                        (
                            BackingDescriptor::FileBacked {
                                mo_cap: owned,
                                mo_offset,
                                file_id0,
                                file_id1,
                                file_offset,
                                file_size,
                                backing_kind,
                                writeback,
                            },
                            raw,
                            mo_offset,
                        )
                    }
                    ShareSrc::Shm {
                        cap_raw,
                        shm_idx,
                        mo_offset,
                    } => {
                        let Some(dup) = crate::txn::dup_cap(cap_raw) else {
                            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
                            return;
                        };
                        // SAFETY: dup_cap minted a fresh copy into a new slot;
                        // adopt it first so a failed map-count bump frees it
                        // via Drop on the early return below.
                        let owned = unsafe {
                            trona_runtime::core::slot_alloc::OwnedCap::adopt_received(dup)
                        };
                        let Ok(shm_slot) = usize::try_from(shm_idx) else {
                            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                            return;
                        };
                        // Bump the shared map count to match the new mapping;
                        // on failure (unreachable for a live region) `owned`
                        // drops here, freeing the dup'd cap.
                        if !state.mo_registry.inc_map_count(shm_slot) {
                            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
                            return;
                        }
                        let raw = owned.as_raw();
                        (
                            BackingDescriptor::Shm {
                                mo_cap: owned,
                                shm_idx,
                                mo_offset,
                            },
                            raw,
                            mo_offset,
                        )
                    }
                };

                // Map the same object into the child with the parent's
                // permissions: writable for SHM / MAP_SHARED anon / shared
                // file, read-only (optionally executable) for image text /
                // rodata. The child region copies the parent's `max_prot`.
                let perms = (KERNITE_PAGE_FLAG_USER as u64)
                    | if parent_region.prot & 0x2 != 0 {
                        KERNITE_PAGE_FLAG_WRITABLE as u64
                    } else {
                        0
                    }
                    | if parent_region.prot & 0x4 != 0 {
                        KERNITE_PAGE_FLAG_EXECUTABLE as u64
                    } else {
                        0
                    };
                let count_and_flags = (region_pages << 32)
                    | perms
                    | ((kernel_region_kind(parent_region.region_type) as u64) << 24);
                let (map_err, mapped) = crate::kernel_vm::vspace_map_mo_with_count(
                    child_vspace,
                    map_cap_raw,
                    parent_region.base,
                    share_offset_pages as u64,
                    count_and_flags,
                );
                if map_err != 0 || mapped != region_pages {
                    for p in 0..mapped.min(region_pages) {
                        let _ = crate::kernel_vm::vspace_unmap(
                            child_vspace,
                            parent_region.base + p * KERNITE_PAGE_BYTES,
                        );
                    }
                    crate::txn::release_region_backing(
                        child_backing,
                        &mut state.mo_registry,
                        &mut state.frames,
                    );
                    let err = if map_err != 0 {
                        map_err as u64
                    } else {
                        KERNITE_ERR_OUT_OF_MEMORY as u64
                    };
                    send_reply(buf, err, &[], 0);
                    return;
                }

                let child_region = MappedRegion {
                    base: parent_region.base,
                    length: parent_region.length,
                    prot: parent_region.prot,
                    max_prot: parent_region.max_prot,
                    region_type: parent_region.region_type,
                    fork_policy: ForkPolicy::InheritShare,
                    lazy: false,
                    backing: child_backing,
                    reservation: None,
                    stack_allocator_badge: parent_region.stack_allocator_badge,
                    guard_reservation_id: None,
                };
                let install_res = unsafe {
                    match state.clients.vm_mut(child_idx) {
                        Some(vm) => vm.install_region(child_region, &mut state.self_vm),
                        None => Err(crate::client::InstallError::OutOfMemory(child_region)),
                    }
                };
                if let Err(e) = install_res {
                    // Unreachable (reserved capacity + hardcoded-valid policy +
                    // distinct child base), but if it ever fires, undo cleanly:
                    // unmap the freshly-mapped range and release the dup'd /
                    // retained backing this share just took.
                    let code = e.code();
                    let region = e.into_region();
                    for p in 0..region_pages {
                        let _ = crate::kernel_vm::vspace_unmap(
                            child_vspace,
                            parent_region.base + p * KERNITE_PAGE_BYTES,
                        );
                    }
                    crate::txn::release_region_backing(
                        region.backing,
                        &mut state.mo_registry,
                        &mut state.frames,
                    );
                    send_reply(buf, code, &[], 0);
                    return;
                }
                continue;
            }
            ForkPolicy::InheritCow => {}
        }
        // Reserve the child's slab slot + index entry BEFORE the kernel
        // fork, so the post-fork publish cannot fail and strand a forked
        // VmArea with no mmsrv-side record.
        let reserved = unsafe {
            match state.clients.vm_mut(child_idx) {
                Some(vm) => vm.reserve_region_capacity(1, &mut state.self_vm),
                None => false,
            }
        };
        if !reserved {
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        }

        let Some(parent_shadow_idx) = state.mo_registry.alloc_slot() else {
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        let Some(parent_shadow_cap) = state.mo_registry.install(
            parent_shadow_idx,
            region_size,
            parent_id,
            MoKind::Anon,
            &mut state.frames,
        ) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        let Some(child_mo_idx) = state.mo_registry.alloc_slot() else {
            state
                .mo_registry
                .vacate(parent_shadow_idx, &mut state.frames);
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        let Some(child_mo_cap) = state.mo_registry.install(
            child_mo_idx,
            region_size,
            child_id,
            MoKind::Anon,
            &mut state.frames,
        ) else {
            state
                .mo_registry
                .vacate(parent_shadow_idx, &mut state.frames);
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };

        // Kernel `ChunkRollbackHeader` layout:
        //   u32 old_mo, page_count, fork_mo_offset, split_kind,
        //   old_mo_offset.
        //
        // The shadow and child MOs are fresh region-local objects, so
        // their forked VmAreas start at MO offset 0 even when the source
        // region was spliced from a larger staging MO at a non-zero
        // offset. Undo still needs the original old-MO cap and offset to
        // merge the parent VmArea back precisely.
        for byte in rollback.iter_mut() {
            *byte = 0;
        }
        // The kernel rollback header needs the raw MO cap slot number.
        // Look it up from the registry via the handle stored in the backing.
        let old_mo_cap_raw = parent_region
            .backing
            .mo_handle()
            .and_then(|h| state.mo_registry.entry(h.0 as usize))
            .map(|e| e.mo_cap.as_raw())
            .unwrap_or(0) as u32;
        let old_mo_offset_pages = parent_region.backing.mo_offset();
        let pc_pages = region_pages as u32;
        let fork_mo_offset_pages = 0u32;
        rollback[0..4].copy_from_slice(&old_mo_cap_raw.to_le_bytes());
        rollback[4..8].copy_from_slice(&pc_pages.to_le_bytes());
        rollback[8..12].copy_from_slice(&fork_mo_offset_pages.to_le_bytes());
        rollback[16..20].copy_from_slice(&old_mo_offset_pages.to_le_bytes());
        let rollback_uaddr = rollback.as_ptr() as u64;

        // Provision the per-tree VmHierarchyState `S` the kernel requires to
        // bind a standalone source into a COW tree (a chained fork of an
        // already-bound source ignores it; mmsrv's drop reaps it either way).
        let Some(s_cap) = mmap::alloc_vm_hierarchy_state(&mut state.frames) else {
            state
                .mo_registry
                .vacate(parent_shadow_idx, &mut state.frames);
            state.mo_registry.vacate(child_mo_idx, &mut state.frames);
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        let (fork_err, _) = crate::kernel_vm::vspace_fork_range(
            parent_vspace,
            child_vspace,
            s_cap.as_raw(),
            parent_shadow_cap,
            child_mo_cap,
            parent_region.base,
            rollback_uaddr,
        );
        // Drop mmsrv's S cap: on success the kernel holds per-MO refs keeping S
        // alive for the tree; on failure / chained-adopt this reaps it.
        drop(s_cap);
        if fork_err != 0 {
            state
                .mo_registry
                .vacate(parent_shadow_idx, &mut state.frames);
            state.mo_registry.vacate(child_mo_idx, &mut state.frames);
            send_reply(buf, fork_err as u64, &[], 0);
            return;
        }

        // The fork primitive rebound the parent's VmArea onto the shadow
        // MO at offset 0; mirror that in the parent region record.
        // Geometry is unchanged, so `region_mut` keeps the index valid.
        if let Some(vm) = state.clients.vm_mut(parent_idx) {
            if let Some(pr) = unsafe { vm.region_mut(parent_region_id) } {
                pr.backing = BackingDescriptor::Anon {
                    mo_handle: MoHandle(parent_shadow_idx as u32),
                    mo_offset: 0,
                };
            }
        }

        // Drop mmsrv's reference to the source MO. The parent region now
        // names parent_shadow, and the kernel fork established cow_parent
        // keep-alive refs from both shadows onto the source MO — so the
        // kernel keeps the source alive until every forked child has
        // dropped its ref (CNODE_REVOKE is refcount-respecting; the
        // HasChildren-guarded UNTYPED_RESET safely no-ops while the source
        // survives). The source is reaped only once no descendant maps its
        // frames. Without this release the source MO leaks across forks.
        match &parent_region.backing {
            BackingDescriptor::Anon { mo_handle, .. }
            | BackingDescriptor::CowChild { mo_handle, .. }
            | BackingDescriptor::Image { mo_handle, .. } => {
                let _ = state
                    .mo_registry
                    .release_by_handle(mo_handle.0 as usize, &mut state.frames);
            }
            _ => {}
        }

        // Publish the child's COW region, back-linked to the parent
        // region it forked from. Capacity was reserved above, so this
        // cannot fail; the defensive arm rolls the MOs back regardless.
        let child_region = MappedRegion {
            base: parent_region.base,
            length: parent_region.length,
            prot: parent_region.prot,
            max_prot: parent_region.max_prot,
            region_type: parent_region.region_type,
            fork_policy: ForkPolicy::InheritCow,
            lazy: parent_region.lazy,
            backing: BackingDescriptor::CowChild {
                mo_handle: MoHandle(child_mo_idx as u32),
                mo_offset: 0,
                parent_region: parent_region_id,
            },
            reservation: None,
            stack_allocator_badge: parent_region.stack_allocator_badge,
            guard_reservation_id: None,
        };
        let install_res = unsafe {
            match state.clients.vm_mut(child_idx) {
                Some(vm) => vm.install_region(child_region, &mut state.self_vm),
                None => Err(crate::client::InstallError::OutOfMemory(child_region)),
            }
        };
        if let Err(e) = install_res {
            // Unreachable (reserved capacity + hardcoded InheritCow + distinct
            // base), but undo cleanly: unmap the child's forked range and
            // release the child COW MO. The parent rebind / source release
            // already committed stay — the caller tears the failed child down.
            let code = e.code();
            let region = e.into_region();
            for p in 0..region_pages {
                let _ = crate::kernel_vm::vspace_unmap(
                    child_vspace,
                    parent_region.base + p * KERNITE_PAGE_BYTES,
                );
            }
            crate::txn::release_region_backing(
                region.backing,
                &mut state.mo_registry,
                &mut state.frames,
            );
            send_reply(buf, code, &[], 0);
            return;
        }
    }

    // Inherit the parent's reservations into the child. Arena / Guard /
    // Exclusion reservations carry the parent's VA shape forward; System
    // (per-process scratch) is filtered out so the child re-establishes
    // its own. A stack guard's back-link is remapped to the child's
    // forked stack region, which sits immediately above the guard and so
    // is found by the guard's end address. Reservations have no kernel
    // side effect, so capacity is reserved up front to make each install
    // infallible.
    let parent_reservation_total = state
        .clients
        .vm(parent_idx)
        .map(|vm| vm.reservation_count())
        .unwrap_or(0);
    if parent_reservation_total > 0 {
        let reserved = unsafe {
            match state.clients.vm_mut(child_idx) {
                Some(vm) => vm.reserve_reservation_capacity(
                    parent_reservation_total as u32,
                    &mut state.self_vm,
                ),
                None => false,
            }
        };
        if !reserved {
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        }
        for pos in 0..parent_reservation_total as u32 {
            let Some((_, src)) = (unsafe {
                match state.clients.vm(parent_idx) {
                    Some(vm) => vm.reservation_snapshot_at(pos),
                    None => None,
                }
            }) else {
                continue;
            };
            if !reservation_kind_inherits_on_fork(src.kind) {
                continue;
            }
            let child_stack_region_id = if src.stack_region_id.is_some() {
                unsafe {
                    match state.clients.vm(child_idx) {
                        Some(vm) => vm.find_region(src.end()),
                        None => None,
                    }
                }
            } else {
                None
            };
            let child_range = ReservedRange {
                base: src.base,
                length: src.length,
                kind: src.kind,
                // Fork copies the parent reservation's provenance verbatim (an
                // image envelope stays an image envelope in the child).
                purpose: src.purpose,
                owner_badge: child_id as u64,
                stack_region_id: child_stack_region_id,
            };
            let installed_guard = unsafe {
                match state.clients.vm_mut(child_idx) {
                    Some(vm) => vm.install_reservation(child_range, &mut state.self_vm),
                    None => None,
                }
            };
            // Complete the stack->guard back-link: the forward link
            // (guard->stack) is set via `child_stack_region_id` above; now
            // point the child's stack region back at its new guard so the
            // pair is symmetric (and unmap can free both).
            if let (Some(guard_id), Some(stack_id)) = (installed_guard, child_stack_region_id) {
                unsafe {
                    if let Some(vm) = state.clients.vm_mut(child_idx) {
                        if let Some(region) = vm.region_mut(stack_id) {
                            region.guard_reservation_id = Some(guard_id);
                        }
                    }
                }
            }
        }
    }

    if !state.clients.inherit_vm_layout_from(parent_idx, child_idx) {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    }

    send_reply(buf, TRONA_OK, &[], 0);
}

/// `MM_REGISTER_FAULT_PIPE(client_id, tcb_id; caps=[fault_mp_recv])`.
/// mmsrv allocates a Watch from the slab, arms it over the recv
/// side's `STATE_READABLE` bit on the fault EQ with cookie =
/// `(client_id<<32 | tcb_id)`, and stamps the cap onto the
/// `FaultEntry`. The cap is re-armed by the dispatcher after every
/// drain.
fn handle_register_fault_pipe(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    let Some(idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    let client_id = state.clients.entry(idx).map(|e| e.client_id).unwrap_or(0);
    let tcb_id = regs[0] as u32;
    let user_cap_count = received_user_cap_count(buf);
    if user_cap_count != 1 {
        delete_recv_user_caps(user_cap_count);
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let fault_mp_recv = match move_recv_user_cap_to_stable(0, b"mmsrv fault mp recv") {
        Ok(cap) => cap,
        Err(err) => {
            delete_recv_user_caps(user_cap_count);
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    // fault_mp_recv is OwnedCap; error paths drop it automatically.
    let fault_mp_raw = fault_mp_recv.as_raw();

    let watch_cap = state.watches.alloc();
    if watch_cap == 0 {
        // fault_mp_recv drops here.
        send_reply(buf, uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    }
    // Register the per-TCB fault MP in the fault dispatcher's cookie
    // table. The cookie carries (kind=MMSRV_FAULT_KIND_PER_TCB, slot,
    // live_gen) — when the Watch fires the dispatcher decodes it,
    // looks up the `MmsrvFaultTarget { client_id, tcb_id }` payload,
    // and resolves the matching `FaultEntry` via `find_entry`.
    let cookie = match unsafe {
        state.fault_cookie_table.arm(
            &mut state.segment_allocator,
            crate::main_loop::MMSRV_FAULT_KIND_PER_TCB,
            fault_mp_raw,
            watch_cap,
            crate::main_loop::MmsrvFaultTarget { client_id, tcb_id },
        )
    } {
        Ok(c) => c,
        Err(_) => {
            state.watches.free(watch_cap);
            // fault_mp_recv drops here.
            send_reply(buf, uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
            return;
        }
    };
    let arm_err = watch_pool::arm(watch_cap, fault_mp_raw, state.startup.fault_eq, cookie);
    if arm_err != 0 {
        let (_kind, slot, _gen) = trona_server::event_loop::decode_cookie(cookie);
        let _ = state
            .fault_cookie_table
            .cancel(crate::main_loop::MMSRV_FAULT_KIND_PER_TCB, slot);
        state.watches.free(watch_cap);
        // fault_mp_recv drops here.
        send_reply(buf, arm_err as u64, &[], 0);
        return;
    }

    // Transfer ownership of fault_mp_recv to the FaultEntry.
    // fault.register() takes OwnedCap directly.
    let fault_id = state
        .fault
        .register(client_id, tcb_id, fault_mp_recv, watch_cap, cookie);
    if fault_id.is_none() {
        // fault.register() returned None without consuming fault_mp_recv
        // (contract: register takes ownership only on success).
        // NOTE: fault_mp_recv was consumed by register(); if register()
        // returns None it must have dropped it. Cookie must still be cancelled.
        let (_kind, slot, _gen) = trona_server::event_loop::decode_cookie(cookie);
        let _ = state
            .fault_cookie_table
            .cancel(crate::main_loop::MMSRV_FAULT_KIND_PER_TCB, slot);
        let _ = trona_kernel::invoke::watch_cancel(resolved_cap_ref(watch_cap));
        state.watches.free(watch_cap);
        send_reply(buf, uapi::KERNITE_ERR_INSUFFICIENT_RESOURCES as u64, &[], 0);
        return;
    }
    send_reply(buf, TRONA_OK, &[fault_id.unwrap() as u64], 0);
}

/// Whether `[dst_va, dst_va + mem_size)` lies inside one of the image
/// windows the staged run is allowed to land in. `STACK` is exempt (the
/// stack sits in its own band anchored near the top of user VA and is not
/// part of any image window); other kinds must land in exactly one of
/// `elf_code`, `interpreter`, or `preloaded_dsos`.
///
/// Used by both exec-txn and live staging paths so a loader cannot place
/// arbitrary code in a child's VSpace.
fn image_window_contains(layout: &VmClientLayout, kind: u64, dst_va: u64, mem_size: u64) -> bool {
    if kind == STAGE_IMAGE_KIND_NONE {
        // Generic anon stage — used by the loader's stack-reserve path.
        // Stacks live outside the image windows, so allow.
        return true;
    }
    let Some(end) = dst_va.checked_add(mem_size) else {
        return false;
    };
    let in_window = |base: u64, limit: u64| -> bool {
        base != 0 && limit != 0 && dst_va >= base && end <= limit
    };
    in_window(layout.elf_code_base, layout.elf_code_limit)
        || in_window(layout.interpreter_base, layout.interpreter_limit)
        || in_window(layout.preloaded_base, layout.preloaded_limit)
}

/// `MM_STAGE_IMAGE_REGION(src_client_id, src_region_id_packed,
/// dst_client_id, dst_va, src_offset, file_size, mem_size, prot,
/// flags)` — share an anon MO from the source client's pre-staged
/// region into the destination client's VSpace at `dst_va`. The MO
/// stays owned by mmsrv; both clients' RegionTable entries reference
/// the same `mo_cap`. `file_size` is informational (the staging
/// caller wrote exactly that many bytes; the trailing `mem_size -
/// file_size` is anon zero in the shared MO).
fn handle_stage_image_region(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    // dst is the operate operand: authorized + identified by the invoked
    // control cap.
    let Some(dst_idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    // exec image staging whose source is the caller-provided exec MO takes a
    // separate path: there is no src *client*, so no partner step. The
    // backing is chosen per image_kind (FileBacked text/rodata, COW-clone
    // data, anon bss).
    if regs[8] & STAGE_FLAG_EXEC_MO_SRC != 0 {
        handle_stage_exec_mo_region(buf, regs, state, dst_idx);
        return;
    }
    // A staged run whose source is a caller-provided code MemoryObject
    // (`caps[0]`, an R-X/R-- code MO minted by the bootstrap loader or ldsrv)
    // takes its own path: no src client / partner, and — for a service-spawn
    // with no exec txn — it lands in the destination client's live VM.
    if regs[8] & STAGE_FLAG_PROVIDED_MO != 0 {
        handle_stage_provided_mo_region(buf, regs, state, dst_idx);
        return;
    }
    // Cross-client region stage: the source client is the consumed pending
    // partner recorded by a prior `MM_STAGE_SET_SOURCE` on its control cap.
    let nonce = regs[0];
    let Some(src_idx) = state.clients.consume_partner(nonce) else {
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    };
    // Owner badge stamped onto the staged reservation in the destination VM.
    let dst_client_id = state
        .clients
        .entry(dst_idx)
        .map(|e| e.client_id)
        .unwrap_or(0);
    let src_region_packed = regs[1];
    let dst_va = regs[3];
    let src_offset = regs[4];
    let file_size = regs[5];
    let mem_size = regs[6];
    let prot = regs[7];
    let _flags = regs[8];
    let image_kind = regs[9];

    if mem_size == 0
        || mem_size % KERNITE_PAGE_BYTES != 0
        || dst_va & (KERNITE_PAGE_BYTES - 1) != 0
        || src_offset & (KERNITE_PAGE_BYTES - 1) != 0
        || file_size > mem_size
    {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let src_region_id = RegionId::unpack(src_region_packed);
    let (src_mo_handle, src_mo_offset_bytes, src_region_len_bytes) = {
        let src_vm = state.clients.vm(src_idx).expect("src vm");
        // `region` (slot_get) validates the handle's epoch, so a stale
        // `src_region_id` deterministically misses here.
        let Some(src_region) = (unsafe { src_vm.region(src_region_id) }) else {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        };
        match src_region.backing {
            BackingDescriptor::Anon {
                mo_handle,
                mo_offset,
            } => (
                mo_handle,
                mo_offset as u64 * KERNITE_PAGE_BYTES,
                src_region.length,
            ),
            _ => {
                send_reply(buf, KERNITE_ERR_NOT_SUPPORTED as u64, &[], 0);
                return;
            }
        }
    };
    let src_mo_idx = src_mo_handle.0 as usize;
    // Fetch the raw cap addr once; used for kernel map invocations below.
    let mo_cap_raw = match state.mo_registry.entry(src_mo_idx) {
        Some(e) => e.mo_cap.as_raw(),
        None => {
            send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
            return;
        }
    };
    let final_mo_offset = src_mo_offset_bytes.saturating_add(src_offset);
    let src_region_end = src_mo_offset_bytes.saturating_add(src_region_len_bytes);
    if final_mo_offset.saturating_add(mem_size) > src_region_end {
        send_reply(buf, KERNITE_ERR_OUT_OF_RANGE as u64, &[], 0);
        return;
    }
    let low_flags = _flags & 0xFFFF_FFFF;
    if low_flags
        & !(STAGE_FLAG_EXEC_TXN
            | STAGE_FLAG_STACK
            | (STAGE_GUARD_PAGES_MASK << STAGE_GUARD_PAGES_SHIFT))
        != 0
    {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let exec_txn = low_flags & STAGE_FLAG_EXEC_TXN != 0;
    let is_stack = low_flags & STAGE_FLAG_STACK != 0;
    // A staged stack's guard width travels in the flags word (the loader
    // packs its `guard_pages`); 0 means the layout asked for no guard.
    // Runtime `MM_MMAP` stacks use the default `STACK_GUARD_BYTES`.
    let stack_guard_bytes = if is_stack {
        ((low_flags >> STAGE_GUARD_PAGES_SHIFT) & STAGE_GUARD_PAGES_MASK) * KERNITE_PAGE_BYTES
    } else {
        0
    };
    let txn_id = _flags >> STAGE_FLAG_TXN_ID_SHIFT;
    if txn_id != 0 && !exec_txn {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let dst_vspace = if exec_txn {
        let Some(p) = state.clients.pending_exec(dst_idx) else {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        };
        if p.txn_id != txn_id {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        }
        // The pending layout is the exec-target's planned image windows.
        // Every staged run must land in `elf_code` / `interpreter` /
        // `preloaded_dsos` (or be a stack / anon run, which is exempt), so
        // a misrouted run is rejected before any kernel mapping happens.
        if !image_window_contains(&p.pending_layout, image_kind, dst_va, mem_size) {
            send_reply(buf, LayoutError::HeapMmapOverlap.wire_code(), &[], 0);
            return;
        }
        p.pending_vspace_cap.as_raw()
    } else {
        // Live-VM staging (a service-spawn loader run) uses the client's
        // registered layout; the same image-window rule applies.
        let Some(entry) = state.clients.entry(dst_idx) else {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        };
        if !image_window_contains(&entry.layout, image_kind, dst_va, mem_size) {
            send_reply(buf, LayoutError::HeapMmapOverlap.wire_code(), &[], 0);
            return;
        }
        entry.vspace_cap.as_raw()
    };

    let pages = mem_size / KERNITE_PAGE_BYTES;
    let perms_bits = (KERNITE_PAGE_FLAG_USER as u64)
        | if prot & 0x2 != 0 {
            KERNITE_PAGE_FLAG_WRITABLE as u64
        } else {
            0
        }
        | if prot & 0x4 != 0 {
            KERNITE_PAGE_FLAG_EXECUTABLE as u64
        } else {
            0
        };
    let (region_type, region_image_kind) = if is_stack {
        (REGION_STACK, None)
    } else {
        match image_kind {
            STAGE_IMAGE_KIND_NONE => (REGION_MMAP, None),
            STAGE_IMAGE_KIND_TEXT => (REGION_IMAGE_TEXT, Some(ImageKind::Text)),
            STAGE_IMAGE_KIND_DATA => (REGION_IMAGE_DATA, Some(ImageKind::Data)),
            STAGE_IMAGE_KIND_RODATA => (REGION_SHARED_LIB, Some(ImageKind::RoData)),
            STAGE_IMAGE_KIND_BSS => (REGION_IMAGE_BSS, Some(ImageKind::Bss)),
            _ => {
                send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
                return;
            }
        }
    };
    let region_kind_bits = (kernel_region_kind(region_type) as u64) << 24;
    let count_and_flags = (pages << 32) | perms_bits | region_kind_bits;
    let mo_offset_pages = final_mo_offset / KERNITE_PAGE_BYTES;
    if !state.mo_registry.retain_by_handle(src_mo_idx) {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return;
    }

    let r = trona_kernel::syscall::invoke(
        dst_vspace,
        KERNITE_INV_VSPACE_MAP_MO as u64,
        mo_cap_raw,
        dst_va,
        mo_offset_pages,
        count_and_flags,
    );
    if r.error != 0 || r.value != pages {
        for p in 0..r.value.min(pages) {
            let _ = trona_kernel::syscall::invoke(
                dst_vspace,
                KERNITE_INV_VSPACE_UNMAP as u64,
                dst_va + p * KERNITE_PAGE_BYTES,
                0,
                0,
                0,
            );
        }
        let _ = state
            .mo_registry
            .release_by_handle(src_mo_idx, &mut state.frames);
        let err = if r.error != 0 {
            r.error
        } else {
            KERNITE_ERR_OUT_OF_MEMORY as u64
        };
        send_reply(buf, err, &[], 0);
        return;
    }

    let mut region = staged_region(
        src_mo_handle,
        dst_va,
        pages,
        mo_offset_pages,
        prot,
        region_type,
        region_image_kind,
    );
    let install_outcome = if exec_txn {
        let p = state
            .clients
            .pending_exec_mut(dst_idx)
            .expect("pending_exec gated above");
        // A staged stack carries the same guard band as a runtime stack,
        // reserved in the staged VM it lands in (guard-first, so a failed
        // install rolls back with a single vacate).
        let guard = if is_stack {
            unsafe {
                crate::txn::reserve_stack_guard_if_free(
                    &mut p.staged_vm,
                    dst_va,
                    stack_guard_bytes,
                    dst_client_id as u64,
                    &mut state.self_vm,
                )
            }
        } else {
            Ok(None)
        };
        match guard {
            // Guard slab exhausted (the slot was free): propagate so the
            // map rollback below tears the staged region down rather than
            // landing a stack that silently lost a guard the layout wanted.
            Err(code) => Err(code),
            Ok(guard_id) => {
                region.guard_reservation_id = guard_id;
                match unsafe { p.staged_vm.install_region(region, &mut state.self_vm) } {
                    Ok(rid) => {
                        if let Some(g) = guard_id {
                            if let Some(res) = unsafe { p.staged_vm.reservation_mut(g) } {
                                res.stack_region_id = Some(rid);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        if let Some(g) = guard_id {
                            unsafe { p.staged_vm.vacate_reservation(g) };
                        }
                        // The outer `install_outcome` error path unmaps the
                        // staged range and releases the source MO; just return
                        // the code (the recovered region drops here).
                        Err(e.code())
                    }
                }
            }
        }
    } else {
        let dst_vm = state.clients.vm_mut(dst_idx).expect("dst vm");
        let guard = if is_stack {
            unsafe {
                crate::txn::reserve_stack_guard_if_free(
                    dst_vm,
                    dst_va,
                    stack_guard_bytes,
                    dst_client_id as u64,
                    &mut state.self_vm,
                )
            }
        } else {
            Ok(None)
        };
        match guard {
            // Guard slab exhausted (the slot was free): propagate so the
            // map rollback below tears the staged region down rather than
            // landing a stack that silently lost a guard the layout wanted.
            Err(code) => Err(code),
            Ok(guard_id) => {
                region.guard_reservation_id = guard_id;
                match unsafe { dst_vm.install_region(region, &mut state.self_vm) } {
                    Ok(rid) => {
                        if let Some(g) = guard_id {
                            if let Some(res) = unsafe { dst_vm.reservation_mut(g) } {
                                res.stack_region_id = Some(rid);
                            }
                        }
                        Ok(())
                    }
                    Err(e) => {
                        if let Some(g) = guard_id {
                            unsafe { dst_vm.vacate_reservation(g) };
                        }
                        // The outer `install_outcome` error path unmaps the
                        // staged range and releases the source MO; just return
                        // the code (the recovered region drops here).
                        Err(e.code())
                    }
                }
            }
        }
    };

    if let Err(err_code) = install_outcome {
        for p in 0..pages {
            let _ = trona_kernel::syscall::invoke(
                dst_vspace,
                KERNITE_INV_VSPACE_UNMAP as u64,
                dst_va + p * KERNITE_PAGE_BYTES,
                0,
                0,
                0,
            );
        }
        let _ = state
            .mo_registry
            .release_by_handle(src_mo_idx, &mut state.frames);
        send_reply(buf, err_code, &[], 0);
        return;
    }

    let _ = file_size;
    send_reply(buf, TRONA_OK, &[], 0);
}

/// How `stage_exec_materialize` revalidates the destination after it drops
/// `STATE_LOCK` for the blocking private-page copy, and which VM a staged
/// run lands in.
#[derive(Clone, Copy)]
enum StageReval {
    /// Pending exec transaction target (`staged_vm`): the txn must still be
    /// live on reacquire. `exec_mo` is the txn's exec MO to re-match (the
    /// exec-MO source path); `0` skips the MO match when the source is a
    /// caller-provided cap (`STAGE_FLAG_PROVIDED_MO`) the server holds itself.
    PendingTxn { txn_id: u64, exec_mo: u64 },
    /// Live service-spawn target (`vm_mut`): the destination control-cap epoch
    /// must still hold (the client did not exit / get reused) and its VSpace
    /// must be unchanged.
    LiveVm { epoch: u64 },
}

impl StageReval {
    #[inline]
    fn use_real_vm(&self) -> bool {
        matches!(self, StageReval::LiveVm { .. })
    }

    fn still_valid(&self, state: &ServerState, dst_idx: usize, staged_vspace_raw: u64) -> bool {
        match *self {
            StageReval::LiveVm { epoch } => {
                state.clients.epoch_of(dst_idx) == Some(epoch)
                    && state
                        .clients
                        .entry(dst_idx)
                        .is_some_and(|e| e.vspace_cap.as_raw() == staged_vspace_raw)
            }
            StageReval::PendingTxn { txn_id, exec_mo } => {
                state.clients.pending_exec(dst_idx).is_some_and(|p| {
                    p.txn_id == txn_id
                        && p.pending_vspace_cap.as_raw() == staged_vspace_raw
                        && (exec_mo == 0 || p.exec_mo_cap.as_raw() == exec_mo)
                })
            }
        }
    }
}

/// Apply a staged region's mapping into the destination VM, borrowing
/// `self_vm` disjointly from the destination table: the client's live VM for a
/// provided-MO service-spawn stage (`use_real_vm`), or the pending exec
/// `staged_vm` for an exec transaction. `apply` consumes the plan, so on any
/// failure — including the no-target arm here, before `apply` runs — the plan
/// drops, releasing a FileBacked region's owned attenuated cap; anon / COW
/// registry backings hold no owned cap and are vacated by the caller.
///
/// # Safety
/// Single-threaded server invariant; the caller holds `STATE_LOCK`.
unsafe fn apply_region_into_target(
    plan: crate::txn::MappingPlan,
    state: &mut ServerState,
    dst_idx: usize,
    vspace_raw: u64,
    use_real_vm: bool,
) -> Result<(), u64> {
    let clients = &mut state.clients;
    let self_vm = &mut state.self_vm;
    let vm = if use_real_vm {
        match clients.vm_mut(dst_idx) {
            Some(v) => v,
            None => return Err(KERNITE_ERR_INVALID_OPERATION as u64),
        }
    } else {
        match clients.pending_exec_mut(dst_idx) {
            Some(p) => &mut p.staged_vm,
            None => return Err(KERNITE_ERR_INVALID_OPERATION as u64),
        }
    };
    unsafe { plan.apply(vm, vspace_raw, self_vm) }.map(|_| ())
}

/// Stage one exec image segment whose source is the caller-provided exec
/// MemoryObject (`STAGE_FLAG_EXEC_MO_SRC`), routed by `image_kind`. The
/// segment always lands in the pending exec `staged_vm` — image segments
/// are never stacks, so no guard band is reserved:
///   - Text / RoData: the exec MO sub-range mapped directly as a shared,
///     demand-paged FileBacked region (a dup of the exec MO carries its
///     EXECUTE right, satisfying the kernel's executable map check).
///   - Data: `ceil(filesz/PAGE)` file pages copied into a private writable
///     anon child, the partial last page's tail zeroed, plus a trailing anon
///     BSS region when `memsz` exceeds the file pages.
///   - Bss: a fresh demand-zero anon region.
fn handle_stage_exec_mo_region(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    state: &mut ServerState,
    dst_idx: usize,
) {
    let dst_client_id = state
        .clients
        .entry(dst_idx)
        .map(|e| e.client_id)
        .unwrap_or(0);
    let dst_va = regs[3];
    let src_offset = regs[4];
    let file_size = regs[5];
    let mem_size = regs[6];
    let flags_word = regs[8];
    let image_kind = regs[9];

    if flags_word & STAGE_FLAG_EXEC_TXN == 0
        || mem_size == 0
        || mem_size % KERNITE_PAGE_BYTES != 0
        || dst_va & (KERNITE_PAGE_BYTES - 1) != 0
        || src_offset & (KERNITE_PAGE_BYTES - 1) != 0
        || file_size > mem_size
    {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let txn_id = flags_word >> STAGE_FLAG_TXN_ID_SHIFT;
    let (staged_vspace_raw, exec_mo_raw) = {
        let Some(p) = state.clients.pending_exec(dst_idx) else {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        };
        if p.txn_id != txn_id || p.exec_mo_cap.as_raw() == 0 {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        }
        // exec-txn staging: every staged run must land inside the pending
        // layout's image windows (`elf_code` / `interpreter` /
        // `preloaded_dsos`); rejects misrouted loader runs before any
        // kernel mapping happens.
        if !image_window_contains(&p.pending_layout, image_kind, dst_va, mem_size) {
            send_reply(buf, LayoutError::HeapMmapOverlap.wire_code(), &[], 0);
            return;
        }
        (p.pending_vspace_cap.as_raw(), p.exec_mo_cap.as_raw())
    };

    let materialize = flags_word & STAGE_FLAG_EXEC_MATERIALIZE != 0;
    match image_kind {
        // A page-aligned, read-only TEXT/RODATA run shares the MO zero-copy.
        STAGE_IMAGE_KIND_TEXT | STAGE_IMAGE_KIND_RODATA if !materialize => stage_exec_filebacked(
            buf,
            regs,
            state,
            dst_idx,
            staged_vspace_raw,
            exec_mo_raw,
            false,
        ),
        // A page-shared / non-page-aligned TEXT/RODATA run is copied into a
        // private anon child (the "boundary carve"). The region keeps the
        // kind's type (and thus max_prot), so a materialised TEXT run stays
        // R-X (never writable) even though its backing anon child carries
        // WRITE rights.
        STAGE_IMAGE_KIND_TEXT | STAGE_IMAGE_KIND_RODATA => {
            let region_type = match image_kind {
                STAGE_IMAGE_KIND_TEXT => REGION_IMAGE_TEXT,
                _ => REGION_SHARED_LIB,
            };
            stage_exec_materialize(
                buf,
                regs,
                dst_idx,
                dst_client_id,
                staged_vspace_raw,
                exec_mo_raw,
                region_type,
                StageReval::PendingTxn {
                    txn_id,
                    exec_mo: exec_mo_raw,
                },
            )
        }
        // A writable DATA run is a private `MO_CLONE_RANGE` COW child of the
        // exec MO, mapped R-W. mmsrv holds READ on the source and WRITE on
        // the child, so the parent's EXECUTE does not taint the writable
        // child. The kernel's fault-path COW break handles borrowed-frames
        // parents.
        STAGE_IMAGE_KIND_DATA => stage_exec_cow_data(
            buf,
            regs,
            dst_idx,
            dst_client_id,
            staged_vspace_raw,
            exec_mo_raw,
            StageReval::PendingTxn {
                txn_id,
                exec_mo: exec_mo_raw,
            },
        ),
        STAGE_IMAGE_KIND_BSS => {
            stage_exec_bss(buf, regs, dst_idx, dst_client_id, staged_vspace_raw, false)
        }
        _ => send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0),
    }
}

/// Stage one image segment whose source is a caller-provided code MemoryObject
/// (`STAGE_FLAG_PROVIDED_MO`, transferred as `caps[0]`), routed by `image_kind`
/// exactly like the exec-MO path. With no exec txn (a service-spawn) the run
/// lands in the destination client's live VM + VSpace; with `STAGE_FLAG_EXEC_TXN`
/// (an execve interpreter staged inside a replace txn) it lands in the pending
/// `staged_vm`, same as the exec-MO source path. The region keeps an attenuated
/// dup of the code MO (text `R-X`, rodata `R--`), so W^X holds by construction;
/// the captured transfer is released once staging has taken that dup.
fn handle_stage_provided_mo_region(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    state: &mut ServerState,
    dst_idx: usize,
) {
    let dst_va = regs[3];
    let src_offset = regs[4];
    let file_size = regs[5];
    let mem_size = regs[6];
    let flags_word = regs[8];
    let image_kind = regs[9];

    // Capture the transferred code MO (caps[0]) up front so every later error
    // path simply drops the OwnedCap, freeing the received slot. The per-run
    // attenuated dup taken by staging is what actually backs the region.
    let Ok(provided_mo) = move_recv_user_cap_to_stable(0, b"mmsrv provided code mo") else {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    };
    let provided_mo_raw = provided_mo.as_raw();

    if mem_size == 0
        || mem_size % KERNITE_PAGE_BYTES != 0
        || dst_va & (KERNITE_PAGE_BYTES - 1) != 0
        || src_offset & (KERNITE_PAGE_BYTES - 1) != 0
        || file_size > mem_size
    {
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }

    let exec_txn = flags_word & STAGE_FLAG_EXEC_TXN != 0;
    let use_real_vm = !exec_txn;
    let txn_id = flags_word >> STAGE_FLAG_TXN_ID_SHIFT;

    let dst_client_id = match state.clients.entry(dst_idx) {
        Some(e) => e.client_id,
        None => {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        }
    };

    // Pick the destination VSpace + the post-lock revalidation: the pending
    // exec VSpace for an interpreter inside a live replace txn, else the
    // client's live VSpace for a service-spawn. In both cases every staged
    // run must land inside the layout's image windows; this is the same
    // check the cross-client and EXEC_MO_SRC paths apply.
    let (target_vspace_raw, reval) = if exec_txn {
        match state.clients.pending_exec(dst_idx) {
            Some(p) if p.txn_id == txn_id && p.pending_vspace_cap.as_raw() != 0 => {
                if !image_window_contains(&p.pending_layout, image_kind, dst_va, mem_size) {
                    send_reply(buf, LayoutError::HeapMmapOverlap.wire_code(), &[], 0);
                    return;
                }
                (
                    p.pending_vspace_cap.as_raw(),
                    StageReval::PendingTxn { txn_id, exec_mo: 0 },
                )
            }
            _ => {
                send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
                return;
            }
        }
    } else {
        let Some(epoch) = state.clients.epoch_of(dst_idx) else {
            send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
            return;
        };
        match state.clients.entry(dst_idx) {
            Some(e) if e.vspace_cap.as_raw() != 0 => {
                if !image_window_contains(&e.layout, image_kind, dst_va, mem_size) {
                    send_reply(buf, LayoutError::HeapMmapOverlap.wire_code(), &[], 0);
                    return;
                }
                (e.vspace_cap.as_raw(), StageReval::LiveVm { epoch })
            }
            _ => {
                send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
                return;
            }
        }
    };

    let materialize = flags_word & STAGE_FLAG_EXEC_MATERIALIZE != 0;
    match image_kind {
        STAGE_IMAGE_KIND_TEXT | STAGE_IMAGE_KIND_RODATA if !materialize => stage_exec_filebacked(
            buf,
            regs,
            state,
            dst_idx,
            target_vspace_raw,
            provided_mo_raw,
            use_real_vm,
        ),
        STAGE_IMAGE_KIND_TEXT | STAGE_IMAGE_KIND_RODATA => {
            let region_type = match image_kind {
                STAGE_IMAGE_KIND_TEXT => REGION_IMAGE_TEXT,
                _ => REGION_SHARED_LIB,
            };
            stage_exec_materialize(
                buf,
                regs,
                dst_idx,
                dst_client_id,
                target_vspace_raw,
                provided_mo_raw,
                region_type,
                reval,
            )
        }
        STAGE_IMAGE_KIND_DATA => stage_exec_cow_data(
            buf,
            regs,
            dst_idx,
            dst_client_id,
            target_vspace_raw,
            provided_mo_raw,
            reval,
        ),
        STAGE_IMAGE_KIND_BSS => stage_exec_bss(
            buf,
            regs,
            dst_idx,
            dst_client_id,
            target_vspace_raw,
            use_real_vm,
        ),
        _ => send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0),
    }

    // The region took its own attenuated dup of the code MO; drop the captured
    // transfer so only the region's rights-narrowed cap survives.
    drop(provided_mo);
}

/// Text / RoData exec segment: map the exec MO sub-range directly as a
/// shared, demand-paged `FileBacked` region. The region owns an attenuated dup
/// of the exec MO cap — `R-X` for text, read-only (no EXECUTE) for rodata — which
/// both backs the region for its lifetime and is the cap the kernel maps, so the
/// cap-derived ceiling enforces W^X. GRANT is retained so a fork after exec can
/// re-derive this region cap via `cnode_copy`.
fn stage_exec_filebacked(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    state: &mut ServerState,
    dst_idx: usize,
    staged_vspace_raw: u64,
    exec_mo_raw: u64,
    use_real_vm: bool,
) {
    let dst_va = regs[3];
    let src_offset = regs[4];
    let file_size = regs[5];
    let mem_size = regs[6];
    let prot = regs[7];
    let image_kind = regs[9];

    let pages = mem_size / KERNITE_PAGE_BYTES;
    let src_offset_pages = src_offset / KERNITE_PAGE_BYTES;
    let region_type = if image_kind == STAGE_IMAGE_KIND_TEXT {
        REGION_IMAGE_TEXT
    } else {
        REGION_SHARED_LIB
    };

    // Attenuate the region's durable backing cap to its kind so the kernel's
    // cap-derived ceiling enforces W^X by construction: text keeps R-X; read-only
    // data drops EXECUTE, so a later mprotect(+X) on it is refused. GRANT is kept
    // so a post-exec fork can re-derive the region cap via cnode_copy. (EXECUTE on
    // a text region requires the exec MO to already be execute-bearing.)
    let mo_rights = if region_type == REGION_IMAGE_TEXT {
        (KERNITE_RIGHT_READ | KERNITE_RIGHT_EXECUTE | KERNITE_RIGHT_GRANT | KERNITE_RIGHT_TRANSFER)
            as u64
    } else {
        (KERNITE_RIGHT_READ | KERNITE_RIGHT_GRANT | KERNITE_RIGHT_TRANSFER) as u64
    };
    let Some(dup_raw) = crate::txn::dup_cap_with_rights(exec_mo_raw, mo_rights) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    // SAFETY: the attenuated dup is a fresh copy of the exec MO cap into a new
    // global slot; this OwnedCap is its sole owner and backs the region.
    let owned = unsafe { trona_runtime::core::slot_alloc::OwnedCap::adopt_received(dup_raw) };
    let map_cap = owned.as_raw();
    let plan = crate::txn::MappingPlan {
        va_base: dst_va,
        pages,
        prot: prot as u8,
        region_type,
        lazy: false,
        mo_cap: map_cap,
        mo_offset_pages: src_offset_pages,
        eager_commit: false,
        fork_policy: ForkPolicy::InheritShare,
        backing: BackingDescriptor::FileBacked {
            mo_cap: owned,
            mo_offset: src_offset_pages as u32,
            file_id0: 0,
            file_id1: 0,
            file_offset: src_offset,
            file_size,
            backing_kind: 0,
            writeback: false,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    // apply consumes the plan and, on failure, unmaps + drops the recovered
    // region (freeing the dup'd cap), so the error arm has nothing more to
    // release. `use_real_vm` routes the run into the live service-spawn VM
    // (provided-MO, no exec txn) or the pending exec `staged_vm`.
    match unsafe { apply_region_into_target(plan, state, dst_idx, staged_vspace_raw, use_real_vm) }
    {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    }
}

/// Stage a fresh demand-zero anonymous region of `pages` pages at `va`
/// into the pending exec `staged_vm`. Shared by the Bss segment kind, a
/// pure-BSS Data segment (`file_size == 0`), and the trailing BSS of a
/// Data segment. Uses `state_mut()` so it composes with the Data path's
/// post-lock-dance state handling. On failure the anon MO is reclaimed
/// (`install` failure needs none — `alloc_slot` does not reserve).
fn stage_exec_anon_region(
    dst_idx: usize,
    dst_client_id: u32,
    staged_vspace_raw: u64,
    va: u64,
    pages: u64,
    prot: u64,
    region_type: u8,
    use_real_vm: bool,
) -> Result<(), u64> {
    let state = crate::main_loop::state_mut();
    let Some(mo_idx) = state.mo_registry.alloc_slot() else {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let Some(mo_cap) = state.mo_registry.install(
        mo_idx,
        pages * KERNITE_PAGE_BYTES,
        dst_client_id,
        MoKind::Anon,
        &mut state.frames,
    ) else {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as u64);
    };
    let plan = crate::txn::MappingPlan {
        va_base: va,
        pages,
        prot: prot as u8,
        region_type,
        lazy: false,
        mo_cap,
        mo_offset_pages: 0,
        eager_commit: false,
        fork_policy: ForkPolicy::InheritCow,
        backing: BackingDescriptor::Anon {
            mo_handle: MoHandle(mo_idx as u32),
            mo_offset: 0,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    match unsafe { apply_region_into_target(plan, state, dst_idx, staged_vspace_raw, use_real_vm) }
    {
        Ok(()) => Ok(()),
        Err(code) => {
            state.mo_registry.vacate(mo_idx, &mut state.frames);
            Err(code)
        }
    }
}

/// Bss exec segment: a fresh anonymous, demand-zero region in the staged VM.
fn stage_exec_bss(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    dst_idx: usize,
    dst_client_id: u32,
    staged_vspace_raw: u64,
    use_real_vm: bool,
) {
    let dst_va = regs[3];
    let pages = regs[6] / KERNITE_PAGE_BYTES;
    let prot = regs[7];
    match stage_exec_anon_region(
        dst_idx,
        dst_client_id,
        staged_vspace_raw,
        dst_va,
        pages,
        prot,
        REGION_IMAGE_BSS,
        use_real_vm,
    ) {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => send_reply(buf, code, &[], 0),
    }
}

fn copy_file_pages_into_private_mo(
    buf: *mut kernite_ipc_buffer,
    src_mo_raw: u64,
    child_cap: u64,
    src_offset: u64,
    file_size: u64,
    file_pages: u64,
) -> Result<(), u64> {
    if KERNITE_PAGE_BYTES as usize > core::mem::size_of::<kernite_ipc_buffer>() {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as u64);
    }

    let mut remaining = file_size;
    for page in 0..file_pages {
        let read_len = core::cmp::min(remaining, KERNITE_PAGE_BYTES);
        // SAFETY: `buf` is this mmsrv thread's mapped IPC buffer. The caller
        // has already copied all request fields it needs, and replies rewrite
        // the buffer after this helper returns.
        unsafe { core::ptr::write_bytes(buf as *mut u8, 0, KERNITE_PAGE_BYTES as usize) };

        if read_len != 0 {
            let read = trona_kernel::syscall::invoke(
                src_mo_raw,
                KERNITE_INV_MO_READ as u64,
                src_offset + page * KERNITE_PAGE_BYTES,
                read_len,
                0,
                0,
            );
            if read.error != 0 {
                return Err(read.error);
            }
            if read.value != read_len {
                return Err(KERNITE_ERR_INVALID_OPERATION as u64);
            }
        }

        let write = trona_kernel::syscall::invoke(
            child_cap,
            KERNITE_INV_MO_WRITE as u64,
            page * KERNITE_PAGE_BYTES,
            KERNITE_PAGE_BYTES,
            0,
            0,
        );
        if write.error != 0 {
            return Err(write.error);
        }
        if write.value != KERNITE_PAGE_BYTES {
            return Err(KERNITE_ERR_INVALID_OPERATION as u64);
        }

        remaining -= read_len;
    }
    Ok(())
}

/// Materialise an exec run as a PRIVATE copy: copy `ceil(filesz/PAGE)` file
/// pages from the exec MO into a private writable anon child, zeroing the
/// partial last page's tail (ELF semantics: bytes past `file_size` read as
/// zero), then stage a trailing anon BSS region for `memsz` beyond the file
/// pages.
///
/// Used for a Data segment, but also for any TEXT / RODATA run that cannot be
/// mapped shared zero-copy — a run that is page-shared by segments with
/// different protections or starts / ends mid-page. `region_type` is the kind
/// of the file-backed part (`REGION_IMAGE_TEXT` / `REGION_SHARED_LIB` /
/// `REGION_IMAGE_DATA`); it sets the region's `max_prot`, so a materialised
/// TEXT run stays non-writable even though its backing anon child holds WRITE.
/// The trailing BSS is always `REGION_IMAGE_BSS`.
///
/// Takes only Copy values: the `MO_READ` / `MO_WRITE` copy can page through the
/// file pager and block, so it MUST run with `STATE_LOCK` released (else
/// mmsrv's fault dispatcher — which the pager read may need — cannot make
/// progress). The caller's `&mut ServerState` borrow is therefore dropped
/// before this runs; state is re-derived via `state_mut()` and the txn
/// revalidated once the lock is reacquired.
fn stage_exec_materialize(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    dst_idx: usize,
    dst_client_id: u32,
    staged_vspace_raw: u64,
    exec_mo_raw: u64,
    region_type: u8,
    reval: StageReval,
) {
    let use_real_vm = reval.use_real_vm();
    let dst_va = regs[3];
    let src_offset = regs[4];
    let file_size = regs[5];
    let mem_size = regs[6];
    let prot = regs[7];

    let file_pages = file_size.div_ceil(KERNITE_PAGE_BYTES);
    let total_pages = mem_size / KERNITE_PAGE_BYTES;

    if file_pages == 0 {
        // Pure BSS (filesz == 0): no file pages to copy, so the whole
        // segment is demand-zero anon. (The caller normally classifies this
        // as Bss, but a writable PT_LOAD with p_filesz == 0 lands here too.)
        match stage_exec_anon_region(
            dst_idx,
            dst_client_id,
            staged_vspace_raw,
            dst_va,
            total_pages,
            prot,
            REGION_IMAGE_BSS,
            use_real_vm,
        ) {
            Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
            Err(code) => send_reply(buf, code, &[], 0),
        }
        return;
    }

    // With STATE_LOCK held: retype the private child and hold a read-cap dup of
    // the source so it stays valid while the copy runs with STATE_LOCK dropped.
    let state = crate::main_loop::state_mut();
    let Some(child_idx) = state.mo_registry.alloc_slot() else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    let Some(child_cap) = state.mo_registry.install(
        child_idx,
        file_pages * KERNITE_PAGE_BYTES,
        dst_client_id,
        MoKind::Anon,
        &mut state.frames,
    ) else {
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    let Some(src_copy_raw) =
        crate::txn::dup_cap_with_rights(exec_mo_raw, KERNITE_RIGHT_READ as u64)
    else {
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
        return;
    };
    // SAFETY: `dup_cap_with_rights` returned a fresh global allocator slot
    // containing the source MO dup; this OwnedCap is its sole owner.
    let src_copy =
        unsafe { trona_runtime::core::slot_alloc::OwnedCap::adopt_received(src_copy_raw) };

    crate::main_loop::state_lock_release();
    let copy = copy_file_pages_into_private_mo(
        buf,
        src_copy.as_raw(),
        child_cap,
        src_offset,
        file_size,
        file_pages,
    );
    crate::main_loop::state_lock_acquire();
    drop(src_copy);

    let state = crate::main_loop::state_mut();
    if let Err(code) = copy {
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, code, &[], 0);
        return;
    }
    if !reval.still_valid(state, dst_idx, staged_vspace_raw) {
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    }

    // With STATE_LOCK held again, publish the materialized file region.
    let data_plan = crate::txn::MappingPlan {
        va_base: dst_va,
        pages: file_pages,
        prot: prot as u8,
        region_type,
        lazy: false,
        mo_cap: child_cap,
        mo_offset_pages: 0,
        eager_commit: false,
        fork_policy: ForkPolicy::InheritCow,
        backing: BackingDescriptor::Anon {
            mo_handle: MoHandle(child_idx as u32),
            mo_offset: 0,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    if let Err(code) = unsafe {
        apply_region_into_target(data_plan, state, dst_idx, staged_vspace_raw, use_real_vm)
    } {
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, code, &[], 0);
        return;
    }

    // Trailing BSS pages (memsz beyond the file pages): a fresh demand-zero
    // anon region. For a pending exec txn a failure here aborts the txn (the
    // caller tears the staged VM down), so the published Data region needs no
    // unwind; a live service-spawn has no such safety net, so a failed trailing
    // BSS must roll the already-published Data region back out of the live VM.
    let bss_pages = total_pages - file_pages;
    if bss_pages == 0 {
        send_reply(buf, TRONA_OK, &[], 0);
        return;
    }
    let bss_va = dst_va + file_pages * KERNITE_PAGE_BYTES;
    match stage_exec_anon_region(
        dst_idx,
        dst_client_id,
        staged_vspace_raw,
        bss_va,
        bss_pages,
        prot,
        REGION_IMAGE_BSS,
        use_real_vm,
    ) {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => {
            if use_real_vm {
                let state = crate::main_loop::state_mut();
                if let Some(vm) = state.clients.vm_mut(dst_idx) {
                    let _ = unsafe {
                        crate::txn::unmap(
                            vm,
                            dst_va,
                            file_pages,
                            staged_vspace_raw,
                            &mut state.self_vm,
                            &mut state.mo_registry,
                            &mut state.frames,
                        )
                    };
                }
            }
            send_reply(buf, code, &[], 0);
        }
    }
}

/// Stage a writable Data run as a private `MO_CLONE_RANGE` copy-on-write
/// child of the exec MO, mapped R-W into the destination.
///
/// Mirrors `stage_exec_filebacked` (the shared-RO text path) but binds a
/// `MO_CLONE_RANGE` child instead of mapping the source shared. mmsrv
/// holds `READ` on the source and `WRITE` on the child, so the parent's
/// `EXECUTE` does not taint the writable child. The kernel's fault-path
/// COW break (`mm/vspace.rs`) handles borrowed-frames parents; on a first
/// write it allocates a fresh MoData frame, byte-copies the borrowed
/// source content, and commits the private frame on the child — leaving
/// the borrowed frame in place.
///
/// Trailing BSS pages (`memsz > file_pages`) are emitted as a fresh
/// demand-zero anon region, matching `stage_exec_materialize`.
fn stage_exec_cow_data(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    dst_idx: usize,
    dst_client_id: u32,
    staged_vspace_raw: u64,
    exec_mo_raw: u64,
    reval: StageReval,
) {
    let use_real_vm = reval.use_real_vm();
    let dst_va = regs[3];
    let src_offset = regs[4];
    let file_size = regs[5];
    let mem_size = regs[6];
    let prot = regs[7];

    let file_pages = file_size.div_ceil(KERNITE_PAGE_BYTES);
    let total_pages = mem_size / KERNITE_PAGE_BYTES;

    // Pure BSS (file_size == 0): no file pages, so the whole segment is
    // demand-zero anon. (A writable PT_LOAD with p_filesz == 0 lands here.)
    if file_pages == 0 {
        match stage_exec_anon_region(
            dst_idx,
            dst_client_id,
            staged_vspace_raw,
            dst_va,
            total_pages,
            prot,
            REGION_IMAGE_BSS,
            use_real_vm,
        ) {
            Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
            Err(code) => send_reply(buf, code, &[], 0),
        }
        return;
    }

    let mo_offset_pages = src_offset / KERNITE_PAGE_BYTES;

    // With STATE_LOCK held: retype the private child MO and provision the
    // per-tree state `S`. mmsrv holds READ on the source (exec MO) and
    // WRITE on the child. `S` is reaped by its drop either way — bind on
    // a standalone parent, ignore+drop on an already-bound parent.
    let (child_idx, child_cap, s_cap) = {
        let state = crate::main_loop::state_mut();
        let Some(child_idx) = state.mo_registry.alloc_slot() else {
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        let Some(child_cap) = state.mo_registry.install(
            child_idx,
            file_pages * KERNITE_PAGE_BYTES,
            dst_client_id,
            MoKind::Anon,
            &mut state.frames,
        ) else {
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        let Some(s_cap) = crate::mmap::alloc_vm_hierarchy_state(&mut state.frames) else {
            state.mo_registry.vacate(child_idx, &mut state.frames);
            send_reply(buf, KERNITE_ERR_OUT_OF_MEMORY as u64, &[], 0);
            return;
        };
        (child_idx, child_cap, s_cap)
    };

    // Bind the child as a sub-range COW clone of the source. The kernel
    // owns the COW topology; mmsrv drops `S` immediately after.
    let clone = trona_kernel::syscall::invoke(
        exec_mo_raw,
        uapi::KERNITE_INV_MO_CLONE_RANGE as u64,
        child_cap,
        mo_offset_pages,
        file_pages,
        s_cap.as_raw(),
    );
    drop(s_cap);
    if clone.error != 0 {
        let state = crate::main_loop::state_mut();
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, clone.error as u64, &[], 0);
        return;
    }

    // Re-validate the destination under STATE_LOCK (matches materialize).
    let state = crate::main_loop::state_mut();
    if !reval.still_valid(state, dst_idx, staged_vspace_raw) {
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    }

    // Publish the COW child as a mapped region. The kernel's `VSPACE_MAP_MO`
    // sees `is_cloned = !cow_parent.is_null()` and installs COW PTEs for
    // inherited parent frames (syscall/vspace.rs:3467-3543). The child MO
    // is sized to the run, so `mo_offset = 0` and `pages = file_pages`.
    let data_plan = crate::txn::MappingPlan {
        va_base: dst_va,
        pages: file_pages,
        prot: prot as u8,
        region_type: REGION_IMAGE_DATA,
        lazy: false,
        mo_cap: child_cap,
        mo_offset_pages: 0,
        eager_commit: false,
        fork_policy: ForkPolicy::InheritCow,
        backing: BackingDescriptor::Anon {
            mo_handle: MoHandle(child_idx as u32),
            mo_offset: 0,
        },
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    };
    if let Err(code) = unsafe {
        apply_region_into_target(data_plan, state, dst_idx, staged_vspace_raw, use_real_vm)
    } {
        state.mo_registry.vacate(child_idx, &mut state.frames);
        send_reply(buf, code, &[], 0);
        return;
    }

    // Trailing BSS: a fresh demand-zero anon region (matches materialize).
    let bss_pages = total_pages - file_pages;
    if bss_pages == 0 {
        send_reply(buf, TRONA_OK, &[], 0);
        return;
    }
    let bss_va = dst_va + file_pages * KERNITE_PAGE_BYTES;
    match stage_exec_anon_region(
        dst_idx,
        dst_client_id,
        staged_vspace_raw,
        bss_va,
        bss_pages,
        prot,
        REGION_IMAGE_BSS,
        use_real_vm,
    ) {
        Ok(()) => send_reply(buf, TRONA_OK, &[], 0),
        Err(code) => {
            if use_real_vm {
                if let Some(vm) = state.clients.vm_mut(dst_idx) {
                    let _ = unsafe {
                        crate::txn::unmap(
                            vm,
                            dst_va,
                            file_pages,
                            staged_vspace_raw,
                            &mut state.self_vm,
                            &mut state.mo_registry,
                            &mut state.frames,
                        )
                    };
                }
            }
            send_reply(buf, code, &[], 0);
        }
    }
}

#[inline]
fn staged_region(
    mo_handle: MoHandle,
    base: u64,
    pages: u64,
    mo_offset_pages: u64,
    prot: u64,
    region_type: u8,
    image_kind: Option<ImageKind>,
) -> MappedRegion {
    let backing = match image_kind {
        Some(image_kind) => BackingDescriptor::Image {
            mo_handle,
            mo_offset: mo_offset_pages as u32,
            image_kind,
        },
        None => BackingDescriptor::Anon {
            mo_handle,
            mo_offset: mo_offset_pages as u32,
        },
    };
    // Exec image text / rodata is shared into a child on fork; writable
    // image (data / bss) and bare anon staging are COW-forked.
    let fork_policy = match image_kind {
        Some(ImageKind::Text) | Some(ImageKind::RoData) => ForkPolicy::InheritShare,
        _ => ForkPolicy::InheritCow,
    };
    MappedRegion {
        base,
        length: pages * KERNITE_PAGE_BYTES,
        prot: prot as u8,
        max_prot: max_prot_for_region_type(region_type),
        region_type,
        fork_policy,
        lazy: false,
        backing,
        reservation: None,
        stack_allocator_badge: 0,
        guard_reservation_id: None,
    }
}

/// Unmap every active region in `regions` from `vspace_cap` and
/// release the matching mmsrv-side ownership. Used by exec
/// transaction commit / abort and by client deregistration.
fn teardown_regions(
    vm: &ClientVm,
    vspace_cap: u64,
    mo_registry: &mut MoRegistry,
    frames: &mut FrameAllocator,
) {
    if vspace_cap == 0 {
        return;
    }
    for (_, region) in unsafe { vm.iter_regions() } {
        let pages = region.length / KERNITE_PAGE_BYTES;
        for p in 0..pages {
            let _ = trona_kernel::syscall::invoke(
                vspace_cap,
                KERNITE_INV_VSPACE_UNMAP as u64,
                region.base + p * KERNITE_PAGE_BYTES,
                0,
                0,
                0,
            );
        }
        match &region.backing {
            // mmsrv-owned registry MOs (anon, forked COW child, image
            // segment): drop the registry refcount, which frees the
            // backing frames when it hits zero. The cap itself is owned
            // by the registry entry, not by the region — no cap free here.
            BackingDescriptor::Anon { mo_handle, .. }
            | BackingDescriptor::CowChild { mo_handle, .. }
            | BackingDescriptor::Image { mo_handle, .. } => {
                let _ = mo_registry.release_by_handle(mo_handle.0 as usize, frames);
            }
            // File-backed and SHM: the mo_cap is an OwnedCap embedded in
            // the slab entry. It will be dropped when the ClientVm slab
            // releases this region entry (drop_in_place). No explicit cap
            // free needed here — only the frame accounting needs attention.
            BackingDescriptor::FileBacked { .. } => {}
            BackingDescriptor::Shm { shm_idx, .. } => {
                if let Ok(idx) = usize::try_from(*shm_idx) {
                    let _ = mo_registry.dec_map_count(idx, frames);
                }
            }
            BackingDescriptor::Device { .. } => {}
        }
    }
}

/// `MM_BEGIN_EXEC_REPLACE(client_id_from_badge, layout; caps=[new_vspace,
/// exec_mo])` — open an exec transaction. Returns `txn_id` to the caller;
/// subsequent `MM_STAGE_IMAGE_REGION(STAGE_FLAG_EXEC_TXN, txn_id)` calls
/// land in the pending VSpace, and `MM_COMMIT_EXEC_REPLACE` swaps it in.
/// `regs[0..12]` carry the new image's `VmClientLayout` (heap/mmap/dso
/// plus the three image windows for staging validation).
fn handle_begin_exec_replace(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    let Some(idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    let layout = VmClientLayout {
        heap_base: regs[0],
        heap_limit: regs[1],
        mmap_base: regs[2],
        mmap_limit: regs[3],
        dso_base: regs[4],
        dso_limit: regs[5],
        elf_code_base: regs[6],
        elf_code_limit: regs[7],
        interpreter_base: regs[8],
        interpreter_limit: regs[9],
        preloaded_base: regs[10],
        preloaded_limit: regs[11],
    };
    if let Err(err) = layout.validate() {
        send_reply(buf, err.wire_code(), &[], 0);
        return;
    }
    let user_cap_count = received_user_cap_count(buf);
    if user_cap_count != 2 {
        delete_recv_user_caps(user_cap_count);
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let new_vspace = match move_recv_user_cap_to_stable(0, b"mmsrv exec vspace") {
        Ok(cap) => cap,
        Err(err) => {
            delete_recv_user_caps(user_cap_count);
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    let exec_mo = match move_recv_user_cap_to_stable(1, b"mmsrv exec mo") {
        Ok(cap) => cap,
        Err(err) => {
            delete_recv_user_caps(user_cap_count);
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    let Some(txn_id) = state
        .clients
        .begin_exec_txn(idx, new_vspace, exec_mo, layout)
    else {
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    };
    send_reply(buf, TRONA_OK, &[txn_id], 0);
}

/// `MM_COMMIT_EXEC_REPLACE(client_id, txn_id)` — atomic VSpace swap +
/// pre-exec region teardown.
fn handle_commit_exec_replace(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    let Some(idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    let txn_id = regs[0];
    let Some((old_vspace, mut old_vm)) = state.clients.commit_exec_txn(idx, txn_id) else {
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    };
    // old_vspace is OwnedCap — pass raw addr to teardown; it drops at end of scope.
    teardown_regions(
        &old_vm,
        old_vspace.as_raw(),
        &mut state.mo_registry,
        &mut state.frames,
    );
    unsafe {
        old_vm.release(&mut state.self_vm);
    }
    // old_vspace OwnedCap drops here (delete-and-free).
    send_reply(buf, TRONA_OK, &[], 0);
}

/// `MM_ABORT_EXEC_REPLACE(client_id, txn_id)` — drop the staged image
/// and release the pending VSpace + regions.
fn handle_abort_exec_replace(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    let Some(idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    let txn_id = regs[0];
    let Some((pending_vspace, mut pending_vm)) = state.clients.abort_exec_txn(idx, txn_id) else {
        send_reply(buf, KERNITE_ERR_INVALID_OPERATION as u64, &[], 0);
        return;
    };
    // pending_vspace is OwnedCap — pass raw addr to teardown; it drops at end of scope.
    teardown_regions(
        &pending_vm,
        pending_vspace.as_raw(),
        &mut state.mo_registry,
        &mut state.frames,
    );
    unsafe {
        pending_vm.release(&mut state.self_vm);
    }
    // pending_vspace OwnedCap drops here (delete-and-free).
    send_reply(buf, TRONA_OK, &[], 0);
}

/// `MM_FORK_SET_PARTNER(nonce)` / `MM_STAGE_SET_SOURCE(nonce)` — step 1 of
/// a two-operand admin verb. The secondary operand's own control cap is
/// invoked; the server records it as the pending partner so the matching
/// operate step (`FORK_VSPACE` / `STAGE_IMAGE_REGION`) on the primary's
/// control cap can pin it. A fresh call overwrites any stale pending.
fn handle_set_partner(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) {
    let Some(secondary_idx) = resolve_control_or_reject(buf, badge, state) else {
        return;
    };
    let nonce = regs[0];
    state.clients.set_partner(secondary_idx, nonce);
    send_reply(buf, TRONA_OK, &[], 0);
}

pub fn dispatch_init(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64; 32],
    badge: u64,
    state: &mut ServerState,
) -> bool {
    let _ = KERNITE_ERR_INVALID_OPERATION;
    match label {
        LABEL_REGISTER_CLIENT => handle_register_client(buf, regs, badge, state),
        LABEL_DEREGISTER_CLIENT => handle_deregister_client(buf, regs, badge, state),
        LABEL_FORK_VSPACE => handle_fork_vspace(buf, regs, badge, state),
        LABEL_REGISTER_FAULT_PIPE => handle_register_fault_pipe(buf, regs, badge, state),
        LABEL_STAGE_IMAGE_REGION => handle_stage_image_region(buf, regs, badge, state),
        LABEL_FORK_SET_PARTNER => handle_set_partner(buf, regs, badge, state),
        LABEL_STAGE_SET_SOURCE => handle_set_partner(buf, regs, badge, state),
        LABEL_BEGIN_EXEC_REPLACE => handle_begin_exec_replace(buf, regs, badge, state),
        LABEL_COMMIT_EXEC_REPLACE => handle_commit_exec_replace(buf, regs, badge, state),
        LABEL_ABORT_EXEC_REPLACE => handle_abort_exec_replace(buf, regs, badge, state),
        // Bootstrap-bind exception in the 0x40x range — gated by
        // matching `client_id`, not `INIT_PRIV_BADGE`.
        LABEL_BIND_CLIENT_SELF => handle_bind_client_self(buf, badge, state),
        _ => return false,
    }
    true
}

/// `MM_REGISTER_VFS_PAGER(; caps=[pager_cap, writeback_mp_send])` — vfs
/// registers its `OBJ_PAGER` cap and explicit writeback request channel with
/// mmsrv. Self-tier label, first-write-wins.
/// The caller arrives on its own per-client MP (cookie identifies
/// the client_idx); we do not validate which client_id the caller
/// is — the cap topology guarantees only one process at a time can
/// usefully serve as the file-backed pager and the cap stored here
/// is whatever they passed. Subsequent calls return
/// `KERNITE_ERR_ALREADY_EXISTS` so a misbehaving second client
/// cannot hijack the slot.
///
/// Once registered, every `MM_FILE_MMAP` invokes
/// `MO_ATTACH_PAGER(mo_cap, vfs_pager_cap_slot)` so the kernel
/// routes file-backed page faults through vfs's bound EventQueue
/// instead of mmsrv's fault dispatcher.
///
/// Security model: boot-order **plus** owner-identity check. vfs is
/// the only client that can reach `MM_REGISTER_VFS_PAGER` before any
/// `MM_FILE_MMAP` fires — init's manifest topology orders vfs spawn
/// after mmsrv but before every fileops-using process. The
/// first-write-wins gate plus the boot order means a hostile late
/// client cannot supplant vfs's pager. On registration mmsrv stamps
/// the caller's `client_idx` into `vfs_pager_owner_client_idx` so
/// `MM_FILE_MMAP` can refuse non-owner callers — boot-order alone
/// does not stop a hostile fileops-using client from issuing
/// `MM_FILE_MMAP` directly with the registered pager.
fn handle_register_vfs_pager(
    buf: *mut kernite_ipc_buffer,
    client_idx: u32,
    state: &mut ServerState,
) {
    let user_cap_count = received_user_cap_count(buf);
    if user_cap_count != 2 {
        delete_recv_user_caps(user_cap_count);
        send_reply(buf, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    if state.vfs_pager_cap_slot != 0 {
        delete_recv_user_caps(user_cap_count);
        send_reply(buf, KERNITE_ERR_ALREADY_EXISTS as u64, &[], 0);
        return;
    }
    let stable = match move_recv_user_cap_to_stable(0, b"mmsrv vfs pager cap") {
        Ok(slot) => slot,
        Err(err) => {
            delete_recv_user_caps(user_cap_count);
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    let writeback = match move_recv_user_cap_to_stable(1, b"mmsrv vfs writeback mp send") {
        Ok(slot) => slot,
        Err(err) => {
            drop(stable);
            delete_recv_user_caps(user_cap_count);
            send_reply(buf, err, &[], 0);
            return;
        }
    };
    // The registered caps are permanent (first-write-wins, never freed), so
    // each OwnedCap slot is moved into server-state as a raw index and its
    // scope-teardown is suppressed.
    state.vfs_pager_cap_slot = stable.into_raw();
    state.vfs_writeback_mp_send_slot = writeback.into_raw();
    state.vfs_pager_owner_client_idx = client_idx;
    send_reply(buf, TRONA_OK, &[], 0);
}

/// Dispatch a self-tier label that arrived on a per-client request
/// MP. `client_idx` is resolved by the main-loop reactor from the
/// service-EQ Watch cookie that armed each per-client MP recv side
/// — kernel cap ownership is the identity guarantee here. The
/// per-client MP send cap that the child holds was minted with
/// `badge = 0` (`RSRC_ALLOC_MP_PAIR` does not set a badge), so the
/// dispatcher does not consult `record.badge`. Cross-client send
/// access is impossible by construction: each recv side lives in a
/// distinct namesrv-distributed cap and the kernel cap system
/// blocks any other process from invoking it.
pub fn dispatch_self(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64; 32],
    client_idx: usize,
    state: &mut ServerState,
) -> bool {
    // Pager registration is independent of any per-client region
    // table — it stamps a server-global slot. Handle it before the
    // borrow on `state.clients` so the handler can mutate
    // `state.vfs_pager_cap_slot` without a borrow split.
    if label == LABEL_REGISTER_VFS_PAGER {
        handle_register_vfs_pager(buf, client_idx as u32, state);
        return true;
    }
    // Cross-client / global reads — handled before the per-client VM
    // borrow because they address a *target* process (or the whole
    // system), not the caller's own VM.
    if label == LABEL_LIST_VMAS {
        mmap::handle_list_vmas(buf, regs, client_idx as u32, state);
        return true;
    }
    if label == LABEL_LIST_RESERVATIONS {
        mmap::handle_list_reservations(buf, regs, client_idx as u32, state);
        return true;
    }
    if label == LABEL_GET_COMMIT_AS {
        mmap::handle_get_commit_as(buf, state);
        return true;
    }
    if label == LABEL_GET_CLIENT_VM_STATS {
        mmap::handle_get_client_vm_stats(buf, regs, client_idx as u32, state);
        return true;
    }
    if label == LABEL_MUNMAP {
        mmap::handle_munmap(buf, regs, client_idx as u32, state);
        return true;
    }
    if label == LABEL_MSYNC {
        mmap::handle_msync(buf, regs, client_idx as u32, state);
        return true;
    }
    if label == LABEL_VFS_WRITEBACK_DONE {
        mmap::handle_vfs_writeback_done(buf, regs, client_idx as u32, state);
        return true;
    }
    if label == LABEL_MMAP {
        mmap::handle_mmap(buf, regs, client_idx as u32, state);
        return true;
    }
    let vfs_pager_cap_slot = state.vfs_pager_cap_slot;
    let vfs_pager_owner_client_idx = state.vfs_pager_owner_client_idx;
    let Some((client, vm)) = state.clients.entry_and_vm_mut(client_idx) else {
        send_reply(buf, KERNITE_ERR_NOT_FOUND as u64, &[], 0);
        return true;
    };
    match label {
        LABEL_MPROTECT => mmap::handle_mprotect(
            buf,
            regs,
            client,
            vm,
            &mut state.self_vm,
            &mut state.mo_registry,
            &mut state.frames,
        ),
        LABEL_RESERVE_IMAGE => {
            mmap::handle_reserve_image(buf, regs, client, vm, &mut state.self_vm)
        }
        LABEL_UNMAP_IMAGE => mmap::handle_unmap_image(
            buf,
            regs,
            client,
            vm,
            &mut state.self_vm,
            &mut state.mo_registry,
            &mut state.frames,
        ),
        LABEL_BRK => mmap::handle_brk(
            buf,
            regs,
            client,
            vm,
            &mut state.self_vm,
            &mut state.mo_registry,
            &mut state.frames,
        ),
        LABEL_SBRK => mmap::handle_sbrk(
            buf,
            regs,
            client,
            vm,
            &mut state.self_vm,
            &mut state.mo_registry,
            &mut state.frames,
        ),
        LABEL_MO_CREATE => {
            mmap::handle_mo_create(buf, regs, client, &mut state.mo_registry, &mut state.frames)
        }
        LABEL_SHM_CREATE => {
            mmap::handle_shm_create(buf, regs, client, &mut state.mo_registry, &mut state.frames)
        }
        LABEL_SHM_MAP => mmap::handle_shm_map(
            buf,
            regs,
            client,
            vm,
            &mut state.self_vm,
            &mut state.mo_registry,
            &mut state.frames,
        ),
        LABEL_SHM_DESTROY => {
            mmap::handle_shm_destroy(buf, regs, &mut state.mo_registry, &mut state.frames)
        }
        LABEL_FILE_MMAP => {
            // vfs-only label — caller must be the same client that
            // registered the pager via `MM_REGISTER_VFS_PAGER`. A
            // hostile fileops-using client cannot smuggle a file-backed
            // MO retype through the self-tier wire.
            if vfs_pager_owner_client_idx == u32::MAX
                || (client_idx as u32) != vfs_pager_owner_client_idx
            {
                send_reply(buf, TRONA_PERMISSION_DENIED, &[], 0);
            } else {
                mmap::handle_file_mmap(
                    buf,
                    regs,
                    client,
                    &mut state.mo_registry,
                    &mut state.frames,
                    &mut state.file_backed_registry,
                    vfs_pager_cap_slot,
                )
            }
        }
        LABEL_RESERVE_RANGE => {
            mmap::handle_reserve_range(buf, regs, client, vm, &mut state.self_vm)
        }
        LABEL_ALLOC_RANGE => mmap::handle_alloc_range(buf, regs, client, vm, &mut state.self_vm),
        LABEL_UNRESERVE_RANGE => mmap::handle_unreserve_range(buf, regs, vm),
        LABEL_SHM_UNMAP => mmap::handle_shm_unmap(
            buf,
            regs,
            client,
            vm,
            &mut state.self_vm,
            &mut state.mo_registry,
            &mut state.frames,
        ),
        LABEL_PREFAULT_RANGE => {
            mmap::handle_prefault_range(buf, regs, client, vm, &state.mo_registry)
        }
        LABEL_GET_SYSTEM_MEMINFO => mmap::handle_get_system_meminfo(buf, state),
        _ => return false,
    }
    true
}
