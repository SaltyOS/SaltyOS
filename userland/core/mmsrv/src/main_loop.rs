// SPDX-License-Identifier: GPL-2.0-only
//
//! Main + fault dispatcher reactors. The main TCB blocks on the
//! `service_eq` (fan-in: master service-EP + every per-client request
//! MP). The fault dispatcher TCB blocks on the `fault_eq` (fan-in: a
//! Watch per registered fault MP). Both TCBs share `STATE` and
//! coordinate via [`STATE_LOCK`].
//!
//! Both reactors run on top of [`trona_server::event_loop`]. Each
//! has its own `CookieTable<T>` (one for `MmsrvMainTarget`, one for
//! `MmsrvFaultTarget`); `arm_master_service_watch` and the
//! `MM_REGISTER_CLIENT` / `MM_REGISTER_FAULT_PIPE` handlers populate
//! those tables before issuing `WATCH_REGISTER`. The `live_gen` part
//! of the encoded cookie protects every dispatch against stale fires
//! after teardown — even if a `WATCH_CANCEL` race leaves a queued
//! record behind, the cookie's generation no longer matches and the
//! reactor drops it.
//!
//! Outbound IPC that can re-enter mmsrv (`INIT_REPORT_FAULT`) is
//! issued only after `STATE_LOCK` is released — see
//! [`MmsrvFaultDispatcher::take_pending_action`].
//! The reactors also use separate CSpace receive windows. They have
//! separate IPC buffers, but CSpace is process-wide; sharing one
//! scratch window would let one TCB clear another TCB's in-flight
//! payload cap while re-arming for its own `MP_READ`.

use trona_kernel::core_types::{Cap, IpcContext, TronaMsg};
use trona_server::event_loop::{CookieTable, EqDispatcher, EventLoop};
use uapi::{KERNITE_ERR_INVALID_OPERATION, KERNITE_STATE_READABLE, kernite_ipc_buffer};

use crate::caps::{fault_recv_base_slot, main_recv_base_slot};
use crate::client::{ClientTable, MAX_CLIENTS};
use crate::dispatch;
use crate::fault::FaultDispatcher;
use crate::file_backed_registry::FileBackedRegistry;
use crate::mo_registry::MoRegistry;
use crate::segment_alloc::MmsrvSegmentAllocator;
use crate::self_vm::SelfVm;
use crate::watch_pool::WatchPool;
use trona_server::frame_alloc::FrameAllocator;

static mut FAULT_IPC_CTX: IpcContext = IpcContext::new();

/// Install the fault dispatcher TCB's private IPC buffer. The
/// dispatcher uses its bound fault MessagePipe endpoint for both
/// fault receives and `reply-marked MP_WRITE` decisions.
pub unsafe fn init_fault_ipc_context(buf: *mut kernite_ipc_buffer) {
    unsafe {
        let ctx = &raw mut FAULT_IPC_CTX;
        trona_kernel::ipc::ipc_context_init(ctx, buf);
    }
}

fn fault_ipc_context() -> *mut IpcContext {
    &raw mut FAULT_IPC_CTX
}

/// Per-cookie target in mmsrv's main reactor cookie table.
#[derive(Clone, Copy)]
pub enum MmsrvMainTarget {
    /// `kind = MMSRV_KIND_MASTER_SERVICE` — master service-EP. Admin-tier
    /// RPCs (init's `MM_REGISTER_CLIENT` / `MM_REGISTER_FAULT_PIPE` /
    /// `MM_FORK_VSPACE` / `MM_DEREGISTER_CLIENT`).
    MasterServiceEp,
    /// `kind = MMSRV_KIND_PER_CLIENT` — per-client request MP. Self-tier
    /// RPCs from the client at table index `idx`.
    Client { idx: u32 },
}

/// Cookie kinds for mmsrv's main reactor.
pub const MMSRV_KIND_PER_CLIENT: u8 = 0;
pub const MMSRV_KIND_MASTER_SERVICE: u8 = 1;

/// Per-cookie target in mmsrv's fault dispatcher cookie table.
#[derive(Clone, Copy)]
pub struct MmsrvFaultTarget {
    pub client_id: u32,
    pub tcb_id: u32,
}

/// Cookie kinds for mmsrv's fault dispatcher reactor.
pub const MMSRV_FAULT_KIND_PER_TCB: u8 = 0;

#[derive(Clone, Copy, Debug)]
pub struct StartupSlots {
    pub init_ep: u64,
    pub master_service_mp_recv: u64,
    /// GRANT-bearing send side of mmsrv's own master service endpoint
    /// (`ROLE_SERVICE_CLIENT_EP`), retained so the register handler can
    /// mint a per-client control cap (a badged copy of this send). Init
    /// delivers it at boot instead of reclaiming it.
    pub master_service_mp_send: u64,
    pub fault_mp_master_recv: u64,
    pub namesrv_ep: u64,
    pub rsrcsrv_ep: u64,
    pub service_eq: u64,
    pub fault_eq: u64,
    /// Pre-allocated TCB for the fault dispatcher (second TCB inside
    /// mmsrv's process). Init retypes this and hands it over via the
    /// cap table; mmsrv's `main` calls `TCB_SET_SPACE +
    /// TCB_CONFIGURE + SC_BIND + TCB_START` to bring it up.
    pub fault_tcb: u64,
    /// SchedContext for the fault dispatcher TCB.
    pub fault_sc: u64,
    /// Frame cap backing the fault dispatcher's stack. Init pre-maps
    /// it at `FAULT_STACK_VA`; mmsrv retains the cap so the backing
    /// object remains owned by the process that uses it.
    pub fault_stack_frame: u64,
}

impl StartupSlots {
    pub const fn zeroed() -> Self {
        Self {
            init_ep: 0,
            master_service_mp_recv: 0,
            master_service_mp_send: 0,
            fault_mp_master_recv: 0,
            namesrv_ep: 0,
            rsrcsrv_ep: 0,
            service_eq: 0,
            fault_eq: 0,
            fault_tcb: 0,
            fault_sc: 0,
            fault_stack_frame: 0,
        }
    }
}

pub struct ServerState {
    pub startup: StartupSlots,
    pub frames: FrameAllocator,
    pub mo_registry: MoRegistry,
    pub clients: ClientTable,
    pub fault: FaultDispatcher,
    pub watches: WatchPool,
    /// Watch cap armed on `startup.master_service_mp_recv`'s
    /// `STATE_READABLE` bit, posting `EVENT_TYPE_STATE` records
    /// into `startup.service_eq`. Re-armed after every fire since
    /// Watches are one-shot.
    pub master_service_watch_cap: u64,
    /// Encoded cookie returned by `main_cookie_table.arm(..)` for
    /// the master service-EP Watch. The dispatcher re-arms with
    /// the same value so the live_gen survives across re-arms.
    pub master_service_cookie: u64,
    /// vfs-supplied `OBJ_PAGER` cap slot. 0 = unregistered (the only
    /// state reachable before vfs has booted and called
    /// `MM_REGISTER_VFS_PAGER`). Once non-zero, every `MM_FILE_MMAP`
    /// invokes `MO_ATTACH_PAGER(mo_cap, vfs_pager_cap_slot)` so the
    /// kernel routes file-backed page faults through vfs's bound
    /// EventQueue rather than mmsrv's fault dispatcher. First-write
    /// wins — re-registration returns `KERNITE_ERR_ALREADY_EXISTS`.
    pub vfs_pager_cap_slot: u64,
    /// vfs-supplied MessagePipe send cap for explicit MAP_SHARED writeback
    /// requests (`VFS_MSYNC_MO`). This is separate from `vfs_pager_cap_slot`:
    /// the pager cap receives kernel page-fault events, while this cap is a
    /// server-to-server control path from mmsrv to VFS.
    pub vfs_writeback_mp_send_slot: u64,
    /// `client_idx` of the client that registered `vfs_pager_cap_slot`.
    /// `u32::MAX` = unregistered. `MM_FILE_MMAP` callers are checked
    /// against this — non-owner callers receive `PERMISSION_DENIED`,
    /// which prevents a hostile non-vfs client from materialising
    /// file-backed MOs and (transitively) intercepting page faults via
    /// the registered pager.
    pub vfs_pager_owner_client_idx: u32,
    /// File-backed MO directory — populated by `MM_FILE_MMAP`,
    /// keyed on `(vnode_slot, vnode_epoch)` and recording the
    /// kernel-issued `mo_id` so reverse lookups (e.g. on
    /// teardown / pager-detach) can resolve back to the vnode.
    pub file_backed_registry: FileBackedRegistry,
    /// Parked client replies waiting for one or more VFS MAP_SHARED
    /// writeback requests to complete. A group owns the original
    /// `MM_MSYNC`/file-backed `MM_MUNMAP` reply target.
    pub pending_vfs_writeback_groups:
        trona_server::ContinuationArena<crate::mmap::PendingVfsWritebackGroup>,
    /// Per-VFS-request continuations. Each request token resolves to the
    /// group token that should be decremented when VFS reports completion.
    pub pending_vfs_writeback_requests:
        trona_server::ContinuationArena<crate::mmap::PendingVfsWritebackRequest>,
    /// Coarse main-reactor tick used only as a defense-in-depth bound for
    /// parked VFS writeback groups whose completions never arrive.
    pub vfs_writeback_sweep_tick: u64,
    /// Cookie table for the main reactor: maps `(kind, slot,
    /// live_gen)` -> `MmsrvMainTarget`. Backed by
    /// `segment_allocator` (frames retyped out of the buddy).
    pub main_cookie_table: CookieTable<MmsrvMainTarget>,
    /// Cookie table for the fault dispatcher reactor: maps
    /// `(kind=MMSRV_FAULT_KIND_PER_TCB, slot, live_gen)` ->
    /// `(client_id, tcb_id)` so the dispatcher can resolve a
    /// fired Watch back to its victim TCB.
    pub fault_cookie_table: CookieTable<MmsrvFaultTarget>,
    /// Frame backing for `main_cookie_table` and
    /// `fault_cookie_table`. Both reactors share the same
    /// allocator — both are mmsrv-internal SegmentedArrays whose
    /// growth must come from the buddy (re-entering mmsrv's own
    /// `MM_MMAP` would deadlock).
    pub segment_allocator: MmsrvSegmentAllocator,
    /// Page backing for the per-client region / reservation slabs
    /// (`trona_server::slab::TrackedSlab` / `BaseSortedIndex`). Distinct
    /// from `segment_allocator`: that one is append-only for the cookie
    /// tables, this one frees reallocated runs so growable per-client
    /// storage is reclaimed on client teardown. Both retype out of the
    /// same buddy but occupy disjoint scratch VA windows.
    pub self_vm: SelfVm,
}

impl ServerState {
    pub const fn new() -> Self {
        Self {
            startup: StartupSlots::zeroed(),
            frames: FrameAllocator::new(),
            mo_registry: MoRegistry::new(),
            clients: ClientTable::new(),
            fault: FaultDispatcher::new(),
            watches: WatchPool::new(),
            master_service_watch_cap: 0,
            master_service_cookie: 0,
            vfs_pager_cap_slot: 0,
            vfs_writeback_mp_send_slot: 0,
            vfs_pager_owner_client_idx: u32::MAX,
            file_backed_registry: FileBackedRegistry::new(),
            pending_vfs_writeback_groups: trona_server::ContinuationArena::new_empty(),
            pending_vfs_writeback_requests: trona_server::ContinuationArena::new_empty(),
            vfs_writeback_sweep_tick: 0,
            main_cookie_table: CookieTable::new_empty(),
            fault_cookie_table: CookieTable::new_empty(),
            segment_allocator: MmsrvSegmentAllocator::new(),
            self_vm: SelfVm::new(),
        }
    }
}

static mut STATE: ServerState = ServerState::new();

/// Coarse-grained mutex guarding every mutable field of `STATE`. Both
/// the main reactor TCB and the fault dispatcher TCB acquire this
/// around any access. The blocking `EQ_WAIT` happens with the mutex
/// released so the peer reactor can keep running. Outbound IPC that
/// can re-enter mmsrv (`INIT_REPORT_FAULT`) is issued only after the
/// mutex is released — see `MmsrvFaultDispatcher::take_pending_action`.
static STATE_LOCK: trona_runtime::thread::sync::Mutex = trona_runtime::thread::sync::Mutex::new();

pub fn state_lock_acquire() {
    STATE_LOCK.lock();
}

pub fn state_lock_release() {
    STATE_LOCK.unlock();
}

pub fn state_mut() -> &'static mut ServerState {
    unsafe { &mut *(&raw mut STATE) }
}

fn arm_recv_window(ctx: *mut IpcContext, base: u64) {
    let window = trona_server::recv_slot::FixedRecvWindow::new(
        base,
        crate::caps::RECV_WINDOW_LEN,
        trona_runtime::core::slot_alloc::slot_invoke_depth_cb,
    );
    unsafe {
        window.arm(ctx, crate::caps::CAP_SELF_CSPACE);
    }
}

fn consume_unknown(buf: *mut kernite_ipc_buffer) {
    if buf.is_null() {
        return;
    }
    let _ = unsafe {
        trona_server::mp_write_reply_to(
            buf,
            dispatch::current_reply_target(),
            uapi::KERNITE_ERR_INVALID_OPERATION as u64,
            &[],
            0,
        )
    };
}

fn yield_briefly() {
    trona_kernel::syscall::invoke(
        uapi::KERNITE_CAP_SELF_TCB as u64,
        uapi::KERNITE_INV_TCB_YIELD as u64,
        0,
        0,
        0,
        0,
    );
}

/// Re-arm a Watch over `watched_cap` on `eq_cap` with `cookie`.
/// Caller already holds `STATE_LOCK`.
fn rearm_watch(watch_cap: u64, watched_cap: u64, eq_cap: u64, cookie: u64) -> i32 {
    if watch_cap == 0 || watched_cap == 0 || eq_cap == 0 {
        return uapi::KERNITE_ERR_INVALID_OPERATION as i32;
    }
    trona_kernel::invoke::watch_register(
        trona_kernel::core_types::CapRef::flat(watch_cap),
        trona_kernel::core_types::CapRef::flat(watched_cap),
        trona_kernel::core_types::CapRef::flat(eq_cap),
        KERNITE_STATE_READABLE,
        cookie,
    )
}

fn rearm_all_main_sources(state: &ServerState) -> i32 {
    let mut first_err = rearm_watch(
        state.master_service_watch_cap,
        state.startup.master_service_mp_recv,
        state.startup.service_eq,
        state.master_service_cookie,
    );
    for idx in 0..MAX_CLIENTS {
        if let Some(client) = state.clients.entry(idx) {
            let recv_raw = client.request_mp_recv.as_raw();
            if client.watch_cap == 0 || recv_raw == 0 {
                continue;
            }
            let err = rearm_watch(
                client.watch_cap,
                recv_raw,
                state.startup.service_eq,
                client.watch_cookie,
            );
            if first_err == 0 && err != 0 {
                first_err = err;
            }
        }
    }
    first_err
}

fn rearm_all_fault_sources(state: &ServerState) -> i32 {
    let mut first_err = 0;
    state.fault.for_each_active(|entry| {
        let err = rearm_watch(
            entry.watch_cap,
            entry.fault_mp_recv,
            state.startup.fault_eq,
            entry.cookie,
        );
        if first_err == 0 && err != 0 {
            first_err = err;
        }
    });
    first_err
}

// -------------------------------------------------------------------
// Main reactor dispatcher.
// -------------------------------------------------------------------

/// `EqDispatcher` impl for the main reactor. Owns a raw pointer back
/// into the `static mut STATE` so it can borrow `&mut ServerState`
/// inside `dispatch_state`. Both `state` accesses run with
/// `STATE_LOCK` held — `run_iteration_with_wait_hooks` calls
/// `state_lock_release` only around the blocking `EQ_WAIT`.
pub struct MmsrvMainDispatcher {
    state: *mut ServerState,
    ipc_ctx: *mut IpcContext,
}

impl MmsrvMainDispatcher {
    pub fn new(state: *mut ServerState, ipc_ctx: *mut IpcContext) -> Self {
        Self { state, ipc_ctx }
    }

    fn state_ref(&self) -> &ServerState {
        unsafe { &*self.state }
    }

    fn state_mut(&mut self) -> &mut ServerState {
        unsafe { &mut *self.state }
    }
}

impl EqDispatcher for MmsrvMainDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let entry = self.state_ref().main_cookie_table.lookup(cookie)?;
        if entry.mp_recv == 0 {
            // STATE_PEER_CLOSED on a registered cap publishes with
            // mp_recv == 0 (no message to drain). Skip MP_READ but
            // let dispatch_state still see the event so it can
            // tombstone the cookie. Stale cookies also surface here
            // (lookup returned None for them already, so this branch
            // only triggers on live-but-readless states).
            None
        } else {
            Some(entry.mp_recv)
        }
    }

    fn dispatch_state(
        &mut self,
        cookie: u64,
        msg: &TronaMsg,
        meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let badge = meta.badge;
        // Look up the cookie a second time to grab the routing target.
        // Stale cookies (lookup returns None) drop silently — typical
        // case is a teardown that has not yet had its EQ records
        // purged.
        let target = match self.state_ref().main_cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        let buf = unsafe { (*self.ipc_ctx).ipc_buffer };
        if buf.is_null() {
            return KERNITE_ERR_INVALID_OPERATION as i32;
        }
        match target {
            MmsrvMainTarget::MasterServiceEp => {
                let st = self.state_mut();
                dispatch::set_current_reply_target(
                    buf as *const _,
                    st.startup.master_service_mp_recv,
                );
                let recognised = dispatch::dispatch_init(buf, msg.label, &msg.regs, badge, st);
                if !recognised {
                    consume_unknown(buf);
                }
                0
            }
            MmsrvMainTarget::Client { idx } => {
                let st = self.state_mut();
                let _client_id = st
                    .clients
                    .entry(idx as usize)
                    .map(|c| c.client_id as u64)
                    .unwrap_or(0);
                // trona_runtime::uinfo!(|_lb| {
                //     _lb.str(b"[MMSRV] client dispatch idx=");
                //     _lb.dec(idx as u64);
                //     _lb.str(b" id=");
                //     _lb.hex(client_id);
                //     _lb.str(b" label=");
                //     _lb.hex(msg.label);
                //     _lb.str(b" badge=");
                //     _lb.hex(badge);
                //     _lb.str(b" cookie=");
                //     _lb.hex(cookie);
                //     _lb.putc(b'\n');
                // });
                let reply_mp = st
                    .clients
                    .entry(idx as usize)
                    .map(|c| c.request_mp_recv.as_raw())
                    .unwrap_or(0);
                dispatch::set_current_reply_target(buf as *const _, reply_mp);
                let recognised =
                    dispatch::dispatch_self(buf, msg.label, &msg.regs, idx as usize, st);
                if !recognised {
                    consume_unknown(buf);
                }
                0
            }
        }
    }

    fn handle_mp_read_error(&mut self, _cookie: u64, err: i32, state_set: u64, status: u32) -> i32 {
        // `status == OBJECT_CLOSED` is the expected signal that a client's
        // request MP closed because the process exited and rsrcsrv revoked
        // its endpoint; the pending MM_DEREGISTER_CLIENT tears the slot down.
        // Only a non-close read error is genuinely unexpected.
        if status == uapi::KERNITE_EVENT_STATUS_OBJECT_CLOSED {
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[MMSRV] main MP_READ closed (teardown) err=");
                _lb.dec(err as u64);
                _lb.str(b" status=");
                _lb.hex(status as u64);
                _lb.putc(b'\n');
            });
        } else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[MMSRV] main MP_READ failed err=");
                _lb.dec(err as u64);
                _lb.str(b" state=");
                _lb.hex(state_set);
                _lb.str(b" status=");
                _lb.hex(status as u64);
                _lb.putc(b'\n');
            });
        }
        err
    }

    fn prepare_mp_read(&mut self, cookie: u64) -> bool {
        if self.state_ref().main_cookie_table.lookup(cookie).is_none() {
            return false;
        }
        arm_recv_window(self.ipc_ctx, main_recv_base_slot());
        true
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let target = match self.state_ref().main_cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        match target {
            MmsrvMainTarget::MasterServiceEp => {
                let st = self.state_mut();
                let err = rearm_watch(
                    st.master_service_watch_cap,
                    st.startup.master_service_mp_recv,
                    st.startup.service_eq,
                    st.master_service_cookie,
                );
                if err != 0 {
                    trona_runtime::uerror!(|_lb| {
                        _lb.str(b"[MMSRV] rearm master watch failed err=");
                        _lb.dec(err as u64);
                        _lb.str(b" recv=");
                        _lb.hex(st.startup.master_service_mp_recv);
                        _lb.str(b" watch=");
                        _lb.hex(st.master_service_watch_cap);
                        _lb.str(b" cookie=");
                        _lb.hex(st.master_service_cookie);
                        _lb.putc(b'\n');
                    });
                }
                err
            }
            MmsrvMainTarget::Client { idx } => {
                let st = self.state_mut();
                let eq = st.startup.service_eq;
                if let Some(c) = st.clients.entry(idx as usize) {
                    let err =
                        rearm_watch(c.watch_cap, c.request_mp_recv.as_raw(), eq, c.watch_cookie);
                    if err != 0 {
                        trona_runtime::udebug!(|_lb| {
                            _lb.str(b"[MMSRV] rearm client watch (teardown) err=");
                            _lb.dec(err as u64);
                            _lb.str(b" idx=");
                            _lb.dec(idx as u64);
                            _lb.str(b" id=");
                            _lb.hex(c.client_id as u64);
                            _lb.str(b" recv=");
                            _lb.hex(c.request_mp_recv.as_raw());
                            _lb.str(b" watch=");
                            _lb.hex(c.watch_cap);
                            _lb.str(b" cookie=");
                            _lb.hex(c.watch_cookie);
                            _lb.putc(b'\n');
                        });
                    }
                    err
                } else {
                    0
                }
            }
        }
    }

    fn continue_readable_drain(&mut self, _cookie: u64) -> bool {
        // Keep mmsrv fair across the master service MP and every
        // per-client self-tier MP. A readable source is re-armed after
        // one message; WATCH_REGISTER immediately fires again if the
        // pipe is still readable, but other queued sources get a
        // scheduling point instead of waiting behind an unbounded drain.
        false
    }

    fn handle_overflow(&mut self, dropped: u64) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] main EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
        let _ = rearm_all_main_sources(self.state_ref());
    }

    fn handle_timer(&mut self, _cookie: u64) {
        // Main reactor doesn't arm timers — the kernel cannot deliver
        // an `EVENT_TYPE_TIMER` here.
    }
}

// -------------------------------------------------------------------
// Fault dispatcher reactor.
// -------------------------------------------------------------------

/// `EqDispatcher` impl for the fault dispatcher. Computes the
/// recovery action under `STATE_LOCK`, then parks it for the outer
/// loop to drain with the lock released. The `ForwardAndAbort` arm
/// calls `INIT_REPORT_FAULT` via MP_CALL, which can re-enter mmsrv
/// if init's reactor invokes us back; running that under
/// `STATE_LOCK` would deadlock against the main reactor.
pub struct MmsrvFaultDispatcher {
    state: *mut ServerState,
    ipc_ctx: *mut IpcContext,
    pending_action: Option<crate::fault::FaultAction>,
}

impl MmsrvFaultDispatcher {
    pub fn new(state: *mut ServerState, ipc_ctx: *mut IpcContext) -> Self {
        Self {
            state,
            ipc_ctx,
            pending_action: None,
        }
    }

    /// Take ownership of the action computed during the most recent
    /// `dispatch_state`. Returns `None` if no action was queued
    /// (overflow / timer / stale cookie). Caller releases
    /// `STATE_LOCK` before invoking `FaultAction::execute`.
    pub fn take_pending_action(&mut self) -> Option<crate::fault::FaultAction> {
        self.pending_action.take()
    }

    fn state_ref(&self) -> &ServerState {
        unsafe { &*self.state }
    }

    fn state_mut(&mut self) -> &mut ServerState {
        unsafe { &mut *self.state }
    }
}

impl EqDispatcher for MmsrvFaultDispatcher {
    fn resolve_mp_recv(&self, cookie: u64) -> Option<Cap> {
        let entry = self.state_ref().fault_cookie_table.lookup(cookie)?;
        if entry.mp_recv == 0 {
            None
        } else {
            Some(entry.mp_recv)
        }
    }

    fn dispatch_state(
        &mut self,
        cookie: u64,
        msg: &TronaMsg,
        _meta: trona_server::event_loop::MpReadMeta,
    ) -> i32 {
        let target = match self.state_ref().fault_cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        let mut words = [0u64; 4];
        for i in 0..4.min(msg.length as usize) {
            words[i] = msg.regs[i];
        }
        let st = self.state_mut();
        // Resolve the per-TCB FaultEntry index. The fault table is
        // separate storage from the cookie table — the cookie carries
        // the routing key (kind, slot, live_gen) and the fault table
        // carries oom_retries / fault_count, etc.
        let entry_idx = match st.fault.find_entry(target.client_id, target.tcb_id) {
            Some(i) => i,
            None => return 0,
        };
        // Compute the action under the lock (state mutation: oom
        // retries, region lookups, frame alloc).
        let action = crate::fault::handle_fault(msg.label, &words, st, entry_idx);
        // Park the action for the outer loop to apply with the lock
        // released. Overwrites any prior unconsumed action — by
        // construction `take_pending_action` is called every iteration
        // before the next `dispatch_state`, so this never drops live
        // work.
        self.pending_action = Some(action);
        0
    }

    fn handle_mp_read_error(&mut self, _cookie: u64, err: i32, state_set: u64, status: u32) -> i32 {
        // A closed fault pipe (status OBJECT_CLOSED) is the expected signal
        // that the faulting thread's TCB exited and its fault MP was revoked;
        // only a non-close read error is genuinely unexpected.
        if status == uapi::KERNITE_EVENT_STATUS_OBJECT_CLOSED {
            trona_runtime::udebug!(|_lb| {
                _lb.str(b"[MMSRV] fault MP_READ closed (teardown) err=");
                _lb.dec(err as u64);
                _lb.str(b" status=");
                _lb.hex(status as u64);
                _lb.putc(b'\n');
            });
        } else {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[MMSRV] fault MP_READ failed err=");
                _lb.dec(err as u64);
                _lb.str(b" state=");
                _lb.hex(state_set);
                _lb.str(b" status=");
                _lb.hex(status as u64);
                _lb.putc(b'\n');
            });
        }
        err
    }

    fn prepare_mp_read(&mut self, cookie: u64) -> bool {
        if self.state_ref().fault_cookie_table.lookup(cookie).is_none() {
            return false;
        }
        arm_recv_window(self.ipc_ctx, fault_recv_base_slot());
        true
    }

    fn rearm_state_source(&mut self, cookie: u64) -> i32 {
        let target = match self.state_ref().fault_cookie_table.lookup(cookie) {
            Some(e) => e.target,
            None => return 0,
        };
        let st = self.state_mut();
        let eq = st.startup.fault_eq;
        if let Some(entry_idx) = st.fault.find_entry(target.client_id, target.tcb_id) {
            if let Some(e) = st.fault.entry_snapshot(entry_idx) {
                if e.active != 0 {
                    return rearm_watch(e.watch_cap, e.fault_mp_recv, eq, e.cookie);
                }
            }
        }
        0
    }

    fn continue_readable_drain(&mut self, _cookie: u64) -> bool {
        false
    }

    fn handle_overflow(&mut self, dropped: u64) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[MMSRV] fault EQ overflow dropped=");
            _lb.hex(dropped);
            _lb.str(b"\n");
        });
        let _ = rearm_all_fault_sources(self.state_ref());
    }

    fn handle_timer(&mut self, _cookie: u64) {
        // Fault dispatcher doesn't currently arm timers — OOM
        // backoff and page-cache writeback are the future timer
        // sources, neither of which has its kernel TIMER cap
        // wired up yet.
    }
}

// -------------------------------------------------------------------
// Reactor drivers.
// -------------------------------------------------------------------

pub fn run_main_reactor() -> ! {
    let ctx: *mut IpcContext = trona_posix::tls::current_ipc_ctx();
    state_lock_acquire();
    arm_recv_window(ctx, main_recv_base_slot());
    let service_eq = state_mut().startup.service_eq;
    let dispatcher = MmsrvMainDispatcher::new(state_mut() as *mut ServerState, ctx);
    let mut reactor: EventLoop<MmsrvMainDispatcher> = EventLoop::new(service_eq, dispatcher);

    loop {
        let r = unsafe {
            reactor.run_iteration_with_wait_hooks(
                ctx,
                || state_lock_release(),
                || state_lock_acquire(),
            )
        };
        if r != 0 {
            // EQ_WAIT / MP_READ / per-source re-arm failed. The
            // reactor already re-arms the specific source whose
            // one-shot watch fired; bulk re-registering every live
            // watch here would briefly detach already-armed watches
            // and can lose a concurrent readable edge.
            state_lock_release();
            yield_briefly();
            state_lock_acquire();
        }
        {
            let st = state_mut();
            st.vfs_writeback_sweep_tick = st.vfs_writeback_sweep_tick.wrapping_add(1);
            let buf = unsafe { (*ctx).ipc_buffer };
            let _ = crate::mmap::sweep_stale_vfs_writeback_groups(buf, st);
        }
        // Re-arm the main recv window every iteration; the shared
        // helper clears stale scratch caps before the next MP_READ.
        arm_recv_window(ctx, main_recv_base_slot());
    }
}

pub extern "C" fn run_fault_dispatcher() -> ! {
    let ctx: *mut IpcContext = fault_ipc_context();
    state_lock_acquire();
    arm_recv_window(ctx, fault_recv_base_slot());
    let fault_eq = state_mut().startup.fault_eq;
    let dispatcher = MmsrvFaultDispatcher::new(state_mut() as *mut ServerState, ctx);
    let mut reactor: EventLoop<MmsrvFaultDispatcher> = EventLoop::new(fault_eq, dispatcher);

    loop {
        let r = unsafe {
            reactor.run_iteration_with_wait_hooks(
                ctx,
                || state_lock_release(),
                || state_lock_acquire(),
            )
        };
        // Drain the action computed during dispatch_state with the
        // lock released. INIT_REPORT_FAULT can re-enter mmsrv via
        // init's reactor; running it under STATE_LOCK would deadlock.
        let pending = reactor.dispatch.take_pending_action();
        if let Some(action) = pending {
            state_lock_release();
            unsafe {
                action.execute(ctx);
            }
            state_lock_acquire();
        }
        if r != 0 {
            // See `run_main_reactor`: only the fired source should be
            // re-armed by the reactor. Bulk re-registration races with
            // incoming fault notifications.
            state_lock_release();
            yield_briefly();
            state_lock_acquire();
        }
        arm_recv_window(ctx, fault_recv_base_slot());
    }
}
