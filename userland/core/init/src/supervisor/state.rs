// SPDX-License-Identifier: GPL-2.0-only
//
//! Aggregate supervisor state — one container the owner thread mutates.
//!
//! Single-threaded reactor: the owner TCB blocks on `EQ_WAIT(control_eq)`
//! and drains every record before re-entering wait. Worker TCBs operate
//! on snapshots and post results back via `worker_completion EQ`; they
//! never mutate `SupervisorState` directly.

use trona_kernel::core_types::SaltyOSFramebufferInfoV1;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::layout::VmClientLayout;
use trona_server::event_loop::CookieTable;
use trona_server::frame_alloc::FrameAllocator;

use crate::supervisor::lifecycle_stream::LifecycleStreams;
use crate::supervisor::manifest::ServiceManifest;
use crate::supervisor::proc_table::{PidTable, ProcessRecord};
use crate::supervisor::registry::InterfaceRegistry;
use crate::supervisor::segment_alloc::InitSegmentAllocator;
use crate::supervisor::self_vm::InitSelfVm;
use crate::supervisor::unit_mgr::UnitGraph;
use crate::supervisor::untyped_split::UntypedChunks;

/// Per-cookie target the owner reactor routes events to.
///
/// Static cookies (master service-EP MP, control timer, worker
/// completion EQ, namesrv subscribe MP) are armed once during boot
/// and kept live for the rest of init's runtime. Dynamic cookies
/// (per-client request MP) are armed at spawn time and tombstoned at
/// exit so stale fires drop on dispatch.
#[derive(Clone, Copy)]
pub enum InitTarget {
    /// Master service-EP MP recv side. Admin-tier labels (mmsrv's
    /// `INIT_REPORT_FAULT`, externally-issued `LABEL_GET_ABI_VERSION`)
    /// arrive here.
    MasterServiceMp,
    /// `control_timer` STATE_TIMED_OUT — itimer / sleep / spawn
    /// timeout sweeps the proc-table.
    ControlTimer,
    /// `worker_completion_eq` STATE_READABLE — lifecycle worker TCBs
    /// post results that the owner forwards to the original caller.
    WorkerCompletion,
    /// namesrv subscribe MP STATE_READABLE — every publisher REGISTER
    /// surfaces here as a `NAMESRV_REGISTER_EVENT` and unblocks the
    /// matching unit-graph dependencies.
    NamesrvRegisterEvent,
    /// Per-client request MP — one entry per spawned process,
    /// payload = `client_id`. Future arm site (lifecycle's
    /// per-spawn handler).
    Request { client_id: u32 },
}

/// Capability slots filled in during boot. Re-read by every supervisor
/// pathway — the owner never `cnode_move`s these out of init's CSpace
/// (exception: `unit_mgr_namesrv_event_mp_send` which is transferred
/// into namesrv at subscribe time and then set to `None`).
pub struct StartupCaps {
    pub bootinfo_frame: Option<OwnedCap>,
    pub control_eq: Option<OwnedCap>,
    pub worker_completion_eq: Option<OwnedCap>,
    pub control_timer: Option<OwnedCap>,
    /// Raw slot index for the IPC receive scratch window — passed directly
    /// to `set_receive_slot_ctx` as a raw u64 (ipc.rs stays raw).
    pub recv_scratch_base: u64,
    pub initrd_va: u64,
    pub initrd_len: usize,
    /// Framebuffer metadata copied from the kernel bootinfo page and
    /// re-advertised to children through `SaltyOSStartupLayoutV1`.
    pub framebuffer: SaltyOSFramebufferInfoV1,
    /// Master service-EP MP recv side (admin labels arrive here from
    /// privileged callers — currently mmsrv's `INIT_REPORT_FAULT`).
    pub master_service_mp_recv: Option<OwnedCap>,
    /// Master service-EP MP send side. The boot path mints per-service
    /// copies of this cap into each spawned core service's cap-table at
    /// `ROLE_INIT_CONTROL`, badged with that service's `INIT_BADGE_FROM_*`
    /// so init's reactor authenticates the originator of inbound
    /// server→init messages. Init holds the unminted send slot — minting
    /// strips Grant from the resulting cap, so re-mints must always come
    /// from this raw send rather than from a previously-minted copy.
    pub master_service_mp_send: Option<OwnedCap>,
    /// init's send side of its own MP into namesrv (admin-class badge),
    /// used to call `NAMESRV_GRANT_PUBLISHER` / `NAMESRV_OWNER_EXITED`.
    /// Minted from `namesrv_master_mp_send_raw`.
    pub namesrv_client_mp: Option<OwnedCap>,
    /// Unminted namesrv master MP send retained for per-child mints.
    /// `cnode_mint` strips Grant from the destination cap, so a child's
    /// publisher / query badge must be minted from this raw cap (not
    /// from `namesrv_client_mp`, which is itself a minted copy without
    /// Grant).
    pub namesrv_master_mp_send_raw: Option<OwnedCap>,
    /// Cached per-caller copy of ldsrv's client-facing service EP, looked
    /// up on first post-handoff `resolve_library` via
    /// `state.caps.namesrv_client_mp` (`NAMESRV_LOOKUP("ldsrv")`). Init
    /// never receives `ROLE_LDSRV_CLIENT` via its startup cap-table
    /// (`ldsrv` does not exist at PID 1 start), so the runtime
    /// weak-symbol lazy resolve path is permanently dead for it — init
    /// owns its cap here and uses
    /// `trona_runtime::client::ldsrv::resolve_library_at` directly.
    pub ldsrv_client_ep: Option<OwnedCap>,
    /// init's send side into rsrcsrv (admin badge), used for
    /// quota/admin operations such as `RSRC_BATCH_ALLOC` and
    /// `RSRC_OWNER_EXITED`.
    /// Children resolve their own per-client rsrcsrv send through
    /// `NAMESRV_LOOKUP("rsrcsrv")` rather than receiving a copy from
    /// init at spawn time.
    pub rsrcsrv_client_mp: Option<OwnedCap>,
    /// mmsrv per-server ROOT control capability — a badged, non-`GRANT`
    /// invoke cap to mmsrv's master EP that authorizes only
    /// `MM_REGISTER_CLIENT`. init mints it at boot from the master-EP send
    /// before delivering a `GRANT`-bearing copy to mmsrv. Every other admin
    /// verb is driven on a per-client control cap instead.
    pub mmsrv_root_control_cap: Option<OwnedCap>,
    /// init's own per-client mmsrv control cap, captured when init
    /// self-registers. Used as the source operand for cross-client
    /// `MM_STAGE_IMAGE_REGION` (init stages ELF/PE bytes from its own VSpace
    /// into a child).
    pub mmsrv_self_control_cap: Option<OwnedCap>,
    /// namesrv's per-client mmsrv control cap, captured at its post-mmsrv
    /// registration. init drives namesrv's mmsrv admin verbs (e.g. the
    /// Stage-F fault-pipe registration) on it.
    pub namesrv_mmsrv_control_cap: Option<OwnedCap>,
    /// rsrcsrv's per-client mmsrv control cap, captured at its registration.
    pub rsrcsrv_mmsrv_control_cap: Option<OwnedCap>,
    /// vfs per-server ROOT control capability — the analogous register-only
    /// cap to vfs's master EP, minted by init from vfs's master-EP send when
    /// vfs is spawned. Authorizes only `VFS_ADMIN_REGISTER_CLIENT`; every
    /// other vfs admin verb is driven on a per-client control cap. `None`
    /// until vfs is spawned.
    pub vfs_root_control_cap: Option<OwnedCap>,
    /// init's own self-only request-MP send into mmsrv. The send cap
    /// itself is unbadged; mmsrv resolves the client from the Watch
    /// cookie armed on the paired recv side. Used when init pre-stages
    /// an anon region in its own VSpace before `MM_STAGE_IMAGE_REGION`
    /// splices it into a child.
    pub mmsrv_self_mp: Option<OwnedCap>,
    /// init's own `client_id` after self-registration with mmsrv. Used
    /// as the `src_client_id` for `MM_STAGE_IMAGE_REGION` calls when
    /// staging ELF/PE bytes from init's VSpace into a child's.
    pub init_client_id: u32,

    /// namesrv main TCB cap (init-side) — retained after Stage C so
    /// Stage F can retro-bind a fault MP onto it.
    pub namesrv_main_tcb: Option<OwnedCap>,
    /// namesrv VSpace cap (retained for `MM_REGISTER_CLIENT`).
    pub namesrv_vspace: Option<OwnedCap>,
    /// namesrv mmsrv `client_id` allocated by init when post-mmsrv
    /// `MM_REGISTER_CLIENT` runs in Stage F. Zero before Stage F.
    pub namesrv_client_id: u32,
    /// Layout plan produced by the loader for namesrv at Stage C.
    /// Carried forward into Stage F so `MM_REGISTER_CLIENT` registers
    /// mmsrv with the actual image windows, not defaults.
    pub namesrv_layout: Option<VmClientLayout>,

    /// rsrcsrv main TCB cap (init-side).
    pub rsrcsrv_main_tcb: Option<OwnedCap>,
    /// rsrcsrv VSpace cap.
    pub rsrcsrv_vspace: Option<OwnedCap>,
    /// rsrcsrv mmsrv `client_id`.
    pub rsrcsrv_client_id: u32,
    /// Layout plan produced by the loader for rsrcsrv at Stage D.
    pub rsrcsrv_layout: Option<VmClientLayout>,

    /// mmsrv main TCB cap (init-side). Init owns the cap before
    /// Stage F so the retroactive fault-binding loop can run
    /// `TCB_SET_FAULT_PIPE` on it after mmsrv is ready.
    pub mmsrv_main_tcb: Option<OwnedCap>,
    /// mmsrv VSpace cap.
    pub mmsrv_vspace: Option<OwnedCap>,
    /// mmsrv's own mmsrv `client_id`. Allocated by init in Stage F.
    pub mmsrv_client_id: u32,
    /// Layout plan produced by the loader for mmsrv at Stage E.
    pub mmsrv_layout: Option<VmClientLayout>,

    /// init's own layout plan, captured when init registers itself with
    /// mmsrv in Stage E. Kept so any later self-mutation (init itself
    /// never re-execs today) sees the same layout the kernel-side
    /// bookkeeping does.
    pub init_layout: Option<VmClientLayout>,

    /// mmsrv fault dispatcher TCB cap (init-side). Spawned by
    /// `spawn_mmsrv` as a second TCB inside mmsrv's process; shares
    /// the mmsrv VSpace + CSpace + client_id.
    pub mmsrv_fault_dispatcher_tcb: Option<OwnedCap>,

    /// init-side recv of the unit_mgr ↔ namesrv subscribe channel.
    /// namesrv writes a `NAMESRV_REGISTER_EVENT` message every time a
    /// publisher's REGISTER succeeds; init's owner loop reads them
    /// off this MP and feeds the prefix into
    /// `unit_mgr::on_namesrv_register`.
    pub unit_mgr_namesrv_event_mp_recv: Option<OwnedCap>,
    /// Send side of the same MP. Transferred into namesrv via
    /// `NAMESRV_SUBSCRIBE_REGISTER`; set to `None` after the call.
    pub unit_mgr_namesrv_event_mp_send: Option<OwnedCap>,
    /// Watch slot in init's CSpace that arms a Watch on
    /// `unit_mgr_namesrv_event_mp_recv` so the control EQ surfaces an
    /// event whenever namesrv publishes a register notification.
    pub unit_mgr_namesrv_event_watch: Option<OwnedCap>,

    /// Encoded cookies returned by `state.cookie_table.arm` for each
    /// boot-time-armed Watch. The master service-MP Watch is consumed
    /// by each core-ready message during Stage D/E/F and re-armed with
    /// its saved cookie so the live_gen survives across re-arms. Zero
    /// before the corresponding Watch is armed.
    pub master_service_mp_watch_cookie: u64,
    pub control_timer_watch_cookie: u64,
    pub worker_completion_watch_cookie: u64,
    pub namesrv_register_event_watch_cookie: u64,
}

impl StartupCaps {
    pub const fn zeroed() -> Self {
        Self {
            bootinfo_frame: None,
            control_eq: None,
            worker_completion_eq: None,
            control_timer: None,
            recv_scratch_base: 0,
            initrd_va: 0,
            initrd_len: 0,
            framebuffer: SaltyOSFramebufferInfoV1::zeroed(),
            master_service_mp_recv: None,
            master_service_mp_send: None,
            namesrv_client_mp: None,
            namesrv_master_mp_send_raw: None,
            ldsrv_client_ep: None,
            rsrcsrv_client_mp: None,
            mmsrv_root_control_cap: None,
            mmsrv_self_control_cap: None,
            namesrv_mmsrv_control_cap: None,
            rsrcsrv_mmsrv_control_cap: None,
            vfs_root_control_cap: None,
            mmsrv_self_mp: None,
            init_client_id: 0,
            namesrv_main_tcb: None,
            namesrv_vspace: None,
            namesrv_client_id: 0,
            namesrv_layout: None,
            rsrcsrv_main_tcb: None,
            rsrcsrv_vspace: None,
            rsrcsrv_client_id: 0,
            rsrcsrv_layout: None,
            mmsrv_main_tcb: None,
            mmsrv_vspace: None,
            mmsrv_client_id: 0,
            mmsrv_layout: None,
            init_layout: None,
            mmsrv_fault_dispatcher_tcb: None,
            unit_mgr_namesrv_event_mp_recv: None,
            unit_mgr_namesrv_event_mp_send: None,
            unit_mgr_namesrv_event_watch: None,
            master_service_mp_watch_cookie: 0,
            control_timer_watch_cookie: 0,
            worker_completion_watch_cookie: 0,
            namesrv_register_event_watch_cookie: 0,
        }
    }
}

pub struct SupervisorState {
    pub caps: StartupCaps,
    pub untyped: UntypedChunks,
    pub manifest: ServiceManifest,
    pub unit_graph: UnitGraph,
    pub procs: PidTable,
    pub interfaces: InterfaceRegistry,
    pub lifecycle: LifecycleStreams,
    /// Monotonic counter for badge tcb_id population. The kernel's
    /// `TCB_GET_TRACE_ID` is the authoritative source — but until each
    /// child's main TCB exists init mints publisher/request badges
    /// using this monotonic id, so the supervisor and clients agree on
    /// which `(client_id, tcb_id)` pair refers to which process.
    pub next_client_id: u32,
    /// Stage-D readiness: every subsystem service has signalled boot.
    /// Pre-readiness, init runs at the boot pace; post-readiness it
    /// transitions to runtime mode (allocator gets self-expand handler,
    /// per-spawn fault MP retroactive binding completes).
    pub runtime_ready: bool,
    /// Cookie table for the owner reactor — every armed Watch
    /// registers its `(kind, slot, live_gen)` triple here. Backed by
    /// `segment_allocator`; lookups validate the live_gen so stale
    /// fires after teardown drop without dispatching.
    pub cookie_table: CookieTable<InitTarget>,
    /// Self-storage allocator for `cookie_table` and any other
    /// init-internal `SegmentedArray<T>`. mmsrv doesn't exist yet at
    /// init's reactor-startup, so growth retypes pages from
    /// `state.untyped.init_private` and maps them into init's own
    /// VSpace at `INIT_SEGMENT_SCRATCH_BASE+`.
    pub segment_allocator: InitSegmentAllocator,
    /// Untyped-backed child allocator for init's slab page source. Owns
    /// a dedicated untyped chunk (carved from `init_private` at boot,
    /// separate from `segment_allocator`'s cookie-table FRAMEs) so its
    /// exhaustion-reset can never recycle a chunk holding live cookie
    /// tables.
    pub frames: FrameAllocator,
    /// `PageBacking` for init's `trona_server` slabs (PID table,
    /// lifecycle stream, per-record extras). Retypes one MemoryObject
    /// per buffer from `frames` and maps it into init's VSpace at
    /// `INIT_SLAB_SCRATCH_BASE+`.
    pub self_vm: InitSelfVm,
    /// Send end of the private PID1→ldsrv adopt MP, held between ldsrv's spawn
    /// (where the recv end is delivered to it) and the post-spawn
    /// `send_adopt_set` that streams the boot code set and moves the
    /// ExecAuthority over it.
    pub ldsrv_adopt_send: Option<OwnedCap>,
    /// Send end of the private PID1→ldsrv exec-control MP. Held for init's
    /// lifetime (unlike the boot-only adopt send): every `resolve_main` for a
    /// program main image goes over this dedicated channel, so conferring
    /// EXECUTE on a caller-supplied backing is gated to init.
    pub ldsrv_exec_control_send: Option<OwnedCap>,
    /// Whether init still holds the boot `ExecAuthority` (`SLOT_EXEC_AUTHORITY`).
    /// True until the Stage-1 handoff MOVEs it to `ldsrv` (`move_authority`);
    /// afterwards init can no longer mint executable code MOs itself and resolves
    /// them through `ldsrv` instead.
    pub exec_authority_held: bool,
}

impl SupervisorState {
    pub const fn new() -> Self {
        Self {
            caps: StartupCaps::zeroed(),
            untyped: UntypedChunks::zeroed(),
            manifest: ServiceManifest::new(),
            unit_graph: UnitGraph::new(),
            procs: PidTable::new(),
            interfaces: InterfaceRegistry::new(),
            lifecycle: LifecycleStreams::new(),
            next_client_id: 1,
            runtime_ready: false,
            cookie_table: CookieTable::new_empty(),
            segment_allocator: InitSegmentAllocator::new(),
            frames: FrameAllocator::new(),
            self_vm: InitSelfVm::new(),
            ldsrv_adopt_send: None,
            ldsrv_exec_control_send: None,
            exec_authority_held: true,
        }
    }

    /// Allocate a fresh `client_id` for badge mint. `client_id == 0` is
    /// reserved (it would mean "unbadged" and we need that signal for
    /// debug paths).
    pub fn alloc_client_id(&mut self) -> u32 {
        // Skip 0 (the "unbadged" signal), the reserved core-server ids, and
        // any id still held by a live or pre-created client, so a fresh
        // client_id never collides with a live one and vfs bind-adoption by
        // client_id stays unambiguous even after the monotonic counter wraps.
        loop {
            let id = self.next_client_id;
            self.next_client_id = self.next_client_id.wrapping_add(1);
            if self.next_client_id == 0 {
                self.next_client_id = 1;
            }
            if id == 0
                || id == self.caps.init_client_id
                || id == self.caps.namesrv_client_id
                || id == self.caps.rsrcsrv_client_id
                || id == self.caps.mmsrv_client_id
                || self.procs.find_by_client_id(id).is_some()
            {
                continue;
            }
            return id;
        }
    }

    /// Locate the per-client request-MP `ProcessRecord` whose
    /// `client_id` matches the badge. Owner-thread only.
    pub fn find_proc_by_client_id_mut(&mut self, client_id: u32) -> Option<&mut ProcessRecord> {
        self.procs.find_by_client_id_mut(client_id)
    }
}
