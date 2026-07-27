// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner-thread state — `VfsState`.
//!
//! Single-mutator invariant: every field of `VfsState` is mutated
//! only by the owner reactor TCB. Backend daemons and pager
//! completions communicate back through `PendingOp` records; vfs
//! does not spawn local helper threads for backend I/O.
//!
//! The spine carried here is the minimum every reactor handler
//! needs: `clients`, `open_objects`, `mounts`, `vnodes`,
//! `pending_ops`, `backend_sessions`, the reactor itself, the
//! resolver cache, the badge map, id counters. Specialty arenas
//! (page cache, shm, pipes, sockets, poll waiters, epoll
//! instances) land alongside their respective handlers in their
//! own modules.

pub(crate) mod client_shm;
pub(crate) mod clients;
pub(crate) mod deferred;
pub(crate) mod dependency;
pub(crate) mod fb_completion;
pub(crate) mod init_rpc;
pub(crate) mod mm_ipc;
pub(crate) mod namei_aux;
pub(crate) mod net_completion;
pub(crate) mod op;
pub(crate) mod ordering;
pub(crate) mod ordering_drain;
pub(crate) mod page_cache;
pub(crate) mod page_cache_lru;
pub(crate) mod pager_rpc;
pub(crate) mod pending;
pub(crate) mod pipe_wait;
pub(crate) mod pty_completion;
pub(crate) mod reactor;
pub(crate) mod reclaim;
pub(crate) mod resume;
pub(crate) mod session;
pub(crate) mod timer;

use trona_kernel::core_types::Cap;
use trona_runtime::core::slot_alloc::{OwnedCap, OwnedMpPair, OwnedRecordedCap};
use trona_server::ReplyLease;

use crate::arena::Arena;
use crate::arena::badge_map::BadgeMap;
use crate::arena::segmented_array::SegmentedArray;
use crate::core::byte_range_lock::ByteRangeLock;
use crate::core::error::VfsError;
use crate::core::identity::{VNODE_RESOLVE_CACHE_CAP, VnodeResolveCacheEntry};
use crate::core::mount::{Mount, MountHandle};
use crate::core::shm::ShmData;
use crate::core::vnode::{Vnode, VnodeHandle};
use crate::owner::client_shm::{CLIENT_SHM_INITIAL_CAP, ClientShmRegion};
use crate::owner::clients::ClientState;
use crate::owner::namei_aux::NameiAuxState;
use crate::owner::ordering::OrderingGate;
use crate::owner::page_cache::PageCacheEntry;
use crate::owner::pending::{PendingOp, PendingOpHandle};
use crate::owner::session::BackendSessionSlot;
use crate::personality::posix::types::EpollInstance;
use crate::personality::win32::cwd_table::Win32CwdTable;
use crate::personality::win32::open_state::Win32HandleState;
use crate::server::open_object::{OpenObject, OpenObjectNamedState};

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct PollWaiter {
    pub(crate) target_op: PendingOpHandle,
    pub(crate) kind_byte: u8,
    _pad: [u8; 3],
    pub(crate) next: u32,
}

const SHM_NAME_MAX: usize = 32;

/// Initial slot count for the in-flight VFS→init read snapshot arena.
/// Concurrent parked init reads are few (procfs / sysctl / ctty), so a
/// small segment suffices; the arena grows on demand.
const INIT_SNAPSHOTS_INITIAL_CAP: u32 = 8;
const SHM_NAME_TABLE_CAP: usize = 64;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct ShmNameEntry {
    active: u8,
    name_len: u8,
    _pad: [u8; 2],
    handle: crate::arena::handle::Handle<ShmData>,
    name: [u8; SHM_NAME_MAX],
}

impl ShmNameEntry {
    const EMPTY: Self = Self {
        active: 0,
        name_len: 0,
        _pad: [0; 2],
        handle: crate::arena::handle::Handle::INVALID,
        name: [0; SHM_NAME_MAX],
    };

    fn matches_name(&self, name: &[u8]) -> bool {
        self.active != 0
            && usize::from(self.name_len) == name.len()
            && &self.name[..name.len()] == name
    }
}

/// `mo_id` → vnode binding installed when mmsrv's `MM_FILE_MMAP`
/// reply lands. The pager-event handler walks this table to resolve
/// a kernel-supplied `mo_id` (`record.object_id`) back to its
/// originating vnode + file extent so it can issue the matching
/// backend READ. Removed when the mapping is torn down via
/// `PAGER_DETACH` / vnode eviction.
///
/// `MoBinding` is the sole owner of the `mo_cap` cspace slot;
/// `release_mo_binding` tears it down explicitly, after which the
/// slot becomes null so the arena entry's eventual overwrite-drop is
/// a no-op.
pub(crate) struct MoBinding {
    pub mo_id: u64,
    /// Stable cspace slot in vfs holding mmsrv's mo_cap reply
    /// (moved out of `recv_scratch_slot` at install time). Owned
    /// exclusively by this binding; callers that need the raw
    /// slot id for invokes (MO_READ, MO_DECOMMIT, PAGER_SUPPLY_COPY)
    /// call `.mo_cap.as_raw()`. Clients that ask for the backing MO
    /// via `VFS_GET_BACKING_MO` receive a `dup_for_transfer` copy.
    pub mo_cap: OwnedCap,
    pub vnode: VnodeHandle,
    pub file_offset: u64,
    pub length: u64,
    pub active: bool,
}

/// Copy projection returned by `lookup_binding_by_vnode` /
/// `lookup_binding_by_mo_id`. Carries only the fields callers
/// need — `mo_cap_raw` is the raw slot id for invokes (mo_read,
/// MO_DECOMMIT, VFS_GET_BACKING_MO dup) without transferring
/// ownership. `MoBinding` in the arena remains the sole owner.
#[derive(Clone, Copy)]
pub(crate) struct MoBindingView {
    pub mo_id: u64,
    /// Raw capability slot — borrow of `MoBinding.mo_cap.as_raw()`.
    /// Valid as long as the binding is active; do not store across
    /// release_mo_binding calls.
    pub mo_cap_raw: Cap,
    pub vnode: VnodeHandle,
    pub file_offset: u64,
    pub length: u64,
}

/// Initial Arena segment caps. Picked so that an idle vfs (no
/// clients yet) takes ~32 KiB of frame backing across the core
/// arenas.
const VNODES_INITIAL_CAP: u32 = 64;
const MOUNTS_INITIAL_CAP: u32 = 16;
const CLIENTS_INITIAL_CAP: u32 = 32;
const OPEN_OBJECTS_INITIAL_CAP: u32 = 64;
const OPEN_OBJECT_NAMED_STATES_INITIAL_CAP: u32 = 32;
const WIN32_HANDLE_STATES_INITIAL_CAP: u32 = 32;
const BACKEND_SESSIONS_INITIAL_CAP: u32 = 16;
const PIPES_INITIAL_CAP: u32 = 32;
const SOCKETS_INITIAL_CAP: u32 = 32;
const SHM_INITIAL_CAP: u32 = 16;
const EPOLLS_INITIAL_CAP: u32 = 16;
const POLL_WAITERS_INITIAL_CAP: u32 = 64;
const BYTE_RANGE_LOCKS_INITIAL_CAP: u32 = 32;
/// Async namei walker scratch slots — symlink target / dual-path
/// rename / link state. Picked low because `NameiAuxState`
/// inline-buffers are large (~4 KiB per Rename slot); the arena
/// auto-grows the next segment by doubling indefinitely if more
/// concurrent multi-stage walks are in flight.
const NAMEI_AUX_INITIAL_CAP: u32 = 4;
/// Page-cache initial cap. The arena auto-grows by doubling once
/// the file-backed working set exceeds this floor; picked so a
/// quiescent vfs (no file mappings) keeps the backing frame small.
const PAGE_CACHE_INITIAL_CAP: u32 = 32;

/// Per-VFS singleton state.
pub(crate) struct VfsState {
    // ---- core arenas ----
    pub vnodes: Arena<Vnode>,
    pub mounts: Arena<Mount>,
    pub clients: Arena<ClientState>,
    pub open_objects: Arena<OpenObject>,
    /// Optional personality-neutral parent/name state attached to
    /// open file descriptions.
    pub open_object_named_states: Arena<OpenObjectNamedState>,
    pub pending_ops: trona_server::ContinuationArena<PendingOp>,
    /// Parked async VFS→init reads (procfs / sysctl / ctty). Each entry
    /// owns the originating client's reply-lease + typed results across
    /// the read's init-query chain; resumed by `init_rpc` on the
    /// `KIND_INIT_REPLY` channel. Keeps the VFS reactor off a blocking
    /// `mp_call` to init (one side of the init↔VFS deadlock).
    pub init_snapshots: Arena<crate::owner::init_rpc::InitQuerySnapshot>,
    pub backend_sessions: Arena<BackendSessionSlot>,
    /// Anonymous-pipe / FIFO ring buffers.
    pub pipes: Arena<crate::core::pipe::PipeState>,
    /// Socket / socketpair backing.
    pub sockets: Arena<crate::core::socket::SocketState>,
    /// Shared-memory descriptors.
    pub shm_data: Arena<crate::core::shm::ShmData>,
    /// POSIX shm_open namespace. Names are independent from the
    /// filesystem tree and pin the matching `ShmData` slot until
    /// `shm_unlink` drops the entry.
    pub shm_names: [ShmNameEntry; SHM_NAME_TABLE_CAP],
    /// POSIX epoll interest tables. Epoll fds are synthetic
    /// `OpenObject`s whose `personality_aux` stores the epoll arena slot.
    pub epolls: Arena<EpollInstance>,
    /// Shared intrusive waiter nodes for socket / tty / INET readiness
    /// queues. Queue heads live on the owning object and store arena slots.
    pub poll_waiters: Arena<PollWaiter>,
    /// Byte-range advisory locks. Records hang off
    /// `Vnode.locks_head` via intrusive `next` link. Used by
    /// Win32 `NtLockFile` / `NtUnlockFile` and POSIX
    /// `fcntl(F_SETLK)` / `fcntl(F_SETLKW)` / `fcntl(F_GETLK)`.
    pub byte_range_locks: Arena<ByteRangeLock>,
    /// Win32-only per-client current-drive / per-drive cwd state.
    /// Stored as a sidecar so the neutral `ClientState` remains
    /// personality-agnostic while NT path decoding can still honour
    /// `C:foo` and current-drive relative path semantics.
    pub win32_cwd: Win32CwdTable,
    /// Win32-only per-HANDLE state. Vnode-backed Win32
    /// `OpenObject`s store this arena's slot in `personality_aux`.
    pub win32_handle_states: Arena<Win32HandleState>,
    /// Async namei walker scratch storage — symlink target bytes,
    /// dual-path rename / link state. Owned by `posix/symlink`,
    /// `posix/rename`, `posix/link`. Released by the terminal
    /// callback or by `cancel_for_badge` on client teardown.
    pub namei_aux: Arena<NameiAuxState>,
    /// Per-client bulk-transfer SHM regions. One region per client
    /// once it calls `VFS_REGISTER_BULK_SHM`; allocator is keyed
    /// off `VfsState.next_shm_id`. Region release driven by
    /// `VFS_RELEASE_BULK_SHM` or by `remove_client` on
    /// `PEER_CLOSED`.
    pub client_shm_regions: Arena<ClientShmRegion>,
    /// Monotonic SHM id used as the `mmsrv MM_SHM_CREATE` key.
    /// Bumped per registration; never reused (mmsrv refuses
    /// duplicate ids on `MM_SHM_CREATE`).
    pub next_shm_id: u64,

    // ---- client lookup ----
    pub badge_map: BadgeMap,
    /// Dedicated per-client-slot reuse counter for control-cap ABA safety.
    /// Indexed by the `clients` arena slot; each entry holds the epoch to
    /// assign at the next init-driven register for that slot, starting at 1
    /// and bumped on every control-client teardown. Kept outside
    /// `ClientState` because the arena zeroes a slot's data on reuse, which
    /// would otherwise reset the counter and defeat ABA safety. Distinct
    /// from the arena's own slot epoch (which is only 32-bit and only bumps
    /// on sweep).
    pub client_control_epochs: SegmentedArray<u64>,
    /// Single-slot pending secondary operand for the two-step admin clone:
    /// the child is pinned by `VFS_ADMIN_CLONE_SET_PARTNER` before the
    /// parent drives `VFS_ADMIN_CLONE_FDS`. init is the sole serial driver,
    /// so one slot suffices; it is overwritten on a fresh SET_PARTNER,
    /// consumed by the operate step, and cleared on the secondary's teardown.
    pub admin_clone_pending: crate::owner::clients::ControlPending,

    // ---- reactor ----
    /// Owner thread's main EQ. Frontend / backend / pager / timer
    /// all fan in here via `EventLoop`.
    pub owner_eq: OwnedCap,
    /// Service-EP recv side — namesrv-published master MP. The
    /// frontend cookie table arms a Watch over this on `owner_eq`.
    pub service_ep_recv: Cap,
    /// One-shot Watch armed on `service_ep_recv` for frontend
    /// readability.
    pub frontend_watch_cap: OwnedCap,
    /// Cookie used when arming `frontend_watch_cap`.
    pub frontend_cookie: u64,
    /// init connection endpoint (`init_ep`) — a process-lifetime cap
    /// from the startup table. VFS both writes async init queries to it
    /// and (via `init_watch_cap`) watches its recv side for replies.
    pub init_ep_cap: Cap,
    /// One-shot Watch armed on `init_ep_cap`'s readable state, bound to
    /// `owner_eq` with a `KIND_INIT_REPLY` cookie.
    pub init_watch_cap: OwnedCap,
    /// Cookie used when arming `init_watch_cap`.
    pub init_cookie: u64,
    /// Stable cnode slot used as receive scratch for inbound payload
    /// caps. Allocated once at reactor boot via `slot_alloc_or_idle`;
    /// the owner reactor clears and re-arms it before each receive
    /// iteration.
    pub recv_scratch_slot: u64,
    /// Owner-private kernel Timer cap. Lazily retyped when the
    /// first finite `poll(2)` wait parks. The Timer publishes
    /// `EVENT_TYPE_TIMER` records into `owner_eq` with
    /// `KIND_TIMER` cookies.
    pub owner_timer_cap: OwnedCap,
    /// Absolute monotonic deadline currently armed on
    /// `owner_timer_cap`, or 0 when no owner timer is armed.
    pub owner_timer_deadline_ns: u64,
    // ---- id counters ----
    pub next_tx_id: u64,
    pub next_session_id: u32,
    pub next_fs_instance_id: u64,
    pub next_pager_gen: u32,

    // ---- resolver cache ----
    pub vnode_resolve_cache: [VnodeResolveCacheEntry; VNODE_RESOLVE_CACHE_CAP],

    // ---- bootstrap flags ----
    /// Set once mmsrv has acknowledged `MM_REGISTER_VFS_PAGER`.
    /// File-backed mmap paths refuse before this flips.
    pub mmsrv_pager_registered: bool,
    /// vfs-owned `OBJ_PAGER` cap. Retyped + bound to `owner_eq` via
    /// `PAGER_BIND_EQ` at boot; the kernel echoes `pager_cookie` on
    /// every `KERNITE_EVENT_TYPE_PAGER_REQUEST` event so the pager
    /// dispatcher can resolve the inbound mo_id. A copy is shipped
    /// to mmsrv via `MM_REGISTER_VFS_PAGER`. Null until
    /// [`pager_rpc::ensure_pager_session`] succeeds.
    pub pager_cap: OwnedCap,
    /// Cookie published to `PAGER_BIND_EQ`; encoded as
    /// `(KIND_PAGER, slot=0, live_gen=1)` so the owner reactor's
    /// EQ-wait demux can route every `EVENT_TYPE_PAGER_REQUEST`
    /// record into the pager handler without a second lookup.
    pub pager_cookie: u64,
    /// Dedicated mmsrv→VFS MessagePipe for explicit MAP_SHARED writeback
    /// requests. mmsrv receives a copy of the send side at pager registration;
    /// the recv side is watched by the owner reactor under
    /// `KIND_MMSRV_WRITEBACK`.
    pub mmsrv_writeback_mp: Option<OwnedMpPair>,
    /// One-shot Watch armed on `mmsrv_writeback_mp.recv`.
    pub mmsrv_writeback_watch_cap: Option<OwnedRecordedCap>,
    /// Cookie used when arming `mmsrv_writeback_watch_cap`.
    pub mmsrv_writeback_cookie: u64,
    /// Explicit mmsrv `MM_MSYNC` / file-backed `MM_MUNMAP` barriers keyed by
    /// the mmsrv-supplied writeback token. VFS completes the token only after
    /// every dirty page in that MO range has reached the backing VOP or failed.
    pub mmsrv_writeback_barriers:
        trona_server::ContinuationArena<crate::owner::pager_rpc::MmsrvWritebackBarrier>,
    /// Lossless VFS→mmsrv `MM_VFS_WRITEBACK_DONE` queue. This is fixed-size
    /// and allocation-free so a completion never asks mmsrv for memory while
    /// mmsrv is parked behind the same completion.
    pub mmsrv_writeback_done_queue: crate::owner::pager_rpc::MmsrvWritebackDoneQueue,
    /// One-shot Watch armed on the mmsrv completion endpoint's WRITABLE bit.
    pub mmsrv_writeback_done_watch_cap: Option<OwnedRecordedCap>,
    /// Cookie used when arming `mmsrv_writeback_done_watch_cap`.
    pub mmsrv_writeback_done_cookie: u64,
    /// `(mo_id → vnode + file_handle + file_offset + length)`
    /// directory populated when mmsrv's `MM_FILE_MMAP` reply lands.
    /// The pager-event handler resolves the kernel-supplied
    /// `mo_id` against this table to locate the originating vnode
    /// before issuing the backend READ. Linear scan — entry count
    /// is bounded by the live file-backed mmap working set, which
    /// stays small in practice.
    pub pager_bindings: SegmentedArray<MoBinding>,
    /// Page-sized staging buffer for the page-cache supply path. The sync
    /// backend (ramfs/tmpfs) fills it in `handle_pager_request_event` and
    /// hands its VA to `PAGER_SUPPLY_COPY`, which copies the bytes into the
    /// kernel-sourced page-cache page. One buffer suffices: sync pager
    /// events are serviced to completion before the next is dequeued, and
    /// async (saltyfs) events stage their bytes in the mount SHM ring, not
    /// here.
    pub pager_read_buf: [u8; uapi::KERNITE_PAGE_BYTES as usize],
    /// Set once `NAMESRV_REGISTER("vfs")` has succeeded — the
    /// `Type=broker` readiness signal that unit_mgr consumes to
    /// unblock `Requires=vfs.socket` consumers.
    pub namesrv_registered: bool,

    // ---- namespace root ----
    //
    // Bootstrap mount handle pointing at the process namespace
    // root. Set during `boot::extract_initrd` once the initial
    // ramfs mount lands; resolves the root vnode for path walks
    // that originate at "/". `MountHandle::INVALID` before
    // bootstrap completes.
    pub root_mount: MountHandle,
    /// Deferred root-pivot repair table. When the disk root
    /// mounts over the initrd root, existing child mounts under
    /// the old root are migrated to matching directories on the
    /// new root through generic lookup/mkdir VOPs. Backend-backed
    /// lookups park through `FsResume::LatePivot`.
    pub late_pivot: crate::boot::late_mount::LatePivotTable,

    // ---- domain-default mount registry ----
    //
    // POSIX `socket(2)` and the path-less device opens (e.g.,
    // `/dev/ptmx` resolution) do not carry a path the namei
    // walker can resolve to a mount. The path-less syscall site
    // looks up the matching mount here instead. Init's mount
    // manifest populates these slots when it mounts the inet /
    // pty / fb providers; vfs never hard-codes the backend names
    // — the only knowledge it has is "this is the mount handle
    // that owns AF_INET" / "this is the mount handle that owns
    // pty" — both injected by manifest mount entries.
    /// Mount handle owning AF_INET / AF_INET6 sockets. Set on
    /// the first successful `mount(target, "inet", ...)`.
    /// `MountHandle::INVALID` until then; a `socket(AF_INET, …)`
    /// call lands `EAFNOSUPPORT` while invalid.
    pub default_inet_mount: MountHandle,
    /// Mount handle owning pty (TTY / PTMX / pts) operations.
    /// Set on the first successful `mount(target, "pty", ...)`.
    pub default_pty_mount: MountHandle,
    /// Mount handle owning framebuffer device operations. Set
    /// on the first successful `mount(target, "fb", ...)`.
    pub default_fb_mount: MountHandle,

    // ---- ordering coordinator ----
    //
    // Per-key FIFO + barrier waiter for vfs reply ordering. Issuing
    // helpers (saltyfs `BACKEND_*`, MAP_SHARED writeback, fsync
    // barrier collection) thread their `(OrderingKey, TxId)` pair
    // through this gate so happens-after relationships between
    // backend RPCs survive even when the backend processes its
    // queue out of order.
    pub ordering: OrderingGate,

    // ---- page cache ----
    //
    // File-backed page residency tracker. Keyed by
    // `(VnodeHandle, page_offset)`; `lru_head` / `lru_tail`
    // anchor the intrusive doubly-linked LRU list rooted on
    // [`PageCacheEntry::lru_prev` / `lru_next`].
    pub page_cache: Arena<PageCacheEntry>,
    pub page_cache_lru_head: u32,
    pub page_cache_lru_tail: u32,

    /// Round-robin cursor for the incremental reclaim sweep. Each
    /// `reclaim::sweep_once` advances it over the reclaim groups so a
    /// single idle tick processes one group (two under pressure)
    /// instead of walking every arena.
    pub sweep_cursor: u32,
}

impl VfsState {
    /// Construct an empty `VfsState`. Returns `None` if any of the
    /// initial Arena allocations fail.
    pub(crate) fn new() -> Option<Self> {
        Some(Self {
            vnodes: Arena::new(VNODES_INITIAL_CAP)?,
            mounts: Arena::new(MOUNTS_INITIAL_CAP)?,
            clients: Arena::new(CLIENTS_INITIAL_CAP)?,
            open_objects: Arena::new(OPEN_OBJECTS_INITIAL_CAP)?,
            open_object_named_states: Arena::new(OPEN_OBJECT_NAMED_STATES_INITIAL_CAP)?,
            pending_ops: trona_server::ContinuationArena::new_empty(),
            init_snapshots: Arena::new(INIT_SNAPSHOTS_INITIAL_CAP)?,
            backend_sessions: Arena::new(BACKEND_SESSIONS_INITIAL_CAP)?,
            pipes: Arena::new(PIPES_INITIAL_CAP)?,
            sockets: Arena::new(SOCKETS_INITIAL_CAP)?,
            shm_data: Arena::new(SHM_INITIAL_CAP)?,
            shm_names: [ShmNameEntry::EMPTY; SHM_NAME_TABLE_CAP],
            epolls: Arena::new(EPOLLS_INITIAL_CAP)?,
            poll_waiters: Arena::new(POLL_WAITERS_INITIAL_CAP)?,
            byte_range_locks: Arena::new(BYTE_RANGE_LOCKS_INITIAL_CAP)?,
            win32_cwd: Win32CwdTable::zeroed(),
            win32_handle_states: Arena::new(WIN32_HANDLE_STATES_INITIAL_CAP)?,
            namei_aux: Arena::new(NAMEI_AUX_INITIAL_CAP)?,
            client_shm_regions: Arena::new(CLIENT_SHM_INITIAL_CAP)?,
            next_shm_id: 0x1000_0000_0000_0000,
            badge_map: BadgeMap::new(32)?,
            client_control_epochs: SegmentedArray::new_empty(),
            admin_clone_pending: crate::owner::clients::ControlPending::EMPTY,
            owner_eq: OwnedCap::null(),
            service_ep_recv: 0,
            frontend_watch_cap: OwnedCap::null(),
            frontend_cookie: 0,
            init_ep_cap: 0,
            init_watch_cap: OwnedCap::null(),
            init_cookie: 0,
            recv_scratch_slot: 0,
            owner_timer_cap: OwnedCap::null(),
            owner_timer_deadline_ns: 0,
            next_tx_id: 1,
            next_session_id: 1,
            next_fs_instance_id: 1,
            next_pager_gen: 1,
            vnode_resolve_cache: [VnodeResolveCacheEntry::EMPTY; VNODE_RESOLVE_CACHE_CAP],
            mmsrv_pager_registered: false,
            pager_cap: OwnedCap::null(),
            pager_cookie: 0,
            mmsrv_writeback_mp: None,
            mmsrv_writeback_watch_cap: None,
            mmsrv_writeback_cookie: 0,
            mmsrv_writeback_barriers: trona_server::ContinuationArena::new_empty(),
            mmsrv_writeback_done_queue: crate::owner::pager_rpc::MmsrvWritebackDoneQueue::new_empty(
            ),
            mmsrv_writeback_done_watch_cap: None,
            mmsrv_writeback_done_cookie: crate::ipc::cookie::encode_cookie(
                crate::ipc::cookie::KIND_MMSRV_WRITEBACK_DONE,
                0,
                0,
            ),
            pager_bindings: SegmentedArray::new_empty(),
            pager_read_buf: [0u8; uapi::KERNITE_PAGE_BYTES as usize],
            namesrv_registered: false,
            root_mount: MountHandle::INVALID,
            late_pivot: crate::boot::late_mount::LatePivotTable::EMPTY,
            default_inet_mount: MountHandle::INVALID,
            default_pty_mount: MountHandle::INVALID,
            default_fb_mount: MountHandle::INVALID,
            ordering: OrderingGate::new(),
            page_cache: Arena::new(PAGE_CACHE_INITIAL_CAP)?,
            page_cache_lru_head: u32::MAX,
            page_cache_lru_tail: u32::MAX,
            sweep_cursor: 0,
        })
    }

    /// In-place construction on a freshly mapped `VfsState` page.
    /// `boot::init_state_in_place` calls this against an
    /// `MM_MMAP`-allocated VA so the giant `vnode_resolve_cache`
    /// array (~16 KiB) and the rest of the spine never need to live
    /// on the caller's stack between construction and storage.
    ///
    /// SAFETY: `state_ptr` must point to writable memory at least
    /// `::core::mem::size_of::<VfsState>()` bytes wide and not yet
    /// hosting a live `VfsState`. The caller owns the storage for
    /// the lifetime of the returned construct; on `Err` the
    /// pointed-to bytes remain uninitialised.
    pub(crate) unsafe fn init_into(state_ptr: *mut Self) -> Result<(), VfsError> {
        let state = Self::new().ok_or(VfsError::NoMem)?;
        unsafe {
            ::core::ptr::write(state_ptr, state);
        }
        Ok(())
    }

    /// Allocate the next monotonic transaction id. The 0 sentinel
    /// is reserved (`TxId::INVALID`); we skip wraparound back onto
    /// 0 by re-incrementing.
    /// Mint a fresh `FsInstanceId` for a new mount. Counter is
    /// monotonic and skips zero so the `FsInstanceId::INVALID`
    /// sentinel stays distinct from any live id.
    pub(crate) fn next_fs_instance_id(&mut self) -> crate::core::identity::FsInstanceId {
        let id = self.next_fs_instance_id;
        self.next_fs_instance_id = id.wrapping_add(1);
        if self.next_fs_instance_id == 0 {
            self.next_fs_instance_id = 1;
        }
        crate::core::identity::FsInstanceId::new(if id == 0 { 1 } else { id })
    }

    /// Mint a fresh mmsrv SHM region id. The vfs-side counter
    /// starts above the bulk-shm range so backend-driven SHM
    /// regions (saltyfs readdir / xattr ring) cannot collide with
    /// per-client bulk SHM ids minted on the client request path.
    pub(crate) fn alloc_shm_id(&mut self) -> u64 {
        let id = self.next_shm_id;
        self.next_shm_id = id.wrapping_add(1);
        if self.next_shm_id == 0 {
            self.next_shm_id = 0x1000_0000_0000_0000;
        }
        id
    }

    pub(crate) fn shm_name_table_lookup(
        &self,
        handle: crate::arena::handle::Handle<ShmData>,
    ) -> Option<&[u8]> {
        for entry in &self.shm_names {
            if entry.active != 0
                && entry.handle.slot() == handle.slot()
                && entry.handle.epoch() == handle.epoch()
            {
                return Some(&entry.name[..usize::from(entry.name_len)]);
            }
        }
        None
    }

    pub(crate) fn shm_name_table_insert(
        &mut self,
        name: &[u8],
        handle: crate::arena::handle::Handle<ShmData>,
    ) -> bool {
        if name.is_empty() || name.len() > SHM_NAME_MAX || !handle.is_valid() {
            return false;
        }
        let name_len = match u8::try_from(name.len()) {
            Ok(value) => value,
            Err(_) => return false,
        };
        let mut free_idx = None;
        for (idx, entry) in self.shm_names.iter().enumerate() {
            if entry.matches_name(name) {
                return false;
            }
            if entry.active == 0 && free_idx.is_none() {
                free_idx = Some(idx);
            }
        }
        let Some(idx) = free_idx else {
            return false;
        };
        let entry = &mut self.shm_names[idx];
        *entry = ShmNameEntry::EMPTY;
        entry.active = 1;
        entry.name_len = name_len;
        entry.handle = handle;
        entry.name[..name.len()].copy_from_slice(name);
        true
    }

    pub(crate) fn shm_name_table_remove(
        &mut self,
        name: &[u8],
    ) -> Option<crate::arena::handle::Handle<ShmData>> {
        for entry in self.shm_names.iter_mut() {
            if entry.matches_name(name) {
                let handle = entry.handle;
                *entry = ShmNameEntry::EMPTY;
                return Some(handle);
            }
        }
        None
    }

    pub(crate) fn alloc_tx_id(&mut self) -> crate::owner::pending::TxId {
        let mut id = self.next_tx_id;
        if id == 0 {
            id = 1;
        }
        self.next_tx_id = id.wrapping_add(1);
        crate::owner::pending::TxId(id)
    }

    /// Locate the live PendingOp whose `tx_id` matches the inbound
    /// completion's correlation header. The op's `tx_id` is its key in
    /// the continuation arena, so this is the arena's own
    /// `lookup_token`. Returns `None` if the slot has already been
    /// reclaimed (stale completion).
    pub(crate) fn find_pending_op(
        &self,
        tx_id: crate::owner::pending::TxId,
    ) -> Option<PendingOpHandle> {
        self.pending_ops.lookup_token(tx_id.raw())
    }

    /// Borrow a backend-session slot by its arena index. Returns
    /// `None` for empty slots (`BackendSessionSlot::is_empty`)
    /// even if the index is in range — the dispatcher's 5-tuple
    /// check should drop "session torn down" replies just as it
    /// drops "wrong session_id".
    pub(crate) fn backend_session_at(&self, idx: usize) -> Option<&BackendSessionSlot> {
        // The arena exposes lookups by typed `Handle`; the
        // BackendSession path stores a raw index on `OpCore` so the
        // dispatcher does not have to round-trip through a handle
        // for every reply. Reconstruct the handle via
        // `handle_from_slot`.
        let slot = self.backend_sessions.handle_from_slot(idx as u32)?;
        let entry = self.backend_sessions.get(slot)?;
        if entry.is_empty() { None } else { Some(entry) }
    }

    /// Locate the live backend-session slot for an
    /// `FsInstanceId`. Linear scan over the small backend-session
    /// arena (one entry per active mount). Returns the slot index
    /// that the saltyfs client stamps into `OpCore.backend_session_idx`.
    pub(crate) fn backend_session_idx_for(
        &self,
        fs_instance_id: crate::core::identity::FsInstanceId,
    ) -> Option<u32> {
        let mut found = None;
        self.backend_sessions.for_each_active(|h, s| {
            if !s.is_empty() && s.fs_instance_id == fs_instance_id {
                found = Some(h.slot());
                false
            } else {
                true
            }
        });
        found
    }

    /// Reserve a PendingOp slot for a saltyfs (or other backend)
    /// async RPC. Returns `(handle, tx_id)` so the issue-side
    /// helper can stamp the correlation header. The kind payload
    /// is stamped onto the slot; resume payload starts as
    /// `Resume::Placeholder` until the posix handler installs
    /// its continuation.
    ///
    /// Returns `None` on arena exhaustion or when the
    /// `fs_instance_id` does not resolve to a live backend
    /// session (mount torn down before the issue site fired).
    pub(crate) fn reserve_fs_pending(
        &mut self,
        fs_instance_id: crate::core::identity::FsInstanceId,
        kind_payload: crate::owner::pending::PendingKindPayload,
    ) -> Option<(
        crate::owner::pending::PendingOpHandle,
        crate::owner::pending::TxId,
    )> {
        let session_idx = self.backend_session_idx_for(fs_instance_id)?;
        let session = self.backend_session_at(session_idx as usize)?;
        let session_gen = session.live_gen;
        let vnode_key = crate::core::identity::VnodeKey {
            fs_instance_id,
            backend_id: crate::core::identity::BackendNodeId::INVALID,
        };
        let handle = crate::owner::pending::alloc_pending(
            self,
            crate::owner::op::OpKind::Namei,
            0,
            0,
            session_idx,
            session_gen,
            vnode_key,
        )?;
        let tx_id = self
            .pending_ops
            .get(handle)
            .map(|op| op.core.tx_id)
            .unwrap_or(crate::owner::pending::TxId::INVALID);
        if let Some(op) = self.pending_ops.get_mut(handle) {
            op.kind_payload = kind_payload;
        }
        Some((handle, tx_id))
    }

    /// Reserve a `PendingOp` slot anchored to a backend session
    /// identified by direct slot index rather than `fs_instance_id`.
    /// pty / netsrv / pager backends are singleton sessions per
    /// vfs lifetime — no fs_instance_id, just a stable session
    /// slot — so they can't go through `reserve_fs_pending`.
    ///
    /// `kind` discriminates which `OpKind::*` variant the slot is
    /// stamped with (`Pty`/`Net`/`Pager`). `vnode_key` is the
    /// identity of the vnode the operation is associated with, or
    /// `VnodeKey::INVALID` when none applies (PTY ioctl, netsrv
    /// connect with no fs vnode).
    fn reserve_pending_for_session(
        &mut self,
        session_idx: u32,
        kind: crate::owner::op::OpKind,
        vnode_key: crate::core::identity::VnodeKey,
    ) -> Option<(
        crate::owner::pending::PendingOpHandle,
        crate::owner::pending::TxId,
    )> {
        let session = self.backend_session_at(session_idx as usize)?;
        let session_gen = session.live_gen;
        let handle = crate::owner::pending::alloc_pending(
            self,
            kind,
            0,
            0,
            session_idx,
            session_gen,
            vnode_key,
        )?;
        let tx_id = self
            .pending_ops
            .get(handle)
            .map(|op| op.core.tx_id)
            .unwrap_or(crate::owner::pending::TxId::INVALID);
        Some((handle, tx_id))
    }

    /// Reserve a `PendingOp` for a posix_ttysrv-backed call. The
    /// pty session is keyed by `session_slot` returned from
    /// `ensure_pty_session`. PTY ops are not associated with a
    /// vnode in the namespace; the slot's `vnode_key` records
    /// `INVALID` and the resume payload carries the pty index.
    pub(crate) fn reserve_pending_for_pty(
        &mut self,
        session: crate::owner::session::BackendSessionHandle,
    ) -> Option<(
        crate::owner::pending::PendingOpHandle,
        crate::owner::pending::TxId,
    )> {
        let session_idx = session.slot();
        let result = self.reserve_pending_for_session(
            session_idx,
            crate::owner::op::OpKind::Pty,
            crate::core::identity::VnodeKey::NONE,
        )?;
        if let Some(op) = self.pending_ops.get_mut(result.0) {
            op.core.credit_held = true;
        }
        Some(result)
    }

    /// Reserve a `PendingOp` for a netsrv-backed call. `sock_h`
    /// identifies the `SocketState` arena entry the operation is
    /// associated with — stamped into the kind payload so the net
    /// completion router can update the matching socket without a
    /// secondary lookup.
    pub(crate) fn reserve_pending_for_net(
        &mut self,
        session: crate::owner::session::BackendSessionHandle,
        sock_h: crate::arena::handle::Handle<crate::core::socket::SocketState>,
    ) -> Option<(
        crate::owner::pending::PendingOpHandle,
        crate::owner::pending::TxId,
    )> {
        let session_idx = session.slot();
        let result = self.reserve_pending_for_session(
            session_idx,
            crate::owner::op::OpKind::Net,
            crate::core::identity::VnodeKey::NONE,
        )?;
        if let Some(op) = self.pending_ops.get_mut(result.0) {
            op.kind_payload.words[0] = sock_h.slot() as u64;
            op.kind_payload.words[1] = sock_h.epoch() as u64;
            op.core.credit_held = true;
        }
        Some(result)
    }

    /// Reserve a `PendingOp` for a dispdrv-backed framebuffer call
    /// (`FB_GET_INFO` / `FB_GET_BACKING_MO` / `FB_PRESENT`). The FB
    /// vnode handle is stamped into the kind payload so the
    /// completion router can update the matching `Vnode.backing_mo`
    /// without a secondary lookup.
    pub(crate) fn reserve_pending_for_fb(
        &mut self,
        session: crate::owner::session::BackendSessionHandle,
        vnode_h: crate::core::vnode::VnodeHandle,
    ) -> Option<(
        crate::owner::pending::PendingOpHandle,
        crate::owner::pending::TxId,
    )> {
        let session_idx = session.slot();
        let vkey = self
            .vnodes
            .get(vnode_h)
            .map(|v| v.key)
            .unwrap_or(crate::core::identity::VnodeKey::NONE);
        let result =
            self.reserve_pending_for_session(session_idx, crate::owner::op::OpKind::Fb, vkey)?;
        if let Some(op) = self.pending_ops.get_mut(result.0) {
            op.kind_payload.words[0] = vnode_h.slot() as u64;
            op.kind_payload.words[1] = vnode_h.epoch() as u64;
            op.core.credit_held = true;
        }
        Some(result)
    }

    /// PendingOp issue wrapper. Caller has already incremented
    /// `inflight_now` via [`Self::backend_credit_reserve`]; this
    /// helper must not increment it a second time, so it merely
    /// delegates to [`Self::reserve_fs_pending`]. Doing otherwise
    /// burns two credits per RPC and locks the session out of
    /// further work after `inflight_max / 2` round-trips.
    pub(crate) fn reserve_fs_pending_credited(
        &mut self,
        fs_instance_id: crate::core::identity::FsInstanceId,
        kind_payload: crate::owner::pending::PendingKindPayload,
    ) -> Option<(
        crate::owner::pending::PendingOpHandle,
        crate::owner::pending::TxId,
    )> {
        let result = self.reserve_fs_pending(fs_instance_id, kind_payload)?;
        if let Some(op) = self.pending_ops.get_mut(result.0) {
            op.core.credit_held = true;
        }
        Some(result)
    }

    /// Tag a secondary `PendingOp` as a coalesced waiter on a
    /// primary lookup's `tx_id`. Returns `false` if the secondary
    /// has already been tagged or if the primary's lookup table
    /// would overflow — caller treats `false` as "fall through to
    /// an independent RPC".
    pub(crate) fn mark_lookup_coalesced_secondary(
        &mut self,
        secondary: crate::owner::pending::PendingOpHandle,
        primary_tx: crate::owner::pending::TxId,
    ) -> bool {
        if let Some(op) = self.pending_ops.get_mut(secondary) {
            if op.core.coalesce_primary_tx.is_valid() {
                return false;
            }
            op.core.coalesce_primary_tx = primary_tx;
            true
        } else {
            false
        }
    }

    /// Observe a backend `mp_write_ctx` result. Non-zero indicates
    /// the kernel refused the send (peer queue full, peer closed,
    /// invalid cap). The caller releases the just-allocated
    /// PendingOp; we keep this hook so future iterations can
    /// surface per-session send-error counters.
    pub(crate) fn observe_backend_send(
        &mut self,
        _fs_instance_id: crate::core::identity::FsInstanceId,
        send_err: i32,
    ) -> i32 {
        send_err
    }

    /// Reserve one inflight credit against the backend session
    /// owning `fs_instance_id`. Returns `false` when the session
    /// has reached `inflight_max` (the caller defers to wait_q)
    /// or when the session is unknown (mount torn down). On
    /// success the issuing helper proceeds with the RPC; the
    /// matching credit is returned by `backend_credit_release`
    /// when the completion arrives or when cancellation drops the
    /// in-flight slot.
    pub(crate) fn backend_credit_reserve(
        &mut self,
        fs_instance_id: crate::core::identity::FsInstanceId,
    ) -> bool {
        let Some(idx) = self.backend_session_idx_for(fs_instance_id) else {
            return false;
        };
        let Some(slot) = self.backend_sessions.handle_from_slot(idx) else {
            return false;
        };
        let Some(s) = self.backend_sessions.get_mut(slot) else {
            return false;
        };
        if s.is_empty() || s.credit_available() == 0 {
            return false;
        }
        s.inflight_now += 1;
        true
    }

    /// Reserve credit by typed `BackendSessionHandle` rather than
    /// by `fs_instance_id`. Used by the path-less default-mount
    /// issue helpers (inet socket / pty open / fb get_backing) that
    /// already hold the session handle.
    pub(crate) fn backend_credit_reserve_for_session(
        &mut self,
        session: crate::owner::session::BackendSessionHandle,
    ) -> bool {
        let Some(s) = self.backend_sessions.get_mut(session) else {
            return false;
        };
        if s.is_empty() || s.credit_available() == 0 {
            return false;
        }
        s.inflight_now += 1;
        true
    }

    /// Release credit reserved via `backend_credit_reserve_for_session`.
    pub(crate) fn backend_credit_release_for_session(
        &mut self,
        session: crate::owner::session::BackendSessionHandle,
    ) {
        let mut drain: Option<(crate::owner::session::DrainFn, u32)> = None;
        if let Some(s) = self.backend_sessions.get_mut(session) {
            if s.inflight_now > 0 {
                s.inflight_now -= 1;
                if let Some(f) = s.drain_fn {
                    drain = Some((f, session.slot()));
                }
            }
        }
        if let Some((f, slot_idx)) = drain {
            f(self, slot_idx, 1);
        }
    }

    /// Release one inflight credit. Saturates at zero so an
    /// over-release (cancel + completion arriving for the same
    /// op, e.g.) cannot underflow the counter into a stuck-empty
    /// state.
    pub(crate) fn backend_credit_release(
        &mut self,
        fs_instance_id: crate::core::identity::FsInstanceId,
    ) {
        let Some(idx) = self.backend_session_idx_for(fs_instance_id) else {
            return;
        };
        let Some(slot) = self.backend_sessions.handle_from_slot(idx) else {
            return;
        };
        let mut drain = None;
        if let Some(s) = self.backend_sessions.get_mut(slot) {
            if s.inflight_now > 0 {
                s.inflight_now -= 1;
                if let Some(f) = s.drain_fn {
                    drain = Some(f);
                }
            }
        }
        if let Some(f) = drain {
            f(self, idx, 1);
        }
    }

    /// Find the live `MountHandle` for a given `FsInstanceId`.
    /// Linear scan over the small mount arena (one entry per
    /// active mount). Returns `None` if the mount has been torn
    /// down — completion routers translate that into a stale-
    /// completion drop.
    pub(crate) fn mount_by_fs_instance_id(
        &self,
        fs_instance_id: crate::core::identity::FsInstanceId,
    ) -> Option<crate::core::mount::MountHandle> {
        let mut found = None;
        self.mounts.for_each_active(|h, m| {
            if m.fs_instance_id == fs_instance_id {
                found = Some(h);
                false
            } else {
                true
            }
        });
        found
    }

    /// Release a saved reply endpoint slot without answering it.
    /// Used by stale-completion / placeholder-resume drops where
    /// the saved reply slot is no longer routed to a real reply
    /// path; the caller observes a kernel-side error rather than a
    /// vfs reply.
    /// Index-keyed variant of [`backend_credit_release_for_session`].
    /// Completion routers receive `OpCore.backend_session_idx` from
    /// the dispatcher and use this to drop the inflight credit
    /// without re-resolving the typed handle.
    pub(crate) fn backend_credit_release_for_session_idx(&mut self, session_idx: u32) {
        let Some(handle) = self.backend_sessions.handle_from_slot(session_idx) else {
            return;
        };
        let mut drain = None;
        if let Some(s) = self.backend_sessions.get_mut(handle) {
            if s.inflight_now > 0 {
                s.inflight_now -= 1;
                if let Some(f) = s.drain_fn {
                    drain = Some(f);
                }
            }
        }
        if let Some(f) = drain {
            f(self, session_idx, 1);
        }
    }

    /// Install a `(VnodeKey, VnodeHandle)` entry into the
    /// direct-mapped resolver cache. No-op when either side is
    /// invalid; collisions over-write (the cache is best-effort
    /// — namei walks fall back to backend lookup on miss).
    pub(crate) fn install_resolve_cache(
        &mut self,
        key: crate::core::identity::VnodeKey,
        handle: crate::core::vnode::VnodeHandle,
    ) {
        if !key.is_valid() || !handle.is_valid() {
            return;
        }
        let slot = (vkey_hash(&key) as usize) % VNODE_RESOLVE_CACHE_CAP;
        let raw_slot = handle.slot();
        let raw_epoch = handle.epoch();
        // Path-hash uses the same vkey_hash mix; the lookup side
        // tests `path_hash != 0`, so reserve 0 for the empty
        // sentinel and OR in a marker bit when the natural hash
        // is zero (extremely rare).
        let mut path_hash = vkey_hash(&key);
        if path_hash == 0 {
            path_hash = 1;
        }
        self.vnode_resolve_cache[slot] = VnodeResolveCacheEntry {
            key,
            vnode_slot: raw_slot,
            vnode_epoch: raw_epoch,
            path_hash,
        };
    }

    /// Walk the direct-mapped resolver cache for an entry matching
    /// `vkey`. Returns the live `VnodeHandle` if the entry is still
    /// valid (matching slot + epoch), `None` otherwise. The cache is
    /// 256-slot direct-mapped; collisions over-write, so a lookup
    /// miss simply means the caller must re-resolve through namei.
    pub(crate) fn lookup_resolve_cache(
        &self,
        vkey: crate::core::identity::VnodeKey,
    ) -> Option<crate::core::vnode::VnodeHandle> {
        if !vkey.is_valid() {
            return None;
        }
        let slot = (vkey_hash(&vkey) as usize) % VNODE_RESOLVE_CACHE_CAP;
        let entry = self.vnode_resolve_cache[slot];
        if entry.path_hash == 0 || entry.key != vkey {
            return None;
        }
        let handle = crate::core::vnode::VnodeHandle::new(entry.vnode_slot, entry.vnode_epoch);
        if !handle.is_valid() {
            return None;
        }
        // Validate the handle is still live in the arena (slot may
        // have been recycled after entry insertion).
        if self.vnodes.get(handle).is_some() {
            Some(handle)
        } else {
            None
        }
    }

    /// Drop any resolver-cache entry whose key matches `vkey`. Used
    /// by mutation completion handlers (unlink / rmdir / rename) to
    /// flush the cache for a vnode whose backend identity is
    /// disappearing.
    pub(crate) fn invalidate_resolve_cache_for(&mut self, vkey: crate::core::identity::VnodeKey) {
        if !vkey.is_valid() {
            return;
        }
        let slot = (vkey_hash(&vkey) as usize) % VNODE_RESOLVE_CACHE_CAP;
        let entry = &mut self.vnode_resolve_cache[slot];
        if entry.path_hash != 0 && entry.key == vkey {
            *entry = VnodeResolveCacheEntry::EMPTY;
        }
    }

    /// Flush every cache entry whose parent matches `parent_vkey` —
    /// invoked after a directory mutation that may have changed
    /// child name resolution (mkdir / rmdir / rename / link / unlink).
    /// Linear sweep over the 256-slot direct-mapped table; cheap
    /// against the cost of stale lookups feeding incorrect children
    /// into namei.
    pub(crate) fn invalidate_parent_dir_caches(
        &mut self,
        parent_vkey: crate::core::identity::VnodeKey,
    ) {
        if !parent_vkey.is_valid() {
            return;
        }
        // Resolver-cache entries are keyed by *child* identity; the
        // path-hash mixes parent into its derivation. Instead of a
        // dedicated parent index we walk the table and drop entries
        // where the child's `fs_instance_id` matches the parent's —
        // a conservative invalidation that flushes children of the
        // mutated directory plus a small fraction of unrelated keys
        // sharing the same fs. Acceptable cost: cache rebuild on
        // next access. Required by: rename / unlink / rmdir / link /
        // mkdir / create / symlink completion handlers.
        for entry in self.vnode_resolve_cache.iter_mut() {
            if entry.path_hash != 0 && entry.key.fs_instance_id == parent_vkey.fs_instance_id {
                *entry = VnodeResolveCacheEntry::EMPTY;
            }
        }
    }

    /// Resolve a vnode handle to its owning mount. Returns `None`
    /// if the vnode has been reclaimed or the mount it points at
    /// has been torn down.
    pub(crate) fn resolve_vnode_mount(
        &self,
        vnode_h: crate::core::vnode::VnodeHandle,
    ) -> Option<crate::core::mount::MountHandle> {
        let vn = self.vnodes.get(vnode_h)?;
        if vn.mount.is_valid() {
            Some(vn.mount)
        } else {
            None
        }
    }

    /// Look up the open object backing a (`client`, `fd`) pair.
    /// Bypasses the dynamic SegmentedSlotTable layer when present;
    /// returns the live OpenObjectHandle through ClientState's
    /// internal table. `None` if the client is gone, the fd is
    /// negative, or the slot is empty.
    pub(crate) fn open_object_at(
        &self,
        client: crate::server::types::ClientHandle,
        fd: usize,
    ) -> Option<crate::server::types::OpenObjectHandle> {
        let cli = self.clients.get(client)?;
        cli.slot_table.lookup(fd as u32)
    }

    /// Stamp the resume continuation onto a parked PendingOp. The
    /// async namei walker / posix handler reserve a slot via the
    /// backend issue path, then call this to attach the resume
    /// context (badge / saved reply slot / `Resume` variant).
    /// Completion routing later invokes the resume by reading the
    /// stamped context and dispatching to the matching handler.
    ///
    /// Closes the issue-side 5-tuple by populating both
    /// `client_badge` and `client_id` (frontend P5a — `client_id`
    /// is the badge's lower 32 bit). The reserve-time wrappers
    /// stamp these fields with `0`; the stamp here is the single
    /// point where the slot's identity becomes complete.
    ///
    /// Returns `Err(reply_lease)` when the handle is stale (slot
    /// recycled between issue and stamp) or when a parked lease
    /// already occupies the slot — the caller is expected to
    /// surface an `Io` error to the client through the returned
    /// lease. The PendingOp arena is owner-thread mutated only,
    /// so this is the single point where `Resume::Placeholder`
    /// flips to a real continuation.
    /// Stamp a `Resume` continuation onto a freshly-allocated
    /// `PendingOp`. `reply_lease` is `Some(lease)` when the issue
    /// originates from a client RPC (the parked lease is the
    /// callback target on completion), or `None` for issue paths
    /// that have no client to reply to — currently the kernel
    /// `EVENT_TYPE_PAGER_REQUEST` flow, where the kernel itself
    /// woke vfs and the eventual `PAGER_SUPPLY_COPY` /
    /// `PAGER_FAIL` invoke replaces the reply.
    ///
    /// On error the original `reply_lease` is returned wrapped in
    /// the same `Option` so callers can propagate or drop without
    /// guessing.
    pub(crate) fn stamp_resume_ctx(
        &mut self,
        handle: crate::owner::pending::PendingOpHandle,
        client_badge: u64,
        reply_lease: Option<ReplyLease>,
        resume: crate::owner::resume::Resume,
    ) -> Result<(), Option<ReplyLease>> {
        let cid = (client_badge & 0xFFFF_FFFF) as u32;
        // Look up the issuing client's personality before
        // touching `pending_ops` so the personality stamp survives
        // any subsequent client teardown — by completion time the
        // client may already be gone, but the OpCore-side copy
        // of `personality` still tells the formatter which wire
        // shape the reply needs to take.
        let mut personality = crate::personality::Personality::Posix;
        self.clients.for_each_active(|_, c| {
            if c.client_id == cid {
                personality = c.personality;
                return false;
            }
            true
        });

        let Some(op) = self.pending_ops.get_mut(handle) else {
            return Err(reply_lease);
        };
        if op.reply_lease.is_some() {
            return Err(reply_lease);
        }
        op.core.client_badge = client_badge;
        op.core.client_id = cid;
        op.core.personality = personality;
        op.reply_lease = reply_lease.map(|l| l.park());
        op.resume = resume;
        Ok(())
    }
}

/// Hash a `VnodeKey` into a u64 used as the resolver-cache slot
/// selector. Mixes `fs_instance_id` with `backend_id.id` and `seq`
/// — enough entropy that two unrelated mounts colliding on the same
/// inode number land in different slots.
#[inline]
fn vkey_hash(vkey: &crate::core::identity::VnodeKey) -> u64 {
    let mut h = vkey
        .fs_instance_id
        .raw()
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= vkey.backend_id.id.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= (vkey.backend_id.seq as u64).wrapping_mul(0x94D0_49BB_1331_11EB);
    h
}
