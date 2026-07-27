// SPDX-License-Identifier: GPL-2.0-only
//
//! Process table — the supervisor's authoritative record of every PID
//! the system has spawned. Entries persist past process exit (Zombie
//! state) until the parent reaps them via `INIT_WAIT`. Owner-thread
//! mutates; lifecycle workers consume snapshots only.
//!
//! Storage is an arena [`TrackedSlab<ProcessRecord>`] backed by init's
//! [`InitSelfVm`](crate::supervisor::self_vm::InitSelfVm). A process's
//! **PID is its slab slot index** (`SlabId.idx`): index 0 is the slab's
//! reserved sentinel (so PID 0 is naturally "unset"), index 1 is PID 1
//! (init), and the slab grows on demand — there is no fixed process
//! ceiling. `get`/`get_mut`/`release` stay PID-keyed by reconstructing
//! `SlabId { idx: pid, epoch: generation_at(pid) }`, so a recycled slot
//! resolves to its current occupant (or `None`), matching the old
//! flat-array semantics. PID reuse follows the slab free list.
//!
//! `client_id → pid` lookups (the fault dispatcher's hot path) go
//! through a [`U32HashIndex`] this table owns: `set_client_id` and
//! `release` keep it in lockstep with slab membership so it never goes
//! stale.

use core::cmp::min;

use crate::supervisor::manifest::{BinaryStr, NameStr, RestartPolicy, ServiceType};
use crate::supervisor::signal::SignalState;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_server::MpReplyTarget;
use trona_server::U32HashIndex;
use trona_server::slab::{PageBacking, SlabId, TrackedSlab};

pub const PID_INIT: u32 = 1;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProcessState {
    /// Reserved while spawn is in-flight (slot allocated, owner has not
    /// yet stamped TCB caps).
    Allocating,
    /// Process running. TCB / VSpace / CNode / SC caps are valid.
    Active,
    /// Process is job-control stopped. TCBs remain owned by init but are
    /// parked with `TCB_STOP` until SIGCONT.
    Stopped,
    /// Process exited (kernel reported via fault MP + fault dispatcher
    /// or explicit INIT_EXIT). Caps revoked, cspace freed; exit_status
    /// retained until the parent waits.
    Zombie,
    /// Reaped — parent waited and consumed exit status. Owner releases
    /// the slab slot opportunistically.
    Reaped,
}

#[derive(Clone, Copy)]
pub struct CredFields {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    /// Saved set-uid/gid for `setresuid` semantics.
    pub suid: u32,
    pub sgid: u32,
    pub umask: u32,
    /// Supplemental group ids. `groups_len` says how many of `groups`
    /// are populated; up to `MAX_GROUPS` per process.
    pub groups: [u32; MAX_GROUPS],
    pub groups_len: u8,
}

pub const MAX_GROUPS: usize = 16;

impl CredFields {
    pub const fn root() -> Self {
        Self {
            uid: 0,
            gid: 0,
            euid: 0,
            egid: 0,
            suid: 0,
            sgid: 0,
            umask: 0o022,
            groups: [0; MAX_GROUPS],
            groups_len: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct RlimitPair {
    pub soft: u64,
    pub hard: u64,
}

impl RlimitPair {
    pub const fn unlimited() -> Self {
        Self {
            soft: u64::MAX,
            hard: u64::MAX,
        }
    }
}

pub const RLIMIT_KIND_COUNT: usize = 16;

#[derive(Clone, Copy)]
pub struct RlimitTable {
    pub limits: [RlimitPair; RLIMIT_KIND_COUNT],
}

impl RlimitTable {
    pub const fn defaults() -> Self {
        Self {
            limits: [RlimitPair::unlimited(); RLIMIT_KIND_COUNT],
        }
    }
}

#[derive(Clone, Copy, Default)]
pub struct ItimerEntry {
    pub interval_ns: u64,
    pub deadline_ns: u64,
}

pub const ITIMER_KIND_COUNT: usize = 3; // REAL / VIRTUAL / PROF

#[derive(Clone, Copy)]
pub struct ItimerTable {
    pub timers: [ItimerEntry; ITIMER_KIND_COUNT],
}

impl ItimerTable {
    pub const fn empty() -> Self {
        Self {
            timers: [ItimerEntry {
                interval_ns: 0,
                deadline_ns: 0,
            }; ITIMER_KIND_COUNT],
        }
    }
}

pub const MAX_EXE_PATH: usize = 64;

#[derive(Clone, Copy)]
pub struct ExePath {
    pub bytes: [u8; MAX_EXE_PATH],
    pub len: u8,
}

impl ExePath {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_EXE_PATH],
            len: 0,
        }
    }

    pub fn from_bytes(s: &[u8]) -> Self {
        let mut p = Self::empty();
        let n = min(s.len(), MAX_EXE_PATH);
        p.bytes[..n].copy_from_slice(&s[..n]);
        p.len = n as u8;
        p
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

/// Maximum persisted argv bytes (NUL-separated). Matches vfs `ARGV_MAX`
/// so `/proc/<pid>/cmdline` can surface the full recorded command line.
pub const MAX_ARGV_BYTES: usize = 512;

/// NUL-terminated argv blob as recorded at spawn / exec — the backing
/// for `INIT_GET_PROC_INFO_SUB_GET_ARGV` (`/proc/<pid>/cmdline`). Each
/// argument is stored followed by a NUL, matching Linux `cmdline`.
#[derive(Clone, Copy)]
pub struct ArgvStore {
    pub bytes: [u8; MAX_ARGV_BYTES],
    pub len: u16,
}

impl ArgvStore {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; MAX_ARGV_BYTES],
            len: 0,
        }
    }

    /// Pack `argv` as NUL-terminated strings, truncating at
    /// `MAX_ARGV_BYTES`. A truncated final entry still ends the blob at
    /// the cap (no partial-then-NUL past the bound).
    pub fn from_argv(argv: &[&[u8]]) -> Self {
        let mut s = Self::empty();
        let mut pos = 0usize;
        for arg in argv {
            if pos >= MAX_ARGV_BYTES {
                break;
            }
            let take = min(arg.len(), MAX_ARGV_BYTES - pos);
            s.bytes[pos..pos + take].copy_from_slice(&arg[..take]);
            pos += take;
            if pos < MAX_ARGV_BYTES {
                s.bytes[pos] = 0;
                pos += 1;
            }
        }
        s.len = pos as u16;
        s
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    Empty,
    Running,
    Joinable,
    Detached,
    Exited,
}

pub struct ThreadRecord {
    pub state: ThreadState,
    /// Owned caps in init's CSpace for this thread's kernel objects.
    /// `None` until the thread is fully installed; `take()`-d on teardown.
    pub tcb: Option<OwnedCap>,
    pub sc: Option<OwnedCap>,
    pub fault_mp_recv: Option<OwnedCap>,
    pub fault_mp_send: Option<OwnedCap>,
    pub join_token: Option<OwnedCap>,
    /// Thread id within the process (1-based). Mirrors POSIX `pthread_t`
    /// inside this process.
    pub tid: u16,
    pub exit_status: u64,
    /// rsrcsrv record ids for this thread's kernel objects (TCB /
    /// SchedContext / fault MP-pair core), allocated in `create_thread`
    /// via init's admin rsrcsrv connection. Released with `RSRC_FREE` on
    /// thread teardown: `owner_exited(process)` cannot reclaim them
    /// because they are init-owned, not process-owned. Zero for the
    /// process main thread (its TCB is process-owned by the spawn bundle
    /// and reclaimed by `owner_exited`).
    pub tcb_record_id: u64,
    pub sc_record_id: u64,
    pub fault_mp_record_id: u64,
}

impl ThreadRecord {
    pub fn empty() -> Self {
        Self {
            state: ThreadState::Empty,
            tcb: None,
            sc: None,
            fault_mp_recv: None,
            fault_mp_send: None,
            join_token: None,
            tid: 0,
            exit_status: 0,
            tcb_record_id: 0,
            sc_record_id: 0,
            fault_mp_record_id: 0,
        }
    }
}

/// Number of [`ThreadRecord`]s packed into one chained [`ThreadBlock`].
/// Most processes run a single thread, so a small block keeps the common
/// case cheap while still chaining without limit for heavily-threaded
/// ones.
pub const THREADS_PER_BLOCK: usize = 4;

/// One node of a process's thread-record chain, stored in the
/// [`PidTable`]'s `thread_blocks` arena. `next` links to the following
/// block, or [`SlabId::INVALID`] at the tail.
struct ThreadBlock {
    next: SlabId,
    threads: [ThreadRecord; THREADS_PER_BLOCK],
}

impl ThreadBlock {
    fn empty() -> Self {
        Self {
            next: SlabId::INVALID,
            threads: core::array::from_fn(|_| ThreadRecord::empty()),
        }
    }
}

pub struct ProcessRecord {
    pub state: ProcessState,
    /// 1-based PID. Always equals this record's slab slot index; kept as
    /// a field for ergonomic access and for the badge-mint paths.
    pub pid: u32,
    pub parent_pid: u32,
    pub pgid: u32,
    pub sid: u32,
    /// 32-bit per-process identity used for badge mint on every
    /// per-client MP we hand to this process. Independent of pid so that
    /// pid recycling does not collide with badge replay detection.
    /// Private: only [`PidTable::set_client_id`] writes it, so the
    /// owning table's `client_id → pid` index can never go stale.
    client_id: u32,
    /// Service index in the manifest if this process was spawned from
    /// a `.service`. `255` means "ad-hoc spawn" (fork/exec from a
    /// running process).
    pub service_idx: u8,
    /// Service-level restart policy, copied at spawn time.
    pub restart: RestartPolicy,
    pub service_type: ServiceType,
    /// Exit status reported either by the process via `INIT_EXIT` or by
    /// init's fault dispatcher when crashing the process. Negative for
    /// signal-terminated.
    pub exit_status: i32,
    /// Last job-control stop status, encoded as POSIX wait status.
    pub stop_status: i32,
    /// True once a parent has consumed the current stop status via
    /// `waitpid(..., WUNTRACED)`.
    pub stop_reported: bool,
    /// Set when the process has started waiting via `INIT_WAIT`.
    /// Carries the reply MP endpoint and txid until a matching child
    /// state change wakes it.
    pub waitpid_parked_reply: MpReplyTarget,
    pub waitpid_parked_target: i32,
    /// Per-process scheduling-context, owned by init (one main TCB
    /// = one SC). Threads above main get their own SCs.
    pub sched_context: Option<OwnedCap>,
    /// Caps init owns for the process.
    pub vspace: Option<OwnedCap>,
    pub cspace: Option<OwnedCap>,
    pub main_tcb: Option<OwnedCap>,
    /// Per-client request MP pair — send side is used for Watch fan-in
    /// via the control EQ; recv side is the inbound IPC label source.
    pub request_mp_send: Option<OwnedCap>,
    pub request_mp_recv: Option<OwnedCap>,
    pub request_watch: Option<OwnedCap>,
    pub request_watch_cookie: u64,
    /// Per-process signal MP send side — init writes SIGCHLD / SIGTERM
    /// / etc. into the process's signal pipe.
    pub signal_mp_send: Option<OwnedCap>,
    pub signal_mp_recv: Option<OwnedCap>,
    /// Per-client mmsrv self-tier MP pair. Init retains the send side;
    /// the recv side is moved to mmsrv during `MM_REGISTER_CLIENT`, so
    /// this field is `None` after successful registration.
    pub mmsrv_request_mp_send: Option<OwnedCap>,
    pub mmsrv_request_mp_recv: Option<OwnedCap>,
    /// Per-client mmsrv control capability — a badged, non-`GRANT` invoke
    /// cap to mmsrv's master EP that mmsrv mints at register and returns to
    /// init. Invoking it both authorizes and targets this client's mmsrv
    /// admin verbs (fork / fault-pipe / exec-replace / deregister). Dropped
    /// after the exit-time deregister.
    pub mmsrv_control_cap: Option<OwnedCap>,
    /// Per-client vfs control capability — the analogous cap to vfs's master
    /// EP, used to drive this client's vfs admin verbs (fork FD-clone, exec
    /// CLOEXEC sweep, deregister). Dropped after the exit-time deregister.
    pub vfs_control_cap: Option<OwnedCap>,
    /// Main TCB's fault MP pair. Init retains the send side for kernel
    /// fault binding; the recv side is moved to mmsrv during fault-pipe
    /// registration and is `None` afterward.
    pub fault_mp_recv: Option<OwnedCap>,
    pub fault_mp_send: Option<OwnedCap>,
    /// Child's master service-EP MP — client-facing peer side
    /// (published through namesrv so other services can RPC into this
    /// child via lazy lookup) and service-side recv endpoint (where
    /// the child's reactor blocks). exec preserves these so a
    /// successful re-exec keeps the same publish endpoint.
    pub service_ep_send: Option<OwnedCap>,
    pub service_ep_recv: Option<OwnedCap>,
    /// ldsrv-only private boot/control capabilities that init keeps in the
    /// process lifetime record after copying child-facing slots into ldsrv.
    /// Other processes leave these fields empty.
    pub ldsrv_adopt_recv: Option<OwnedCap>,
    pub ldsrv_exec_control_recv: Option<OwnedCap>,
    pub ldsrv_plumbing_untyped: Option<OwnedCap>,
    /// Saved exe path so `INIT_GET_PROC_INFO_SUB_GET_EXE_PATH` can
    /// return it without re-reading the manifest.
    pub exe: ExePath,
    pub name: NameStr,
    /// NUL-separated argv recorded at spawn / exec, surfaced by
    /// `/proc/<pid>/cmdline`.
    pub argv: ArgvStore,
    pub cred: CredFields,
    pub rlimits: RlimitTable,
    pub itimers: ItimerTable,
    /// POSIX signal dispositions + pending/block masks. Co-located with
    /// the record (rather than a parallel array) so it grows with the
    /// slab and is addressed by the same PID-as-slot-index identity.
    pub signal_state: SignalState,
    /// Head of this process's thread-record chain in the `PidTable`'s
    /// `thread_blocks` arena ([`SlabId::INVALID`] before the first block
    /// exists). `threads_len` is the logical high-water of occupied slots
    /// across the chain. Both are private — all thread access goes through
    /// `PidTable`'s thread methods so the arena stays coherent.
    threads_head: SlabId,
    threads_len: u32,
    /// Monotonic ns time at which this process was spawned. Used by
    /// `getrusage` and procfs to compute uptime.
    pub start_ns: u64,
    /// User stack bounds installed on the main TCB. Forked children
    /// inherit these because their VSpace inherits the parent's stack
    /// mapping.
    pub stack_top: u64,
    pub stack_min: u64,
    pub stack_guard_bottom: u64,
    /// Per-process layout registered with mmsrv. Cached so a future
    /// `INIT_FORK` from this process can pass `rec.layout` directly into the
    /// child's `BootstrapPlan.client_layout` (fork inherits the parent's
    /// current layout exactly).
    pub layout: trona_runtime::spawn::layout::VmClientLayout,
    /// Accumulated user / kernel CPU time stamped at exit. While the
    /// process is alive, init queries the kernel via TCB_GET_CPU_TIMES
    /// instead.
    pub user_cpu_ns: u64,
    pub sys_cpu_ns: u64,
}

impl ProcessRecord {
    pub fn empty() -> Self {
        Self {
            state: ProcessState::Allocating,
            pid: 0,
            parent_pid: 0,
            pgid: 0,
            sid: 0,
            client_id: 0,
            service_idx: 255,
            restart: RestartPolicy::Never,
            service_type: ServiceType::Simple,
            exit_status: 0,
            stop_status: 0,
            stop_reported: false,
            waitpid_parked_reply: MpReplyTarget::none(),
            waitpid_parked_target: 0,
            sched_context: None,
            vspace: None,
            cspace: None,
            main_tcb: None,
            request_mp_send: None,
            request_mp_recv: None,
            request_watch: None,
            request_watch_cookie: 0,
            signal_mp_send: None,
            signal_mp_recv: None,
            mmsrv_request_mp_send: None,
            mmsrv_request_mp_recv: None,
            mmsrv_control_cap: None,
            vfs_control_cap: None,
            fault_mp_recv: None,
            fault_mp_send: None,
            service_ep_send: None,
            service_ep_recv: None,
            ldsrv_adopt_recv: None,
            ldsrv_exec_control_recv: None,
            ldsrv_plumbing_untyped: None,
            exe: ExePath::empty(),
            name: NameStr::empty(),
            argv: ArgvStore::empty(),
            cred: CredFields::root(),
            rlimits: RlimitTable::defaults(),
            itimers: ItimerTable::empty(),
            signal_state: SignalState::new(),
            threads_head: SlabId::INVALID,
            threads_len: 0,
            start_ns: 0,
            stack_top: 0,
            stack_min: 0,
            stack_guard_bottom: 0,
            layout: trona_runtime::spawn::layout::VmClientLayout::zero(),
            user_cpu_ns: 0,
            sys_cpu_ns: 0,
        }
    }

    /// Read-only accessor for the badge identity. Writes go through
    /// [`PidTable::set_client_id`] so the table's index stays coherent.
    pub fn client_id(&self) -> u32 {
        self.client_id
    }
}

/// A reserved thread slot from [`PidTable::reserve_thread_slot`],
/// committed via [`PidTable::install_reserved_thread`]. Opaque to
/// consumers except for the assigned `tid`.
#[derive(Clone, Copy)]
pub struct ReservedThread {
    pid: u32,
    global_idx: u32,
    pub tid: u16,
    grows: bool,
}

pub struct PidTable {
    /// Arena of process records. `SlabId.idx` is the PID; the slab's
    /// index-0 sentinel keeps PID 0 reserved as "unset".
    slab: TrackedSlab<ProcessRecord>,
    /// `client_id → pid` index for O(1) badge resolution on the fault
    /// path. Kept in lockstep with `slab` by `set_client_id`/`release`.
    client_index: U32HashIndex,
    /// Chained thread-record blocks for every process (per-record chains
    /// rooted at `ProcessRecord::threads_head`). Freed by `release`.
    thread_blocks: TrackedSlab<ThreadBlock>,
}

impl PidTable {
    pub const fn new() -> Self {
        Self {
            slab: TrackedSlab::empty(),
            client_index: U32HashIndex::empty(),
            thread_blocks: TrackedSlab::empty(),
        }
    }

    /// Number of live records (any non-released state).
    pub fn count(&self) -> u32 {
        self.slab.len() as u32
    }

    /// Reconstruct the slab handle for `pid` at its current epoch, or
    /// `INVALID` when the slot is freed / out of range.
    #[inline]
    fn handle_for(&self, pid: u32) -> SlabId {
        // SAFETY: single-threaded owner; generation_at bounds-checks idx.
        let epoch = unsafe { self.slab.generation_at(pid) };
        SlabId { idx: pid, epoch }
    }

    /// Reserve the PID 1 slot for init at boot. Must run after the slab
    /// backing is bound (`bind_slab_backing`); the first `slot_alloc`
    /// lands at index 1 = PID 1. Does not consume a `client_id` from the
    /// supervisor counter — init is fixed at `client_id == 1`.
    ///
    /// # Safety
    ///
    /// `backing` must be live (slab backing bound).
    pub unsafe fn install_init(&mut self, backing: &mut impl PageBacking) -> bool {
        unsafe {
            let mut rec = ProcessRecord::empty();
            rec.state = ProcessState::Active;
            rec.pid = PID_INIT;
            rec.parent_pid = 0;
            rec.pgid = PID_INIT;
            rec.sid = PID_INIT;
            rec.client_id = 1;
            rec.service_type = ServiceType::Server;
            rec.name = NameStr::from_bytes(b"init");
            rec.exe = ExePath::from_bytes(b"/bin/init");
            rec.argv = ArgvStore::from_argv(&[b"/bin/init"]);
            rec.signal_state.install_defaults();
            let Some(id) = self.slab.slot_alloc(rec, backing) else {
                return false;
            };
            // Index 1 is the first live slot, so this always equals PID 1.
            if id.idx != PID_INIT {
                return false;
            }
            self.client_index.insert(1, PID_INIT, backing)
        }
    }

    /// Allocate a fresh process slot. The PID is the slab index; the
    /// returned record has `pid`/`pgid`/`sid` stamped and `state =
    /// Allocating`. The caller fills the remaining fields and assigns a
    /// `client_id` via [`set_client_id`](Self::set_client_id).
    ///
    /// # Safety
    ///
    /// `backing` must be live.
    pub unsafe fn alloc(&mut self, backing: &mut impl PageBacking) -> Option<&mut ProcessRecord> {
        unsafe {
            let id = self.slab.slot_alloc(ProcessRecord::empty(), backing)?;
            let pid = id.idx;
            // Pre-allocate the first thread block so the spawn path can
            // install the main thread without a late out-of-memory.
            let Some(head) = self.thread_blocks.slot_alloc(ThreadBlock::empty(), backing) else {
                self.slab.slot_free(id);
                return None;
            };
            let rec = self.slab.slot_get_mut(id)?;
            rec.pid = pid;
            rec.pgid = pid;
            rec.sid = pid;
            rec.threads_head = head;
            Some(rec)
        }
    }

    /// Install a boot-core service record at the next PID slot. Boot-core
    /// services are spawned before the normal lifecycle allocator is available,
    /// but they still occupy real PIDs and must advance the slab allocator so
    /// later service spawns cannot reuse 2/3/4.
    ///
    /// # Safety
    ///
    /// `backing` must be live.
    #[allow(clippy::too_many_arguments)]
    pub unsafe fn install_boot_core_service(
        &mut self,
        backing: &mut impl PageBacking,
        expected_pid: u32,
        parent_pid: u32,
        service_idx: u8,
        name: NameStr,
        binary: BinaryStr,
        service_type: ServiceType,
        restart: RestartPolicy,
        start_ns: u64,
    ) -> bool {
        unsafe {
            let Some(id) = self.slab.slot_alloc(ProcessRecord::empty(), backing) else {
                return false;
            };
            if id.idx != expected_pid {
                self.slab.slot_free(id);
                return false;
            }
            let Some(head) = self.thread_blocks.slot_alloc(ThreadBlock::empty(), backing) else {
                self.slab.slot_free(id);
                return false;
            };
            let Some(rec) = self.slab.slot_get_mut(id) else {
                self.free_thread_chain(head);
                self.slab.slot_free(id);
                return false;
            };
            rec.state = ProcessState::Active;
            rec.pid = expected_pid;
            rec.parent_pid = parent_pid;
            rec.pgid = expected_pid;
            rec.sid = expected_pid;
            rec.service_idx = service_idx;
            rec.restart = restart;
            rec.service_type = service_type;
            rec.name = name;
            rec.exe = ExePath::from_bytes(binary.as_bytes());
            rec.argv = ArgvStore::from_argv(&[binary.as_bytes()]);
            rec.start_ns = start_ns;
            rec.signal_state.install_defaults();
            rec.threads_head = head;
            rec.threads_len = 1;
            let Some(block) = self.thread_blocks.slot_get_mut(head) else {
                self.free_thread_chain(head);
                self.slab.slot_free(id);
                return false;
            };
            block.threads[0] = ThreadRecord {
                state: ThreadState::Running,
                tcb: None,
                sc: None,
                fault_mp_recv: None,
                fault_mp_send: None,
                join_token: None,
                tid: 1,
                exit_status: 0,
                tcb_record_id: 0,
                sc_record_id: 0,
                fault_mp_record_id: 0,
            };
            true
        }
    }

    /// Release `pid`'s slot, removing its badge from the index first so
    /// the `client_id → pid` map never points at a freed slot.
    pub fn release(&mut self, pid: u32) {
        let id = self.handle_for(pid);
        // SAFETY: single-threaded owner.
        unsafe {
            let head = match self.slab.slot_get(id) {
                Some(rec) => {
                    let cid = rec.client_id;
                    if cid != 0 {
                        self.client_index.remove(cid);
                    }
                    rec.threads_head
                }
                None => SlabId::INVALID,
            };
            self.free_thread_chain(head);
            self.slab.slot_free(id);
        }
    }

    pub fn get(&self, pid: u32) -> Option<&ProcessRecord> {
        let id = self.handle_for(pid);
        // SAFETY: single-threaded owner.
        unsafe { self.slab.slot_get(id) }
    }

    pub fn get_mut(&mut self, pid: u32) -> Option<&mut ProcessRecord> {
        let id = self.handle_for(pid);
        // SAFETY: single-threaded owner.
        unsafe { self.slab.slot_get_mut(id) }
    }

    /// Assign (or re-assign) `pid`'s badge identity, keeping the
    /// `client_id → pid` index transactional: reject `client_id == 0`
    /// and duplicate live keys, insert the new mapping before mutating
    /// the record, then drop the record's old mapping.
    ///
    /// # Safety
    ///
    /// `backing` must be live.
    pub unsafe fn set_client_id(
        &mut self,
        pid: u32,
        client_id: u32,
        backing: &mut impl PageBacking,
    ) -> bool {
        if client_id == 0 {
            return false;
        }
        unsafe {
            if let Some(existing) = self.client_index.get(client_id) {
                if existing != pid {
                    return false;
                }
            }
            let id = self.handle_for(pid);
            let old_cid = match self.slab.slot_get(id) {
                Some(rec) => rec.client_id,
                None => return false,
            };
            if !self.client_index.insert(client_id, pid, backing) {
                return false;
            }
            if let Some(rec) = self.slab.slot_get_mut(id) {
                rec.client_id = client_id;
            }
            if old_cid != 0 && old_cid != client_id {
                self.client_index.remove(old_cid);
            }
            true
        }
    }

    /// Resolve a badge to its live, dispatchable record (Active /
    /// Stopped / Zombie only), via the O(1) index.
    pub fn find_by_client_id(&self, client_id: u32) -> Option<&ProcessRecord> {
        let pid = self.client_index.get(client_id)?;
        let rec = self.get(pid)?;
        if matches!(
            rec.state,
            ProcessState::Active | ProcessState::Stopped | ProcessState::Zombie
        ) {
            Some(rec)
        } else {
            None
        }
    }

    /// Resolve a badge to any live record (used where Allocating /
    /// Reaped must also be reachable), via the O(1) index.
    pub fn find_by_client_id_mut(&mut self, client_id: u32) -> Option<&mut ProcessRecord> {
        let pid = self.client_index.get(client_id)?;
        self.get_mut(pid)
    }

    /// Immutable counterpart of [`find_by_client_id_mut`] — resolves a record
    /// in *any* live state (including `Allocating` mid-spawn and `Zombie`
    /// mid-exit), unlike the dispatch-filtered [`find_by_client_id`]. init's
    /// per-client control-cap resolvers use this because they drive admin verbs
    /// (fault-pipe, fork clone, deregister) before the child is `Active` and
    /// after it becomes `Zombie`.
    pub fn find_by_client_id_any(&self, client_id: u32) -> Option<&ProcessRecord> {
        let pid = self.client_index.get(client_id)?;
        self.get(pid)
    }

    pub fn iter_active(&self) -> impl Iterator<Item = &ProcessRecord> {
        // SAFETY: single-threaded owner; iterator borrows the slab.
        unsafe { self.slab.iter() }
            .map(|(_, rec)| rec)
            .filter(|rec| {
                matches!(
                    rec.state,
                    ProcessState::Active | ProcessState::Stopped | ProcessState::Zombie
                )
            })
    }

    pub fn iter_mut_active(&mut self) -> impl Iterator<Item = &mut ProcessRecord> {
        // SAFETY: single-threaded owner; iterator holds the &mut borrow.
        unsafe { self.slab.iter_mut() }
            .map(|(_, rec)| rec)
            .filter(|rec| {
                matches!(
                    rec.state,
                    ProcessState::Active | ProcessState::Stopped | ProcessState::Zombie
                )
            })
    }

    /// Find the first zombie owned by `parent` (used by `INIT_WAIT`
    /// when called with `pid == -1`).
    pub fn find_zombie_for_parent_mut(&mut self, parent: u32) -> Option<&mut ProcessRecord> {
        // SAFETY: single-threaded owner.
        unsafe { self.slab.iter_mut() }
            .map(|(_, rec)| rec)
            .find(|rec| rec.state == ProcessState::Zombie && rec.parent_pid == parent)
    }

    pub fn find_thread_mut(&mut self, pid: u32, tid: u16) -> Option<&mut ThreadRecord> {
        let head = self.get(pid)?.threads_head;
        // SAFETY: single-threaded owner.
        unsafe {
            let mut block_id = head;
            while block_id.is_valid() {
                let (within, next) = match self.thread_blocks.slot_get(block_id) {
                    Some(b) => (
                        b.threads
                            .iter()
                            .position(|t| t.state != ThreadState::Empty && t.tid == tid),
                        b.next,
                    ),
                    None => return None,
                };
                if let Some(w) = within {
                    return self
                        .thread_blocks
                        .slot_get_mut(block_id)
                        .map(|b| &mut b.threads[w]);
                }
                block_id = next;
            }
        }
        None
    }

    /// Reserve a thread slot for `pid` (reusing the first freed slot, else
    /// appending and growing the chain). `threads_len` is not bumped
    /// until [`install_reserved_thread`](Self::install_reserved_thread)
    /// commits, so a resource-allocation failure after reserve leaves the
    /// slot empty for reuse rather than leaking it.
    ///
    /// # Safety
    /// `backing` must be live.
    pub unsafe fn reserve_thread_slot(
        &mut self,
        pid: u32,
        backing: &mut impl PageBacking,
    ) -> Option<ReservedThread> {
        unsafe {
            let id = self.handle_for(pid);
            let (mut head, len) = {
                let rec = self.slab.slot_get(id)?;
                (rec.threads_head, rec.threads_len)
            };
            // Reuse the first freed slot inside the used range.
            let mut block_id = head;
            let mut base = 0u32;
            while base < len && block_id.is_valid() {
                let (reuse, next) = match self.thread_blocks.slot_get(block_id) {
                    Some(b) => {
                        let mut hit = None;
                        let mut w = 0;
                        while w < THREADS_PER_BLOCK && (base + w as u32) < len {
                            if b.threads[w].state == ThreadState::Empty {
                                hit = Some(base + w as u32);
                                break;
                            }
                            w += 1;
                        }
                        (hit, b.next)
                    }
                    None => return None,
                };
                if let Some(found) = reuse {
                    return Some(ReservedThread {
                        pid,
                        global_idx: found,
                        tid: (found as u16) + 1,
                        grows: false,
                    });
                }
                base += THREADS_PER_BLOCK as u32;
                block_id = next;
            }
            // No reusable slot — append at `len`, growing the chain.
            if !head.is_valid() {
                let new = self
                    .thread_blocks
                    .slot_alloc(ThreadBlock::empty(), backing)?;
                head = new;
                if let Some(rec) = self.slab.slot_get_mut(id) {
                    rec.threads_head = new;
                }
            }
            let block_pos = len / THREADS_PER_BLOCK as u32;
            self.ensure_block(head, block_pos, backing)?;
            Some(ReservedThread {
                pid,
                global_idx: len,
                tid: (len as u16) + 1,
                grows: true,
            })
        }
    }

    /// Commit a reserved thread slot with `rec`, bumping `threads_len`
    /// when the reservation extended the chain.
    ///
    /// # Safety
    /// `reserved` must come from a prior [`reserve_thread_slot`] on the
    /// same `pid` with no intervening structural change to its chain.
    pub unsafe fn install_reserved_thread(
        &mut self,
        reserved: &ReservedThread,
        rec: ThreadRecord,
    ) -> bool {
        unsafe {
            let id = self.handle_for(reserved.pid);
            let head = match self.slab.slot_get(id) {
                Some(r) => r.threads_head,
                None => return false,
            };
            let block_pos = reserved.global_idx / THREADS_PER_BLOCK as u32;
            let within = (reserved.global_idx % THREADS_PER_BLOCK as u32) as usize;
            let Some(block_id) = self.find_block(head, block_pos) else {
                return false;
            };
            let Some(b) = self.thread_blocks.slot_get_mut(block_id) else {
                return false;
            };
            b.threads[within] = rec;
            if reserved.grows {
                if let Some(r) = self.slab.slot_get_mut(id) {
                    r.threads_len += 1;
                }
            }
            true
        }
    }

    /// Visit each live thread of `pid` in chain order.
    pub fn for_each_thread(&self, pid: u32, mut f: impl FnMut(&ThreadRecord)) {
        let Some(rec) = self.get(pid) else {
            return;
        };
        let (head, len) = (rec.threads_head, rec.threads_len);
        // SAFETY: single-threaded owner.
        unsafe {
            let mut block_id = head;
            let mut gidx = 0u32;
            while gidx < len && block_id.is_valid() {
                let Some(b) = self.thread_blocks.slot_get(block_id) else {
                    return;
                };
                let next = b.next;
                let mut w = 0;
                while w < THREADS_PER_BLOCK && gidx < len {
                    if b.threads[w].state != ThreadState::Empty {
                        f(&b.threads[w]);
                    }
                    gidx += 1;
                    w += 1;
                }
                block_id = next;
            }
        }
    }

    /// Visit each live thread of `pid` for mutation.
    pub fn for_each_thread_mut(&mut self, pid: u32, mut f: impl FnMut(&mut ThreadRecord)) {
        let Some(rec) = self.get(pid) else {
            return;
        };
        let (head, len) = (rec.threads_head, rec.threads_len);
        // SAFETY: single-threaded owner.
        unsafe {
            let mut block_id = head;
            let mut gidx = 0u32;
            while gidx < len && block_id.is_valid() {
                let next = match self.thread_blocks.slot_get(block_id) {
                    Some(b) => b.next,
                    None => return,
                };
                if let Some(b) = self.thread_blocks.slot_get_mut(block_id) {
                    let mut w = 0;
                    while w < THREADS_PER_BLOCK && gidx < len {
                        if b.threads[w].state != ThreadState::Empty {
                            f(&mut b.threads[w]);
                        }
                        gidx += 1;
                        w += 1;
                    }
                }
                block_id = next;
            }
        }
    }

    /// Reset `pid` to exactly one thread (`main`), freeing extra blocks.
    /// Used by exec replace and the spawn main-thread install.
    pub fn set_single_thread(&mut self, pid: u32, main: ThreadRecord) -> bool {
        let id = self.handle_for(pid);
        // SAFETY: single-threaded owner.
        unsafe {
            let head = match self.slab.slot_get(id) {
                Some(r) => r.threads_head,
                None => return false,
            };
            if !head.is_valid() {
                return false;
            }
            let tail = if let Some(b) = self.thread_blocks.slot_get_mut(head) {
                b.threads[0] = main;
                for w in 1..THREADS_PER_BLOCK {
                    b.threads[w] = ThreadRecord::empty();
                }
                let tail = b.next;
                b.next = SlabId::INVALID;
                tail
            } else {
                return false;
            };
            self.free_thread_chain(tail);
            if let Some(r) = self.slab.slot_get_mut(id) {
                r.threads_len = 1;
            }
            true
        }
    }

    /// Walk to the `pos`-th block of a chain (read-only); `None` if the
    /// chain is shorter than `pos + 1`.
    ///
    /// # Safety
    /// Single-threaded owner.
    unsafe fn find_block(&self, head: SlabId, pos: u32) -> Option<SlabId> {
        unsafe {
            let mut cur = head;
            let mut i = 0;
            while i < pos {
                cur = self.thread_blocks.slot_get(cur)?.next;
                if !cur.is_valid() {
                    return None;
                }
                i += 1;
            }
            if cur.is_valid() { Some(cur) } else { None }
        }
    }

    /// Walk to the `pos`-th block, allocating and linking blocks as
    /// needed. `head` must be valid.
    ///
    /// # Safety
    /// Single-threaded owner; `backing` live.
    unsafe fn ensure_block(
        &mut self,
        head: SlabId,
        pos: u32,
        backing: &mut impl PageBacking,
    ) -> Option<SlabId> {
        unsafe {
            let mut cur = head;
            let mut i = 0;
            while i < pos {
                let next = self.thread_blocks.slot_get(cur)?.next;
                if next.is_valid() {
                    cur = next;
                } else {
                    let new = self
                        .thread_blocks
                        .slot_alloc(ThreadBlock::empty(), backing)?;
                    if let Some(b) = self.thread_blocks.slot_get_mut(cur) {
                        b.next = new;
                    }
                    cur = new;
                }
                i += 1;
            }
            Some(cur)
        }
    }

    /// Free an entire thread-block chain back to the arena.
    ///
    /// # Safety
    /// Single-threaded owner.
    unsafe fn free_thread_chain(&mut self, head: SlabId) {
        unsafe {
            let mut cur = head;
            while cur.is_valid() {
                let next = match self.thread_blocks.slot_get(cur) {
                    Some(b) => b.next,
                    None => break,
                };
                self.thread_blocks.slot_free(cur);
                cur = next;
            }
        }
    }
}
