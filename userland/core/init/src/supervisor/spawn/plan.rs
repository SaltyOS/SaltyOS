// SPDX-License-Identifier: GPL-2.0-only
//
//! Spawn plan types — the data shape that describes "what process
//! shall come into existence". Three discriminators steer the
//! `realize_process` pipeline:
//!
//! * [`SpawnKind`] — fresh service vs. POSIX fork vs. POSIX exec.
//!   Decides proc-record allocation strategy and whether the kernel
//!   object set is freshly retyped or partially reused.
//! * [`AddressSpacePlan`] — fresh image vs. COW-fork vs. exec
//!   replacement. Decides the path image bytes take into the child
//!   VSpace.
//! * [`BootstrapPlan`] — the aggregate description with bounds and
//!   parent pid wired in.
//!
//! `realize_process` returns a [`RealizeOutcome`] with the child pid
//! visible to the caller. Internal phases keep the client id scoped
//! to supervisor bookkeeping and badge minting.
//!
//! [`ChildBundle`] holds slot indices in *init's* CSpace; the spawn
//! pipeline `cnode_copy/mint/move`s these into the child's
//! freshly-retyped CNode at spawn time.

use crate::supervisor::manifest::ServiceDef;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::layout::VmClientLayout;
use trona_runtime::spawn::stack_plan::{
    StackLayoutSpec, StackMaterialization, plan_stack_materialization,
};

/// Base receive-window slot count for every spawn. TCB + VSpace +
/// CNode + SC (4 singles) + request/signal/fault/mmsrv/service_ep
/// MP pairs (5 × 2 = 10) = 14 slots. The allocator hands out this
/// run from the dynamic pool; `BootstrapPlan::receive_window_size`
/// adds the ldsrv-only extra slots on top.
pub const RECEIVE_WINDOW_BASE: u64 = 14;

/// Extra receive-window slots reserved only for ldsrv: adopt MP pair
/// + exec-control MP pair (2 × 2 = 4 slots). No other service uses
/// these; their spawns allocate `RECEIVE_WINDOW_BASE` only.
pub const RECEIVE_WINDOW_LDSRV_EXTRA: u64 = 4;

/// Which lifecycle transition is being realised. Discriminates the
/// proc-record allocation strategy and whether the kernel object set
/// is freshly retyped or partially reused (Exec keeps TCB / CSpace
/// and only rebuilds VSpace contents).
#[derive(Clone, Copy)]
/// Top-level driver of the lifecycle pipeline. Each variant carries
/// the per-spawn parameters specific to its source flow:
/// - `Service` / `Exec` need the manifest service index of the
///   binary to load.
/// - `Fork` needs the parent's saved RSP and the child entry-point
///   address — both produced by `lib/trona/posix/arch/<arch>/fork.S`
///   and forwarded through the `INIT_FORK` IPC.
pub enum SpawnKind {
    /// `INIT_SPAWN(svc_idx, ...)` — fresh service from the manifest.
    Service { svc_idx: usize },
    /// `INIT_FORK` — duplicate the parent process. New proc-record,
    /// new client_id, but VSpace is COW-shared with the parent.
    Fork {
        parent_pid: u32,
        /// Parent RSP captured by `posix_fork`'s assembly trampoline
        /// after pushing callee-saved GPRs (and XMM under
        /// `SALTY_X86_SIMD`). The child resumes at `child_entry`
        /// with this exact RSP — `fork_child_entry` then pops the
        /// saved registers and returns 0 to the caller.
        saved_rsp: u64,
        /// Address of `fork_child_entry` inside the child's mapped
        /// image. The child's TCB starts execution here; the
        /// trampoline calls `_trona_post_fork_child` to re-init
        /// substrate state, then restores GPRs and returns 0.
        child_entry: u64,
        /// Parent thread-pointer base captured by the POSIX fork
        /// trampoline. The child starts on the parent's COW TLS block
        /// long enough for `_trona_post_fork_child` to rebuild its
        /// process-local runtime state.
        tls_base: u64,
    },
    /// `INIT_EXEC` — replace the existing process image in place.
    /// Same proc-record, same TCB, same CSpace; VSpace contents are
    /// torn down and re-staged from the new binary.
    Exec { existing_pid: u32 },
}

/// How the child VSpace is populated.
#[derive(Clone, Copy)]
pub enum AddressSpacePlan {
    /// Brand-new VSpace, ELF/PE segments staged from the initrd via
    /// `MM_STAGE_IMAGE_REGION`. The CPIO entry is named by the plan's
    /// `def.binary` field.
    FreshImage,
    /// COW-fork the source client's VSpace via `MM_FORK_VSPACE`.
    ForkCow { parent_client_id: u32 },
    /// Replace the existing client's VSpace contents. mmsrv tears down
    /// every region except the stack / brk anchor before staging the
    /// new image; the actual decommit is the final commit step so
    /// failures roll back to the pre-exec state. The exec MemoryObject and
    /// argv/envp travel out-of-band via [`ExecImage`].
    ExecReplace { existing_client_id: u32 },
}

/// The exec MemoryObject plus parsed headers and argv/envp for an
/// `execve`. Built by `handle_exec` from the path-based request: the
/// calling process resolved the binary under its own VFS authority and
/// forwarded a non-exec backing MemoryObject; init asks ldsrv to confer
/// the code MO, reads the headers from it (via `MO_READ`, which is
/// recoverable — a VFS pager failure never faults PID 1), and stages the
/// image's segments zero-copy from it.
/// Borrowed through `realize_process` → `phase_stage` → `exec_in_place`
/// for the duration of the synchronous exec call chain.
#[derive(Clone, Copy)]
pub struct ExecImage<'a> {
    /// Read+execute MemoryObject for the binary. mmsrv stages each
    /// segment directly from it (text/rodata shared, data copy-on-write
    /// sub-range, bss zero); init never copies the image bytes.
    pub exec_mo: trona_kernel::core_types::CapRef,
    /// The leading ELF/PE headers read out of `exec_mo` — enough to parse the
    /// segment geometry and interpreter/runtime path. Not the full image.
    pub header_bytes: &'a [u8],
    /// Program name to record / pass as `argv[0]`'s backing when the
    /// caller did not supply one (e.g. the resolved path).
    pub name: &'a [u8],
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
}

/// Aggregate description of the lifecycle transition.
pub struct BootstrapPlan {
    pub kind: SpawnKind,
    pub parent_pid: Option<u32>,
    pub def: ServiceDef,
    pub address_space: AddressSpacePlan,
    pub stack_spec: StackLayoutSpec,
    /// Per-process layout contract registered with mmsrv at
    /// `MM_REGISTER_CLIENT` / `MM_BEGIN_EXEC_REPLACE` time. For `Service` it
    /// is derived from `DEFAULT_CHILD_*` constants; for `Fork` it is copied
    /// from the parent's `ProcessRecord.layout` so the child registers
    /// before mmsrv's `inherit_vm_layout_from` step copies the parent's
    /// cursors (`heap_current`, `mmap_hint`); for `Exec` it is computed by
    /// `handle_exec_inner` from the new image's geometry via
    /// `compute_vm_layout(...).client_layout()`.
    pub client_layout: VmClientLayout,
}

impl BootstrapPlan {
    /// Total consecutive receive-window slots the allocator must hand
    /// out for this spawn. ldsrv additionally gets the adopt +
    /// exec-control MP pairs; every other service uses the base 14.
    /// `phase_alloc_bundle` reads this once into a local `window_count`
    /// and threads it through both the alloc and the failure cleanup —
    /// never the global constant directly — so the two never drift.
    pub fn receive_window_size(&self) -> u64 {
        if self.def.name.as_bytes() == b"ldsrv" {
            RECEIVE_WINDOW_BASE + RECEIVE_WINDOW_LDSRV_EXTRA
        } else {
            RECEIVE_WINDOW_BASE
        }
    }
}

/// Outcome of `realize_process`. For `Service` / `Fork` the child pid
/// is fresh; for `Exec` it refers to the existing process whose image
/// was replaced.
pub struct RealizeOutcome {
    pub child_pid: u32,
    /// Present when the lifecycle pipeline configured the child's main
    /// TCB but intentionally left it stopped until the caller's reply
    /// has been emitted. Raw TCB slot borrowed from the child's
    /// `ProcessRecord` (which owns the cap); `0` when there is no
    /// deferred start.
    pub deferred_start_tcb: u64,
}

/// Aggregate of caps init owns during spawn, in init's CSpace.
/// The spawn pipeline `cnode_copy/mint/move`s these into the child's
/// freshly-retyped CNode, then surviving caps are stamped into
/// `ProcessRecord` by `phase_install_proc_record`.
///
/// `mmsrv_request_mp_send` / `mmsrv_request_mp_recv` carry the
/// per-client mmsrv MP_CORE_PAIR retyped through `RSRC_ALLOC_MP_PAIR`
/// — init keeps the send side so mmsrv can receive a duplicate during
/// `MM_REGISTER_CLIENT` and later hand each child its self-tier send
/// via `MM_BIND_CLIENT_SELF`; the recv side is handed to mmsrv.
pub struct ChildBundle {
    pub tcb: Option<OwnedCap>,
    pub vspace: Option<OwnedCap>,
    pub cspace: Option<OwnedCap>,
    pub sched_context: Option<OwnedCap>,
    pub request_mp_send: Option<OwnedCap>,
    pub request_mp_recv: Option<OwnedCap>,
    pub signal_mp_send: Option<OwnedCap>,
    pub signal_mp_recv: Option<OwnedCap>,
    pub fault_mp_send: Option<OwnedCap>,
    pub fault_mp_recv: Option<OwnedCap>,
    pub mmsrv_request_mp_send: Option<OwnedCap>,
    pub mmsrv_request_mp_recv: Option<OwnedCap>,
    /// Child's self-master MP endpoint pair. The child waits on the
    /// recv side via `ROLE_SERVICE_EP`; it publishes the peer side via
    /// `ROLE_SERVICE_CLIENT_EP` / `NAMESRV_REGISTER` so client writes
    /// arrive at the service-side receive queue.
    pub service_ep_send: Option<OwnedCap>,
    pub service_ep_recv: Option<OwnedCap>,
    /// Recv end of the private PID1→ldsrv adopt MP, installed into `ldsrv`'s
    /// CSpace as `ROLE_LDSRV_ADOPT_RECV`. `None` for every service but `ldsrv`.
    pub adopt_recv: Option<OwnedCap>,
    /// Recv end of the private PID1→ldsrv exec-control MP, installed as
    /// `ROLE_LDSRV_EXEC_CONTROL_RECV`. A separate steady-state channel from the
    /// boot-only adopt MP — only init holds the send, gating `resolve_main`.
    /// `None` for every service but `ldsrv`.
    pub exec_control_recv: Option<OwnedCap>,
    /// Plumbing untyped init carves for ldsrv, from which it retypes its reactor
    /// objects (EventQueue + per-EP Watches). `None` for every service but
    /// `ldsrv`.
    pub ldsrv_untyped: Option<OwnedCap>,
}

impl ChildBundle {
    pub fn empty() -> Self {
        Self {
            tcb: None,
            vspace: None,
            cspace: None,
            sched_context: None,
            request_mp_send: None,
            request_mp_recv: None,
            signal_mp_send: None,
            signal_mp_recv: None,
            fault_mp_send: None,
            fault_mp_recv: None,
            mmsrv_request_mp_send: None,
            mmsrv_request_mp_recv: None,
            service_ep_send: None,
            service_ep_recv: None,
            adopt_recv: None,
            exec_control_recv: None,
            ldsrv_untyped: None,
        }
    }
}

/// Default stack top in a freshly-spawned child. Mirrors substrate
/// `layout::STACK_TOP_ANCHOR` (USER_VA_TOP - 128 MiB).
pub const DEFAULT_CHILD_STACK_TOP: u64 = (1u64 << 47) - 0x0800_0000;

// DEFAULT_CHILD_HEAP_BASE / _LIMIT, DEFAULT_CHILD_MMAP_BASE / _LIMIT, and
// DEFAULT_RUNTIME_DSO_BASE / _LIMIT all live in
// `trona_runtime::spawn::layout`. The layout module owns the disjointness
// guard (`assert_vm_windows_disjoint` + the DSO-arena top-level assertion),
// so init must not redefine these locally.

/// Child VA at which init maps the per-TCB IPC buffer page. The
/// kernel records this address via `TCB_CONFIGURE` so the syscall
/// fastpath can resolve receive windows without walking the CSpace.
/// Shared between boot path (`boot_core`) and post-mmsrv path
/// (`lifecycle::phase`).
pub const CHILD_IPC_BUFFER_VA: u64 = trona_runtime::spawn::layout::IPC_BUF_BASE;

/// Resolve the service's stack policy into concrete VA bounds for
/// `TCB_SET_STACK_BOUNDS` and mmsrv `REGION_KIND_STACK` staging.
pub fn child_stack_materialization(spec: StackLayoutSpec) -> Result<StackMaterialization, i32> {
    plan_stack_materialization(spec, DEFAULT_CHILD_STACK_TOP)
        .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)
}
