// SPDX-License-Identifier: GPL-2.0-only
//
//! Mmsrv-backed cap-table delivery for the post-mmsrv spawn path
//! (regular service spawn, fork, exec).
//!
//! For the boot path (Stage C/D/E core servers), init builds and maps
//! the cap-table directly via `spawn::cspace::build_and_map_cap_table`
//! using a pre-retyped FRAME from `CorePlumbing`. That path cannot run
//! once mmsrv is alive because mmsrv tracks every page-mapping in its
//! `RegionTable`; bypassing it would leave a segment mmsrv cannot
//! resolve on page-fault.
//!
//! The post-mmsrv equivalent stages the cap-table in a writable anon
//! region in init's own VSpace (`MM_MMAP`), runs `CapTableBuilder` on
//! the scratch bytes, then asks mmsrv to splice the same MO into the
//! child VSpace at `CHILD_CAP_TABLE_VA` read-only via
//! `MM_STAGE_IMAGE_REGION`. mmsrv's RegionTable now tracks the mapping
//! on both sides, so a child page-fault on the cap-table area resolves
//! correctly.
//!
//! `txn_id == Some(_)` routes the splice through an exec transaction
//! so the new cap-table lands in the pending VSpace until
//! `MM_COMMIT_EXEC_REPLACE` swaps it in.
//!
//! **Critical invariant**: every entry in the cap-table references a
//! slot that init has actually populated in the child's CSpace via
//! `cnode_copy / cnode_mint / cnode_move`. The role_id alone is not a
//! cap — the child's substrate looks up the role to find the child's
//! slot, then `invoke`s against that slot. If the slot were left
//! empty, every invoke would return `KERNITE_ERR_INVALID_CAPABILITY`.

use trona_kernel::core_types::CapRef;
use trona_runtime::core::slot_alloc::OwnedCap;
use trona_runtime::spawn::cap_table::CapTableBuilder;
use trona_runtime::spawn::role_consts::{
    ROLE_CLOCK, ROLE_COM1_IOPORT, ROLE_COM1_IRQ, ROLE_DEVICE_CONTROL, ROLE_FB_UNTYPED,
    ROLE_INIT_CONTROL, ROLE_INITRD_UNTYPED, ROLE_KBD_IOPORT, ROLE_KBD_IRQ, ROLE_KERNEL_DEBUG,
    ROLE_KERNEL_RNG, ROLE_LDSRV_ADOPT_RECV, ROLE_LDSRV_CLIENT, ROLE_LDSRV_EXEC_CONTROL_RECV,
    ROLE_LDSRV_PLUMBING_UNTYPED, ROLE_LOG_CLIENT, ROLE_MMSRV_CLIENT, ROLE_NAMESRV_CLIENT,
    ROLE_PCI_IOPORT, ROLE_SC_CAP, ROLE_SERVICE_CLIENT_EP, ROLE_SERVICE_EP, ROLE_SIGNAL_PIPE,
    ROLE_SYSTEM_CONTROL, ROLE_SYSTEM_INFO, local_role_id,
};

use crate::internal_slots::{
    SLOT_SYSCAP_CLOCK, SLOT_SYSCAP_KERNEL_DEBUG, SLOT_SYSCAP_KERNEL_RNG,
    SLOT_SYSCAP_SYSTEM_CONTROL, SLOT_SYSCAP_SYSTEM_INFO,
};
use crate::supervisor::SupervisorState;
use crate::supervisor::manifest::{IfaceKey, NameStr, ServiceDef, ServiceManifest, UnitRef};
use crate::supervisor::mm_ipc::{
    MMAP_KIND_ANON, PROT_READ, PROT_WRITE, STAGE_IMAGE_KIND_NONE, mm_mmap_self, mm_munmap_self,
    mm_stage_image_region, mm_stage_image_region_exec,
};
use crate::supervisor::namesrv_ipc::lookup_as_client_at;
use crate::supervisor::proc_table::PidTable;
use crate::supervisor::registry::InterfaceRegistry;
use crate::supervisor::spawn::cspace::{
    deliver_cap, deliver_cap_minted, place_empty_slot_range, push_cap_table_entry,
};
use crate::supervisor::spawn::plan::ChildBundle;
use trona_runtime::spawn::layout::CHILD_CAP_TABLE_VA;

/// First child-CNode slot the post-mmsrv cap-table delivery starts
/// vending from. Slots 0/1/2 are reserved for `KERNITE_CAP_SELF_TCB
/// / VSPACE / CSPACE` (seeded by `spawn::cspace::seed_self_caps`);
/// the boot-path child CNode reserves slots 3..16 as well, so post-
/// mmsrv delivery uses the same `CHILD_RUNTIME_BASE_SLOT = 16`
/// convention.
const CHILD_RUNTIME_BASE_SLOT: u64 = 16;

/// Publisher-class bits used in namesrv child badges (matches
/// `userland/core/namesrv/src/authz.rs`'s class encoding: bits 63:62
/// = `0b01` for publisher tier).
const NAMESRV_PUBLISHER_CLASS: u64 = 0b01u64 << 62;

/// Compute the first child-CNode slot that remains available for the
/// runtime slot allocator after init installs the cap-table entries
/// described by `def`.
pub fn planned_alloc_slot_base(def: &ServiceDef, manifest: &ServiceManifest) -> u64 {
    let mut child_slot = CHILD_RUNTIME_BASE_SLOT;

    // Always-on system caps: KernelRng, Clock, SystemInfo.
    child_slot += 3;
    if def.bootstrap_privileged {
        // SystemControl and KernelDebug.
        child_slot += 2;
    }
    if receives_log_client(def) {
        child_slot += 1;
    }

    for u in 0..def.unit_requires_len as usize {
        if let UnitRef::Cap(_) = def.unit_requires[u] {
            child_slot += 1;
        }
    }

    // InitControl, NamesrvClient, MmsrvClient, SignalPipe, SC cap,
    // ServiceEp recv, ServiceEp client peer, and LdsrvClient. The ldsrv
    // client slot is still consumed on pre-handoff spawns, but no role entry
    // is emitted until the provider exists.
    child_slot += 8;

    if def.name.as_bytes() == b"ldsrv" {
        // Private ldsrv startup caps: adopt recv, exec-control recv, and its
        // plumbing untyped. `install_caps` emits these only for ldsrv; the
        // planned allocator floor must reserve the same slots.
        child_slot += 3;
    }

    for u in 0..def.unit_requires_len as usize {
        if let UnitRef::LocalAlias { .. } = def.unit_requires[u] {
            child_slot += 1;
        }
    }

    for u in 0..def.unit_requires_len as usize {
        if let UnitRef::Socket(name) = def.unit_requires[u] {
            if matches!(
                manifest.find_socket_by_name(name.as_bytes()),
                Some(sock) if !sock.alias.as_bytes().is_empty()
            ) {
                child_slot += 1;
            }
        }
    }

    for i in 0..def.provides_len as usize {
        if def.provides[i].role_id != 0 {
            child_slot += 1;
        }
    }

    child_slot
}

/// Build the child's `SaltyOSCapTableV1` and stage it from a fresh
/// mmsrv-managed anon region in init's VSpace into the child's
/// VSpace at [`CHILD_CAP_TABLE_VA`] read-only. The child's rtld
/// reads the table address from the auxv `AT_SALTYOS_STARTUP` entry
/// (composed by [`super::stack::compose`]) and walks
/// `(role_id → child_slot)` pairs to resolve named caps at runtime.
///
/// For each role, this routine first installs the underlying cap in
/// the child's CNode at a freshly chosen slot via `cnode_copy /
/// cnode_mint`, then records `(role_id → child_slot)` in the
/// builder. Without the install step the child's slot is empty and
/// every invoke against the resolved address fails with
/// `KERNITE_ERR_INVALID_CAPABILITY`.
///
/// `dst_client_id` is the new process's mmsrv client id; the source
/// is always init's own client (`state.caps.init_client_id`).
/// `txn_id == Some(_)` routes the staging through an exec
/// transaction so the new cap-table lands in the pending VSpace.
/// Returns the first child-CNode slot not consumed by installed caps
/// or reserved empty cap-table ranges; the stack composer advertises
/// that value as `SaltyOSCspaceLayoutV1.alloc_base`.
pub fn populate_via_mmsrv(
    state: &mut SupervisorState,
    dst_client_id: u32,
    def: &ServiceDef,
    bundle: &ChildBundle,
    exec_fallback: Option<ExecMpFallback>,
    txn_id: Option<u64>,
) -> Result<u64, i32> {
    let frame_bytes = uapi::KERNITE_PAGE_BYTES as u64;
    let src_client_id = state.caps.init_client_id;

    // Snapshot the unminted namesrv master MP send before borrowing
    // `state` mutably for the staging path — `install_caps` mints a
    // per-child publisher copy from this slot. The source must be
    // the raw (Grant-bearing) send, not the admin-minted
    // `state.caps.namesrv_client_mp` whose Grant was stripped at
    // mint time.
    let namesrv_raw = state
        .caps
        .namesrv_master_mp_send_raw
        .as_ref()
        .map(OwnedCap::borrow);
    let ldsrv_required = !state.exec_authority_held;

    // Seed `KERNITE_CAP_SELF_TCB / VSPACE / CSPACE` at slots 0/1/2.
    // Every spawn kind — Service, Fork, and Exec — retypes a fresh child
    // CNode, so copying into empty slots always succeeds.
    crate::supervisor::spawn::cspace::seed_self_caps(bundle)?;

    let (scratch_va, src_region_packed) = mm_mmap_self(
        state,
        MMAP_KIND_ANON,
        0,
        frame_bytes,
        PROT_READ | PROT_WRITE,
        0,
    )?;

    let mut builder =
        unsafe { CapTableBuilder::new_at(scratch_va as *mut u8, frame_bytes as usize) };
    let install_result = install_caps(
        &mut builder,
        bundle,
        exec_fallback,
        dst_client_id,
        def,
        namesrv_raw,
        ldsrv_required,
        &state.manifest,
        &state.interfaces,
        &state.procs,
    );
    let _hdr_bytes = unsafe { builder.finalize() };

    let alloc_slot_base = match install_result {
        Ok(slot) => slot,
        Err(e) => {
            let _ = mm_munmap_self(state, scratch_va, frame_bytes);
            return Err(e);
        }
    };

    let stage_result = match txn_id {
        Some(txn) => mm_stage_image_region_exec(
            state,
            src_client_id,
            src_region_packed,
            dst_client_id,
            CHILD_CAP_TABLE_VA,
            0,
            frame_bytes,
            frame_bytes,
            PROT_READ,
            STAGE_IMAGE_KIND_NONE,
            txn,
        ),
        None => mm_stage_image_region(
            state,
            src_client_id,
            src_region_packed,
            dst_client_id,
            CHILD_CAP_TABLE_VA,
            0,
            frame_bytes,
            frame_bytes,
            PROT_READ,
            STAGE_IMAGE_KIND_NONE,
            0,
        ),
    };

    mm_munmap_self(state, scratch_va, frame_bytes)?;
    stage_result?;
    Ok(alloc_slot_base)
}

/// Process-level MP capabilities the ProcessRecord retains across an
/// `execve`. The exec image's `ChildBundle` carries `None` for them — only
/// the fresh VSpace / TCB / SchedContext / CNode are new — so `install_caps`
/// falls back to these when a process-MP role's bundle slot is `None`.
#[derive(Clone, Copy)]
pub struct ExecMpFallback {
    pub request_mp_send: Option<CapRef>,
    pub mmsrv_request_mp_send: Option<CapRef>,
    pub signal_mp_recv: Option<CapRef>,
    pub service_ep_recv: Option<CapRef>,
    pub service_ep_send: Option<CapRef>,
}

fn require_cap(src: Option<CapRef>) -> Result<CapRef, i32> {
    src.ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)
}

fn deliver_required_cap(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    role_id: u32,
    src: Option<CapRef>,
    dest_slot: u64,
    flags: u32,
) -> Result<(), i32> {
    deliver_cap(
        child_cnode,
        builder,
        role_id,
        Some(require_cap(src)?),
        dest_slot,
        flags,
    )
}

fn deliver_required_cap_minted(
    child_cnode: CapRef,
    builder: &mut CapTableBuilder,
    role_id: u32,
    src: Option<CapRef>,
    dest_slot: u64,
    badge: u64,
    flags: u32,
) -> Result<(), i32> {
    deliver_cap_minted(
        child_cnode,
        builder,
        role_id,
        Some(require_cap(src)?),
        dest_slot,
        badge,
        flags,
    )
}

/// Install every role's cap in the child's CNode and push the
/// matching `(role_id → child_slot)` entry into the cap-table
/// builder. Returns the child-slot high-water mark, or `Err` if any
/// `cnode_copy / cnode_mint` rejects.
///
/// `namesrv_raw_send` is the unminted namesrv master MP send (Grant
/// preserved) that init holds for per-child minting. `cnode_mint`
/// strips Grant from the destination, so once a per-child publisher
/// copy is minted from it the copy cannot itself serve as a re-mint
/// source — acceptable since each child only uses its own send.
///
/// Non-aliased service endpoints are not installed here — children
/// resolve them lazily through `NAMESRV_LOOKUP("<service>")` on first
/// use. Aliased `.socket` units (`Provider=pcidrv`, `Alias=pcidrv_ep`)
/// are explicit service-local imports and are installed under
/// `local_role_id("<consumer>:<alias>")`.
///
/// Policy caps (manifest `Requires=foo.cap`) are resolved against
/// `manifest.caps[]` (every `*.cap` unit's `[Capability] SourceSlot=`
/// — the actual init-side slot the bootloader populated). Each cap
/// is delivered with the role id derived from its name.
///
/// Service-local `Requires=provider:alias` entries are resolved
/// against `interfaces` (init's runtime registry of provider
/// `INIT_REGISTER_INTERFACE` calls). Aliased `.socket` entries are
/// resolved directly against the provider's process record.
fn install_caps(
    builder: &mut CapTableBuilder,
    bundle: &ChildBundle,
    exec_fallback: Option<ExecMpFallback>,
    dst_client_id: u32,
    def: &ServiceDef,
    namesrv_raw_send: Option<CapRef>,
    ldsrv_required: bool,
    manifest: &ServiceManifest,
    interfaces: &InterfaceRegistry,
    procs: &PidTable,
) -> Result<u64, i32> {
    let mut child_slot = CHILD_RUNTIME_BASE_SLOT;
    let child_cnode = bundle
        .cspace
        .as_ref()
        .map(OwnedCap::borrow)
        .unwrap_or_default();

    // Always-on system caps — RNG / Clock / SystemInfo. Every process
    // gets these regardless of privilege. `cnode_copy` from init's
    // well-known slots into consecutive child slots.
    deliver_cap(
        child_cnode,
        builder,
        ROLE_KERNEL_RNG,
        Some(CapRef::flat(SLOT_SYSCAP_KERNEL_RNG)),
        child_slot,
        0,
    )?;
    child_slot += 1;
    deliver_cap(
        child_cnode,
        builder,
        ROLE_CLOCK,
        Some(CapRef::flat(SLOT_SYSCAP_CLOCK)),
        child_slot,
        0,
    )?;
    child_slot += 1;
    deliver_cap(
        child_cnode,
        builder,
        ROLE_SYSTEM_INFO,
        Some(CapRef::flat(SLOT_SYSCAP_SYSTEM_INFO)),
        child_slot,
        0,
    )?;
    child_slot += 1;

    // Privileged system caps — SystemControl (shutdown/reboot) and
    // KernelDebug (debug printk).
    if def.bootstrap_privileged {
        deliver_cap(
            child_cnode,
            builder,
            ROLE_SYSTEM_CONTROL,
            Some(CapRef::flat(SLOT_SYSCAP_SYSTEM_CONTROL)),
            child_slot,
            0,
        )?;
        child_slot += 1;
        deliver_cap(
            child_cnode,
            builder,
            ROLE_KERNEL_DEBUG,
            Some(CapRef::flat(SLOT_SYSCAP_KERNEL_DEBUG)),
            child_slot,
            0,
        )?;
        child_slot += 1;
    }

    // Non-privileged diagnostics flow through logsrv, not KernelDebug.
    // The slot is still reserved before logsrv itself exists so
    // `planned_alloc_slot_base` stays deterministic for early
    // services such as console. Once logsrv is active, post-logsrv
    // services receive a real endpoint at the same role.
    if receives_log_client(def) {
        let log_ep = logsrv_send_cap(manifest, procs);
        deliver_cap(child_cnode, builder, ROLE_LOG_CLIENT, log_ep, child_slot, 0)?;
        child_slot += 1;
    }

    // Policy caps — `Requires=foo.cap` units. Resolved against the
    // manifest's `caps[]` table; every `.cap` unit's `SourceSlot`
    // names an init-side cap-table slot the bootloader populated.
    for u in 0..def.unit_requires_len as usize {
        if let UnitRef::Cap(name) = def.unit_requires[u] {
            let cap_def = manifest
                .find_cap_by_name(name.as_bytes())
                .ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
            let role = role_for_policy_cap(name.as_bytes())
                .ok_or(uapi::KERNITE_ERR_INVALID_ARGUMENT as i32)?;
            deliver_cap(
                child_cnode,
                builder,
                role,
                Some(CapRef::flat(cap_def.source_slot)),
                child_slot,
                0,
            )?;
            child_slot += 1;
        }
    }

    // `ROLE_INIT_CONTROL` is mint-stamped with `dst_client_id` as
    // the badge so init's reactor demultiplexes inbound records by
    // client identity.
    deliver_required_cap_minted(
        child_cnode,
        builder,
        ROLE_INIT_CONTROL,
        bundle
            .request_mp_send
            .as_ref()
            .map(OwnedCap::borrow)
            .or_else(|| exec_fallback.as_ref().and_then(|f| f.request_mp_send)),
        child_slot,
        dst_client_id as u64,
        0,
    )?;
    child_slot += 1;

    // `ROLE_NAMESRV_CLIENT` — mint a per-child copy of the unminted
    // namesrv master MP send badged with the publisher class (bits
    // 63:62 = 0b01) plus the child's `client_id` packed into the
    // identity field. Publisher class lets the child call
    // `NAMESRV_REGISTER` / `_UNREGISTER` for its own prefix and also
    // `NAMESRV_LOOKUP` for any prefix; admin labels
    // (`_GRANT_PUBLISHER`, `_OWNER_EXITED`) require the admin class
    // which only init holds.
    let namesrv_child_badge = NAMESRV_PUBLISHER_CLASS | (dst_client_id as u64);
    deliver_required_cap_minted(
        child_cnode,
        builder,
        ROLE_NAMESRV_CLIENT,
        namesrv_raw_send,
        child_slot,
        namesrv_child_badge,
        0,
    )?;
    child_slot += 1;

    // `ROLE_MMSRV_CLIENT` — per-client self-tier send. This is a
    // bootstrap cap, not a lazy service dependency: dynamic loaders may
    // need `MM_MPROTECT` before the process slot allocator is ready for
    // namesrv-based lazy resolution.
    deliver_required_cap(
        child_cnode,
        builder,
        ROLE_MMSRV_CLIENT,
        bundle
            .mmsrv_request_mp_send
            .as_ref()
            .map(OwnedCap::borrow)
            .or_else(|| exec_fallback.as_ref().and_then(|f| f.mmsrv_request_mp_send)),
        child_slot,
        0,
    )?;
    child_slot += 1;

    // `ROLE_SIGNAL_PIPE` — recv side of the per-process signal MP.
    // Init writes signal records, child reads. Plain copy of the
    // recv side suffices.
    deliver_required_cap(
        child_cnode,
        builder,
        ROLE_SIGNAL_PIPE,
        bundle
            .signal_mp_recv
            .as_ref()
            .map(OwnedCap::borrow)
            .or_else(|| exec_fallback.as_ref().and_then(|f| f.signal_mp_recv)),
        child_slot,
        0,
    )?;
    child_slot += 1;

    // `ROLE_SC_CAP` — main-thread SchedContext cap. Fork children
    // reinstall this from the cap-table before returning to user code,
    // so they do not need to synchronously ask init during post-fork
    // repair.
    deliver_required_cap(
        child_cnode,
        builder,
        ROLE_SC_CAP,
        bundle.sched_context.as_ref().map(OwnedCap::borrow),
        child_slot,
        0,
    )?;
    child_slot += 1;

    // `ROLE_SERVICE_EP` — service-side receive endpoint. Server loops
    // block here with MP_READ / mp_write_reply_read.
    deliver_required_cap(
        child_cnode,
        builder,
        ROLE_SERVICE_EP,
        bundle
            .service_ep_recv
            .as_ref()
            .map(OwnedCap::borrow)
            .or_else(|| exec_fallback.as_ref().and_then(|f| f.service_ep_recv)),
        child_slot,
        0,
    )?;
    child_slot += 1;

    // `ROLE_SERVICE_CLIENT_EP` — peer endpoint for clients, namesrv
    // publication, and same-process synthetic wake messages. Writes
    // through this side arrive on `ROLE_SERVICE_EP`.
    deliver_required_cap(
        child_cnode,
        builder,
        ROLE_SERVICE_CLIENT_EP,
        bundle
            .service_ep_send
            .as_ref()
            .map(OwnedCap::borrow)
            .or_else(|| exec_fallback.as_ref().and_then(|f| f.service_ep_send)),
        child_slot,
        0,
    )?;
    child_slot += 1;

    // `ROLE_LDSRV_CLIENT` — direct ldsrv client endpoint. Before the ldsrv
    // handoff, no provider exists yet, so the role is omitted and runtime
    // lazy resolution remains possible after ldsrv publishes. After handoff,
    // every mmsrv-backed spawn/exec receives this role directly; absence is a
    // supervisor error, same as missing `ROLE_MMSRV_CLIENT` in this path.
    if ldsrv_required {
        lookup_as_client_at(
            require_cap(namesrv_raw_send)?,
            dst_client_id,
            b"ldsrv",
            child_cnode,
            child_slot,
            trona_runtime::current_ipc_ctx(),
        )?;
        push_cap_table_entry(builder, ROLE_LDSRV_CLIENT, child_slot, 0, 0)?;
    }
    child_slot += 1;

    // `ROLE_LDSRV_ADOPT_RECV` — recv end of the private PID1→ldsrv adopt MP.
    // Delivered only to ldsrv (the bundle field is `None` for every other
    // service), so no other process is on the adopt channel.
    if let Some(adopt_recv) = bundle.adopt_recv.as_ref() {
        deliver_cap(
            child_cnode,
            builder,
            ROLE_LDSRV_ADOPT_RECV,
            Some(adopt_recv.borrow()),
            child_slot,
            0,
        )?;
        child_slot += 1;
    }

    // `ROLE_LDSRV_EXEC_CONTROL_RECV` — recv end of the dedicated exec-control MP
    // over which init issues `resolve_main`. Delivered only to ldsrv.
    if let Some(exec_control_recv) = bundle.exec_control_recv.as_ref() {
        deliver_cap(
            child_cnode,
            builder,
            ROLE_LDSRV_EXEC_CONTROL_RECV,
            Some(exec_control_recv.borrow()),
            child_slot,
            0,
        )?;
        child_slot += 1;
    }

    // `ROLE_LDSRV_PLUMBING_UNTYPED` — small untyped ldsrv retypes its reactor
    // objects from. Delivered only to ldsrv.
    if let Some(ldsrv_untyped) = bundle.ldsrv_untyped.as_ref() {
        deliver_cap(
            child_cnode,
            builder,
            ROLE_LDSRV_PLUMBING_UNTYPED,
            Some(ldsrv_untyped.borrow()),
            child_slot,
            0,
        )?;
        child_slot += 1;
    }

    // Service-local `Requires=provider:alias` consumer caps. Each
    // entry resolves through init's `InterfaceRegistry`, populated
    // by the provider's `INIT_REGISTER_INTERFACE` call when the
    // provider service started. The graph guarantees the provider
    // is ready before any consumer dispatches, so a missing entry
    // here is a manifest bug — fail loud with `KERNITE_ERR_NOT_FOUND`
    // so the supervisor's spawn loop logs it.
    for u in 0..def.unit_requires_len as usize {
        if let UnitRef::LocalAlias { provider, alias } = def.unit_requires[u] {
            let mut key_buf = [0u8; crate::supervisor::manifest::MAX_IFACE_KEY_BYTES];
            let key = build_iface_key(&mut key_buf, provider, alias);
            let entry = interfaces
                .lookup(&IfaceKey::from_bytes(key))
                .ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
            let role = local_role_id(key);
            deliver_cap(
                child_cnode,
                builder,
                role,
                Some(CapRef::flat(entry.provider_mp_send)),
                child_slot,
                0,
            )?;
            child_slot += 1;
        }
    }

    // Aliased `.socket` units are service-local endpoint imports:
    // `Requires=pcidrv-ep.socket` with `Alias=pcidrv_ep` installs the
    // provider's master service endpoint under the consumer-local role
    // `"<consumer>:pcidrv_ep"`. Non-aliased sockets are readiness-only
    // edges and are resolved by the runtime through namesrv.
    for u in 0..def.unit_requires_len as usize {
        if let UnitRef::Socket(name) = def.unit_requires[u] {
            let Some(sock) = manifest.find_socket_by_name(name.as_bytes()) else {
                return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
            };
            if sock.alias.as_bytes().is_empty() {
                continue;
            }
            let provider_idx = manifest
                .find_index_by_name(sock.provider.as_bytes())
                .ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)? as u8;
            let provider_ep = procs
                .iter_active()
                .find(|p| p.service_idx == provider_idx && p.service_ep_send.is_some())
                .and_then(|p| p.service_ep_send.as_ref().map(OwnedCap::borrow))
                .ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
            let mut key_buf = [0u8; crate::supervisor::manifest::MAX_IFACE_KEY_BYTES];
            let key = build_iface_key(&mut key_buf, def.name, sock.alias);
            let role = local_role_id(key);
            deliver_cap(child_cnode, builder, role, Some(provider_ep), child_slot, 0)?;
            child_slot += 1;
        }
    }

    // Service-declared `ProvidesInterface=` entries with an explicit
    // `InterfaceRole=` reserve a child-side role slot. Metadata-only
    // interfaces, such as filesystem backend type tags, have role_id=0
    // and intentionally do not consume cap-table space.
    for i in 0..def.provides_len as usize {
        let p = def.provides[i];
        if p.role_id == 0 {
            continue;
        }
        place_empty_slot_range(builder, p.role_id, child_slot)?;
        child_slot += 1;
    }

    Ok(child_slot)
}

fn receives_log_client(def: &ServiceDef) -> bool {
    def.name.as_bytes() != b"logsrv"
}

fn logsrv_send_cap(manifest: &ServiceManifest, procs: &PidTable) -> Option<CapRef> {
    let idx = manifest.find_index_by_name(b"logsrv")? as u8;
    procs
        .iter_active()
        .find(|p| p.service_idx == idx && p.service_ep_send.is_some())
        .and_then(|p| p.service_ep_send.as_ref().map(OwnedCap::borrow))
}

/// Map a manifest `Requires=foo.cap` token to its hardware/policy
/// role id. Returns `None` for unknown names so the supervisor can
/// fail loud. The manifest validator already rejects unknown `.cap`
/// references at parse time, but install_caps adds a second guard
/// against drift.
fn role_for_policy_cap(name: &[u8]) -> Option<u32> {
    match name {
        b"fb_untyped.cap" => Some(ROLE_FB_UNTYPED),
        b"initrd_untyped.cap" => Some(ROLE_INITRD_UNTYPED),
        b"pci_ioport.cap" => Some(ROLE_PCI_IOPORT),
        b"com1_ioport.cap" => Some(ROLE_COM1_IOPORT),
        b"com1_irq.cap" => Some(ROLE_COM1_IRQ),
        b"kbd_ioport.cap" => Some(ROLE_KBD_IOPORT),
        b"kbd_irq.cap" => Some(ROLE_KBD_IRQ),
        b"device_control.cap" => Some(ROLE_DEVICE_CONTROL),
        _ => None,
    }
}

/// Compose the `provider:alias` byte sequence used both as the
/// `IfaceKey` lookup key in `InterfaceRegistry` and as input to
/// `local_role_id`. Writes into `key_buf` and returns the populated
/// slice.
fn build_iface_key<'a>(key_buf: &'a mut [u8], provider: NameStr, alias: NameStr) -> &'a [u8] {
    let p = provider.as_bytes();
    let a = alias.as_bytes();
    let total = p.len() + 1 + a.len();
    let n = total.min(key_buf.len());
    let mut written = 0;
    for &b in p {
        if written >= n {
            break;
        }
        key_buf[written] = b;
        written += 1;
    }
    if written < n {
        key_buf[written] = b':';
        written += 1;
    }
    for &b in a {
        if written >= n {
            break;
        }
        key_buf[written] = b;
        written += 1;
    }
    &key_buf[..written]
}
