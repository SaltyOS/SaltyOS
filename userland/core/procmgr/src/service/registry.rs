//! Boot-time service-def registry for procmgr.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Init parses every unit file in the initrd at boot. Pre-procmgr services it
//! spawns directly. Post-procmgr services it ships to procmgr as a chunked
//! `PM_REGISTER_SERVICE_DEFS` stream: each IPC call transfers one frame cap
//! containing a `TronaServiceDefs` header followed by
//! `service_count` `TronaServiceDef` entries and then
//! `attachment_count` `TronaServiceAttachment` entries.
//!
//! Procmgr validates the chunk header and keeps each received chunk mapped in
//! a dedicated registry VA range. The registry is consulted later by
//! `spawn_tx` when building the cap_table for a post-procmgr child: the wire
//! record names both the provider namespace and the attachment family, so
//! procmgr can handle endpoint attachments and capability attachments as
//! distinct cases instead of inferring everything from a pre-resolved
//! `role_id`.

use core::ptr;
use trona_kernel::core_types::{
    ATTACHMENT_TYPE_CAP, ATTACHMENT_TYPE_ENDPOINT, Cap, MAX_REQUIRE_PROVIDER, REQUIRE_KIND_LOCAL,
    REQUIRE_KIND_SYSTEM, TRONA_SERVICE_DEFS_FLAG_FIRST, TRONA_SERVICE_DEFS_MAGIC, TronaMsg,
    TronaServiceAttachment, TronaServiceDef, TronaServiceDefs,
};
use trona_runtime::spawn::cap_table::{CapTableBuilder, CapTableErr};
use uapi::CAP_TBL_FLAG_BADGED;

const FRAME_SIZE: usize = 4096;
const SERVICE_REGISTRY_BASE_VADDR: u64 = crate::PROCMGR_SCRATCH_VADDR + 0x0010_0000;
const SERVICE_REGISTRY_CHUNK_STRIDE: u64 = FRAME_SIZE as u64;

static mut REGISTERED_PROVIDER_COUNT: u32 = 0;
static mut SERVICE_REGISTRY_ATTACHMENT_COUNT: u32 = 0;

fn bootstrap_provider_count() -> u32 {
    let mut count = 0u32;
    if trona_runtime::client::caps::namesrv_ep() != 0 {
        count += 1;
    }
    if crate::base::cap_helpers::vfs_provider_ep() != 0 {
        count += 1;
    }
    if crate::base::cap_helpers::mmsrv_authority_raw() != 0 {
        count += 1;
    }
    if crate::base::cap_helpers::rsrcsrv_authority_raw() != 0 {
        count += 1;
    }
    count
}

unsafe fn publish_well_known_provider(name: &[u8], slot: u64) {
    if slot == 0 {
        return;
    }
    if name == b"vfs" {
        let _ = unsafe { crate::base::cap_helpers::refresh_vfs_caps(slot as Cap) };
    }
}

/// Outcome of `resolve_registry_attachments`. Carries enough information for the
/// caller to log a meaningful message but is otherwise opaque.
#[derive(Debug, Clone, Copy)]
pub enum ResolveErr {
    /// Service has more materialized attachment entries than the child cspace
    /// `[extras_base, frame_slot_start)` window can hold.
    SlotRangeExhausted,
    /// `cnode_mint` / `cnode_copy` from the procmgr provider slot into
    /// the child failed.
    CnodeOpFailed,
    /// `CapTableBuilder::push` ran out of space.
    BuilderOverflow,
    /// A lowered local endpoint attachment references a provider procmgr does
    /// not know about. The boot order should arrange for the provider to be
    /// spawned (and auto-registered) before any consumer.
    UnknownProvider,
    /// The registry described an attachment family procmgr cannot materialize
    /// into the child cap_table yet.
    UnsupportedAttachment,
}

impl From<CapTableErr> for ResolveErr {
    fn from(_: CapTableErr) -> Self {
        ResolveErr::BuilderOverflow
    }
}

#[derive(Clone, Copy)]
struct RegistryServiceView {
    entry: *mut TronaServiceDef,
    attachments: *mut TronaServiceAttachment,
    attachment_total: usize,
}

#[inline]
unsafe fn service_defs_ptr(header: *mut TronaServiceDefs) -> *mut TronaServiceDef {
    unsafe {
        (header as *mut u8).add(core::mem::size_of::<TronaServiceDefs>()) as *mut TronaServiceDef
    }
}

#[inline]
unsafe fn attachments_ptr(
    header: *mut TronaServiceDefs,
    service_count: usize,
) -> *mut TronaServiceAttachment {
    unsafe {
        (service_defs_ptr(header) as *mut u8)
            .add(service_count * core::mem::size_of::<TronaServiceDef>())
            as *mut TronaServiceAttachment
    }
}

fn attachment_kind_valid(kind: u8) -> bool {
    kind == REQUIRE_KIND_SYSTEM || kind == REQUIRE_KIND_LOCAL
}

fn attachment_type_valid(attachment_type: u8) -> bool {
    attachment_type == ATTACHMENT_TYPE_ENDPOINT || attachment_type == ATTACHMENT_TYPE_CAP
}

unsafe fn validate_registry_attachment(
    service_name: &[u8],
    entry: &TronaServiceAttachment,
) -> Result<(), u64> {
    if !attachment_kind_valid(entry.kind) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] register_service_defs: invalid attachment kind for ");
            _lb.bytes(service_name);
            _lb.str(b"\n");
        });
        return Err(crate::TRONA_INVALID_ARGUMENT);
    }
    if !attachment_type_valid(entry.attachment_type) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] register_service_defs: invalid attachment type for ");
            _lb.bytes(service_name);
            _lb.str(b"\n");
        });
        return Err(crate::TRONA_INVALID_ARGUMENT);
    }
    let provider_len = entry.provider_len as usize;
    if provider_len == 0 || provider_len > MAX_REQUIRE_PROVIDER {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] register_service_defs: invalid provider name for ");
            _lb.bytes(service_name);
            _lb.str(b"\n");
        });
        return Err(crate::TRONA_INVALID_ARGUMENT);
    }
    if entry.badged > 1 || entry.raw > 1 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] register_service_defs: invalid attachment flags for ");
            _lb.bytes(service_name);
            _lb.str(b"\n");
        });
        return Err(crate::TRONA_INVALID_ARGUMENT);
    }
    Ok(())
}

/// Resolve every lowered registry attachment entry for `service_name` and push
/// the resulting cap_table entries into `builder`.
///
/// - System-scope entries are silently skipped — they have already been pushed
///   by `ChildCapLayout::populate_cap_table` from the layout's well-known cap
///   fields. Pushing them again would create duplicates.
/// - `*_AUTHORITY_RAW` entries are skipped: they are procmgr-private and
///   never delivered to a child via the public cap_table.
/// - Local endpoint entries trigger a `lookup_provider(provider_name)`. The
///   matched procmgr-side cap is `cnode_mint`'d (badged with the consumer
///   `pid`) or `cnode_copy`'d (unbadged) into a freshly allocated slot in
///   `[cap_layout.extras_base, cap_layout.frame_slot_start)`, then pushed
///   to the builder.
/// - Local capability entries are rejected explicitly for now. The registry
///   can describe them, but procmgr does not yet have a generic
///   materialization path for service-provided capabilities.
///
/// `service_name` may be empty — in that case the function returns
/// `Ok(0)` immediately. This lets fork/exec paths share a single helper
/// without paying for a registry lookup.
pub unsafe fn resolve_registry_attachments(
    service_name: &[u8],
    pid: u32,
    child_cn: Cap,
    cap_layout: &trona_runtime::spawn::layout::ChildCapLayout,
    builder: &mut CapTableBuilder,
) -> Result<u32, ResolveErr> {
    if service_name.is_empty() {
        return Ok(0);
    }
    let view = match lookup_service_view(service_name) {
        Some(v) => v,
        None => return Ok(0),
    };
    let def = unsafe { &*view.entry };

    let mut next_slot = cap_layout.extras_base;
    let limit = cap_layout.frame_slot_start;
    let mut emitted: u32 = 0;
    let attachment_start = def.attachment_start as usize;
    let attachment_count = def.attachment_count as usize;
    if attachment_start > view.attachment_total
        || attachment_start.saturating_add(attachment_count) > view.attachment_total
    {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] resolve_registry_attachments: invalid attachment span for ");
            _lb.bytes(service_name);
            _lb.str(b"\n");
        });
        return Err(ResolveErr::UnknownProvider);
    }

    for r in 0..attachment_count {
        let entry = unsafe { &*view.attachments.add(attachment_start + r) };
        // System-owned roles are materialized elsewhere — never re-push.
        if entry.kind == REQUIRE_KIND_SYSTEM {
            continue;
        }
        if entry.kind != REQUIRE_KIND_LOCAL {
            continue;
        }
        if entry.attachment_type == ATTACHMENT_TYPE_CAP {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] resolve_registry_attachments: unsupported local cap attachment for ");
                _lb.bytes(service_name);
                _lb.str(b"\n");
            });
            return Err(ResolveErr::UnsupportedAttachment);
        }
        if entry.attachment_type != ATTACHMENT_TYPE_ENDPOINT {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] resolve_registry_attachments: unknown attachment type for ");
                _lb.bytes(service_name);
                _lb.str(b"\n");
            });
            return Err(ResolveErr::UnsupportedAttachment);
        }
        // Privileged raw caps are procmgr-private and not deliverable
        // through the public cap_table. The parser only sets `raw = 1`
        // when the manifest explicitly asks for `*_AUTHORITY_RAW`, which
        // requires `BootstrapPrivileged=yes` on the consumer — currently
        // procmgr only.
        if entry.raw != 0 {
            continue;
        }

        let provider_len = entry.provider_len as usize;
        if provider_len == 0 || provider_len > MAX_REQUIRE_PROVIDER {
            continue;
        }
        let provider_name = &entry.provider[..provider_len];

        let provider_slot = match lookup_provider(provider_name) {
            Some(s) => s,
            None => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] resolve_registry_attachments: ");
                    _lb.bytes(service_name);
                    _lb.str(b" needs unknown provider ");
                    _lb.bytes(provider_name);
                    _lb.str(b"\n");
                });
                return Err(ResolveErr::UnknownProvider);
            }
        };

        if next_slot >= limit {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] resolve_registry_attachments: ");
                _lb.bytes(service_name);
                _lb.str(b" extras window exhausted at slot ");
                _lb.dec(next_slot);
                _lb.str(b"\n");
            });
            return Err(ResolveErr::SlotRangeExhausted);
        }
        let child_slot = next_slot;
        next_slot += 1;

        let mint_err = if entry.badged != 0 {
            trona_kernel::invoke::cnode_mint(
                crate::CAP_SELF_CSPACE,
                provider_slot,
                child_cn,
                child_slot,
                pid as u64,
            )
        } else {
            trona_kernel::invoke::cnode_copy(
                crate::CAP_SELF_CSPACE,
                provider_slot,
                child_cn,
                child_slot,
                crate::CAP_RIGHTS_ALL,
            )
        };
        if mint_err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] resolve_registry_attachments: cnode op for ");
                _lb.bytes(service_name);
                _lb.str(b"<-");
                _lb.bytes(provider_name);
                _lb.str(b" err=");
                _lb.hex(mint_err as u64);
                _lb.str(b"\n");
            });
            return Err(ResolveErr::CnodeOpFailed);
        }

        let flags = if entry.badged != 0 {
            CAP_TBL_FLAG_BADGED
        } else {
            0
        };
        builder.push(entry.role_id, child_slot, 0, flags)?;
        emitted += 1;
    }

    if emitted > 0 {
        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] resolve_registry_attachments: ");
            _lb.bytes(service_name);
            _lb.str(b" emitted ");
            _lb.dec(emitted as u64);
            _lb.str(b" local entries\n");
        });
    }
    Ok(emitted)
}

/// Adopt the provider EP currently sitting in `crate::CAP_RECV_SCRATCH`
/// (received via INIT_SPAWN cap transfer) into a permanent allocator-managed
/// CSpace slot. The scratch slot is **left intact** so the caller can still
/// `cnode_move` it into the child's CSpace.
///
/// This is the spawn-time auto-registration path: every post-procmgr
/// service that init creates with a `pre_ep` (i.e. the listener EP shipped
/// alongside `INIT_SPAWN`) ends up here. The procmgr-side copy is what
/// `spawn_tx`'s cap_table builder later mints into other consumer
/// children when lowered local attachments reference this provider.
///
/// Returns `true` on success or if the name was already registered (the
/// scratch slot is left untouched in the duplicate case — caller still
/// owns it).
pub unsafe fn adopt_provider_from_scratch(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_REQUIRE_PROVIDER {
        return false;
    }
    if lookup_provider(name).is_some() {
        return true;
    }
    let provider_slot = match unsafe { (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() } {
        Some(s) => s,
        None => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] adopt_provider: allocator exhausted for ");
                _lb.bytes(name);
                _lb.str(b"\n");
            });
            return false;
        }
    };
    let copy_err = trona_kernel::invoke::cnode_copy(
        crate::CAP_SELF_CSPACE,
        crate::CAP_RECV_SCRATCH,
        crate::CAP_SELF_CSPACE,
        provider_slot,
        crate::CAP_RIGHTS_ALL,
    );
    if copy_err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] adopt_provider: cnode_copy err=");
            _lb.hex(copy_err as u64);
            _lb.str(b" for ");
            _lb.bytes(name);
            _lb.str(b"\n");
        });
        return false;
    }
    match register_provider(name, provider_slot) {
        RegisterOutcome::Added => true,
        RegisterOutcome::Duplicate => {
            let _ = trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, provider_slot);
            true
        }
        RegisterOutcome::Failed => {
            let _ = trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, provider_slot);
            false
        }
    }
}

/// Number of mapped registry chunks currently installed.
static mut SERVICE_REGISTRY_CHUNK_COUNT: u32 = 0;
/// Total number of service defs across all mapped chunks.
static mut SERVICE_REGISTRY_ENTRY_COUNT: u32 = 0;

#[inline]
fn service_registry_chunk_vaddr(idx: u32) -> u64 {
    SERVICE_REGISTRY_BASE_VADDR + (idx as u64) * SERVICE_REGISTRY_CHUNK_STRIDE
}

unsafe fn reset_service_registry() {
    unsafe {
        let self_vspace = crate::CAP_SELF_VSPACE;
        let chunk_count = ptr::read_volatile(&raw const SERVICE_REGISTRY_CHUNK_COUNT);
        for idx in 0..chunk_count {
            let _ =
                trona_kernel::invoke::vspace_unmap(self_vspace, service_registry_chunk_vaddr(idx));
        }
        ptr::write_volatile(&raw mut SERVICE_REGISTRY_CHUNK_COUNT, 0);
        ptr::write_volatile(&raw mut SERVICE_REGISTRY_ENTRY_COUNT, 0);
        ptr::write_volatile(&raw mut SERVICE_REGISTRY_ATTACHMENT_COUNT, 0);
        ptr::write_volatile(&raw mut REGISTERED_PROVIDER_COUNT, 0);
    }
}

unsafe fn lookup_service_view(name: &[u8]) -> Option<RegistryServiceView> {
    unsafe {
        let chunk_count = ptr::read_volatile(&raw const SERVICE_REGISTRY_CHUNK_COUNT);
        for idx in 0..chunk_count {
            let header = service_registry_chunk_vaddr(idx) as *mut TronaServiceDefs;
            let service_count = ptr::read_volatile(&raw const (*header).service_count) as usize;
            let attachment_total =
                ptr::read_volatile(&raw const (*header).attachment_count) as usize;
            let services = service_defs_ptr(header);
            let attachments = attachments_ptr(header, service_count);
            for i in 0..service_count {
                let entry = services.add(i);
                let len = ptr::read_volatile(&raw const (*entry).name_len) as usize;
                if len == name.len() && &(&(*entry).name)[..len] == name {
                    return Some(RegistryServiceView {
                        entry,
                        attachments,
                        attachment_total,
                    });
                }
            }
        }
        None
    }
}

pub fn service_has_system_cap_attachment(service_name: &[u8], role_id: u32) -> bool {
    if service_name.is_empty() {
        return false;
    }
    let Some(view) = (unsafe { lookup_service_view(service_name) }) else {
        return false;
    };
    let def = unsafe { &*view.entry };
    let attachment_start = def.attachment_start as usize;
    let attachment_count = def.attachment_count as usize;
    if attachment_start > view.attachment_total
        || attachment_start.saturating_add(attachment_count) > view.attachment_total
    {
        return false;
    }
    for r in 0..attachment_count {
        let entry = unsafe { &*view.attachments.add(attachment_start + r) };
        if entry.kind == REQUIRE_KIND_SYSTEM
            && entry.attachment_type == ATTACHMENT_TYPE_CAP
            && entry.role_id == role_id
        {
            return true;
        }
    }
    false
}

unsafe fn lookup_service_def_ptr(name: &[u8]) -> Option<*mut TronaServiceDef> {
    unsafe { lookup_service_view(name).map(|view| view.entry) }
}

fn bootstrap_provider_slot(name: &[u8]) -> Option<u64> {
    if name == b"namesrv" {
        Some(trona_runtime::client::caps::namesrv_ep())
    } else if name == b"vfs" {
        Some(crate::base::cap_helpers::vfs_provider_ep())
    } else if name == b"mmsrv" {
        Some(crate::base::cap_helpers::mmsrv_authority_raw())
    } else if name == b"rsrcsrv" {
        Some(crate::base::cap_helpers::rsrcsrv_authority_raw())
    } else {
        None
    }
}

fn is_bootstrap_provider_slot(slot: u64) -> bool {
    slot == trona_runtime::client::caps::namesrv_ep()
        || slot == crate::base::cap_helpers::vfs_provider_ep()
        || slot == crate::base::cap_helpers::mmsrv_authority_raw()
        || slot == crate::base::cap_helpers::rsrcsrv_authority_raw()
}

unsafe fn seed_bootstrap_provider_slots(services: *mut TronaServiceDef, service_count: usize) {
    unsafe {
        for i in 0..service_count {
            let entry = services.add(i);
            if ptr::read_volatile(&raw const (*entry).provider_slot) != 0 {
                continue;
            }
            let name_len = ptr::read_volatile(&raw const (*entry).name_len) as usize;
            if name_len == 0 || name_len > MAX_REQUIRE_PROVIDER {
                continue;
            }
            let name = &(&(*entry).name)[..name_len];
            let Some(slot) = bootstrap_provider_slot(name) else {
                continue;
            };
            ptr::write_volatile(&raw mut (*entry).provider_slot, slot);
        }
    }
}

/// Number of populated entries in the registry.
pub fn registry_count() -> u32 {
    unsafe { ptr::read_volatile(&raw const SERVICE_REGISTRY_ENTRY_COUNT) }
}

/// Number of populated lowered attachment entries in the registry.
pub fn attachment_count() -> u32 {
    unsafe { ptr::read_volatile(&raw const SERVICE_REGISTRY_ATTACHMENT_COUNT) }
}

/// Number of provider endpoints procmgr can resolve.
pub fn provider_count() -> u32 {
    unsafe { bootstrap_provider_count() + ptr::read_volatile(&raw const REGISTERED_PROVIDER_COUNT) }
}

/// Look up a provider's cap slot by name. Returns `None` if not registered.
///
/// Used by `spawn_tx`'s cap_table builder to resolve service-local attachment
/// entries — the returned slot is procmgr's own CSpace slot, suitable for
/// `cnode_copy` / `cnode_mint` into a consumer child's CSpace. Bootstrap
/// providers are seeded directly into their streamed registry entries when
/// the service-def chunks arrive, so provider resolution stays registry-based
/// even for built-in singleton services.
pub fn lookup_provider(name: &[u8]) -> Option<u64> {
    unsafe {
        if let Some(entry) = lookup_service_def_ptr(name) {
            let slot = ptr::read_volatile(&raw const (*entry).provider_slot);
            if slot != 0 {
                return Some(slot);
            }
        }
        None
    }
}

unsafe fn refresh_provider_slot_from_scratch(name: &[u8], slot: u64) -> bool {
    let self_cspace = crate::CAP_SELF_CSPACE;
    let scratch = crate::CAP_RECV_SCRATCH;

    let _ = trona_kernel::invoke::cnode_delete(self_cspace, slot);
    let move_err = trona_kernel::invoke::cnode_move(self_cspace, slot, self_cspace, scratch);
    if move_err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] register_provider: provider refresh err=");
            _lb.hex(move_err as u64);
            _lb.str(b" for ");
            _lb.bytes(name);
            _lb.str(b"\n");
        });
        let _ = trona_kernel::invoke::cnode_delete(self_cspace, scratch);
        return false;
    }

    true
}

/// Outcome of a `register_provider` call.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RegisterOutcome {
    /// New entry created.
    Added,
    /// Name was already registered — registry left untouched. The caller
    /// should release any cap slot it allocated speculatively for this
    /// registration (the existing entry's slot is the canonical one).
    Duplicate,
    /// Registry is full or the name is invalid.
    Failed,
}

/// Register a provider. **Strictly first-write-wins** — if `name` already
/// has a provider slot recorded in the streamed service registry, the
/// existing slot is preserved and `RegisterOutcome::Duplicate` is returned.
/// `name` must refer to a non-bootstrap service already present in the
/// registry stream.
pub fn register_provider(name: &[u8], slot: u64) -> RegisterOutcome {
    if name.is_empty() || name.len() > MAX_REQUIRE_PROVIDER {
        return RegisterOutcome::Failed;
    }
    unsafe {
        let Some(entry) = lookup_service_def_ptr(name) else {
            if bootstrap_provider_slot(name).is_some() {
                return RegisterOutcome::Duplicate;
            }
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_provider: unknown service ");
                _lb.bytes(name);
                _lb.str(b"\n");
            });
            return RegisterOutcome::Failed;
        };
        if ptr::read_volatile(&raw const (*entry).provider_slot) != 0 {
            return RegisterOutcome::Duplicate;
        }
        ptr::write_volatile(&raw mut (*entry).provider_slot, slot);
        if bootstrap_provider_slot(name).is_none() {
            let count = ptr::read_volatile(&raw const REGISTERED_PROVIDER_COUNT);
            ptr::write_volatile(&raw mut REGISTERED_PROVIDER_COUNT, count.saturating_add(1));
        }

        trona_runtime::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] register_provider: ");
            _lb.bytes(name);
            _lb.str(b" -> slot ");
            _lb.dec(slot);
            _lb.str(b"\n");
        });
        RegisterOutcome::Added
    }
}

/// Announce that bootstrap singleton provider slots are available. The
/// concrete slot numbers still come from procmgr's own built-in attachment
/// layout; when init streams the registry, matching service entries get
/// those slots written into `provider_slot` so later lookups stay purely
/// registry-driven.
///
/// Should be called once from `main()` before the IPC dispatch loop starts.
pub fn install_bootstrap_providers() {
    trona_runtime::uinfo!(|_lb| {
        _lb.str(b"[PROCMGR] bootstrap providers installed: ");
        _lb.dec(bootstrap_provider_count() as u64);
        _lb.str(b"\n");
    });
}

/// Handle `PM_REGISTER_SERVICE_DEFS`.
///
/// Wire shape:
///
/// - `extra_caps[0]` = frame cap (received at `crate::CAP_RECV_SCRATCH`)
/// - `msg.regs[0]`   = byte length of the serialized payload (informational)
/// - `msg.regs[1]`   = chunk flags mirror (informational)
///
/// The frame is mapped read/write into the persistent service-registry VA
/// range, validated in place, and left mapped there for later lookups. The
/// cap at `CAP_RECV_SCRATCH` is deleted on the way out so the next IPC starts
/// clean.
pub unsafe fn handle_register_service_defs(_msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let frame_cap = crate::CAP_RECV_SCRATCH;
        let self_vspace = crate::CAP_SELF_VSPACE;
        let self_cspace = crate::CAP_SELF_CSPACE;
        let scratch_vaddr = crate::PROCMGR_SCRATCH_VADDR;

        let map_err = trona_kernel::invoke::vspace_map(
            self_vspace,
            frame_cap,
            scratch_vaddr,
            crate::VSPACE_FLAG_WRITABLE | crate::VSPACE_FLAG_USER,
        );
        if map_err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: vspace_map err=");
                _lb.hex(map_err as u64);
                _lb.str(b"\n");
            });
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        let header = scratch_vaddr as *const TronaServiceDefs;
        let magic = ptr::read_volatile(&raw const (*header).magic);
        let flags = ptr::read_volatile(&raw const (*header).flags);
        let service_count = ptr::read_volatile(&raw const (*header).service_count);
        let attachment_count = ptr::read_volatile(&raw const (*header).attachment_count);

        if magic != TRONA_SERVICE_DEFS_MAGIC {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: bad magic=");
                _lb.hex(magic as u64);
                _lb.str(b"\n");
            });
            let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        let chunk_idx = if (flags & TRONA_SERVICE_DEFS_FLAG_FIRST) != 0 {
            reset_service_registry();
            0
        } else {
            ptr::read_volatile(&raw const SERVICE_REGISTRY_CHUNK_COUNT)
        };
        if chunk_idx == 0 && (flags & TRONA_SERVICE_DEFS_FLAG_FIRST) == 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: first chunk missing FIRST flag\n");
            });
            let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        let header_size = core::mem::size_of::<TronaServiceDefs>();
        let service_size = core::mem::size_of::<TronaServiceDef>();
        let attachment_size = core::mem::size_of::<TronaServiceAttachment>();
        let total = header_size
            + (service_count as usize) * service_size
            + (attachment_count as usize) * attachment_size;
        if total > FRAME_SIZE {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: payload ");
                _lb.dec(total as u64);
                _lb.str(b" exceeds frame size\n");
            });
            let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_OUT_OF_RANGE;
            return;
        }

        let services = service_defs_ptr(header as *mut TronaServiceDefs);
        for i in 0..(service_count as usize) {
            let entry = services.add(i);
            let name_len = ptr::read_volatile(&raw const (*entry).name_len) as usize;
            if name_len == 0 || name_len > MAX_REQUIRE_PROVIDER {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] register_service_defs: invalid service name length\n");
                });
                let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
                let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
                reply.label = crate::TRONA_INVALID_ARGUMENT;
                return;
            }
            let name = &(&(*entry).name)[..name_len];
            let start = ptr::read_volatile(&raw const (*entry).attachment_start) as usize;
            let count = ptr::read_volatile(&raw const (*entry).attachment_count) as usize;
            if start > (attachment_count as usize)
                || start.saturating_add(count) > (attachment_count as usize)
            {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] register_service_defs: bad attachment span for ");
                    _lb.bytes(name);
                    _lb.str(b"\n");
                });
                let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
                let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
                reply.label = crate::TRONA_INVALID_ARGUMENT;
                return;
            }
            let attachments =
                attachments_ptr(header as *mut TronaServiceDefs, service_count as usize);
            for attachment_i in 0..count {
                let attachment = &*attachments.add(start + attachment_i);
                if let Err(err) = validate_registry_attachment(name, attachment) {
                    let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
                    let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
                    reply.label = err;
                    return;
                }
            }
        }
        seed_bootstrap_provider_slots(services, service_count as usize);

        let chunk_vaddr = service_registry_chunk_vaddr(chunk_idx);
        let persist_map_err = trona_kernel::invoke::vspace_map(
            self_vspace,
            frame_cap,
            chunk_vaddr,
            crate::VSPACE_FLAG_WRITABLE | crate::VSPACE_FLAG_USER,
        );
        if persist_map_err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: persistent map err=");
                _lb.hex(persist_map_err as u64);
                _lb.str(b"\n");
            });
            let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }
        let _ = trona_kernel::invoke::vspace_unmap(self_vspace, scratch_vaddr);

        ptr::write_volatile(&raw mut SERVICE_REGISTRY_CHUNK_COUNT, chunk_idx + 1);
        let total_entries = ptr::read_volatile(&raw const SERVICE_REGISTRY_ENTRY_COUNT);
        let total_attachments = ptr::read_volatile(&raw const SERVICE_REGISTRY_ATTACHMENT_COUNT);
        ptr::write_volatile(
            &raw mut SERVICE_REGISTRY_ENTRY_COUNT,
            total_entries.saturating_add(service_count),
        );
        ptr::write_volatile(
            &raw mut SERVICE_REGISTRY_ATTACHMENT_COUNT,
            total_attachments.saturating_add(attachment_count),
        );

        trona_runtime::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] service registry chunk installed: idx=");
            _lb.dec(chunk_idx as u64);
            _lb.str(b" defs=");
            _lb.dec(service_count as u64);
            _lb.str(b" attachments=");
            _lb.dec(attachment_count as u64);
            _lb.str(b" total=");
            _lb.dec((total_entries + service_count) as u64);
            if (flags & TRONA_SERVICE_DEFS_FLAG_FIRST) != 0 {
                _lb.str(b" first");
            }
            if (flags & trona_kernel::core_types::core::TRONA_SERVICE_DEFS_FLAG_LAST) != 0 {
                _lb.str(b" last");
            }
            _lb.str(b"\n");
        });

        let _ = trona_kernel::invoke::cnode_delete(self_cspace, frame_cap);
        reply.label = crate::TRONA_OK;
    }
}

/// Handle `PM_REGISTER_PROVIDER`.
///
/// Wire shape:
///
/// - `extra_caps[0]` = provider EP cap (received at `crate::CAP_RECV_SCRATCH`)
/// - `msg.regs[0]`   = `name_len` (bytes)
/// - `msg.regs[1..]` = packed provider name bytes (NUL-padded into u64 words)
///
/// Procmgr allocates a fresh CSpace slot from its allocator, moves the cap
/// from `CAP_RECV_SCRATCH` to that slot, and records the slot in the
/// streamed service registry entry for `name`.
///
/// The slot persists for the rest of procmgr's lifetime so future
/// `cnode_mint` derivations (per-consumer badge) work without re-receiving
/// the cap.
pub unsafe fn handle_register_provider(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let scratch = crate::CAP_RECV_SCRATCH;
        let self_cspace = crate::CAP_SELF_CSPACE;

        let name_len = msg.regs[0] as usize;
        if name_len == 0 || name_len > MAX_REQUIRE_PROVIDER {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_provider: invalid name_len=");
                _lb.dec(name_len as u64);
                _lb.str(b"\n");
            });
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, scratch);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        // Unpack provider name from regs[1..] u64 words.
        let mut name = [0u8; MAX_REQUIRE_PROVIDER];
        let src = &raw const msg.regs[1] as *const u8;
        for i in 0..name_len {
            name[i] = ptr::read_volatile(src.add(i));
        }

        // Idempotent: if the name is already in the registry (e.g. a
        // bootstrap provider), drop the just-received cap and report OK.
        // Init re-registers everything indiscriminately, so this is the
        // common case for namesrv/vfs/mmsrv/rsrcsrv.
        if let Some(existing_slot) = lookup_provider(&name[..name_len]) {
            if existing_slot != 0
                && is_bootstrap_provider_slot(existing_slot)
                && refresh_provider_slot_from_scratch(&name[..name_len], existing_slot)
            {
                publish_well_known_provider(&name[..name_len], existing_slot);
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[PROCMGR] register_provider: refreshed bootstrap ");
                    _lb.bytes(&name[..name_len]);
                    _lb.str(b" slot\n");
                });
            } else {
                let _ = trona_kernel::invoke::cnode_delete(self_cspace, scratch);
                trona_runtime::udebug!(|_lb| {
                    _lb.str(b"[PROCMGR] register_provider: ");
                    _lb.bytes(&name[..name_len]);
                    _lb.str(b" already registered, ignoring duplicate\n");
                });
            }
            reply.label = crate::TRONA_OK;
            return;
        }

        // Allocate a permanent procmgr-side slot and move the cap out of the
        // receive scratch slot. Using `cnode_copy` here leaves a CDT child
        // behind, so deleting `CAP_RECV_SCRATCH` would not actually free the
        // slot for the next cap-transfer IPC.
        let provider_slot = match (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] register_provider: allocator exhausted\n");
                });
                let _ = trona_kernel::invoke::cnode_delete(self_cspace, scratch);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let move_err =
            trona_kernel::invoke::cnode_move(self_cspace, provider_slot, self_cspace, scratch);
        if move_err != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_provider: cnode_move err=");
                _lb.hex(move_err as u64);
                _lb.str(b"\n");
            });
            let _ = trona_kernel::invoke::cnode_delete(self_cspace, scratch);
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        match register_provider(&name[..name_len], provider_slot) {
            RegisterOutcome::Added => {
                publish_well_known_provider(&name[..name_len], provider_slot);
                trona_runtime::uinfo!(|_lb| {
                    _lb.str(b"[PROCMGR] register_provider: ");
                    _lb.bytes(&name[..name_len]);
                    _lb.str(b" -> slot ");
                    _lb.dec(provider_slot);
                    _lb.str(b"\n");
                });
                reply.label = crate::TRONA_OK;
            }
            RegisterOutcome::Duplicate => {
                // Race against an internal register_provider call between
                // our lookup_provider above and now. Free the speculative
                // copy and report OK.
                let _ = trona_kernel::invoke::cnode_delete(self_cspace, provider_slot);
                reply.label = crate::TRONA_OK;
            }
            RegisterOutcome::Failed => {
                let _ = trona_kernel::invoke::cnode_delete(self_cspace, provider_slot);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
            }
        }
    }
}
