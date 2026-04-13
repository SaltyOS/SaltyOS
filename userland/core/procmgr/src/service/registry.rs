//! Boot-time service-def registry for procmgr.
//! SPDX-License-Identifier: GPL-2.0-only
//!
//! Init parses every `.service` file in the initrd at boot. Pre-procmgr
//! services it spawns directly. Post-procmgr services it ships to procmgr in
//! one shot via `PM_REGISTER_SERVICE_DEFS`: a single frame cap whose contents
//! are a `TronaProcmgrServiceDefsV1` header followed by `count` entries of
//! `TronaProcmgrServiceDefV1`.
//!
//! Procmgr maps the frame at its scratch VA, validates the magic + version,
//! copies entries into the static `SERVICE_REGISTRY` below, unmaps, and acks
//! `TRONA_OK`. The registry is consulted later by `spawn_tx` when building
//! the cap_table for a post-procmgr child: each `Require=` entry resolves to
//! a `(role_id, slot)` pair via the provider name and procmgr's provider
//! registry.

use core::ptr;
use trona::cap_table::{CapTableBuilder, CapTableErr};
use trona::consts::kernel::CAP_TBL_FLAG_BADGED;
use trona::types::core::{
    Cap, TronaMsg, TronaProcmgrServiceDefV1, TronaProcmgrServiceDefsV1, MAX_PROCMGR_SERVICE_DEFS,
    MAX_REQUIRE_PROVIDER, REQUIRE_KIND_LOCAL, REQUIRE_KIND_SYSTEM, TRONA_PROCMGR_DEFS_MAGIC,
    TRONA_PROCMGR_DEFS_VERSION,
};

const FRAME_SIZE: usize = 4096;

/// Maximum number of providers procmgr tracks. Bootstrap pre-procmgr
/// providers (namesrv/vfs/mmsrv/rsrcsrv = 4) plus post-procmgr providers
/// procmgr will register as it spawns them. The post-procmgr count is
/// bounded by `MAX_PROCMGR_SERVICE_DEFS`, so 4 + MAX_PROCMGR_SERVICE_DEFS
/// is the worst case.
pub const MAX_PROVIDERS: usize = 4 + MAX_PROCMGR_SERVICE_DEFS;

/// One entry in `PROVIDER_REGISTRY`. `slot` is the cap slot in procmgr's
/// own CSpace; for bootstrap providers it's the startup cap_table slot
/// surfaced via `trona::caps::*()`, for post-procmgr providers it's a
/// procmgr-side scratch slot copied from the EP that init or `spawn_tx`
/// set up.
#[derive(Clone, Copy)]
struct ProviderEntry {
    name: [u8; MAX_REQUIRE_PROVIDER],
    name_len: u8,
    slot: u64,
}

impl ProviderEntry {
    const fn zeroed() -> Self {
        ProviderEntry {
            name: [0; MAX_REQUIRE_PROVIDER],
            name_len: 0,
            slot: 0,
        }
    }
}

static mut PROVIDER_REGISTRY: [ProviderEntry; MAX_PROVIDERS] =
    [ProviderEntry::zeroed(); MAX_PROVIDERS];
static mut PROVIDER_REGISTRY_COUNT: u32 = 0;

/// Procmgr-side CSpace slots used to hold provider EP copies.
///
/// The bootstrap providers (`namesrv`/`vfs`/`mmsrv`/`rsrcsrv`) live at fixed
/// system slots already (64..71) — they do **not** consume this range.
/// Slots in this range are allocated on demand for:
///
/// - Pre-procmgr providers registered via `PM_REGISTER_PROVIDER`
///   (e.g. `console`, `com1` — caps that arrive from init).
/// - Post-procmgr providers registered by `spawn_tx` after a successful
///   spawn (the child's listener EP, copied so procmgr can later mint
///   per-consumer badged copies).
///
/// `MAX_PROVIDERS - 4` = 14 dynamic slots — exactly enough to mirror every
/// post-procmgr service def the registry can hold, with bootstrap entries
/// staying in their fixed slots.
const PROVIDER_SLOT_BASE: u64 = 1024;
const PROVIDER_SLOT_LIMIT: u64 = PROVIDER_SLOT_BASE + (MAX_PROVIDERS as u64) - 4;
static mut NEXT_PROVIDER_SLOT: u64 = PROVIDER_SLOT_BASE;

/// Bump-allocate a CSpace slot inside `[PROVIDER_SLOT_BASE,
/// PROVIDER_SLOT_LIMIT)` for a new provider EP copy. Returns `None` when
/// the range is exhausted — at that point procmgr is being asked to track
/// more providers than the registry was sized for, which is a build-time
/// configuration bug.
pub fn alloc_provider_slot() -> Option<u64> {
    unsafe {
        let cur = ptr::read_volatile(&raw const NEXT_PROVIDER_SLOT);
        if cur >= PROVIDER_SLOT_LIMIT {
            return None;
        }
        ptr::write_volatile(&raw mut NEXT_PROVIDER_SLOT, cur + 1);
        Some(cur)
    }
}

/// Outcome of `resolve_local_requires`. Carries enough information for the
/// caller to log a meaningful message but is otherwise opaque.
#[derive(Debug, Clone, Copy)]
pub enum ResolveErr {
    /// Service has more `Require=` entries than the child cspace
    /// `[extras_base, frame_slot_start)` window can hold.
    SlotRangeExhausted,
    /// `cnode_mint` / `cnode_copy` from the procmgr provider slot into
    /// the child failed.
    CnodeOpFailed,
    /// `CapTableBuilder::push` ran out of space.
    BuilderOverflow,
    /// `Require=<provider>:<alias>` references a provider procmgr does
    /// not know about. The boot order should arrange for the provider
    /// to be spawned (and auto-registered) before any consumer.
    UnknownProvider,
}

impl From<CapTableErr> for ResolveErr {
    fn from(_: CapTableErr) -> Self {
        ResolveErr::BuilderOverflow
    }
}

/// Resolve every `Require=` entry for `service_name` and push the
/// resulting cap_table entries into `builder`.
///
/// - System-role entries are silently skipped — they have already been
///   pushed by `ChildCapLayout::populate_cap_table` from the layout's
///   well-known cap fields. Pushing them again would create duplicates.
/// - `*_AUTHORITY_RAW` entries are skipped: they are procmgr-private and
///   never delivered to a child via the public cap_table.
/// - Local-role entries trigger a `lookup_provider(provider_name)`. The
///   matched procmgr-side cap is `cnode_mint`'d (badged with the consumer
///   `pid`) or `cnode_copy`'d (unbadged) into a freshly allocated slot in
///   `[cap_layout.extras_base, cap_layout.frame_slot_start)`, then pushed
///   to the builder.
///
/// `service_name` may be empty — in that case the function returns
/// `Ok(0)` immediately. This lets fork/exec paths share a single helper
/// without paying for a registry lookup.
pub unsafe fn resolve_local_requires(
    service_name: &[u8],
    pid: u32,
    child_cn: Cap,
    cap_layout: &crate::base::child_layout::ChildCapLayout,
    builder: &mut CapTableBuilder,
) -> Result<u32, ResolveErr> {
    if service_name.is_empty() {
        return Ok(0);
    }
    let def = match lookup(service_name) {
        Some(d) => d,
        None => return Ok(0),
    };

    let mut next_slot = cap_layout.extras_base;
    let limit = cap_layout.frame_slot_start;
    let mut emitted: u32 = 0;

    for r in 0..(def.require_count as usize) {
        let entry = &def.requires[r];
        // System roles are owned by populate_cap_table — never re-push.
        if entry.kind == REQUIRE_KIND_SYSTEM {
            continue;
        }
        if entry.kind != REQUIRE_KIND_LOCAL {
            continue;
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
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] resolve_local_requires: ");
                    _lb.bytes(service_name);
                    _lb.str(b" needs unknown provider ");
                    _lb.bytes(provider_name);
                    _lb.str(b"\n");
                });
                return Err(ResolveErr::UnknownProvider);
            }
        };

        if next_slot >= limit {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] resolve_local_requires: ");
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
            trona::invoke::cnode_mint(
                crate::CAP_SELF_CSPACE,
                provider_slot,
                child_cn,
                child_slot,
                pid as u64,
            )
        } else {
            trona::invoke::cnode_copy(
                crate::CAP_SELF_CSPACE,
                provider_slot,
                child_cn,
                child_slot,
                crate::CAP_RIGHTS_ALL,
            )
        };
        if mint_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] resolve_local_requires: cnode op for ");
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
        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] resolve_local_requires: ");
            _lb.bytes(service_name);
            _lb.str(b" emitted ");
            _lb.dec(emitted as u64);
            _lb.str(b" local entries\n");
        });
    }
    Ok(emitted)
}

/// Adopt the provider EP currently sitting in `crate::CAP_RECV_SCRATCH`
/// (received via PM_SPAWN cap transfer) into procmgr's permanent provider
/// slot range. The scratch slot is **left intact** so the caller can still
/// `cnode_move` it into the child's CSpace.
///
/// This is the spawn-time auto-registration path: every post-procmgr
/// service that init creates with a `pre_ep` (i.e. the listener EP shipped
/// alongside `PM_SPAWN`) ends up here. The procmgr-side copy is what
/// `spawn_tx`'s cap_table builder later mints into other consumer
/// children when they `Require=<this service>`.
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
    let provider_slot = match alloc_provider_slot() {
        Some(s) => s,
        None => {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] adopt_provider: slot range exhausted for ");
                _lb.bytes(name);
                _lb.str(b"\n");
            });
            return false;
        }
    };
    let copy_err = trona::invoke::cnode_copy(
        crate::CAP_SELF_CSPACE,
        crate::CAP_RECV_SCRATCH,
        crate::CAP_SELF_CSPACE,
        provider_slot,
        crate::CAP_RIGHTS_ALL,
    );
    if copy_err != 0 {
        trona::uerror!(|_lb| {
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
            let _ = trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, provider_slot);
            true
        }
        RegisterOutcome::Failed => {
            let _ = trona::invoke::cnode_delete(crate::CAP_SELF_CSPACE, provider_slot);
            false
        }
    }
}

/// Static registry of service defs received from init at boot. Indexed by
/// `[..registry_count()]`. Touched only via raw pointers to satisfy the
/// Rust 2024 `static mut` rules.
static mut SERVICE_REGISTRY: [TronaProcmgrServiceDefV1; MAX_PROCMGR_SERVICE_DEFS] =
    [TronaProcmgrServiceDefV1::zeroed(); MAX_PROCMGR_SERVICE_DEFS];
static mut SERVICE_REGISTRY_COUNT: u32 = 0;

/// Number of populated entries in the registry.
pub fn registry_count() -> u32 {
    unsafe { ptr::read_volatile(&raw const SERVICE_REGISTRY_COUNT) }
}

/// Number of populated entries in `PROVIDER_REGISTRY`.
pub fn provider_count() -> u32 {
    unsafe { ptr::read_volatile(&raw const PROVIDER_REGISTRY_COUNT) }
}

/// Look up a provider's cap slot by name. Returns `None` if not registered.
///
/// Used by `spawn_tx`'s cap_table builder to resolve `Require=<provider>:<alias>`
/// service-local entries — the returned slot is procmgr's own CSpace slot,
/// suitable for `cnode_copy` / `cnode_mint` into a consumer child's CSpace.
pub fn lookup_provider(name: &[u8]) -> Option<u64> {
    unsafe {
        let n = provider_count() as usize;
        let base = &raw const PROVIDER_REGISTRY as *const ProviderEntry;
        for i in 0..n {
            let entry = ptr::read_volatile(base.add(i));
            let len = entry.name_len as usize;
            if len == name.len() && &entry.name[..len] == name {
                return Some(entry.slot);
            }
        }
        None
    }
}

fn provider_bootstrap_slot(name: &[u8]) -> Option<u64> {
    if name == b"namesrv" {
        Some(trona::caps::namesrv_ep())
    } else if name == b"vfs" {
        Some(trona::caps::vfs_ep())
    } else if name == b"mmsrv" {
        Some(crate::base::cap_helpers::mmsrv_authority_raw())
    } else if name == b"rsrcsrv" {
        Some(crate::base::cap_helpers::rsrcsrv_authority_raw())
    } else {
        None
    }
}

unsafe fn refresh_bootstrap_provider_from_scratch(name: &[u8]) -> bool {
    let Some(slot) = provider_bootstrap_slot(name) else {
        return false;
    };

    let self_cspace = crate::CAP_SELF_CSPACE;
    let scratch = crate::CAP_RECV_SCRATCH;

    let _ = trona::invoke::cnode_delete(self_cspace, slot);
    let move_err = trona::invoke::cnode_move(self_cspace, slot, self_cspace, scratch);
    if move_err != 0 {
        trona::uerror!(|_lb| {
            _lb.str(b"[PROCMGR] register_provider: bootstrap refresh err=");
            _lb.hex(move_err as u64);
            _lb.str(b" for ");
            _lb.bytes(name);
            _lb.str(b"\n");
        });
        let _ = trona::invoke::cnode_delete(self_cspace, scratch);
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
/// exists in the registry, the existing slot is preserved and
/// `RegisterOutcome::Duplicate` is returned. Callers that want to handle
/// the duplicate case (release the speculative slot copy etc.) should use
/// `lookup_provider` first or interpret the outcome.
pub fn register_provider(name: &[u8], slot: u64) -> RegisterOutcome {
    if name.is_empty() || name.len() > MAX_REQUIRE_PROVIDER {
        return RegisterOutcome::Failed;
    }
    unsafe {
        let base = &raw mut PROVIDER_REGISTRY as *mut ProviderEntry;
        let n = provider_count() as usize;

        // First-write-wins: refuse silently if name already present.
        for i in 0..n {
            let entry = ptr::read_volatile(base.add(i));
            let len = entry.name_len as usize;
            if len == name.len() && &entry.name[..len] == name {
                return RegisterOutcome::Duplicate;
            }
        }

        if n >= MAX_PROVIDERS {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_provider: registry full (");
                _lb.dec(MAX_PROVIDERS as u64);
                _lb.str(b" entries) - dropping ");
                _lb.bytes(name);
                _lb.str(b"\n");
            });
            return RegisterOutcome::Failed;
        }

        let mut entry = ProviderEntry::zeroed();
        for j in 0..name.len() {
            entry.name[j] = name[j];
        }
        entry.name_len = name.len() as u8;
        entry.slot = slot;
        ptr::write_volatile(base.add(n), entry);
        ptr::write_volatile(&raw mut PROVIDER_REGISTRY_COUNT, (n + 1) as u32);

        trona::udebug!(|_lb| {
            _lb.str(b"[PROCMGR] register_provider: ");
            _lb.bytes(name);
            _lb.str(b" -> slot ");
            _lb.dec(slot);
            _lb.str(b"\n");
        });
        RegisterOutcome::Added
    }
}

/// Pre-populate the provider registry with the system-role caps procmgr
/// already holds at boot. These come from procmgr's own `NeedEP=` slots
/// (declared in `procmgr.service`) and are available the moment `main()`
/// runs — no IPC required. The unbadged copies (`mmsrv:68`, `rsrcsrv:71`)
/// are registered so future `cnode_mint` derivations can attach a
/// per-consumer badge.
///
/// Should be called once from `main()` before the IPC dispatch loop starts.
pub fn install_bootstrap_providers() {
    let _ = register_provider(b"namesrv", trona::caps::namesrv_ep());
    let _ = register_provider(b"vfs", trona::caps::vfs_ep());
    let _ = register_provider(b"mmsrv", crate::base::cap_helpers::mmsrv_authority_raw());
    let _ = register_provider(b"rsrcsrv", crate::base::cap_helpers::rsrcsrv_authority_raw());

    trona::uinfo!(|_lb| {
        _lb.str(b"[PROCMGR] bootstrap providers installed: ");
        _lb.dec(provider_count() as u64);
        _lb.str(b"\n");
    });
}

/// Look up a service def by name. Returns a value copy (the type is `Copy`).
/// `None` if no entry matches.
pub fn lookup(name: &[u8]) -> Option<TronaProcmgrServiceDefV1> {
    unsafe {
        let n = registry_count() as usize;
        let base = &raw const SERVICE_REGISTRY as *const TronaProcmgrServiceDefV1;
        for i in 0..n {
            let entry = ptr::read_volatile(base.add(i));
            let len = entry.name_len as usize;
            if len == name.len() && &entry.name[..len] == name {
                return Some(entry);
            }
        }
        None
    }
}

/// Handle `PM_REGISTER_SERVICE_DEFS`.
///
/// Wire shape:
///
/// - `extra_caps[0]` = frame cap (received at `crate::CAP_RECV_SCRATCH`)
/// - `msg.regs[0]`   = byte length of the serialized payload (informational;
///                     procmgr trusts the frame's own header)
///
/// The frame is mapped read/write at `crate::PROCMGR_SCRATCH_VADDR`,
/// validated, copied into `SERVICE_REGISTRY`, then unmapped. The cap at
/// `CAP_RECV_SCRATCH` is deleted on the way out so the next IPC starts
/// clean.
pub unsafe fn handle_register_service_defs(_msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let scratch_vaddr = crate::PROCMGR_SCRATCH_VADDR;
        let frame_cap = crate::CAP_RECV_SCRATCH;
        let self_vspace = crate::CAP_SELF_VSPACE;
        let self_cspace = crate::CAP_SELF_CSPACE;

        let map_err = trona::invoke::vspace_map(
            self_vspace,
            frame_cap,
            scratch_vaddr,
            crate::VSPACE_FLAG_WRITABLE | crate::VSPACE_FLAG_USER,
        );
        if map_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: vspace_map err=");
                _lb.hex(map_err as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        let header = scratch_vaddr as *const TronaProcmgrServiceDefsV1;
        let magic = ptr::read_volatile(&raw const (*header).magic);
        let version = ptr::read_volatile(&raw const (*header).version);
        let count = ptr::read_volatile(&raw const (*header).count);

        if magic != TRONA_PROCMGR_DEFS_MAGIC {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: bad magic=");
                _lb.hex(magic as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        if version != TRONA_PROCMGR_DEFS_VERSION {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: version mismatch got=");
                _lb.hex(version as u64);
                _lb.str(b" want=");
                _lb.hex(TRONA_PROCMGR_DEFS_VERSION as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }
        if count as usize > MAX_PROCMGR_SERVICE_DEFS {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: count=");
                _lb.dec(count as u64);
                _lb.str(b" exceeds max=");
                _lb.dec(MAX_PROCMGR_SERVICE_DEFS as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_OUT_OF_RANGE;
            return;
        }

        // Bounds-check: header + count*sizeof(def) ≤ FRAME_SIZE.
        let entry_size = core::mem::size_of::<TronaProcmgrServiceDefV1>();
        let header_size = core::mem::size_of::<TronaProcmgrServiceDefsV1>();
        let total = header_size + (count as usize) * entry_size;
        if total > FRAME_SIZE {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_service_defs: payload ");
                _lb.dec(total as u64);
                _lb.str(b" exceeds frame size\n");
            });
            let _ = trona::invoke::vspace_unmap(self_vspace, scratch_vaddr);
            let _ = trona::invoke::cnode_delete(self_cspace, frame_cap);
            reply.label = crate::TRONA_OUT_OF_RANGE;
            return;
        }

        let entries_src =
            (scratch_vaddr as *const u8).add(header_size) as *const TronaProcmgrServiceDefV1;
        let dst_base = &raw mut SERVICE_REGISTRY as *mut TronaProcmgrServiceDefV1;
        for i in 0..count as usize {
            let entry = ptr::read_volatile(entries_src.add(i));
            ptr::write_volatile(dst_base.add(i), entry);
        }
        ptr::write_volatile(&raw mut SERVICE_REGISTRY_COUNT, count);

        trona::uinfo!(|_lb| {
            _lb.str(b"[PROCMGR] service registry installed: ");
            _lb.dec(count as u64);
            _lb.str(b" defs\n");
        });

        let _ = trona::invoke::vspace_unmap(self_vspace, scratch_vaddr);
        let _ = trona::invoke::cnode_delete(self_cspace, frame_cap);
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
/// Procmgr allocates a fresh slot in `[PROVIDER_SLOT_BASE,
/// PROVIDER_SLOT_LIMIT)`, copies the cap from `CAP_RECV_SCRATCH` to that
/// slot, deletes the scratch slot, and registers `(name, slot)` in
/// `PROVIDER_REGISTRY`.
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
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_provider: invalid name_len=");
                _lb.dec(name_len as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::cnode_delete(self_cspace, scratch);
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
        if lookup_provider(&name[..name_len]).is_some() {
            if refresh_bootstrap_provider_from_scratch(&name[..name_len]) {
                trona::uinfo!(|_lb| {
                    _lb.str(b"[PROCMGR] register_provider: refreshed bootstrap ");
                    _lb.bytes(&name[..name_len]);
                    _lb.str(b" slot\n");
                });
            } else {
                let _ = trona::invoke::cnode_delete(self_cspace, scratch);
                trona::udebug!(|_lb| {
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
        let provider_slot = match alloc_provider_slot() {
            Some(s) => s,
            None => {
                trona::uerror!(|_lb| {
                    _lb.str(b"[PROCMGR] register_provider: provider slot range exhausted\n");
                });
                let _ = trona::invoke::cnode_delete(self_cspace, scratch);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let move_err = trona::invoke::cnode_move(self_cspace, provider_slot, self_cspace, scratch);
        if move_err != 0 {
            trona::uerror!(|_lb| {
                _lb.str(b"[PROCMGR] register_provider: cnode_move err=");
                _lb.hex(move_err as u64);
                _lb.str(b"\n");
            });
            let _ = trona::invoke::cnode_delete(self_cspace, scratch);
            reply.label = crate::TRONA_INVALID_OPERATION;
            return;
        }

        match register_provider(&name[..name_len], provider_slot) {
            RegisterOutcome::Added => {
                trona::uinfo!(|_lb| {
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
                let _ = trona::invoke::cnode_delete(self_cspace, provider_slot);
                reply.label = crate::TRONA_OK;
            }
            RegisterOutcome::Failed => {
                let _ = trona::invoke::cnode_delete(self_cspace, provider_slot);
                reply.label = crate::TRONA_OUT_OF_MEMORY;
            }
        }
    }
}
