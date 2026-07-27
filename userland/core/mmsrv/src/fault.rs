// SPDX-License-Identifier: GPL-2.0-only
//
//! Fault dispatcher. Each registered TCB has its own fault MP recv
//! side; the fault EQ Watch's cookie packs `(client_id high32 |
//! tcb_id low32)`. PAGE_FAULT / OOM are handled here; ILLEGAL /
//! BREAKPOINT / USER_EXCEPTION / CAP forward to init via
//! `INIT_REPORT_FAULT`.
//!
//! Reply semantics (kernite/src/ipc/fault.rs):
//! * `reply-marked MP_WRITE` with `KERNITE_OK` — caller resumes at the faulting RIP.
//! * `reply-marked MP_WRITE` with a non-OK label — arch handler escalates to
//!   `task::quiesce::begin_destroy`.

use trona_kernel::core_types::IpcContext;
use trona_kernel::invoke;
use trona_runtime::core::slot_alloc::{OwnedCap, resolved_cap_ref};
use trona_server::event_loop::{CookieTable, decode_cookie};
use uapi::{
    KERNITE_FAULT_BREAKPOINT, KERNITE_FAULT_CAP, KERNITE_FAULT_ILLEGAL_INSTRUCTION,
    KERNITE_FAULT_OOM, KERNITE_FAULT_PAGE_FAULT, KERNITE_FAULT_USER_EXCEPTION,
    KERNITE_INV_VSPACE_MAP_MO, KERNITE_OK, KERNITE_PAGE_FLAG_EXECUTABLE, KERNITE_PAGE_FLAG_USER,
    KERNITE_PAGE_FLAG_WRITABLE,
};

use crate::main_loop::MmsrvFaultTarget;
use crate::region::{BackingDescriptor, kernel_region_kind};

// File-backed page faults are routed by the kernel directly to vfs
// via `KERNITE_EVENT_TYPE_PAGER_REQUEST` (delivered through the
// `OBJ_PAGER` cap mmsrv attached at `MM_FILE_MMAP` time). The
// fault dispatcher in this file therefore only sees anonymous /
// shm faults plus the non-page-fault categories.

const MAX_FAULT_ENTRIES: usize = 256;
const OOM_BACKOFF_LIMIT: u32 = 3;

pub struct FaultEntry {
    pub client_id: u32,
    pub tcb_id: u32,
    /// Fault MP recv-side cap. Owned by this entry; dropped when the
    /// entry is evicted via `evict_by_client` or `tombstone`.
    pub fault_mp_recv: OwnedCap,
    /// Watch object armed over `fault_mp_recv`'s `STATE_READABLE`
    /// bit on the fault EQ. Re-armed after every drain (one-shot
    /// per kernite ABI). Pool-managed — NOT an `OwnedCap`; the caller
    /// calls `pool.free(watch_cap)` on teardown.
    pub watch_cap: u64,
    /// Encoded `EventLoop` cookie returned by
    /// `state.fault_cookie_table.arm(...)`. The kernel publishes
    /// this value back through `EventRecord.cookie` whenever the
    /// Watch fires; the dispatcher re-arms with the same cookie so
    /// the live_gen survives across re-arms.
    pub cookie: u64,
    pub oom_retries: u32,
    pub active: u8,
}

impl FaultEntry {
    const fn empty() -> Self {
        Self {
            client_id: 0,
            tcb_id: 0,
            fault_mp_recv: OwnedCap::null(),
            watch_cap: 0,
            cookie: 0,
            oom_retries: 0,
            active: 0,
        }
    }
}

/// Copy-able snapshot of the scalar fields in a `FaultEntry`.
///
/// `fault_mp_recv` is exposed as a raw `u64` address — callers that need
/// to send IPC replies use the raw slot directly without taking ownership.
/// The entry itself retains ownership; only `evict_by_client` drops the cap.
#[derive(Clone, Copy)]
pub struct FaultEntrySnapshot {
    pub client_id: u32,
    pub tcb_id: u32,
    pub fault_mp_recv: u64,
    /// Raw Watch cap (pool-managed, not owned by the snapshot) — read-only
    /// for re-arming the fault Watch from the dispatcher.
    pub watch_cap: u64,
    pub cookie: u64,
    pub oom_retries: u32,
    pub active: u8,
}

pub struct FaultDispatcher {
    entries: [FaultEntry; MAX_FAULT_ENTRIES],
    fault_eq: u64,
    fault_mp_master: u64,
    oom_kills_total: u64,
    init_ep: u64,
}

impl FaultDispatcher {
    pub const fn new() -> Self {
        Self {
            entries: [const { FaultEntry::empty() }; MAX_FAULT_ENTRIES],
            fault_eq: 0,
            fault_mp_master: 0,
            oom_kills_total: 0,
            init_ep: 0,
        }
    }

    pub fn bind(&mut self, fault_eq: u64, fault_mp_master: u64, init_ep: u64) {
        self.fault_eq = fault_eq;
        self.fault_mp_master = fault_mp_master;
        self.init_ep = init_ep;
    }

    pub fn register(
        &mut self,
        client_id: u32,
        tcb_id: u32,
        fault_mp_recv: OwnedCap,
        watch_cap: u64,
        cookie: u64,
    ) -> Option<usize> {
        for (idx, e) in self.entries.iter_mut().enumerate() {
            if e.active == 0 {
                e.client_id = client_id;
                e.tcb_id = tcb_id;
                e.fault_mp_recv = fault_mp_recv;
                e.watch_cap = watch_cap;
                e.cookie = cookie;
                e.oom_retries = 0;
                e.active = 1;
                return Some(idx);
            }
        }
        None
    }

    /// Evict every entry whose `client_id` matches: tombstone the
    /// dispatcher's cookie-table slot for each, fire `WATCH_CANCEL`
    /// to detach the Watch and purge bound EQ records, return the
    /// Watch cap to `pool`, and let the `OwnedCap` in `fault_mp_recv`
    /// drop to delete the kernel object. Used by `MM_DEREGISTER_CLIENT`
    /// to tear down the entire fault MP set when a client exits.
    pub fn evict_by_client(
        &mut self,
        client_id: u32,
        pool: &mut crate::watch_pool::WatchPool,
        cookie_table: &mut CookieTable<MmsrvFaultTarget>,
    ) {
        for e in self.entries.iter_mut() {
            if e.active != 0 && e.client_id == client_id {
                let (kind, slot, _gen) = decode_cookie(e.cookie);
                let _ = cookie_table.cancel(kind, slot);
                let _ = invoke::watch_cancel(resolved_cap_ref(e.watch_cap));
                pool.free(e.watch_cap);
                // Replace fault_mp_recv with null; the displaced OwnedCap
                // drops here, which fires delete_and_free on the
                // kernel object. watch_cap is pool-managed, so pool.free()
                // above is the only cleanup needed for it.
                let _ = core::mem::replace(&mut e.fault_mp_recv, OwnedCap::null());
                // Reset scalars (fault_mp_recv is now null, will no-op Drop).
                e.active = 0;
                e.client_id = 0;
                e.tcb_id = 0;
                e.watch_cap = 0;
                e.cookie = 0;
                e.oom_retries = 0;
            }
        }
    }

    pub fn oom_kills_total(&self) -> u64 {
        self.oom_kills_total
    }

    /// Resolve `(client_id, tcb_id)` into the matching `FaultEntry`
    /// index. The dispatcher uses this after the cookie table has
    /// already mapped a kernel-published cookie back to its
    /// `MmsrvFaultTarget` payload. O(N) over the fixed
    /// `MAX_FAULT_ENTRIES` table — fine for fault frequency, but
    /// worth replacing with a secondary index when the TCB count
    /// outgrows the array.
    pub fn find_entry(&self, client_id: u32, tcb_id: u32) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.active != 0 && e.client_id == client_id && e.tcb_id == tcb_id)
    }

    /// Return a `FaultEntrySnapshot` (Copy, scalars only) for `idx`.
    /// The `fault_mp_recv` field in the snapshot is the raw slot
    /// address — use it for IPC reply calls without taking ownership
    /// of the cap.
    pub fn entry_snapshot(&self, idx: usize) -> Option<FaultEntrySnapshot> {
        let e = self.entries.get(idx)?;
        Some(FaultEntrySnapshot {
            client_id: e.client_id,
            tcb_id: e.tcb_id,
            fault_mp_recv: e.fault_mp_recv.as_raw(),
            watch_cap: e.watch_cap,
            cookie: e.cookie,
            oom_retries: e.oom_retries,
            active: e.active,
        })
    }

    pub fn for_each_active<F: FnMut(FaultEntrySnapshot)>(&self, mut f: F) {
        for e in self.entries.iter() {
            if e.active != 0 {
                f(FaultEntrySnapshot {
                    client_id: e.client_id,
                    tcb_id: e.tcb_id,
                    fault_mp_recv: e.fault_mp_recv.as_raw(),
                    watch_cap: e.watch_cap,
                    cookie: e.cookie,
                    oom_retries: e.oom_retries,
                    active: e.active,
                });
            }
        }
    }
}

fn send_fault_reply(ctx: *mut IpcContext, fault_mp_recv: u64, label: u64) {
    if ctx.is_null() || fault_mp_recv == 0 {
        return;
    }
    unsafe {
        let buf = (*ctx).ipc_buffer;
        if buf.is_null() {
            return;
        }
        let target = trona_server::MpReplyTarget::from_ipc_buffer(buf as *const _, fault_mp_recv);
        let _ = trona_server::mp_write_reply_to(buf, target, label, &[], 0);
    }
}

fn forward_to_init(
    ctx: *mut IpcContext,
    init_ep: u64,
    tcb_id: u32,
    client_id: u32,
    fault_kind: u64,
    words: &[u64; 4],
) {
    if init_ep == 0 {
        return;
    }
    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = trona_protocol::posix::INIT_REPORT_FAULT;
    msg.length = 7;
    msg.regs[0] = ((client_id as u64) << 32) | tcb_id as u64;
    msg.regs[1] = 0;
    msg.regs[2] = fault_kind;
    msg.regs[3] = words[0];
    msg.regs[4] = words[1];
    msg.regs[5] = words[2];
    msg.regs[6] = words[3];
    let mut reply = trona_kernel::core_types::TronaMsg::zeroed();
    let _ = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ctx,
            init_ep,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
}

/// Action `handle_fault` returns to the dispatcher. The dispatcher
/// drops `STATE_LOCK` before calling [`FaultAction::execute`] so the
/// outbound `INIT_REPORT_FAULT` MP_CALL cannot re-enter mmsrv under
/// a held lock and deadlock against init's reactor.
pub enum FaultAction {
    /// Reply with `KERNITE_OK` — faulter resumes at the faulting RIP.
    Resume { fault_mp_recv: u64 },
    /// Reply with non-OK — arch handler escalates to begin_destroy.
    Abort { fault_mp_recv: u64 },
    /// Forward the fault to init via `INIT_REPORT_FAULT`, then reply
    /// with non-OK. The IPC call may block; STATE_LOCK MUST be
    /// released before calling.
    ForwardAndAbort {
        init_ep: u64,
        tcb_id: u32,
        client_id: u32,
        fault_kind: u64,
        words: [u64; 4],
        fault_mp_recv: u64,
    },
}

impl FaultAction {
    /// Execute the action. Caller MUST hold no `STATE_LOCK` for
    /// `Forward*` variants (the outbound MP_CALL can re-enter
    /// mmsrv).
    ///
    /// # Safety
    /// `ctx` must be the fault dispatcher thread's IPC context.
    pub unsafe fn execute(self, ctx: *mut IpcContext) {
        match self {
            FaultAction::Resume { fault_mp_recv } => {
                send_fault_reply(ctx, fault_mp_recv, KERNITE_OK as u64)
            }
            FaultAction::Abort { fault_mp_recv } => send_fault_reply(
                ctx,
                fault_mp_recv,
                uapi::KERNITE_ERR_INVALID_OPERATION as u64,
            ),
            FaultAction::ForwardAndAbort {
                init_ep,
                tcb_id,
                client_id,
                fault_kind,
                words,
                fault_mp_recv,
            } => {
                forward_to_init(ctx, init_ep, tcb_id, client_id, fault_kind, &words);
                send_fault_reply(
                    ctx,
                    fault_mp_recv,
                    uapi::KERNITE_ERR_INVALID_OPERATION as u64,
                );
            }
        }
    }
}

/// Process one fault delivered on `entry.fault_mp_recv`. The caller
/// has already drained the `MpRecord` into `label` / `words`. Returns
/// the action the dispatcher must apply after releasing `STATE_LOCK`.
pub fn handle_fault(
    label: u64,
    words: &[u64; 4],
    state: &mut crate::main_loop::ServerState,
    entry_idx: usize,
) -> FaultAction {
    // Snapshot the entry into Copy scalars so the borrow on
    // `state.fault.entries` is released before we borrow `state.clients`.
    let entry = match state.fault.entry_snapshot(entry_idx) {
        Some(s) if s.active != 0 => s,
        _ => {
            return FaultAction::Abort { fault_mp_recv: 0 };
        }
    };
    let init_ep = state.fault.init_ep;
    let fault_mp_recv = entry.fault_mp_recv;
    match label {
        KERNITE_FAULT_PAGE_FAULT => {
            let va = words[0];
            let Some(client_idx) = state.clients.find_by_client_id(entry.client_id) else {
                return FaultAction::Abort { fault_mp_recv };
            };
            // Snapshot the faulting region's scalar fields; the borrow on
            // the client table is released before the commit / map
            // syscalls below.
            let (
                backing_is_fb_or_dev,
                mo_handle,
                owned_mo_cap_raw,
                mo_offset_base,
                region_base,
                region_prot,
                region_type,
            ) = {
                let vm = state.clients.vm(client_idx).expect("registered client");
                let Some(region_id) = (unsafe { vm.find_region(va) }) else {
                    return FaultAction::ForwardAndAbort {
                        init_ep,
                        tcb_id: entry.tcb_id,
                        client_id: entry.client_id,
                        fault_kind: KERNITE_FAULT_USER_EXCEPTION as u64,
                        words: *words,
                        fault_mp_recv,
                    };
                };
                // `MappedRegion` / `BackingDescriptor` own a cap (non-Copy), so
                // snapshot the scalar fields the fault path needs under the borrow
                // rather than moving the region out of the client VM. Registry-
                // managed backings expose only an `MoHandle` here; the raw cap is
                // resolved through `mo_registry` after the borrow is released.
                let region =
                    unsafe { vm.region(region_id) }.expect("index resolved to a live region");
                (
                    matches!(
                        region.backing,
                        BackingDescriptor::FileBacked { .. } | BackingDescriptor::Device { .. }
                    ),
                    region.backing.mo_handle(),
                    region.backing.owned_mo_cap_raw(),
                    region.backing.mo_offset() as u64,
                    region.base,
                    region.prot,
                    region.region_type,
                )
            };
            // File-backed faults are routed by the kernel directly to
            // vfs via `KERNITE_EVENT_TYPE_PAGER_REQUEST`; the fault
            // dispatcher should never see one. Device mappings never
            // fault here either. A stale descriptor of either kind is
            // forwarded as a generic user-exception so init can decide
            // whether to kill.
            if backing_is_fb_or_dev {
                return FaultAction::ForwardAndAbort {
                    init_ep,
                    tcb_id: entry.tcb_id,
                    client_id: entry.client_id,
                    fault_kind: KERNITE_FAULT_USER_EXCEPTION as u64,
                    words: *words,
                    fault_mp_recv,
                };
            }
            // Anonymous / forked-COW / image backings name their MO through the
            // domain registry, so resolve the raw cap via the snapshotted
            // `MoHandle`; SHM (and any other caller-owned backing) carries its
            // own cap directly. Mirrors the resolution the setup paths use
            // (`handle_fork_vspace`, `handle_prefault_range`).
            let mo_cap = match mo_handle {
                Some(h) => state
                    .mo_registry
                    .entry(h.0 as usize)
                    .map(|e| e.mo_cap.as_raw())
                    .unwrap_or(0),
                None => owned_mo_cap_raw,
            };
            if mo_cap == 0 {
                return FaultAction::ForwardAndAbort {
                    init_ep,
                    tcb_id: entry.tcb_id,
                    client_id: entry.client_id,
                    fault_kind: KERNITE_FAULT_USER_EXCEPTION as u64,
                    words: *words,
                    fault_mp_recv,
                };
            }
            let vspace_cap = state
                .clients
                .entry(client_idx)
                .expect("registered client")
                .vspace_cap
                .as_raw();
            let page_vaddr = va & !(uapi::KERNITE_PAGE_BYTES - 1);
            let page_delta = (page_vaddr - region_base) / (uapi::KERNITE_PAGE_BYTES as u64);
            let mo_offset_pages = mo_offset_base + page_delta;
            let commit_err =
                unsafe { crate::kernel_vm::commit_mo_pages(mo_cap, mo_offset_pages, 1) };
            if commit_err != 0 {
                state.fault.entries[entry_idx].oom_retries += 1;
                if state.fault.entries[entry_idx].oom_retries >= OOM_BACKOFF_LIMIT {
                    state.fault.oom_kills_total = state.fault.oom_kills_total.saturating_add(1);
                    return FaultAction::ForwardAndAbort {
                        init_ep,
                        tcb_id: entry.tcb_id,
                        client_id: entry.client_id,
                        fault_kind: KERNITE_FAULT_OOM as u64,
                        words: *words,
                        fault_mp_recv,
                    };
                }
                return FaultAction::Resume { fault_mp_recv };
            }
            let map_flags = (KERNITE_PAGE_FLAG_USER as u64)
                | if region_prot & 0x2 != 0 {
                    KERNITE_PAGE_FLAG_WRITABLE as u64
                } else {
                    0
                }
                | if region_prot & 0x4 != 0 {
                    KERNITE_PAGE_FLAG_EXECUTABLE as u64
                } else {
                    0
                }
                | ((kernel_region_kind(region_type) as u64) << 24);
            let count_and_flags = (1u64 << 32) | map_flags;
            let r = trona_kernel::syscall::invoke(
                vspace_cap,
                KERNITE_INV_VSPACE_MAP_MO as u64,
                mo_cap,
                page_vaddr,
                mo_offset_pages,
                count_and_flags,
            );
            if r.error != 0 {
                return FaultAction::ForwardAndAbort {
                    init_ep,
                    tcb_id: entry.tcb_id,
                    client_id: entry.client_id,
                    fault_kind: KERNITE_FAULT_OOM as u64,
                    words: *words,
                    fault_mp_recv,
                };
            }
            state.fault.entries[entry_idx].oom_retries = 0;
            FaultAction::Resume { fault_mp_recv }
        }
        KERNITE_FAULT_OOM => {
            state.fault.oom_kills_total = state.fault.oom_kills_total.saturating_add(1);
            FaultAction::ForwardAndAbort {
                init_ep,
                tcb_id: entry.tcb_id,
                client_id: entry.client_id,
                fault_kind: KERNITE_FAULT_OOM as u64,
                words: *words,
                fault_mp_recv,
            }
        }
        KERNITE_FAULT_ILLEGAL_INSTRUCTION
        | KERNITE_FAULT_BREAKPOINT
        | KERNITE_FAULT_USER_EXCEPTION
        | KERNITE_FAULT_CAP => FaultAction::ForwardAndAbort {
            init_ep,
            tcb_id: entry.tcb_id,
            client_id: entry.client_id,
            fault_kind: label,
            words: *words,
            fault_mp_recv,
        },
        _ => FaultAction::Abort { fault_mp_recv },
    }
}
