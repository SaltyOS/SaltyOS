// SPDX-License-Identifier: GPL-2.0-only
//
//! Owner-thread pager helpers — `OBJ_PAGER` retype + bind, the
//! `KERNITE_EVENT_TYPE_PAGER_REQUEST` event handler, the
//! `(mo_id → vnode)` binding table, the page-cache read buffer,
//! and the kernel pager invoke wrappers (`PAGER_SUPPLY_COPY` /
//! `PAGER_FAIL` / `PAGER_WRITEBACK_DONE`).
//!
//! Wire model: file-backed page faults bypass mmsrv. The kernel
//! emits `EVENT_TYPE_PAGER_REQUEST` directly onto vfs's
//! `OBJ_PAGER`-bound `owner_eq`; the owner-reactor's
//! `handle_pager_request` callback decodes the record, fetches
//! the page from the backend into a vfs-owned buffer, and hands the
//! bytes to the kernel via `PAGER_SUPPLY_COPY` (the kernel sources the
//! page-cache page from the global PMM and copies the bytes in — vfs
//! donates no frame). mmsrv only sees the
//! `MM_REGISTER_VFS_PAGER` boot handshake and the
//! `MM_FILE_MMAP(vnode, ...)` round-trip that materialises new MOs.

use trona_kernel::core_types::{Cap, TronaMsg};
use trona_protocol::common::{TRONA_INVALID_OPERATION, TRONA_IO_ERROR, TRONA_NOT_FOUND};
use trona_protocol::mm::MM_VFS_WRITEBACK_DONE;
use trona_protocol::posix_abi::mm::{MS_ASYNC, MS_INVALIDATE, MS_SYNC};
use trona_protocol::vfs::public::{
    VFS_MSYNC_MO, VFS_PUBLIC_REPLY_INVALID, VFS_PUBLIC_REPLY_IO_ERROR, VFS_PUBLIC_REPLY_OK,
};
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::arena::segmented_array::MmapAllocator;
use crate::core::error::VfsError;
use crate::core::outcome::{Parked, Ready};
use crate::core::vnode::VnodeHandle;
use crate::core::vop_context::OwnerVopCtx;
use crate::ipc::cookie::{KIND_PAGER, encode_cookie};
use crate::owner::op::{CancelDisposition, OpKind};
use crate::owner::page_cache::{PageCacheHandle, PageKey, PageState};
use crate::owner::resume::{PAGERRESUME_OP_READ, PAGERRESUME_OP_WRITEBACK, PagerResume, Resume};
use crate::owner::{MoBinding, MoBindingView, VfsState};

#[derive(Clone, Copy)]
pub(crate) struct MmsrvWritebackBarrier {
    pub token: u64,
    pub mo_id: u64,
    pub mo_offset: u64,
    pub length: u64,
    pub remaining: u32,
    pub status: u64,
    /// A backend credit miss happened after the barrier was issued. Already
    /// issued pages still have to drain first; when `remaining` reaches zero
    /// the barrier is made unissued again instead of completed to mmsrv.
    pub retry: bool,
    /// Set by the owner reactor when the barrier's page writebacks have been
    /// dispatched, or at birth for an immediate-completion barrier (no page
    /// writebacks) installed by `deliver_mmsrv_writeback_done_immediate`. The
    /// per-tick `retry_finished_mmsrv_writeback_barriers_budget` sweep selects
    /// on `issued && remaining == 0`, so an undelivered immediate completion is
    /// retried just like a page-writeback barrier.
    pub issued: bool,
}

const MMSRV_WRITEBACK_DONE_QUEUE_CAP: usize = 128;
const MMSRV_WRITEBACK_DONE_QUEUE_BACKPRESSURE: usize = 96;

#[derive(Clone, Copy)]
struct MmsrvWritebackDoneEntry {
    token: u64,
    status: u64,
    issued: u64,
}

impl MmsrvWritebackDoneEntry {
    const EMPTY: Self = Self {
        token: 0,
        status: 0,
        issued: 0,
    };
}

/// Fixed, allocation-free completion queue for VFS→mmsrv writeback replies.
///
/// This deliberately does not use `MmapAllocator`: a completion may run while
/// mmsrv is holding the originating `munmap` / `msync` request parked, so a
/// queue grow that asks mmsrv for anonymous memory would recreate the cycle the
/// queue is meant to break.
pub(crate) struct MmsrvWritebackDoneQueue {
    entries: [MmsrvWritebackDoneEntry; MMSRV_WRITEBACK_DONE_QUEUE_CAP],
    head: u16,
    len: u16,
}

impl MmsrvWritebackDoneQueue {
    pub(crate) const fn new_empty() -> Self {
        Self {
            entries: [MmsrvWritebackDoneEntry::EMPTY; MMSRV_WRITEBACK_DONE_QUEUE_CAP],
            head: 0,
            len: 0,
        }
    }

    #[inline]
    pub(crate) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub(crate) const fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub(crate) fn is_near_full(&self) -> bool {
        self.len() >= MMSRV_WRITEBACK_DONE_QUEUE_BACKPRESSURE
    }

    #[inline]
    fn is_full(&self) -> bool {
        self.len as usize == MMSRV_WRITEBACK_DONE_QUEUE_CAP
    }

    fn push(&mut self, entry: MmsrvWritebackDoneEntry) -> bool {
        if self.is_full() {
            return false;
        }
        let idx = ((self.head as usize) + (self.len as usize)) % MMSRV_WRITEBACK_DONE_QUEUE_CAP;
        self.entries[idx] = entry;
        self.len += 1;
        true
    }

    fn front(&self) -> Option<MmsrvWritebackDoneEntry> {
        if self.is_empty() {
            None
        } else {
            Some(self.entries[self.head as usize])
        }
    }

    fn pop_front(&mut self) {
        if self.is_empty() {
            return;
        }
        self.entries[self.head as usize] = MmsrvWritebackDoneEntry::EMPTY;
        self.head = ((self.head as usize + 1) % MMSRV_WRITEBACK_DONE_QUEUE_CAP) as u16;
        self.len -= 1;
    }
}

fn try_send_mmsrv_writeback_done(entry: MmsrvWritebackDoneEntry) -> i32 {
    let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();
    if mmsrv_ep == 0 {
        return TRONA_NOT_FOUND as i32;
    }
    let mut msg = TronaMsg::zeroed();
    msg.label = MM_VFS_WRITEBACK_DONE;
    msg.length = 3;
    msg.regs[0] = entry.token;
    msg.regs[1] = entry.status;
    msg.regs[2] = entry.issued;
    unsafe { trona_kernel::ipc::mp_write_ctx(crate::ipc_ctx(), mmsrv_ep, &raw const msg) }
}

fn arm_mmsrv_writeback_done_watch(state: &VfsState) {
    if state.mmsrv_writeback_done_queue.is_empty() {
        return;
    }
    let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();
    let watch_addr = state
        .mmsrv_writeback_done_watch_cap
        .as_ref()
        .and_then(|watch| watch.as_raw())
        .unwrap_or(0);
    if mmsrv_ep == 0 || watch_addr == 0 || state.owner_eq.as_raw() == 0 {
        return;
    }
    let err = trona_kernel::invoke::watch_register(
        trona_runtime::core::slot_alloc::resolved_cap_ref(watch_addr),
        trona_runtime::core::slot_alloc::resolved_cap_ref(mmsrv_ep),
        state.owner_eq.borrow(),
        uapi::KERNITE_STATE_WRITABLE as u64,
        state.mmsrv_writeback_done_cookie,
    );
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv writeback done watch arm failed err=");
            _lb.dec(err as u64);
            _lb.putc(b'\n');
        });
    }
}

fn submit_mmsrv_writeback_done(state: &mut VfsState, token: u64, status: u64, issued: u64) -> bool {
    let entry = MmsrvWritebackDoneEntry {
        token,
        status,
        issued,
    };
    if state.mmsrv_writeback_done_queue.is_empty() {
        let err = try_send_mmsrv_writeback_done(entry);
        if err == 0 {
            return true;
        }
        if err != uapi::KERNITE_ERR_WOULD_BLOCK as i32 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] mmsrv writeback done send deferred token=");
                _lb.hex(token);
                _lb.str(b" err=");
                _lb.dec(err as u64);
                _lb.putc(b'\n');
            });
        }
    }

    if state.mmsrv_writeback_done_queue.is_full() {
        drain_mmsrv_writeback_done_queue(state);
    }
    if !state.mmsrv_writeback_done_queue.push(entry) {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv writeback done queue full; retaining token=");
            _lb.hex(token);
            _lb.putc(b'\n');
        });
        arm_mmsrv_writeback_done_watch(state);
        return false;
    }
    arm_mmsrv_writeback_done_watch(state);
    true
}

pub(crate) fn drain_mmsrv_writeback_done_queue(state: &mut VfsState) {
    loop {
        let Some(entry) = state.mmsrv_writeback_done_queue.front() else {
            break;
        };
        let err = try_send_mmsrv_writeback_done(entry);
        if err == 0 {
            state.mmsrv_writeback_done_queue.pop_front();
            continue;
        }
        if err == uapi::KERNITE_ERR_WOULD_BLOCK as i32 {
            arm_mmsrv_writeback_done_watch(state);
            break;
        }
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] retaining mmsrv writeback completion token=");
            _lb.hex(entry.token);
            _lb.str(b" err=");
            _lb.dec(err as u64);
            _lb.putc(b'\n');
        });
        arm_mmsrv_writeback_done_watch(state);
        break;
    }
}

pub(crate) fn handle_mmsrv_writeback_done_writable(state: &mut VfsState) {
    drain_mmsrv_writeback_done_queue(state);
    retry_finished_mmsrv_writeback_barriers_budget(state, 8);
}

fn finish_mmsrv_writeback_barrier(state: &mut VfsState, token: u64, issued: u64) -> bool {
    let Some(handle) = state.mmsrv_writeback_barriers.lookup_token(token) else {
        return false;
    };
    let Some(barrier) = state.mmsrv_writeback_barriers.get(handle).copied() else {
        return false;
    };
    if barrier.retry && barrier.status == VFS_PUBLIC_REPLY_OK {
        if let Some(barrier) = state.mmsrv_writeback_barriers.get_mut(handle) {
            barrier.remaining = 0;
            barrier.retry = false;
            barrier.issued = false;
        }
        return true;
    }
    if !submit_mmsrv_writeback_done(state, token, barrier.status, issued) {
        return false;
    }
    let _ = state.mmsrv_writeback_barriers.take_by_token(token);
    true
}

/// Deliver an immediate `MM_VFS_WRITEBACK_DONE` (invalid flags, no dirty
/// pages, or barrier-registration failure) losslessly. These paths have no
/// page-writeback barrier to retain the completion, so install a finished
/// barrier (remaining = 0, status = `status`) keyed by `token` and drive it
/// through `finish_mmsrv_writeback_barrier` — the same path the per-tick
/// `retry_finished_mmsrv_writeback_barriers_budget` sweep uses to retry
/// undelivered completions until mmsrv drains them. Falls back to a
/// best-effort direct send only if the barrier arena itself is exhausted.
unsafe fn deliver_mmsrv_writeback_done_immediate(state: &mut VfsState, token: u64, status: u64) {
    if token == 0 {
        return;
    }
    if state.mmsrv_writeback_barriers.lookup_token(token).is_none() {
        let barrier = MmsrvWritebackBarrier {
            token,
            mo_id: 0,
            mo_offset: 0,
            length: 0,
            remaining: 0,
            status,
            retry: false,
            issued: true,
        };
        let mut alloc = MmapAllocator::new();
        if unsafe {
            state
                .mmsrv_writeback_barriers
                .alloc_with_token(&mut alloc, token, barrier)
                .is_err()
        } {
            let _ = submit_mmsrv_writeback_done(state, token, status, 0);
            return;
        }
    }
    let _ = finish_mmsrv_writeback_barrier(state, token, 0);
}

pub(crate) fn retry_finished_mmsrv_writeback_barriers_budget(
    state: &mut VfsState,
    budget: usize,
) -> usize {
    const MAX_BATCH: usize = 8;
    if budget == 0 {
        return 0;
    }
    let limit = core::cmp::min(budget, MAX_BATCH);
    let mut tokens = [0u64; MAX_BATCH];
    let mut count = 0usize;
    state
        .mmsrv_writeback_barriers
        .for_each_active(|_handle, barrier| {
            if barrier.issued && barrier.remaining == 0 && count < limit {
                tokens[count] = barrier.token;
                count += 1;
            }
            count < limit
        });

    let mut progressed = 0usize;
    for token in tokens.iter().take(count) {
        if finish_mmsrv_writeback_barrier(state, *token, 0) {
            progressed += 1;
        } else {
            break;
        }
    }
    progressed
}

pub(crate) fn mmsrv_writeback_page_done(state: &mut VfsState, token: u64, ok: bool) {
    if token == 0 {
        return;
    }
    let Some(handle) = state.mmsrv_writeback_barriers.lookup_token(token) else {
        return;
    };
    let mut finished = false;
    if let Some(barrier) = state.mmsrv_writeback_barriers.get_mut(handle) {
        if !ok && barrier.status == VFS_PUBLIC_REPLY_OK {
            barrier.status = VFS_PUBLIC_REPLY_IO_ERROR;
        }
        barrier.remaining = barrier.remaining.saturating_sub(1);
        finished = barrier.remaining == 0;
    }
    if finished {
        finish_mmsrv_writeback_barrier(state, token, 0);
    }
}

fn mmsrv_writeback_page_retry(state: &mut VfsState, token: u64) {
    if token == 0 {
        return;
    }
    let Some(handle) = state.mmsrv_writeback_barriers.lookup_token(token) else {
        return;
    };
    let mut finished = false;
    if let Some(barrier) = state.mmsrv_writeback_barriers.get_mut(handle) {
        barrier.retry = true;
        barrier.remaining = barrier.remaining.saturating_sub(1);
        finished = barrier.remaining == 0;
    }
    if finished {
        finish_mmsrv_writeback_barrier(state, token, 0);
    }
}

/// Retype vfs's `OBJ_PAGER` cap and bind it to the owner EQ so the
/// kernel can deliver `KERNITE_EVENT_TYPE_PAGER_REQUEST` events
/// straight to the owner reactor. Returns the pager cap so the
/// caller can ship a copy to mmsrv via `MM_REGISTER_VFS_PAGER`;
/// every subsequent `MM_FILE_MMAP` invokes
/// `MO_ATTACH_PAGER(mo_cap, pager_cap)` against this cap so the
/// kernel routes faults through `owner_eq` instead of mmsrv's
/// fault dispatcher.
///
/// Idempotent: the second call short-circuits and returns the
/// already-bound cap. mmsrv's first-write-wins gate would reject a
/// second `MM_REGISTER_VFS_PAGER` anyway, but the idempotent
/// behaviour keeps the helper safe to call from boot retries.
pub(crate) fn ensure_pager_session(state: &mut VfsState) -> Result<Cap, VfsError> {
    if state.pager_cap.as_raw() != 0 {
        return Ok(state.pager_cap.as_raw());
    }
    if state.owner_eq.as_raw() == 0 {
        return Err(VfsError::Io);
    }
    ensure_mmsrv_writeback_done_watch(state)?;

    let pager_cap =
        match trona_runtime::core::slot_alloc::alloc_object(uapi::KERNITE_OBJ_PAGER as u64, 0) {
            Ok(c) => c,
            Err(err) => {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[VFS] pager alloc failed err=");
                    _lb.hex(err);
                    _lb.str(b"\n");
                });
                return Err(VfsError::NoMem);
            }
        };

    // Encode `(KIND_PAGER, slot=0, live_gen=state.next_pager_gen)`. The pager event is
    // a vfs-process singleton — there is exactly one armed pager
    // cookie at any time so the slot field is unused; the live_gen
    // field still advances on each bind attempt so stale pager
    // events from a future detach / rebind cycle do not alias the
    // new event stream.
    let pager_epoch = state.next_pager_gen;
    state.next_pager_gen = state.next_pager_gen.wrapping_add(1);
    if state.next_pager_gen == 0 {
        state.next_pager_gen = 1;
    }
    let cookie = encode_cookie(KIND_PAGER, 0, pager_epoch);
    let r = trona_kernel::syscall::invoke(
        pager_cap,
        uapi::KERNITE_INV_PAGER_BIND_EQ as u64,
        state.owner_eq.as_raw(),
        cookie,
        0,
        0,
    );
    if r.error != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] pager bind eq failed err=");
            _lb.hex(r.error);
            _lb.str(b" owner_eq=");
            _lb.hex(state.owner_eq.as_raw());
            _lb.str(b"\n");
        });
        // SAFETY: pager_cap is the pager cap from the alloc above, solely owned
        // here; freed once on this pager-bind failure path.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(pager_cap) };
        return Err(VfsError::Io);
    }

    // SAFETY: pager_cap is solely owned by state.pager_cap from here; the
    // returned raw is a borrow of the same slot for the immediate caller use.
    state.pager_cap =
        unsafe { trona_runtime::core::slot_alloc::OwnedCap::adopt_received(pager_cap) };
    state.pager_cookie = cookie;
    Ok(pager_cap)
}

#[inline]
fn monotonic_now_ns() -> u64 {
    let clock = trona_runtime::client::caps::clock_cap().addr();
    if clock == 0 {
        0
    } else {
        trona_kernel::syscall::clock_read_monotonic(clock)
    }
}

pub(crate) fn record_supplied_page_clean(
    state: &mut VfsState,
    vnode: VnodeHandle,
    page_offset: u64,
) {
    let key = PageKey { vnode, page_offset };
    let _ = crate::owner::page_cache::record_supplied_clean(state, key, monotonic_now_ns());
}

fn ensure_mmsrv_writeback_done_watch(state: &mut VfsState) -> Result<(), VfsError> {
    if state.mmsrv_writeback_done_watch_cap.is_some() {
        return Ok(());
    }
    if state.owner_eq.as_raw() == 0 {
        return Err(VfsError::Io);
    }
    let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();
    if mmsrv_ep == 0 {
        return Err(VfsError::NoEnt);
    }

    let watch = match trona_runtime::core::slot_alloc::alloc_object_owned(
        uapi::KERNITE_OBJ_WATCH as u64,
        0,
    ) {
        Ok(watch) => watch,
        Err(_) => return Err(VfsError::NoMem),
    };
    let watch_addr = watch.as_raw().unwrap_or(0);
    if watch_addr == 0 {
        let _ = watch.release();
        return Err(VfsError::Io);
    }
    let err = trona_kernel::invoke::watch_register(
        trona_runtime::core::slot_alloc::resolved_cap_ref(watch_addr),
        trona_runtime::core::slot_alloc::resolved_cap_ref(mmsrv_ep),
        state.owner_eq.borrow(),
        uapi::KERNITE_STATE_WRITABLE as u64,
        state.mmsrv_writeback_done_cookie,
    );
    if err != 0 {
        let _ = trona_kernel::invoke::watch_cancel(
            trona_runtime::core::slot_alloc::resolved_cap_ref(watch_addr),
        );
        let _ = watch.release();
        return Err(VfsError::Io);
    }

    state.mmsrv_writeback_done_watch_cap = Some(watch);
    Ok(())
}

/// Start writeback for every resident page-cache entry belonging
/// to `vnode`. This is the concrete MAP_SHARED flush path used by
/// `fsync` / `fdatasync`: vfs asks the kernel to mark the MO page
/// writeback, copies the current MO bytes into its IPC buffer via
/// `MO_READ`, and then sends the bytes through the backend's normal
/// `VopDataOps::write` hook. Backend-specific policy stays in the
/// backend VOP table; pager/writeback remains generic.
pub(crate) unsafe fn issue_writebacks_for_vnode(state: &mut VfsState, vnode: VnodeHandle) -> usize {
    let Some(binding) = lookup_binding_by_vnode(state, vnode) else {
        return 0;
    };
    let actual_size = match unsafe { vnode_data_size(state, vnode) } {
        Some(size) if size != 0 => size,
        _ => return 0,
    };

    let mut issued = 0usize;
    let total = state.page_cache.total_cap();
    for slot in 0..total {
        let Some(handle) = state.page_cache.handle_from_slot(slot) else {
            continue;
        };
        let Some((key, page_state)) = state.page_cache.get(handle).map(|e| (e.key, e.state)) else {
            continue;
        };
        if key.vnode != vnode {
            continue;
        }
        if matches!(page_state, PageState::Empty | PageState::Writeback) {
            continue;
        }
        if key.page_offset < binding.file_offset || key.page_offset >= actual_size {
            continue;
        }
        let relative = key.page_offset - binding.file_offset;
        if relative % (uapi::KERNITE_PAGE_BYTES as u64) != 0 {
            continue;
        }
        let page_idx = relative / (uapi::KERNITE_PAGE_BYTES as u64);
        let tail_len = actual_size.saturating_sub(key.page_offset);
        let write_len = ::core::cmp::min(tail_len, uapi::KERNITE_PAGE_BYTES as u64);
        if write_len == 0 {
            continue;
        }
        if unsafe { issue_writeback_for_page(state, handle, binding, key, page_idx, write_len, 0) }
        {
            issued += 1;
        }
    }
    issued
}

fn validate_msync_flags(flags: u64) -> bool {
    let known = (MS_ASYNC | MS_INVALIDATE | MS_SYNC) as u64;
    if flags & !known != 0 {
        return false;
    }
    let sync = flags & (MS_SYNC as u64) != 0;
    let async_ = flags & (MS_ASYNC as u64) != 0;
    !(sync && async_)
}

unsafe fn issue_writebacks_for_binding_file_range(
    state: &mut VfsState,
    binding: MoBindingView,
    file_start: u64,
    length: u64,
    mmsrv_writeback_token: u64,
) -> usize {
    if length == 0 {
        return 0;
    }
    let actual_size = match unsafe { vnode_data_size(state, binding.vnode) } {
        Some(size) if size != 0 => size,
        _ => return 0,
    };
    let Some(request_end) = file_start.checked_add(length) else {
        return 0;
    };
    let end = core::cmp::min(request_end, actual_size);
    if file_start >= end {
        return 0;
    }

    let mut issued = 0usize;
    let total = state.page_cache.total_cap();
    for slot in 0..total {
        let Some(handle) = state.page_cache.handle_from_slot(slot) else {
            continue;
        };
        let Some((key, page_state)) = state.page_cache.get(handle).map(|e| (e.key, e.state)) else {
            continue;
        };
        if key.vnode != binding.vnode {
            continue;
        }
        if matches!(page_state, PageState::Empty | PageState::Writeback) {
            continue;
        }
        if key.page_offset < binding.file_offset || key.page_offset >= actual_size {
            continue;
        }
        let page_end = key
            .page_offset
            .saturating_add(uapi::KERNITE_PAGE_BYTES as u64);
        if page_end <= file_start || key.page_offset >= end {
            continue;
        }
        let relative = key.page_offset - binding.file_offset;
        if relative % (uapi::KERNITE_PAGE_BYTES as u64) != 0 {
            continue;
        }
        let page_idx = relative / (uapi::KERNITE_PAGE_BYTES as u64);
        let write_len = core::cmp::min(
            actual_size.saturating_sub(key.page_offset),
            uapi::KERNITE_PAGE_BYTES as u64,
        );
        if write_len == 0 {
            continue;
        }
        if unsafe {
            issue_writeback_for_page(
                state,
                handle,
                binding,
                key,
                page_idx,
                write_len,
                mmsrv_writeback_token,
            )
        } {
            issued += 1;
        }
    }
    issued
}

unsafe fn count_writeback_candidates_for_binding_file_range(
    state: &mut VfsState,
    binding: MoBindingView,
    file_start: u64,
    length: u64,
) -> usize {
    if length == 0 {
        return 0;
    }
    let actual_size = match unsafe { vnode_data_size(state, binding.vnode) } {
        Some(size) if size != 0 => size,
        _ => return 0,
    };
    let Some(request_end) = file_start.checked_add(length) else {
        return 0;
    };
    let end = core::cmp::min(request_end, actual_size);
    if file_start >= end {
        return 0;
    }

    let mut count = 0usize;
    let total = state.page_cache.total_cap();
    for slot in 0..total {
        let Some(handle) = state.page_cache.handle_from_slot(slot) else {
            continue;
        };
        let Some((key, page_state)) = state.page_cache.get(handle).map(|e| (e.key, e.state)) else {
            continue;
        };
        if key.vnode != binding.vnode {
            continue;
        }
        if matches!(page_state, PageState::Empty | PageState::Writeback) {
            continue;
        }
        if key.page_offset < binding.file_offset || key.page_offset >= actual_size {
            continue;
        }
        let page_end = key
            .page_offset
            .saturating_add(uapi::KERNITE_PAGE_BYTES as u64);
        if page_end <= file_start || key.page_offset >= end {
            continue;
        }
        let relative = key.page_offset - binding.file_offset;
        if relative % (uapi::KERNITE_PAGE_BYTES as u64) != 0 {
            continue;
        }
        if actual_size.saturating_sub(key.page_offset) == 0 {
            continue;
        }
        count += 1;
    }
    count
}

pub(crate) unsafe fn issue_writebacks_for_mo_range(
    state: &mut VfsState,
    mo_id: u64,
    mo_offset: u64,
    length: u64,
) -> Result<usize, VfsError> {
    let Some(binding) = lookup_binding_by_mo_id(state, mo_id) else {
        return Err(VfsError::NoEnt);
    };
    if length == 0 || mo_offset >= binding.length {
        return Ok(0);
    }
    let range_len = core::cmp::min(length, binding.length - mo_offset);
    let file_start = binding
        .file_offset
        .checked_add(mo_offset)
        .ok_or(VfsError::Range)?;
    Ok(
        unsafe {
            issue_writebacks_for_binding_file_range(state, binding, file_start, range_len, 0)
        },
    )
}

unsafe fn register_mmsrv_writeback_barrier(
    state: &mut VfsState,
    token: u64,
    mo_id: u64,
    mo_offset: u64,
    length: u64,
) -> Result<bool, VfsError> {
    if token == 0 {
        return Err(VfsError::Inval);
    }
    if state.mmsrv_writeback_barriers.lookup_token(token).is_some() {
        return Err(VfsError::Busy);
    }
    let Some(binding) = lookup_binding_by_mo_id(state, mo_id) else {
        return Err(VfsError::NoEnt);
    };
    if length == 0 || mo_offset >= binding.length {
        return Ok(false);
    }
    let barrier = MmsrvWritebackBarrier {
        token,
        mo_id,
        mo_offset,
        length,
        remaining: 0,
        status: VFS_PUBLIC_REPLY_OK,
        retry: false,
        issued: false,
    };
    let mut alloc = MmapAllocator::new();
    unsafe {
        state
            .mmsrv_writeback_barriers
            .alloc_with_token(&mut alloc, token, barrier)
            .map_err(|_| VfsError::NoMem)?;
    }
    Ok(true)
}

unsafe fn prepare_mmsrv_writeback_issue(
    state: &mut VfsState,
    token: u64,
) -> Result<Option<(MoBindingView, u64, u64, u32)>, VfsError> {
    let Some(handle) = state.mmsrv_writeback_barriers.lookup_token(token) else {
        return Ok(None);
    };
    let Some(barrier) = state.mmsrv_writeback_barriers.get(handle).copied() else {
        return Ok(None);
    };
    if barrier.issued {
        return Ok(None);
    }
    if state.pager_cap.as_raw() == 0 {
        return Err(VfsError::Io);
    }
    let Some(binding) = lookup_binding_by_mo_id(state, barrier.mo_id) else {
        return Err(VfsError::NoEnt);
    };
    if barrier.length == 0 || barrier.mo_offset >= binding.length {
        return Ok(None);
    }
    let range_len = core::cmp::min(barrier.length, binding.length - barrier.mo_offset);
    let file_start = binding
        .file_offset
        .checked_add(barrier.mo_offset)
        .ok_or(VfsError::Range)?;
    let count = unsafe {
        count_writeback_candidates_for_binding_file_range(state, binding, file_start, range_len)
    };
    if count == 0 {
        return Ok(None);
    }
    let remaining = u32::try_from(count).map_err(|_| VfsError::Range)?;
    if let Some(barrier) = state.mmsrv_writeback_barriers.get_mut(handle) {
        barrier.remaining = remaining;
        barrier.issued = true;
    }
    Ok(Some((binding, file_start, range_len, remaining)))
}

unsafe fn fail_mmsrv_writeback_barrier(state: &mut VfsState, token: u64, err: VfsError) {
    let Some(handle) = state.mmsrv_writeback_barriers.lookup_token(token) else {
        return;
    };
    if let Some(barrier) = state.mmsrv_writeback_barriers.get_mut(handle) {
        barrier.status = crate::ipc::protocol::public::vfs_error_to_public_reply(err);
        barrier.issued = true;
    }
    finish_mmsrv_writeback_barrier(state, token, 0);
}

unsafe fn issue_one_mmsrv_writeback_barrier(state: &mut VfsState, token: u64) -> bool {
    let prepared = unsafe { prepare_mmsrv_writeback_issue(state, token) };
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(err) => {
            unsafe { fail_mmsrv_writeback_barrier(state, token, err) };
            return true;
        }
    };
    let Some((binding, file_start, range_len, _remaining)) = prepared else {
        finish_mmsrv_writeback_barrier(state, token, 0);
        return true;
    };

    let _issued = unsafe {
        issue_writebacks_for_binding_file_range(state, binding, file_start, range_len, token)
    };
    let Some(handle) = state.mmsrv_writeback_barriers.lookup_token(token) else {
        return true;
    };
    let finished = state
        .mmsrv_writeback_barriers
        .get(handle)
        .map(|barrier| barrier.remaining == 0)
        .unwrap_or(false);
    if finished {
        finish_mmsrv_writeback_barrier(state, token, 0);
    }
    true
}

pub(crate) unsafe fn issue_mmsrv_writeback_barriers_budget(
    state: &mut VfsState,
    budget: usize,
) -> usize {
    const MAX_BATCH: usize = 4;
    if budget == 0 {
        return 0;
    }
    if state.mmsrv_writeback_done_queue.is_near_full() {
        return 0;
    }
    let limit = core::cmp::min(budget, MAX_BATCH);
    let mut tokens = [0u64; MAX_BATCH];
    let mut count = 0usize;
    state
        .mmsrv_writeback_barriers
        .for_each_active(|_handle, barrier| {
            if !barrier.issued && count < limit {
                tokens[count] = barrier.token;
                count += 1;
            }
            count < limit
        });
    let mut issued = 0usize;
    for token in tokens.iter().take(count) {
        if unsafe { issue_one_mmsrv_writeback_barrier(state, *token) } {
            issued += 1;
        }
    }
    issued
}

pub(crate) unsafe fn issue_writebacks_for_vnode_range(
    state: &mut VfsState,
    vnode: VnodeHandle,
    file_offset: u64,
    length: u64,
) -> usize {
    let Some(binding) = lookup_binding_by_vnode(state, vnode) else {
        return 0;
    };
    unsafe { issue_writebacks_for_binding_file_range(state, binding, file_offset, length, 0) }
}

pub(crate) unsafe fn handle_mmsrv_writeback_request(state: &mut VfsState, msg: &TronaMsg) {
    if msg.label != VFS_MSYNC_MO || msg.length < 5 {
        return;
    }
    let token = msg.regs[0];
    let flags = msg.regs[4];
    if !validate_msync_flags(flags) {
        unsafe {
            deliver_mmsrv_writeback_done_immediate(state, token, VFS_PUBLIC_REPLY_INVALID);
        }
        return;
    }
    match unsafe {
        register_mmsrv_writeback_barrier(state, token, msg.regs[1], msg.regs[2], msg.regs[3])
    } {
        Ok(false) => unsafe {
            deliver_mmsrv_writeback_done_immediate(state, token, VFS_PUBLIC_REPLY_OK);
        },
        Ok(true) => {}
        Err(err) => {
            let status = crate::ipc::protocol::public::vfs_error_to_public_reply(err);
            unsafe {
                deliver_mmsrv_writeback_done_immediate(state, token, status);
            }
        }
    }
}

/// Resolve a page-cache handle's MO binding, page index, and tail-aware
/// write length, then drive one writeback through `issue_writeback_for_page`.
/// Shared by the reactor's budgeted sweep and the page-cache eviction path,
/// which flushes a dirty page before it can be reclaimed. Returns `true` if a
/// writeback was issued for `handle`.
pub(crate) unsafe fn writeback_handle(state: &mut VfsState, handle: PageCacheHandle) -> bool {
    let Some((key, page_state)) = state.page_cache.get(handle).map(|e| (e.key, e.state)) else {
        return false;
    };
    if matches!(page_state, PageState::Empty | PageState::Writeback) {
        return false;
    }
    let Some(binding) = lookup_binding_by_vnode(state, key.vnode) else {
        return false;
    };
    let Some(actual_size) = (unsafe { vnode_data_size(state, key.vnode) }) else {
        return false;
    };
    if key.page_offset < binding.file_offset || key.page_offset >= actual_size {
        return false;
    }
    let relative = key.page_offset - binding.file_offset;
    if relative % (uapi::KERNITE_PAGE_BYTES as u64) != 0 {
        return false;
    }
    let page_idx = relative / (uapi::KERNITE_PAGE_BYTES as u64);
    let write_len = ::core::cmp::min(
        actual_size.saturating_sub(key.page_offset),
        uapi::KERNITE_PAGE_BYTES as u64,
    );
    if write_len == 0 {
        return false;
    }
    unsafe { issue_writeback_for_page(state, handle, binding, key, page_idx, write_len, 0) }
}

/// Opportunistic writeback sweep for the reactor idle path. It is
/// deliberately budgeted so normal frontend/backend traffic is not
/// starved; `fsync` calls use [`issue_writebacks_for_vnode`] to
/// flush all pages for one vnode before installing their barrier.
pub(crate) unsafe fn issue_writeback_budget(state: &mut VfsState, budget: usize) -> usize {
    if budget == 0 {
        return 0;
    }
    let mut issued = 0usize;
    let total = state.page_cache.total_cap();
    for slot in 0..total {
        if issued >= budget {
            break;
        }
        let Some(handle) = state.page_cache.handle_from_slot(slot) else {
            continue;
        };
        if unsafe { writeback_handle(state, handle) } {
            issued += 1;
        }
    }
    issued
}

unsafe fn vnode_data_size(state: &mut VfsState, vnode: VnodeHandle) -> Option<u64> {
    unsafe {
        let mut ctx = OwnerVopCtx::from_state(state, vnode)?;
        let ops = (*ctx.vnode).ops;
        if ops.is_null() {
            return None;
        }
        Some(((*ops).meta.data_size)(&mut ctx))
    }
}

unsafe fn current_ipc_buffer_bytes() -> Option<*const u8> {
    unsafe {
        let ctx = trona_runtime::current_ipc_ctx();
        if ctx.is_null() || (*ctx).ipc_buffer.is_null() {
            None
        } else {
            Some((*ctx).ipc_buffer as *const u8)
        }
    }
}

unsafe fn issue_writeback_for_page(
    state: &mut VfsState,
    handle: PageCacheHandle,
    binding: MoBindingView,
    key: PageKey,
    page_idx: u64,
    write_len: u64,
    mmsrv_writeback_token: u64,
) -> bool {
    unsafe {
        let Some(entry_state) = state.page_cache.get(handle).map(|e| e.state) else {
            return false;
        };
        if matches!(entry_state, PageState::Empty | PageState::Writeback) {
            return false;
        }

        let pager_cap = state.pager_cap.as_raw();
        if pager_cap == 0 {
            return false;
        }
        let epoch = match invoke_pager_begin_writeback(pager_cap, binding.mo_id, page_idx) {
            Ok(Some(epoch)) => epoch,
            Ok(None) => {
                crate::owner::page_cache::mark_clean(state, handle);
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, true);
                return false;
            }
            Err(_) => {
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
                return false;
            }
        };
        crate::owner::page_cache::mark_writeback(state, handle);

        let mo_byte_offset = page_idx.saturating_mul(uapi::KERNITE_PAGE_BYTES as u64);
        let (read_err, bytes_read) = trona_kernel::invoke::mo_read(
            trona_runtime::core::slot_alloc::resolved_cap_ref(binding.mo_cap_raw),
            mo_byte_offset,
            write_len,
        );
        let Some(src) = current_ipc_buffer_bytes() else {
            let _ = invoke_pager_writeback_done(
                pager_cap,
                binding.mo_id,
                page_idx,
                epoch,
                TRONA_IO_ERROR,
            );
            crate::owner::page_cache::complete_writeback(state, handle, false);
            mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
            return false;
        };
        if read_err != 0 || bytes_read != write_len {
            let _ = invoke_pager_writeback_done(
                pager_cap,
                binding.mo_id,
                page_idx,
                epoch,
                TRONA_IO_ERROR,
            );
            crate::owner::page_cache::complete_writeback(state, handle, false);
            mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
            return false;
        }

        let (outcome, vkey) = {
            let Some(ctx_owner) = OwnerVopCtx::from_state(state, key.vnode) else {
                let _ = invoke_pager_writeback_done(
                    pager_cap,
                    binding.mo_id,
                    page_idx,
                    epoch,
                    TRONA_IO_ERROR,
                );
                crate::owner::page_cache::complete_writeback(state, handle, false);
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
                return false;
            };
            let ops = (*ctx_owner.vnode).ops;
            if ops.is_null() {
                let _ = invoke_pager_writeback_done(
                    pager_cap,
                    binding.mo_id,
                    page_idx,
                    epoch,
                    TRONA_IO_ERROR,
                );
                crate::owner::page_cache::complete_writeback(state, handle, false);
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
                return false;
            }
            let vkey = (*ctx_owner.vnode).key;
            let data_ctx = ctx_owner.data_ctx();
            (
                ((*ops).data.writeback)(&data_ctx, key.page_offset, src, write_len),
                vkey,
            )
        };

        match outcome {
            Ok(Ready(n)) if n == write_len => {
                let (rc, dirty_pending) =
                    invoke_pager_writeback_done(pager_cap, binding.mo_id, page_idx, epoch, 0);
                crate::owner::page_cache::complete_writeback(
                    state,
                    handle,
                    rc == 0 && !dirty_pending,
                );
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, rc == 0);
                rc == 0
            }
            Ok(Ready(_)) => {
                let _ = invoke_pager_writeback_done(
                    pager_cap,
                    binding.mo_id,
                    page_idx,
                    epoch,
                    TRONA_IO_ERROR,
                );
                crate::owner::page_cache::complete_writeback(state, handle, false);
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
                false
            }
            Err(VfsError::Busy) => {
                let _ = invoke_pager_writeback_done(
                    pager_cap,
                    binding.mo_id,
                    page_idx,
                    epoch,
                    uapi::KERNITE_ERR_BUSY as u64,
                );
                crate::owner::page_cache::mark_dirty(state, handle);
                mmsrv_writeback_page_retry(state, mmsrv_writeback_token);
                false
            }
            Err(_) => {
                let _ = invoke_pager_writeback_done(
                    pager_cap,
                    binding.mo_id,
                    page_idx,
                    epoch,
                    TRONA_IO_ERROR,
                );
                crate::owner::page_cache::complete_writeback(state, handle, false);
                mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
                false
            }
            Ok(Parked(pending_handle)) => {
                let mut tx_id = crate::owner::pending::TxId::INVALID;
                if let Some(op) = state.pending_ops.get_mut(pending_handle) {
                    op.core.kind = OpKind::Pager;
                    op.core.vnode_key = vkey;
                    tx_id = op.core.tx_id;
                }
                if tx_id.is_valid() {
                    state.ordering.begin_unordered(
                        crate::owner::ordering::OrderingKey::VnodeMutate(vkey),
                        tx_id,
                    );
                }
                let pager_resume = PagerResume {
                    op_type: PAGERRESUME_OP_WRITEBACK,
                    vnode: key.vnode,
                    vkey,
                    page_offset: key.page_offset,
                    length: write_len as u32,
                    mo_id: binding.mo_id,
                    page_idx,
                    writeback_epoch: epoch,
                    mmsrv_writeback_token,
                };
                if state
                    .stamp_resume_ctx(pending_handle, 0, None, Resume::Pager(pager_resume))
                    .is_err()
                {
                    crate::owner::pending::cancel_op_handle(
                        state,
                        pending_handle,
                        CancelDisposition::Drop,
                    );
                    let _ = invoke_pager_writeback_done(
                        pager_cap,
                        binding.mo_id,
                        page_idx,
                        epoch,
                        TRONA_IO_ERROR,
                    );
                    crate::owner::page_cache::complete_writeback(state, handle, false);
                    mmsrv_writeback_page_done(state, mmsrv_writeback_token, false);
                    return false;
                }
                true
            }
        }
    }
}

/// Resolve a vnode to its installed pager binding. Linear scan;
/// the live mapping count stays small. Returns a `MoBindingView`
/// copy projection so callers can hold the raw cap slot for invokes
/// while `&mut VfsState` borrows remain valid.
pub(crate) fn lookup_binding_by_vnode(
    state: &VfsState,
    vnode: VnodeHandle,
) -> Option<MoBindingView> {
    let n = state.pager_bindings.len();
    for i in 0..n {
        if let Some(b) = state.pager_bindings.get(i) {
            if b.active && b.vnode == vnode {
                return Some(MoBindingView {
                    mo_id: b.mo_id,
                    mo_cap_raw: b.mo_cap.as_raw(),
                    vnode: b.vnode,
                    file_offset: b.file_offset,
                    length: b.length,
                });
            }
        }
    }
    None
}

/// Decommit the page range `[new_size_pages, mo_pages)` from a
/// file-backed MO when the underlying file shrank below the
/// previously-mapped size. The kernel releases each page's phys
/// backing; subsequent client faults on the trimmed range produce
/// fresh `EVENT_TYPE_PAGER_REQUEST` events that the pager-event
/// handler can then surface as SIGBUS via `PAGER_FAIL`.
///
/// `MO_DECOMMIT(mo_cap, page_offset, page_count)` invokes the
/// kernel ABI directly — no userland round-trip through mmsrv.
pub(crate) unsafe fn invoke_mo_decommit_for_truncate(
    state: &VfsState,
    vnode: VnodeHandle,
    new_size: u64,
) {
    let Some(binding) = lookup_binding_by_vnode(state, vnode) else {
        return;
    };
    let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
    let new_size_pages = new_size.div_ceil(page_bytes);
    let mo_pages = binding.length.div_ceil(page_bytes);
    if new_size_pages >= mo_pages {
        return;
    }
    let count = mo_pages - new_size_pages;
    let _ = trona_kernel::syscall::invoke(
        binding.mo_cap_raw,
        uapi::KERNITE_INV_MO_DECOMMIT as u64,
        new_size_pages,
        count,
        0,
        0,
    );
}

// ---------------------------------------------------------------------------
// `(mo_id → vnode)` binding table.
// ---------------------------------------------------------------------------

/// Install a fresh `(mo_id → vnode + file backing)` binding when
/// mmsrv's `MM_FILE_MMAP` reply lands. Reuses the first inactive
/// slot if available, otherwise pushes a new entry. Returns the
/// table index for callers that want to remove the binding later.
pub(crate) unsafe fn install_mo_binding(
    state: &mut VfsState,
    binding: MoBinding,
) -> Result<u32, VfsError> {
    let mut alloc = MmapAllocator::new();
    let n = state.pager_bindings.len();
    for i in 0..n {
        if let Some(slot) = state.pager_bindings.get_mut(i) {
            if !slot.active {
                *slot = binding;
                return Ok(i);
            }
        }
    }
    let pushed = unsafe {
        state
            .pager_bindings
            .push(binding, &mut alloc)
            .map_err(|_| VfsError::NoMem)?
    };
    let _ = pushed;
    Ok(state.pager_bindings.len().saturating_sub(1))
}

/// Resolve a kernel-supplied `mo_id` to its installed binding.
/// Linear scan over `state.pager_bindings`; the live mo_id count
/// is bounded by the file-backed mmap working set so a hash side
/// table is not yet justified. Returns a `MoBindingView` copy
/// projection for the same reason as `lookup_binding_by_vnode`.
pub(crate) fn lookup_binding_by_mo_id(state: &VfsState, mo_id: u64) -> Option<MoBindingView> {
    let n = state.pager_bindings.len();
    for i in 0..n {
        if let Some(b) = state.pager_bindings.get(i) {
            if b.active && b.mo_id == mo_id {
                return Some(MoBindingView {
                    mo_id: b.mo_id,
                    mo_cap_raw: b.mo_cap.as_raw(),
                    vnode: b.vnode,
                    file_offset: b.file_offset,
                    length: b.length,
                });
            }
        }
    }
    None
}

/// `PAGER_SUPPLY_COPY(pager, mo_id, page_idx, src_va, bytes_read)` —
/// page-cache supply. The kernel sources the page from the global PMM,
/// copies `bytes_read` bytes from `src_va` (a present VA in vfs's own
/// address space: the sync read buffer, or the saltyfs SHM ring on the
/// async completion path), and commits it into the file MO at
/// `(mo_id, page_idx)`. vfs donates no frame — the page is kernel-owned
/// page-cache memory, so it never charges vfs's untyped quota. The
/// kernel zero-fills the page first, so a partial `bytes_read` leaves a
/// zero tail (POSIX `mmap(2)` semantics). Wakes every TCB blocked on the
/// matching `PendingPagerRequest`.
pub(crate) unsafe fn invoke_pager_supply_copy(
    pager_cap: Cap,
    mo_id: u64,
    page_idx: u64,
    src_va: u64,
    bytes_read: u64,
) -> i32 {
    let r = trona_kernel::syscall::invoke(
        pager_cap,
        uapi::KERNITE_INV_PAGER_SUPPLY_COPY as u64,
        mo_id,
        page_idx,
        src_va,
        bytes_read,
    );
    r.error as i32
}

/// `PAGER_FAIL(pager, mo_id, page_idx, errno)` — surface a
/// SIGBUS-equivalent for the requested page. The kernel installs a
/// `PHYS_TAG_PAGER_FAILED` tombstone in the MO's radix tree and
/// wakes every TCB blocked on the matching pending request; on
/// retry the fault hook detects the tombstone and falls through to
/// the existing fault-delivery path so init can deliver SIGBUS.
pub(crate) unsafe fn invoke_pager_fail(
    pager_cap: Cap,
    mo_id: u64,
    page_idx: u64,
    errno: u64,
) -> i32 {
    let r = trona_kernel::syscall::invoke(
        pager_cap,
        uapi::KERNITE_INV_PAGER_FAIL as u64,
        mo_id,
        page_idx,
        errno,
        0,
    );
    r.error as i32
}

/// `PAGER_BEGIN_WRITEBACK(pager, mo_id, page_idx)` — transition the
/// kernel's MO page into writeback state before vfs copies bytes out
/// and sends a backend `data.write`. The returned value is the
/// pager cancel epoch to echo through `PAGER_WRITEBACK_DONE`.
pub(crate) unsafe fn invoke_pager_begin_writeback(
    pager_cap: Cap,
    mo_id: u64,
    page_idx: u64,
) -> Result<Option<u64>, VfsError> {
    let r = trona_kernel::syscall::invoke(
        pager_cap,
        uapi::KERNITE_INV_PAGER_BEGIN_WRITEBACK as u64,
        mo_id,
        page_idx,
        0,
        0,
    );
    if r.error == 0 {
        Ok(Some(r.value))
    } else if r.error == uapi::KERNITE_ERR_WOULD_BLOCK as u64 {
        Ok(None)
    } else if r.error == uapi::KERNITE_ERR_BUSY as u64 {
        Err(VfsError::Busy)
    } else if r.error == uapi::KERNITE_ERR_NOT_FOUND as u64 {
        Err(VfsError::NoEnt)
    } else {
        Err(VfsError::Io)
    }
}

/// `PAGER_WRITEBACK_DONE(pager, mo_id, page_idx)` — signal that an
/// in-flight writeback for `(mo_id, page_idx)` has finished. The
/// kernel clears the writeback flag on the MO's radix entry so the
/// page can be reclaimed / re-dirtied.
pub(crate) unsafe fn invoke_pager_writeback_done(
    pager_cap: Cap,
    mo_id: u64,
    page_idx: u64,
    epoch: u64,
    status: u64,
) -> (i32, bool) {
    let r = trona_kernel::syscall::invoke(
        pager_cap,
        uapi::KERNITE_INV_PAGER_WRITEBACK_DONE as u64,
        mo_id,
        page_idx,
        epoch,
        status,
    );
    (r.error as i32, r.value != 0)
}

/// Outcome of [`invoke_pager_evict_page`].
pub(crate) enum PagerEvict {
    /// Kernel unmapped the page from every mapping and freed the frame.
    Evicted,
    /// Frame is dirty (kernel frame-level authority): still resident and
    /// mapped. The caller must write it back before it can be reclaimed.
    Dirty,
    /// Page is not resident — already gone, or the binding/MO is absent.
    NotResident,
}

/// `PAGER_EVICT_PAGE(pager, mo_id, page_idx)` — ask the kernel to reclaim a
/// CLEAN, resident page: it unmaps the page from every mapping and frees the
/// frame so a later access re-faults and the pager re-supplies. The kernel
/// refuses (returning [`PagerEvict::Dirty`]) when the frame is dirty, leaving
/// it resident and mapped for the caller to write back and retry. The
/// owner-side page-cache mirror is advisory; this call is how the owner asks
/// the dirty-bit authority before dropping a "Clean" mirror entry.
pub(crate) unsafe fn invoke_pager_evict_page(
    pager_cap: Cap,
    mo_id: u64,
    page_idx: u64,
) -> PagerEvict {
    let r = trona_kernel::syscall::invoke(
        pager_cap,
        uapi::KERNITE_INV_PAGER_EVICT_PAGE as u64,
        mo_id,
        page_idx,
        0,
        0,
    );
    if r.error == 0 {
        PagerEvict::Evicted
    } else if r.error == uapi::KERNITE_ERR_BUSY as u64 {
        PagerEvict::Dirty
    } else if r.error == uapi::KERNITE_ERR_NOT_FOUND as u64 {
        PagerEvict::NotResident
    } else {
        // Unexpected (bad cap / arg): conservatively treat as dirty so the
        // caller does NOT drop the mirror and risk losing a resident page.
        PagerEvict::Dirty
    }
}

/// Release a single `MoBinding` at index `binding_idx`. The
/// kernel's `cancel_epoch`-driven detach already wakes any TCB
/// blocked on the matching MO, so the userland-side responsibility
/// is to:
///   * Issue `PAGER_DETACH(mo_id)` so the kernel drops its
///     attached-MO link and increments `cancel_epoch` (idempotent
///     against an already-detached MO).
///   * Delete the stable cspace slot holding vfs's mo_cap copy
///     and return the alloc-pool slot.
///   * Mark the binding inactive so future
///     `lookup_binding_by_mo_id` / `lookup_binding_by_vnode`
///     callers skip it.
///
/// Does not invalidate in-flight `Resume::Pager` ops — those are
/// drained by the cancel-epoch cascade plus the
/// `cancel_op_handle` Pager arm separately. Idempotent on an
/// already-released binding.
pub(crate) unsafe fn release_mo_binding(state: &mut VfsState, binding_idx: u32) {
    let (pager_cap, mo_id, mo_cap) = {
        let Some(binding) = state.pager_bindings.get_mut(binding_idx) else {
            return;
        };
        if !binding.active {
            return;
        }
        let pager_cap = state.pager_cap.as_raw();
        let mo_id = binding.mo_id;
        // Disarm the field before any invoke so the eventual Drop on the
        // arena slot entry is a no-op regardless of what happens below.
        let mo_cap = core::mem::replace(&mut binding.mo_cap, OwnedCap::null());
        binding.active = false;
        binding.mo_id = 0;
        (pager_cap, mo_id, mo_cap)
    };
    if pager_cap != 0 && mo_id != 0 {
        let _ = trona_kernel::syscall::invoke(
            pager_cap,
            uapi::KERNITE_INV_PAGER_DETACH as u64,
            mo_id,
            0,
            0,
            0,
        );
    }
    // Drop fires delete_and_free exactly once; null guard is
    // already in OwnedCap::drop so a null mo_cap is a no-op.
    drop(mo_cap);
}

/// Walk the binding table and release every binding whose vnode
/// matches. Used by the vnode-evict path so a recycled vnode
/// arena slot does not carry a stale MO pointing at the previous
/// incarnation. Linear scan — bound by the live mmap working
/// set, which mirrors `MoBinding`'s install pattern.
pub(crate) unsafe fn release_mo_binding_for_vnode(
    state: &mut VfsState,
    vnode: crate::core::vnode::VnodeHandle,
) {
    let n = state.pager_bindings.len();
    for i in 0..n {
        let matches = if let Some(b) = state.pager_bindings.get(i) {
            b.active && b.vnode == vnode
        } else {
            false
        };
        if matches {
            unsafe { release_mo_binding(state, i) };
        }
    }
}

/// Owner-reactor entry for `EVENT_TYPE_PAGER_REQUEST`. The
/// dispatcher already validated `record.cookie == state.pager_cookie`.
///
/// Flow:
/// 1. Resolve `mo_id` → vnode binding; reject past-EOF faults with SIGBUS.
/// 2. Run the vop chain `data.read` against the binding. A sync backend
///    (ramfs/tmpfs) fills vfs's `pager_read_buf` and returns `Ready`; an
///    async backend (saltyfs) returns `Parked` and lands its bytes in the
///    mount SHM ring, completed in the saltyfs completion router.
/// 3. Sync `Ready` → `PAGER_SUPPLY_COPY(read_buf, bytes_read)`: the kernel
///    sources the page from the global PMM, copies the bytes in, and
///    commits it into the MO. vfs donates no frame.
/// 4. Async `Parked` → stamp `Resume::Pager`; the completion router fires
///    `PAGER_SUPPLY_COPY` / `PAGER_FAIL` once the backend reply lands.
/// 5. Any error surfaces SIGBUS via `PAGER_FAIL`.
pub(crate) unsafe fn handle_pager_request_event(
    state: &mut VfsState,
    record: &uapi::kernite_event_record,
) -> i32 {
    let mo_id = record.object_id;
    let page_idx = record.payload0;
    let _length = record.payload1;
    let _access_flags = record.state_set;
    let _trace_id = record.payload2;

    let pager_cap = state.pager_cap.as_raw();
    if pager_cap == 0 {
        return 0;
    }

    let binding = match lookup_binding_by_mo_id(state, mo_id) {
        Some(b) => b,
        None => {
            return unsafe { invoke_pager_fail(pager_cap, mo_id, page_idx, TRONA_NOT_FOUND) };
        }
    };

    // POSIX-style EOF / past-end-of-file check. `binding.length` is
    // the page-aligned cached file size at mmap time; any fault
    // whose page sits at or beyond that boundary surfaces SIGBUS via
    // a tombstone (`PAGER_FAIL` → kernel installs
    // `PHYS_TAG_PAGER_FAILED` → faulter retry → existing
    // user-exception delivery). Partial pages (file_size between
    // page boundaries) fall through; the saltyfs read returns
    // `bytes_read < PAGE_BYTES` and the frame's zero-init covers
    // the trailing bytes per POSIX `mmap(2)` semantics.
    let page_byte_offset = page_idx.saturating_mul(uapi::KERNITE_PAGE_BYTES as u64);
    if page_byte_offset >= binding.length {
        return unsafe {
            invoke_pager_fail(
                pager_cap,
                mo_id,
                page_idx,
                uapi::KERNITE_ERR_OUT_OF_RANGE as u64,
            )
        };
    }

    let vnode = binding.vnode;
    let file_offset = binding
        .file_offset
        .saturating_add(page_idx.saturating_mul(uapi::KERNITE_PAGE_BYTES as u64));
    let length = uapi::KERNITE_PAGE_BYTES as u32;

    // vfs-owned read buffer. The sync backend fills it in place; the async
    // backend ignores it (its bytes land in the mount SHM ring) and the
    // completion router supplies from there. A single buffer is safe: a sync
    // request is serviced to completion before the next event is dequeued,
    // and async requests never touch it.
    let read_buf_va = state.pager_read_buf.as_mut_ptr() as u64;

    // SAFETY: pager events are handled on the VFS owner thread; `vnode` came
    // from the active pager binding table.
    let ctx_owner = match unsafe { OwnerVopCtx::from_state(state, vnode) } {
        Some(c) => c,
        None => {
            return unsafe { invoke_pager_fail(pager_cap, mo_id, page_idx, TRONA_NOT_FOUND) };
        }
    };
    // SAFETY: `ctx_owner.vnode` is the live vnode pointer captured above.
    let ops = unsafe { (*ctx_owner.vnode).ops };
    if ops.is_null() {
        return unsafe { invoke_pager_fail(pager_cap, mo_id, page_idx, TRONA_INVALID_OPERATION) };
    }
    // SAFETY: same live vnode context; `data_ctx` borrows the vnode-private
    // data for this single VOP call.
    let vkey = unsafe { (*ctx_owner.vnode).key };
    let data_ctx = unsafe { ctx_owner.data_ctx() };
    let outcome = unsafe {
        ((*ops).data.read)(
            &data_ctx,
            file_offset,
            read_buf_va as *mut u8,
            length as u64,
        )
    };

    let pending_handle = match outcome {
        Ok(Ready(bytes_read)) => {
            // Sync backend (ramfs / tmpfs) filled `pager_read_buf` in place.
            // Hand the bytes to the kernel, which sources the page from the
            // global PMM and commits it into the MO.
            let rc = unsafe {
                invoke_pager_supply_copy(pager_cap, mo_id, page_idx, read_buf_va, bytes_read)
            };
            if rc == 0 {
                record_supplied_page_clean(state, vnode, file_offset);
            }
            return rc;
        }
        Ok(Parked(h)) => h,
        Err(_) => {
            return unsafe { invoke_pager_fail(pager_cap, mo_id, page_idx, TRONA_IO_ERROR) };
        }
    };

    if let Some(op) = state.pending_ops.get_mut(pending_handle) {
        op.core.kind = OpKind::Pager;
        op.core.vnode_key = vkey;
    }
    let pager_resume = PagerResume {
        op_type: PAGERRESUME_OP_READ,
        vnode,
        vkey,
        page_offset: file_offset,
        length,
        mo_id,
        page_idx,
        writeback_epoch: 0,
        mmsrv_writeback_token: 0,
    };
    if let Err(_lease) =
        state.stamp_resume_ctx(pending_handle, 0, None, Resume::Pager(pager_resume))
    {
        unsafe {
            crate::owner::pending::cancel_op_handle(state, pending_handle, CancelDisposition::Drop);
            return invoke_pager_fail(pager_cap, mo_id, page_idx, TRONA_INVALID_OPERATION);
        }
    }
    0
}
