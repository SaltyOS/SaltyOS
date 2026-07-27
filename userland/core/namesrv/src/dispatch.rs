// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-label handlers. Each handler runs synchronously inside the
//! reactor: it inspects the inbound `MpRecord`, mutates internal state,
//! and writes the reply via `reply-marked MP_WRITE` on the master MessagePipe.
//!
//! `MpRecord` arrives via `MP_READ`. Sender-attached caps land in
//! `CAP_RECV_SCRATCH_SLOT..`; the reply endpoint is the master MP recv
//! endpoint that produced the record.

use core::sync::atomic::{AtomicU64, Ordering};
use trona_kernel::invoke;
use trona_server::MpReplyTarget;
use trona_server::event_loop::{CookieTable, decode_cookie};

use crate::authz::{BadgeClass, BadgeFields};
use crate::entry::pack_entry_id;
use crate::eviction;
use crate::main_loop::{NAMESRV_KIND_REGISTERED_CAP, NamesrvTarget};
use crate::owner::OwnerTable;
use crate::policy::{GrantErr, PublisherPolicy};
use crate::registry::{MAX_NAMES, NameRegistry};
use crate::segment_alloc::NamesrvSegmentAllocator;
use crate::slots::{CAP_SELF_CSPACE, cap_recv_scratch, registered_cap_base};
use crate::subs::{KIND_LOOKUP, KIND_LOOKUP_TIMEOUT, KIND_SUBSCRIBE, PendingSubs};
use crate::watch::WatchSlab;
use crate::wire::{
    LABEL_GRANT_PUBLISHER, LABEL_LIST, LABEL_LIST_BY_PREFIX, LABEL_LOOKUP, LABEL_LOOKUP_NONBLOCK,
    LABEL_LOOKUP_TIMEOUT, LABEL_OWNER_EXITED, LABEL_REGISTER, LABEL_SUBSCRIBE,
    LABEL_SUBSCRIBE_REGISTER, LABEL_UNREGISTER, LABEL_UNSUBSCRIBE, MAX_NAME_BYTES, NAME_PACK_BASE,
    REPLY_REGS_ENTRY_ID, REPLY_REGS_FLAGS, SUBSCRIBE_COOKIE_TAIL_OFFSET,
};

use uapi::{
    KERNITE_ERR_ALREADY_EXISTS, KERNITE_ERR_INSUFFICIENT_RESOURCES,
    KERNITE_ERR_INSUFFICIENT_RIGHTS, KERNITE_ERR_INVALID_ARGUMENT, KERNITE_ERR_INVALID_CAPABILITY,
    KERNITE_ERR_NOT_FOUND, KERNITE_ERR_OUT_OF_MEMORY, KERNITE_ERR_OUT_OF_RANGE,
    KERNITE_ERR_TIMED_OUT, KERNITE_STATE_PEER_CLOSED, kernite_ipc_buffer,
};

const TRONA_OK: u64 = 0;
static CURRENT_REPLY_MP: AtomicU64 = AtomicU64::new(0);
static CURRENT_REPLY_TXID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn set_current_reply_target(buf: *const kernite_ipc_buffer, slot: u64) {
    let target = unsafe { MpReplyTarget::from_ipc_buffer(buf, slot) };
    CURRENT_REPLY_MP.store(target.mp_slot, Ordering::Relaxed);
    CURRENT_REPLY_TXID.store(target.txid, Ordering::Relaxed);
}

/// Current request's reply MessagePipe endpoint.
pub(crate) fn reply_mp_slot(buf: *mut kernite_ipc_buffer) -> u64 {
    let _ = buf;
    CURRENT_REPLY_MP.load(Ordering::Relaxed)
}

fn reply_target_for_slot(mp_slot: u64) -> MpReplyTarget {
    MpReplyTarget::new(mp_slot, CURRENT_REPLY_TXID.load(Ordering::Relaxed))
}

/// First sender-attached cap slot. If the inbound call did not carry
/// a payload cap, returning the first scratch slot is still safe:
/// cleanup paths may delete an empty slot.
fn payload_cap_slot(buf: *mut kernite_ipc_buffer) -> u64 {
    if buf.is_null() {
        return cap_recv_scratch();
    }
    let _ = unsafe { trona_kernel::ipc_buffer::read_received_cap_count(buf) };
    cap_recv_scratch()
}

/// Read packed name bytes from `regs[NAME_PACK_BASE..]`. Returns
/// `(byte_buf, byte_len)`. `byte_len > MAX_NAME_BYTES` is silently
/// clamped — caller validates min length separately.
unsafe fn read_packed_name(regs: &[u64; 32]) -> ([u8; MAX_NAME_BYTES], usize) {
    let raw_len = regs[NAME_PACK_BASE - 1] as usize;
    let len = raw_len.min(MAX_NAME_BYTES);
    let mut out = [0u8; MAX_NAME_BYTES];
    let mut written = 0;
    let mut word_idx = NAME_PACK_BASE;
    while written < len && word_idx < 32 {
        let word = regs[word_idx];
        let bytes = word.to_le_bytes();
        for &b in bytes.iter() {
            if written == len {
                break;
            }
            out[written] = b;
            written += 1;
        }
        word_idx += 1;
    }
    (out, written)
}

fn send_reply_to_target(
    buf: *mut kernite_ipc_buffer,
    target: MpReplyTarget,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) -> i32 {
    if buf.is_null() {
        return KERNITE_ERR_INVALID_ARGUMENT as i32;
    }
    unsafe { trona_server::mp_write_reply_to(buf, target, label, regs, cap_count) }
}

/// Reply on `mp_slot` with the supplied payload.
pub(crate) fn send_reply(
    buf: *mut kernite_ipc_buffer,
    mp_slot: u64,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) {
    if buf.is_null() {
        return;
    }
    let target = reply_target_for_slot(mp_slot);
    let _ = send_reply_to_target(buf, target, label, regs, cap_count);
}

fn send_reply_if_requested(
    buf: *mut kernite_ipc_buffer,
    mp_slot: u64,
    label: u64,
    regs: &[u64],
    cap_count: u64,
) {
    let target = reply_target_for_slot(mp_slot);
    if target.has_txid() {
        let _ = send_reply_to_target(buf, target, label, regs, cap_count);
    }
}

fn entry_reply_regs(entry_id: u64, flags: u64) -> [u64; 2] {
    let mut regs = [0u64; 2];
    regs[REPLY_REGS_ENTRY_ID] = entry_id;
    regs[REPLY_REGS_FLAGS] = flags;
    regs
}

/// Handle REGISTER. Caps: [publisher_cap_at_scratch].
pub fn handle_register(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    registry: &mut NameRegistry,
    owners: &mut OwnerTable,
    policy: &PublisherPolicy,
    watches: &mut WatchSlab,
    cookie_table: &mut CookieTable<NamesrvTarget>,
    segment_allocator: &mut NamesrvSegmentAllocator,
    master_eq: u64,
    unit_mgr_subscriber: u64,
) {
    if badge.class != BadgeClass::Publisher {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    }
    let (name, len) = unsafe { read_packed_name(regs) };
    let name = &name[..len];
    if name.is_empty() {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INVALID_ARGUMENT as u64,
            &[],
            0,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    }
    if !policy.allows(badge.policy_id, name) {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    }
    if registry.find_idx(name).is_some() {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_ALREADY_EXISTS as u64,
            &[],
            0,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    }
    let Some(slot_idx) = registry.alloc_slot() else {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RESOURCES as u64,
            &[],
            0,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    };
    let cap_dest = registered_cap_base() + slot_idx as u64;
    // Move the publisher's cap from the first receive scratch slot to its
    // permanent home in the registered_cap zone.
    let move_err = invoke::cnode_move(
        CAP_SELF_CSPACE,
        cap_dest,
        CAP_SELF_CSPACE,
        payload_cap_slot(buf),
    );
    if move_err != 0 {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INVALID_CAPABILITY as u64,
            &[],
            0,
        );
        return;
    }
    // Caller may opt into per-caller badged mint-on-LOOKUP by setting
    // `ENTRY_FLAG_BADGE_AS_CALLER` in the optional flags register.
    let caller_flags =
        (regs[crate::wire::REGISTER_FLAGS_REG] as u32) & crate::wire::ENTRY_FLAG_BADGE_AS_CALLER;
    registry.install(
        slot_idx,
        name,
        cap_dest,
        badge.client_id,
        badge.policy_id,
        caller_flags,
    );
    if !owners.register(badge.client_id, slot_idx as u8) {
        // Owner table full / per-owner cap. Roll back the install.
        registry.vacate(slot_idx);
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, cap_dest);
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RESOURCES as u64,
            &[],
            0,
        );
        return;
    }
    // Arm STATE_PEER_CLOSED watch on the registered cap. The
    // cookie is registered in the reactor's `CookieTable` first
    // so the dispatcher can route the published EventRecord back
    // to `eviction::evict_one`. `mp_recv = 0` marks the entry as
    // a close-without-read source — the reactor skips `MP_READ`
    // and routes the fire straight into `dispatch_state` on the
    // way to eviction. Best-effort: a slab-saturated or
    // cookie-table-saturated REGISTER is still accepted, and
    // eviction falls back to `OWNER_EXITED` on init's
    // notification.
    if let Some((watch_idx, watch_slot)) = watches.alloc() {
        let arm_result = unsafe {
            cookie_table.arm(
                segment_allocator,
                NAMESRV_KIND_REGISTERED_CAP,
                0,
                watch_slot,
                NamesrvTarget::RegisteredCap {
                    idx: slot_idx as u32,
                },
            )
        };
        match arm_result {
            Ok(cookie) => {
                let _ = invoke::watch_register(
                    trona_runtime::core::slot_alloc::resolved_cap_ref(watch_slot),
                    trona_runtime::core::slot_alloc::resolved_cap_ref(cap_dest),
                    trona_runtime::core::slot_alloc::resolved_cap_ref(master_eq),
                    KERNITE_STATE_PEER_CLOSED as u64,
                    cookie,
                );
                let (_, cookie_slot, _) = decode_cookie(cookie);
                let entry = registry.entry_mut(slot_idx);
                entry.watch_idx = watch_idx;
                entry.cookie_slot = cookie_slot;
            }
            Err(_) => {
                // Cookie-table allocation failed — release the
                // WatchSlab slot so it stays available for the
                // next REGISTER attempt.
                watches.free(watch_idx);
            }
        }
    }
    let entry_id = pack_entry_id(registry.entry(slot_idx).generation, slot_idx as u32);
    let regs = entry_reply_regs(entry_id, 0);
    send_reply(buf, reply_mp_slot(buf), TRONA_OK, &regs, 0);
    // Notify unit_mgr (if subscribed) that a new prefix is published.
    push_register_event(unit_mgr_subscriber, name);
}

/// Best-effort fan-out to unit_mgr's subscribe channel. namesrv writes
/// `NAMESRV_REGISTER_EVENT` (label-only) onto the subscriber MP after a
/// publisher's REGISTER succeeds. Used by init's unit_mgr to wake
/// services whose `Requires=` blocked on the new prefix.
fn push_register_event(subscriber_slot: u64, name: &[u8]) {
    if subscriber_slot == 0 {
        return;
    }
    let mut msg = trona_kernel::core_types::TronaMsg::zeroed();
    msg.label = crate::wire::LABEL_REGISTER_EVENT;
    msg.regs[0] = name.len() as u64;
    let mut word = [0u8; 8];
    let mut packed_words = 0usize;
    for (i, chunk) in name.chunks(8).enumerate() {
        if 1 + i >= 32 {
            break;
        }
        word[..chunk.len()].copy_from_slice(chunk);
        // Zero-fill the high bytes of the partial word.
        for b in word.iter_mut().skip(chunk.len()) {
            *b = 0;
        }
        msg.regs[1 + i] = u64::from_le_bytes(word);
        packed_words = i + 1;
    }
    msg.length = (1 + packed_words) as u64;
    let ipc_ctx = trona_posix::tls::current_ipc_ctx();
    let err = unsafe { trona_kernel::ipc::mp_write_ctx(ipc_ctx, subscriber_slot, &raw const msg) };
    if err != 0 {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[NAMESRV] register event write failed name=");
            _lb.bytes(name);
            _lb.str(b" err=");
            _lb.dec(err as u64);
            _lb.putc(b'\n');
        });
    }
}

/// Admin call: install the unit_mgr subscriber MP. Caller transfers a
/// MessagePipe send-side via caps[0]; namesrv stores the slot and
/// pushes `NAMESRV_REGISTER_EVENT` on every subsequent REGISTER
/// success. Idempotent only on first call — re-binding requires the
/// supervisor to delete the existing slot first.
pub fn handle_subscribe_register(
    buf: *mut kernite_ipc_buffer,
    badge: BadgeFields,
    target_slot: &mut u64,
) {
    if badge.class != BadgeClass::Admin {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        return;
    }
    if *target_slot != 0 {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_ALREADY_EXISTS as u64,
            &[],
            0,
        );
        return;
    }
    // Move the subscriber MP send out of the receive-scratch slot
    // (which is overwritten by every subsequent inbound REGISTER) into
    // a dedicated long-lived slot. cnode_move auto-empties the source.
    let stable =
        trona_runtime::core::slot_alloc::slot_alloc_or_idle(b"namesrv unit_mgr subscriber");
    if stable == 0 {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_OUT_OF_MEMORY as u64,
            &[],
            0,
        );
        return;
    }
    let rc = invoke::cnode_move(
        CAP_SELF_CSPACE,
        stable,
        CAP_SELF_CSPACE,
        payload_cap_slot(buf),
    );
    if rc != 0 {
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        send_reply(buf, reply_mp_slot(buf), rc as u64, &[], 0);
        return;
    }
    *target_slot = stable;
    send_reply(buf, reply_mp_slot(buf), TRONA_OK, &[], 0);
}

pub fn handle_unregister(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    registry: &mut NameRegistry,
    owners: &mut OwnerTable,
    watches: &mut WatchSlab,
    cookie_table: &mut CookieTable<NamesrvTarget>,
) {
    if badge.class != BadgeClass::Publisher {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        return;
    }
    let entry_id = regs[0];
    let (entry_epoch, idx) = crate::entry::unpack_entry_id(entry_id);
    if (idx as usize) >= MAX_NAMES {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_NOT_FOUND as u64,
            &[],
            0,
        );
        return;
    }
    let entry = registry.entry(idx as usize);
    if entry.active == 0 || entry.generation != entry_epoch {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_NOT_FOUND as u64,
            &[],
            0,
        );
        return;
    }
    if entry.owner_tcb != badge.client_id {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        return;
    }
    eviction::evict_one(registry, owners, watches, cookie_table, idx as usize);
    send_reply(buf, reply_mp_slot(buf), TRONA_OK, &[], 0);
}

/// LOOKUP variants share the resolve path; the blocking behaviour
/// differs in what to do on miss. `caller_client_id` is the lower 32
/// bits of the caller's badge — used as the per-caller badge when the
/// entry was registered with `ENTRY_FLAG_BADGE_AS_CALLER`.
fn lookup_resolve(
    buf: *mut kernite_ipc_buffer,
    name: &[u8],
    registry: &NameRegistry,
    caller_client_id: u32,
) -> bool {
    let Some(idx) = registry.find_idx(name) else {
        return false;
    };
    let entry = registry.entry(idx);
    let entry_id = pack_entry_id(entry.generation, idx as u32);
    let cap_slot = entry.cap_slot;
    let badge_as_caller = (entry.flags & crate::wire::ENTRY_FLAG_BADGE_AS_CALLER) != 0;

    if !badge_as_caller {
        // Direct copy of the registered cap onto the caller's receive
        // slot via `caps[0] = cap_slot` + reply-marked MP_WRITE. Kernel
        // `capture_caps_into_carriers` copies from our cap_slot into
        // the caller's receive slot atomically with the reply.
        unsafe {
            (*buf).caps[0] = cap_slot;
        }
        let result =
            consume_entry_reply_with_cap(buf, reply_target_for_slot(reply_mp_slot(buf)), entry_id);
        if result.primary_error != 0 && result.fallback_error != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[NAMESRV] lookup cap reply fallback failed primary=");
                _lb.dec(result.primary_error as u64);
                _lb.str(b" fallback=");
                _lb.dec(result.fallback_error as u64);
                _lb.putc(b'\n');
            });
        }
        return true;
    }

    // Mint-via-temp: borrow a transient slot, mint a per-caller
    // badged copy into it, hand the temp through the reply path,
    // then free the slot index. The kernel moves the temp out of
    // namesrv's CNode during the reply, so namesrv's persistent
    // CSpace footprint stays unchanged.
    let temp = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"namesrv lookup mint temp");
    let mint_err = invoke::cnode_mint(
        CAP_SELF_CSPACE,
        cap_slot,
        CAP_SELF_CSPACE,
        temp.addr(),
        caller_client_id as u64,
    );
    if mint_err != 0 {
        // mint failed: `temp` (OwnedSlot, empty) Drop frees the slot.
        send_reply(
            buf,
            reply_mp_slot(buf),
            uapi::KERNITE_ERR_INVALID_CAPABILITY as u64,
            &[],
            0,
        );
        return true;
    }
    // The minted cap now occupies the slot; adopt it as an OwnedCap. Its Drop
    // handles every exit: a successful reply moves the cap out (delete
    // no-ops on the emptied slot) + frees it; a reply failure deletes the
    // rolled-back cap + frees it.
    let temp = temp.assume_filled();
    unsafe {
        (*buf).caps[0] = temp.as_raw();
    }
    let result =
        consume_entry_reply_with_cap(buf, reply_target_for_slot(reply_mp_slot(buf)), entry_id);
    if result.primary_error != 0 && result.fallback_error != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[NAMESRV] minted cap reply fallback failed primary=");
            _lb.dec(result.primary_error as u64);
            _lb.str(b" fallback=");
            _lb.dec(result.fallback_error as u64);
            _lb.putc(b'\n');
        });
    }
    // `temp` (OwnedCap) drops here, releasing the slot exactly once.
    true
}

fn consume_entry_reply_with_cap(
    buf: *mut kernite_ipc_buffer,
    target: MpReplyTarget,
    entry_id: u64,
) -> trona_server::ReplyConsumeResult {
    let regs = entry_reply_regs(entry_id, 0);
    unsafe { trona_server::mp_write_reply_to_with_error_fallback(buf, target, TRONA_OK, &regs, 1) }
}

pub fn handle_lookup_nonblock(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    registry: &NameRegistry,
) {
    let (name, len) = unsafe { read_packed_name(regs) };
    let name = &name[..len];
    if name.is_empty() {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INVALID_ARGUMENT as u64,
            &[],
            0,
        );
        return;
    }
    if !lookup_resolve(buf, name, registry, badge.client_id) {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_NOT_FOUND as u64,
            &[],
            0,
        );
    }
}

pub fn handle_lookup_blocking(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    kind: u8,
    deadline_ns: u64,
    registry: &NameRegistry,
    pending: &mut PendingSubs,
) {
    let (name, len) = unsafe { read_packed_name(regs) };
    let name = &name[..len];
    if name.is_empty() {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INVALID_ARGUMENT as u64,
            &[],
            0,
        );
        return;
    }
    if lookup_resolve(buf, name, registry, badge.client_id) {
        return;
    }
    // Park the reply endpoint slot and MP_CALL txid; do not move or
    // delete the service MessagePipe cap. The eventual resolver will
    // answer with `reply-marked MP_WRITE` on this same endpoint.
    let reply_mp = reply_mp_slot(buf);
    let reply_target = reply_target_for_slot(reply_mp);
    if reply_mp == 0 || !reply_target.has_txid() {
        send_reply(buf, reply_mp, KERNITE_ERR_INVALID_CAPABILITY as u64, &[], 0);
        return;
    }
    if pending
        .push(name, kind, reply_target, deadline_ns, badge.client_id, 0)
        .is_none()
    {
        send_reply(
            buf,
            reply_mp,
            KERNITE_ERR_INSUFFICIENT_RESOURCES as u64,
            &[],
            0,
        );
    }
    // No reply yet — the caller stays blocked until eventual REGISTER
    // or Timer-driven timeout reaches `wakeup::resolve_pending`.
}

pub fn handle_subscribe(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    pending: &mut PendingSubs,
) {
    let (name, len) = unsafe { read_packed_name(regs) };
    let name = &name[..len];
    if name.is_empty() {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INVALID_ARGUMENT as u64,
            &[],
            0,
        );
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    }
    let reply_mp = reply_mp_slot(buf);
    let reply_target = reply_target_for_slot(reply_mp);
    if reply_mp == 0 || !reply_target.has_txid() {
        send_reply(buf, reply_mp, KERNITE_ERR_INVALID_CAPABILITY as u64, &[], 0);
        let _ = invoke::cnode_delete(CAP_SELF_CSPACE, payload_cap_slot(buf));
        return;
    };
    let cookie_words = len.div_ceil(8);
    let cookie_reg = NAME_PACK_BASE + cookie_words + SUBSCRIBE_COOKIE_TAIL_OFFSET;
    if cookie_reg >= regs.len() {
        send_reply(buf, reply_mp, KERNITE_ERR_INVALID_ARGUMENT as u64, &[], 0);
        return;
    }
    let cookie = regs[cookie_reg];
    if pending
        .push(
            name,
            KIND_SUBSCRIBE,
            reply_target,
            0,
            badge.client_id,
            cookie,
        )
        .is_none()
    {
        send_reply(
            buf,
            reply_mp,
            KERNITE_ERR_INSUFFICIENT_RESOURCES as u64,
            &[],
            0,
        );
    }
}

pub fn handle_unsubscribe(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    pending: &mut PendingSubs,
) {
    let sub_id = regs[0] as usize;
    let entry = pending.entry(sub_id);
    if entry.active == 0 {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_NOT_FOUND as u64,
            &[],
            0,
        );
        return;
    }
    pending.vacate(sub_id);
    send_reply(buf, reply_mp_slot(buf), TRONA_OK, &[], 0);
}

pub fn handle_owner_exited(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    registry: &mut NameRegistry,
    owners: &mut OwnerTable,
    watches: &mut WatchSlab,
    cookie_table: &mut CookieTable<NamesrvTarget>,
) {
    if badge.class != BadgeClass::Admin {
        send_reply_if_requested(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        return;
    }
    let tcb_id = regs[0] as u32;
    let n = eviction::evict_for_owner(registry, owners, watches, cookie_table, tcb_id);
    send_reply_if_requested(buf, reply_mp_slot(buf), TRONA_OK, &[n as u64], 0);
}

pub fn handle_grant_publisher(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    badge: BadgeFields,
    policy: &mut PublisherPolicy,
) {
    if badge.class != BadgeClass::Admin {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        return;
    }
    let prefix_len = regs[0] as usize;
    let policy_id = regs[1] as u32;
    let mut prefix_buf = [0u8; crate::wire::MAX_PREFIX_BYTES];
    let take = prefix_len.min(crate::wire::MAX_PREFIX_BYTES);
    let mut written = 0;
    let mut word_idx = 2usize;
    while written < take && word_idx < 32 {
        let word = regs[word_idx];
        let bytes = word.to_le_bytes();
        for &b in bytes.iter() {
            if written == take {
                break;
            }
            prefix_buf[written] = b;
            written += 1;
        }
        word_idx += 1;
    }
    let label = match policy.grant(policy_id, &prefix_buf[..take]) {
        Ok(()) => TRONA_OK,
        Err(GrantErr::Full) => KERNITE_ERR_INSUFFICIENT_RESOURCES as u64,
        Err(GrantErr::PrefixTooLong) => KERNITE_ERR_OUT_OF_RANGE as u64,
        Err(GrantErr::Duplicate) => KERNITE_ERR_ALREADY_EXISTS as u64,
    };
    send_reply(buf, reply_mp_slot(buf), label, &[], 0);
}

/// Resolve any PendingSubs whose name matches a freshly-registered
/// entry. Called from REGISTER's success path right after `install` /
/// `owners.register` / Watch arm complete. Mirrors
/// `lookup_resolve`'s `BADGE_AS_CALLER` branch — each parked caller's
/// stored `subscriber_tcb` is the lower-32-bit `client_id` used to
/// mint per-caller badged copies when the publisher requested it.
pub fn resolve_pending_after_register(
    buf: *mut kernite_ipc_buffer,
    name: &[u8],
    entry_idx: usize,
    registry: &NameRegistry,
    pending: &mut PendingSubs,
) {
    use crate::subs::PENDING_SUBS_RING;
    let entry = registry.entry(entry_idx);
    let cap_slot = entry.cap_slot;
    let entry_id = pack_entry_id(entry.generation, entry_idx as u32);
    let badge_as_caller = (entry.flags & crate::wire::ENTRY_FLAG_BADGE_AS_CALLER) != 0;

    for sub_idx in 0..PENDING_SUBS_RING {
        let psub = pending.entry(sub_idx);
        if psub.active == 0 || psub.name_bytes() != name {
            continue;
        }
        let reply_target = psub.reply_target;
        let caller_client_id = psub.subscriber_tcb;

        if !badge_as_caller {
            unsafe {
                (*buf).caps[0] = cap_slot;
            }
            let result = consume_entry_reply_with_cap(buf, reply_target, entry_id);
            if result.primary_error != 0 && result.fallback_error != 0 {
                trona_runtime::uerror!(|_lb| {
                    _lb.str(b"[NAMESRV] parked lookup cap reply fallback failed primary=");
                    _lb.dec(result.primary_error as u64);
                    _lb.str(b" fallback=");
                    _lb.dec(result.fallback_error as u64);
                    _lb.putc(b'\n');
                });
            }
            pending.vacate(sub_idx);
            continue;
        }

        // Mint-via-temp: borrow a transient slot, mint a per-caller
        // badged copy, hand it through the parked reply endpoint,
        // then free the slot index. Matches the immediate-hit code
        // path in `lookup_resolve`.
        let temp = trona_runtime::core::slot_alloc::alloc_slot_or_idle(b"namesrv parked mint temp");
        let mint_err = invoke::cnode_mint(
            CAP_SELF_CSPACE,
            cap_slot,
            CAP_SELF_CSPACE,
            temp.addr(),
            caller_client_id as u64,
        );
        if mint_err != 0 {
            // mint failed: `temp` (OwnedSlot, empty) Drop frees the slot.
            let _ = send_reply_to_target(
                buf,
                reply_target,
                uapi::KERNITE_ERR_INVALID_CAPABILITY as u64,
                &[],
                0,
            );
            pending.vacate(sub_idx);
            continue;
        }
        // The minted cap now occupies the slot; adopt it as an OwnedCap whose
        // Drop releases it on every exit (reply move + no-op delete, or the
        // rolled-back cap deleted).
        let temp = temp.assume_filled();
        unsafe {
            (*buf).caps[0] = temp.as_raw();
        }
        let result = consume_entry_reply_with_cap(buf, reply_target, entry_id);
        if result.primary_error != 0 && result.fallback_error != 0 {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[NAMESRV] parked minted cap reply fallback failed primary=");
                _lb.dec(result.primary_error as u64);
                _lb.str(b" fallback=");
                _lb.dec(result.fallback_error as u64);
                _lb.putc(b'\n');
            });
        }
        // `temp` (OwnedCap) drops here, releasing the slot exactly once.
        pending.vacate(sub_idx);
    }
}

/// Drain any LOOKUP_TIMEOUT entries whose deadline has elapsed.
pub fn fire_timed_outs(buf: *mut kernite_ipc_buffer, now_ns: u64, pending: &mut PendingSubs) {
    use crate::subs::PENDING_SUBS_RING;
    for sub_idx in 0..PENDING_SUBS_RING {
        let entry = pending.entry(sub_idx);
        if entry.active == 0 || entry.kind != KIND_LOOKUP_TIMEOUT || entry.deadline_ns > now_ns {
            continue;
        }
        let reply_target = entry.reply_target;
        let _ = send_reply_to_target(buf, reply_target, KERNITE_ERR_TIMED_OUT as u64, &[], 0);
        pending.vacate(sub_idx);
    }
}

pub fn handle_list(buf: *mut kernite_ipc_buffer, regs: &[u64; 32], registry: &NameRegistry) {
    let offset = regs[0] as usize;
    let max = (regs[1] as usize).min(64);
    let mut count = 0;
    let mut written_bytes = 0;
    let buf_capacity = 467 * 8;
    for (idx, entry) in registry.iter_active().skip(offset) {
        if count >= max {
            break;
        }
        let need = 1 + entry.name_len as usize;
        if written_bytes + need > buf_capacity {
            break;
        }
        unsafe {
            let dst = &mut (*buf).reserved[written_bytes / 8] as *mut u64 as *mut u8;
            *dst.add(written_bytes % 8) = entry.name_len;
            for (i, b) in entry.name_bytes().iter().enumerate() {
                *dst.add((written_bytes % 8) + 1 + i) = *b;
            }
        }
        written_bytes += need;
        count += 1;
        let _ = idx;
    }
    send_reply(buf, reply_mp_slot(buf), TRONA_OK, &[count as u64], 0);
}

pub fn handle_list_by_prefix(
    buf: *mut kernite_ipc_buffer,
    regs: &[u64; 32],
    registry: &NameRegistry,
) {
    let prefix_len = regs[0] as usize;
    let mut prefix = [0u8; crate::wire::MAX_PREFIX_BYTES];
    let take = prefix_len.min(crate::wire::MAX_PREFIX_BYTES);
    let mut written = 0;
    let mut word_idx = 1usize;
    while written < take && word_idx < 32 {
        let word = regs[word_idx];
        let bytes = word.to_le_bytes();
        for &b in bytes.iter() {
            if written == take {
                break;
            }
            prefix[written] = b;
            written += 1;
        }
        word_idx += 1;
    }
    let prefix = &prefix[..take];
    let offset = regs[word_idx] as usize;
    let max = (regs[word_idx + 1] as usize).min(64);
    let mut count = 0;
    for (idx, entry) in registry.iter_active() {
        if !entry.name_bytes().starts_with(prefix) {
            continue;
        }
        if count < offset {
            count += 1;
            continue;
        }
        if count - offset >= max {
            break;
        }
        let _ = idx;
        count += 1;
    }
    send_reply(buf, reply_mp_slot(buf), TRONA_OK, &[count as u64], 0);
}

/// Top-level dispatch. Returns `true` when the inbound record was
/// recognised (regardless of whether the handler succeeded or set an
/// error reply).
pub fn dispatch(
    buf: *mut kernite_ipc_buffer,
    label: u64,
    regs: &[u64; 32],
    raw_badge: u64,
    state: &mut crate::main_loop::ServerState,
) -> bool {
    let Some(badge) = BadgeFields::parse(raw_badge) else {
        send_reply(
            buf,
            reply_mp_slot(buf),
            KERNITE_ERR_INSUFFICIENT_RIGHTS as u64,
            &[],
            0,
        );
        return true;
    };
    match label {
        LABEL_REGISTER => {
            handle_register(
                buf,
                regs,
                badge,
                &mut state.registry,
                &mut state.owners,
                &state.policy,
                &mut state.watches,
                &mut state.cookie_table,
                &mut state.segment_allocator,
                state.startup.master_eq,
                state.startup.unit_mgr_subscriber,
            );
            // After REGISTER success, walk pending subs that match.
            let (name, len) = unsafe { read_packed_name(regs) };
            let name_slice = &name[..len];
            if let Some(idx) = state.registry.find_idx(name_slice) {
                resolve_pending_after_register(
                    buf,
                    name_slice,
                    idx,
                    &state.registry,
                    &mut state.pending,
                );
            }
        }
        LABEL_UNREGISTER => handle_unregister(
            buf,
            regs,
            badge,
            &mut state.registry,
            &mut state.owners,
            &mut state.watches,
            &mut state.cookie_table,
        ),
        LABEL_LOOKUP => handle_lookup_blocking(
            buf,
            regs,
            badge,
            KIND_LOOKUP,
            0,
            &state.registry,
            &mut state.pending,
        ),
        LABEL_LOOKUP_NONBLOCK => handle_lookup_nonblock(buf, regs, badge, &state.registry),
        LABEL_LOOKUP_TIMEOUT => {
            let timeout_ns = regs[NAME_PACK_BASE + 7];
            handle_lookup_blocking(
                buf,
                regs,
                badge,
                KIND_LOOKUP_TIMEOUT,
                timeout_ns,
                &state.registry,
                &mut state.pending,
            );
        }
        LABEL_SUBSCRIBE => handle_subscribe(buf, regs, badge, &mut state.pending),
        LABEL_UNSUBSCRIBE => handle_unsubscribe(buf, regs, &mut state.pending),
        LABEL_LIST => handle_list(buf, regs, &state.registry),
        LABEL_LIST_BY_PREFIX => handle_list_by_prefix(buf, regs, &state.registry),
        LABEL_GRANT_PUBLISHER => handle_grant_publisher(buf, regs, badge, &mut state.policy),
        LABEL_OWNER_EXITED => handle_owner_exited(
            buf,
            regs,
            badge,
            &mut state.registry,
            &mut state.owners,
            &mut state.watches,
            &mut state.cookie_table,
        ),
        LABEL_SUBSCRIBE_REGISTER => {
            handle_subscribe_register(buf, badge, &mut state.startup.unit_mgr_subscriber)
        }
        _ => return false,
    }
    true
}
