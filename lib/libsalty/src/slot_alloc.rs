//! Per-process dynamic capability slot allocator
//!
//! Provides a bump allocator over a chained array of CNode slot segments.
//! The initial segment is assigned by procmgr/init at spawn time. When all
//! segments are exhausted, an async expansion protocol requests more slots
//! from the process manager via NBSend + Call.
//!
//! Untyped expansion uses a Signal-based async protocol: the child signals
//! a bound notification on the procmgr, which places untypeds at deterministic
//! CNode slots (UT_EXPAND_BASE + N). The child probes those slots to detect
//! completion — the probe retype doubles as both completion check and frame
//! creation.
//!
//! The pool base and count are communicated via auxv entries
//! `AT_SALTY_SLOT_BASE` and `AT_SALTY_SLOT_COUNT`.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::consts::*;
use crate::invoke;
use crate::ipc;
use crate::serial;
use crate::syscall::syscall;
use crate::types::Cap;

const SLOT_EXPAND_BITS_DEFAULT: u64 = 10;
const MAX_SEGMENTS: usize = 16;
const MAX_EXTRA_UT: usize = MAX_UT_EXPANSIONS;
const MIRRORED_UT_SCAN_LIMIT: usize = 200;
const MIRRORED_UT_BITMAP_BITS: usize = MIRRORED_UT_SCAN_LIMIT - CAP_UNTYPED_START as usize;
const MIRRORED_UT_BITMAP_WORDS: usize = (MIRRORED_UT_BITMAP_BITS + 63) / 64;

/// A contiguous range of CNode slots available for allocation.
#[derive(Clone, Copy)]
struct Segment {
    base: Cap,
    count: u64,
    next: u64,
}

/// Result of an async slot allocation attempt.
#[derive(Clone, Copy, PartialEq)]
pub enum SlotResult {
    /// Successfully allocated a slot.
    Ok(Cap),
    /// Expansion in progress; caller should yield and retry.
    WouldBlock,
    /// All segments exhausted and expansion failed permanently.
    Exhausted,
}

/// State machine for the CSpace expansion protocol.
#[derive(Clone, Copy, PartialEq)]
enum ExpandState {
    /// No expansion in progress.
    Idle,
    /// Signal sent to procmgr; probing for sub-CNode at deterministic slot.
    Requested,
    /// Expansion permanently failed (segment table full or max expansions).
    Failed,
}

/// Internal state for the per-process slot allocator.
struct SlotAllocState {
    segments: [Segment; MAX_SEGMENTS],
    seg_count: usize,
    active_seg: usize,
    initialized: bool,
    /// Procmgr EP for CSpace expansion (always CAP_PROCMGR_EP).
    procmgr_ep: Cap,
    /// Bound notification cap for UT expansion signaling.
    expand_ntfn: Cap,
    /// Notification cap for CSpace expansion signaling.
    cspace_ntfn: Cap,
    expand_state: ExpandState,
    /// Root CNode size_bits (queried from cnode_get_info).
    root_bits: u8,
    /// Total CNode depth after expansion (root_bits + sub_bits), 0 if not expanded.
    expanded_depth: u8,
    /// Number of completed CSpace expansions (probed sub-CNodes).
    cspace_expand_count: usize,
}

static mut SLOT_ALLOC: SlotAllocState = SlotAllocState {
    segments: [Segment { base: 0, count: 0, next: 0 }; MAX_SEGMENTS],
    seg_count: 0,
    active_seg: 0,
    initialized: false,
    procmgr_ep: 0,
    expand_ntfn: 0,
    cspace_ntfn: 0,
    expand_state: ExpandState::Idle,
    root_bits: 0,
    expanded_depth: 0,
    cspace_expand_count: 0,
};

// Dynamic untyped expansion state (Signal-based)
static mut UT_EXPAND_REQUESTED: bool = false;
static mut EXTRA_UT_SLOTS: [Cap; MAX_EXTRA_UT] = [0; MAX_EXTRA_UT];
static mut EXTRA_UT_COUNT: usize = 0;
static mut PENDING_FRAME_SLOT: Cap = 0;
static mut MIRRORED_UT_HINT: Cap = CAP_UNTYPED_START;
static mut EXTRA_UT_HINT: usize = 0;
static mut UNTYPED_SCAN_END_CACHE: Cap = 0;
static mut MIRRORED_UT_SKIP_BITMAP: [u64; MIRRORED_UT_BITMAP_WORDS] = [0; MIRRORED_UT_BITMAP_WORDS];
static mut EXTRA_UT_SKIP_MASK: u16 = 0;

/// Initialize the per-process slot allocator.
///
/// Called during process startup (from CRT or RTLD) with values from auxv.
/// `base==0` means "not provided".
/// `expand_ep` is the notification cap for UT expansion signaling
/// (from AT_SALTY_EXPAND_EP auxv), or 0 if not available.
/// `cspace_ntfn` is the notification cap for CSpace expansion signaling
/// (from AT_SALTY_CSPACE_NTFN auxv), or 0 if not available.
///
/// # Safety
/// Must be called exactly once during process initialization.
pub unsafe fn slot_alloc_init(base: Cap, count: u64, expand_ep: u64, cspace_ntfn: u64) {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        state.segments[0] = Segment { base, count, next: 0 };
        state.seg_count = 1;
        state.active_seg = 0;
        state.initialized = base != 0;
        state.procmgr_ep = CAP_PROCMGR_EP;
        state.expand_ntfn = expand_ep;
        state.cspace_ntfn = cspace_ntfn;
        state.expand_state = ExpandState::Idle;
        state.root_bits = 0;
        state.expanded_depth = 0;
        state.cspace_expand_count = 0;
        *(&raw mut UT_EXPAND_REQUESTED) = false;
        *(&raw mut EXTRA_UT_SLOTS) = [0; MAX_EXTRA_UT];
        *(&raw mut EXTRA_UT_COUNT) = 0;
        *(&raw mut PENDING_FRAME_SLOT) = 0;
        *(&raw mut MIRRORED_UT_HINT) = CAP_UNTYPED_START;
        *(&raw mut EXTRA_UT_HINT) = 0;
        *(&raw mut UNTYPED_SCAN_END_CACHE) = 0;
        *(&raw mut MIRRORED_UT_SKIP_BITMAP) = [0; MIRRORED_UT_BITMAP_WORDS];
        *(&raw mut EXTRA_UT_SKIP_MASK) = 0;
    }
}

/// Check whether the slot allocator has been initialized.
pub fn slot_alloc_is_initialized() -> bool {
    unsafe { (*(&raw const SLOT_ALLOC)).initialized }
}

/// Return the pool base slot (first segment).
pub fn slot_alloc_base() -> Cap {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if state.seg_count > 0 { state.segments[0].base } else { 0 }
    }
}

/// Return the total pool size across all segments.
pub fn slot_alloc_count() -> u64 {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        let mut total: u64 = 0;
        for i in 0..state.seg_count {
            total += state.segments[i].count;
        }
        total
    }
}

/// Return the number of slots remaining across all segments.
pub fn slot_alloc_remaining() -> u64 {
    unsafe {
        let state = &*(&raw const SLOT_ALLOC);
        if !state.initialized {
            return 0;
        }
        let mut remaining: u64 = 0;
        for i in state.active_seg..state.seg_count {
            remaining += state.segments[i].count.saturating_sub(state.segments[i].next);
        }
        remaining
    }
}

/// Override the procmgr EP used for expansion (escape hatch).
pub fn slot_alloc_set_procmgr_ep(ep: Cap) {
    unsafe {
        (*(&raw mut SLOT_ALLOC)).procmgr_ep = ep;
    }
}

/// Async slot allocation with self-healing NBSend expansion protocol.
///
/// Returns `SlotResult::Ok(cap)` on success, `WouldBlock` if expansion is
/// in progress (caller should yield and retry), or `Exhausted` if expansion
/// failed permanently.
pub fn slot_alloc_async() -> SlotResult {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return SlotResult::Exhausted;
        }

        // Fast path: scan segment chain for an available slot
        while state.active_seg < state.seg_count {
            let seg = &mut state.segments[state.active_seg];
            if seg.next < seg.count {
                let slot = seg.base + seg.next;
                seg.next += 1;
                return SlotResult::Ok(slot);
            }
            state.active_seg += 1;
        }

        // All segments exhausted — enter CSpace expansion protocol.
        // Uses Signal+probe: signal the procmgr's bound notification, then
        // probe the deterministic root CNode slot to detect when the sub-CNode
        // has been placed there by the procmgr.
        let ntfn = state.cspace_ntfn;

        match state.expand_state {
            ExpandState::Idle => {
                if ntfn == 0 || state.cspace_expand_count >= MAX_CSPACE_EXPANSIONS {
                    // No cspace ntfn or max expansions reached — fall back to
                    // blocking expansion via procmgr EP if available.
                    return try_blocking_cspace_expand(state);
                }
                // Ensure root_bits is known for depth-aware probing
                ensure_root_bits(state);

                // Signal procmgr's bound notification for CSpace expansion
                syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                state.expand_state = ExpandState::Requested;
                SlotResult::WouldBlock
            }
            ExpandState::Requested => {
                // Probe: try copying a known cap into the first slot of the
                // expected sub-CNode. If the sub-CNode exists, the copy
                // succeeds. We then delete the probe cap and register the
                // new segment.
                let probe_root_slot = CSPACE_EXPAND_BASE + state.cspace_expand_count as u64;
                let expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
                let probe_addr = probe_root_slot << SLOT_EXPAND_BITS_DEFAULT;

                let err = invoke::cnode_copy_depth(
                    CAP_SELF_CSPACE, CAP_SELF_TCB,
                    CAP_SELF_CSPACE, probe_addr,
                    CAP_RIGHTS_ALL,
                    0, expanded_depth,
                );
                if err == 0 {
                    // Sub-CNode exists — clean up probe cap
                    invoke::cnode_delete_depth(
                        CAP_SELF_CSPACE, probe_addr, expanded_depth,
                    );

                    let base = probe_addr;
                    let count = 1u64 << SLOT_EXPAND_BITS_DEFAULT;

                    if state.seg_count >= MAX_SEGMENTS {
                        state.expand_state = ExpandState::Failed;
                        return SlotResult::Exhausted;
                    }

                    let si = state.seg_count;
                    state.segments[si] = Segment { base, count, next: 0 };
                    state.seg_count += 1;
                    state.active_seg = si;
                    state.cspace_expand_count += 1;
                    state.expand_state = ExpandState::Idle;
                    *(&raw mut UNTYPED_SCAN_END_CACHE) = 0;

                    if state.root_bits > 0 {
                        state.expanded_depth = expanded_depth;
                    }

                    {
                        let mut lb = serial::LineBuf::new();
                        lb.str(b"[SLOT] cspace-expand: probed base=");
                        lb.hex(base);
                        lb.str(b" count=");
                        lb.hex(count);
                        lb.str(b" (seg ");
                        lb.hex(si as u64);
                        lb.str(b")\n");
                        lb.flush();
                    }

                    // Allocate from the new segment
                    let seg = &mut state.segments[si];
                    let slot = seg.base + seg.next;
                    seg.next += 1;
                    SlotResult::Ok(slot)
                } else {
                    // Not ready yet — re-signal (idempotent: OR same badge bit)
                    syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                    SlotResult::WouldBlock
                }
            }
            ExpandState::Failed => {
                SlotResult::Exhausted
            }
        }
    }
}

/// Allocate a single CNode slot from the pool (synchronous path).
///
/// Returns the absolute CNode slot index, or `None` if the pool is exhausted
/// or a blocking CSpace expansion request fails.
pub fn slot_alloc() -> Option<Cap> {
    unsafe {
        let state = &mut *(&raw mut SLOT_ALLOC);
        if !state.initialized {
            return None;
        }

        // Fast path: allocate from existing segments.
        while state.active_seg < state.seg_count {
            let seg = &mut state.segments[state.active_seg];
            if seg.next < seg.count {
                let slot = seg.base + seg.next;
                seg.next += 1;
                return Some(slot);
            }
            state.active_seg += 1;
        }

        // Slow path: perform a blocking CSpace expansion request.
        let ep = if state.procmgr_ep != 0 {
            state.procmgr_ep
        } else {
            CAP_PROCMGR_EP
        };
        let (base, count) = request_expand_blocking(ep)?;
        if state.seg_count >= MAX_SEGMENTS {
            state.expand_state = ExpandState::Failed;
            return None;
        }

        let si = state.seg_count;
        state.segments[si] = Segment {
            base,
            count,
            next: 0,
        };
        state.seg_count += 1;
        state.active_seg = si;
        state.expand_state = ExpandState::Idle;
        *(&raw mut UNTYPED_SCAN_END_CACHE) = 0;
        update_expansion_depth(state);

        {
            let mut lb = serial::LineBuf::new();
            lb.str(b"[SLOT] expand(sync): base=");
            lb.hex(base);
            lb.str(b" count=");
            lb.hex(count);
            lb.str(b" (seg ");
            lb.hex(si as u64);
            lb.str(b")\n");
            lb.flush();
        }

        let seg = &mut state.segments[si];
        if seg.next >= seg.count {
            return None;
        }
        let slot = seg.base + seg.next;
        seg.next += 1;
        Some(slot)
    }
}

/// Allocate a single CNode slot and retype a frame into it from any
/// available untyped capability.
///
/// This is the most common operation: allocate a slot and create a frame.
/// Tries the dedicated untyped (slot 7) first, then scans mirrored untypeds.
///
/// Returns the frame's CNode slot on success, or `None` on failure.
pub fn slot_alloc_frame() -> Option<Cap> {
    let slot = slot_alloc()?;
    let err = try_retype_frame(slot);
    if err == 0 {
        Some(slot)
    } else {
        None
    }
}

/// Allocate a frame slot and map it at the given virtual address.
///
/// Convenience wrapper: alloc slot -> retype frame -> vspace_map.
/// Returns the frame slot on success.
pub fn slot_alloc_frame_map(vspace: Cap, vaddr: u64, flags: u64) -> Option<Cap> {
    let slot = slot_alloc_frame()?;
    let err = invoke::vspace_map(vspace, slot, vaddr, flags);
    if err != 0 {
        return None;
    }
    Some(slot)
}

/// Async version of slot_alloc_frame_map: uses slot_alloc_async internally.
///
/// Returns `SlotResult::Ok(frame_slot)` on success, `WouldBlock` if expansion
/// is in progress (CNode slot or untyped), or `Exhausted` on permanent failure.
///
/// Untyped expansion uses Signal-based async protocol: signals the procmgr's
/// bound notification, then probes deterministic expansion slots. The probe
/// retype doubles as both completion check and frame creation.
pub fn slot_alloc_frame_map_async(vspace: Cap, vaddr: u64, flags: u64) -> SlotResult {
    unsafe {
        // If we saved a frame slot from a previous WouldBlock, reuse it
        let slot = if *(&raw const PENDING_FRAME_SLOT) != 0 {
            *(&raw const PENDING_FRAME_SLOT)
        } else {
            match slot_alloc_async() {
                SlotResult::Ok(s) => s,
                other => return other,
            }
        };

        let err = try_retype_frame(slot);
        if err != 0 {
            // Retype failed — enter Signal-based untyped expansion
            let ntfn = (*(&raw const SLOT_ALLOC)).expand_ntfn;
            let count = *(&raw const EXTRA_UT_COUNT);

            if ntfn == 0 || count >= MAX_EXTRA_UT {
                *(&raw mut PENDING_FRAME_SLOT) = 0;
                return SlotResult::Exhausted;
            }

            if *(&raw const UT_EXPAND_REQUESTED) {
                // Probe the deterministic expansion slot — acts as both
                // completion check AND frame retype in one operation
                let expected = UT_EXPAND_BASE + count as u64;
                let probe = invoke::untyped_retype(expected, OBJ_FRAME, 0, slot);
                if probe == 0 {
                    // Expansion completed — register new untyped
                    (*(&raw mut EXTRA_UT_SLOTS))[count] = expected;
                    *(&raw mut EXTRA_UT_COUNT) = count + 1;
                    extra_ut_clear_skipped(count);
                    *(&raw mut UT_EXPAND_REQUESTED) = false;
                    *(&raw mut PENDING_FRAME_SLOT) = 0;

                    {
                        let mut lb = serial::LineBuf::new();
                        lb.str(b"[SLOT] ut-expand: granted slot=");
                        lb.hex(expected);
                        lb.str(b"\n");
                        lb.flush();
                    }

                    // Frame was already retyped by the probe — fall through to map
                } else {
                    // Not ready yet — re-signal (idempotent: OR same badge bit)
                    syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                    *(&raw mut PENDING_FRAME_SLOT) = slot;
                    return SlotResult::WouldBlock;
                }
            } else {
                // First request — signal procmgr's bound notification
                syscall(SYS_SIGNAL, ntfn, 0, 0, 0, 0, 0);
                *(&raw mut UT_EXPAND_REQUESTED) = true;
                *(&raw mut PENDING_FRAME_SLOT) = slot;
                return SlotResult::WouldBlock;
            }
        } else {
            *(&raw mut PENDING_FRAME_SLOT) = 0;
        }

        // Map the frame
        let err = invoke::vspace_map(vspace, slot, vaddr, flags);
        if err != 0 {
            return SlotResult::Exhausted;
        }
        SlotResult::Ok(slot)
    }
}

/// Try to retype a frame from any available untyped, scanning primary
/// untyped (slot 7), mirrored untypeds (CAP_UNTYPED_START..), then
/// dynamically-granted untypeds (EXTRA_UT_SLOTS).
fn try_retype_frame(dest_slot: Cap) -> i32 {
    // Try dedicated untyped first
    let err = invoke::untyped_retype(CAP_UNTYPED, OBJ_FRAME, 0, dest_slot);
    if err == 0 {
        return 0;
    }

    let mut last_err = err;
    let scan_end = cached_untyped_scan_end();

    // Scan mirrored untyped caps, starting from the last successful source.
    if scan_end > CAP_UNTYPED_START {
        let span = scan_end - CAP_UNTYPED_START;
        let mut ut = unsafe {
            let hint = *(&raw const MIRRORED_UT_HINT);
            if hint >= CAP_UNTYPED_START && hint < scan_end {
                hint
            } else {
                CAP_UNTYPED_START
            }
        };
        for _ in 0..span {
            let idx = (ut - CAP_UNTYPED_START) as usize;
            if !mirrored_ut_is_skipped(idx) {
                let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, dest_slot);
                if err == 0 {
                    unsafe {
                        *(&raw mut MIRRORED_UT_HINT) = next_mirrored_ut(ut, scan_end);
                    }
                    return 0;
                }
                if is_permanent_untyped_failure(err) {
                    mirrored_ut_mark_skipped(idx);
                }
                last_err = err;
            }
            ut = next_mirrored_ut(ut, scan_end);
        }
    }

    // Try dynamically-granted untypeds with a round-robin hint.
    unsafe {
        let count = *(&raw const EXTRA_UT_COUNT);
        if count != 0 {
            let mut idx = *(&raw const EXTRA_UT_HINT);
            if idx >= count {
                idx = 0;
            }
            for _ in 0..count {
                if extra_ut_is_skipped(idx) {
                    idx += 1;
                    if idx == count {
                        idx = 0;
                    }
                    continue;
                }

                let ut = (*(&raw const EXTRA_UT_SLOTS))[idx];
                if ut != 0 {
                    let err = invoke::untyped_retype(ut, OBJ_FRAME, 0, dest_slot);
                    if err == 0 {
                        *(&raw mut EXTRA_UT_HINT) = if idx + 1 < count { idx + 1 } else { 0 };
                        return 0;
                    }
                    if is_permanent_untyped_failure(err) {
                        extra_ut_mark_skipped(idx);
                    }
                    last_err = err;
                }
                idx += 1;
                if idx == count {
                    idx = 0;
                }
            }
        }
    }

    last_err
}

#[inline]
fn next_mirrored_ut(ut: Cap, scan_end: Cap) -> Cap {
    if ut + 1 < scan_end {
        ut + 1
    } else {
        CAP_UNTYPED_START
    }
}

#[inline]
fn is_permanent_untyped_failure(err: i32) -> bool {
    err == SALTY_INVALID_CAPABILITY as i32
        || err == SALTY_INVALID_OPERATION as i32
        || err == SALTY_INSUFFICIENT_RIGHTS as i32
        || err == SALTY_NOT_FOUND as i32
}

#[inline]
fn mirrored_ut_is_skipped(idx: usize) -> bool {
    let word = idx / 64;
    if word >= MIRRORED_UT_BITMAP_WORDS {
        return false;
    }
    let bit = 1u64 << (idx % 64);
    unsafe { ((*(&raw const MIRRORED_UT_SKIP_BITMAP))[word] & bit) != 0 }
}

#[inline]
fn mirrored_ut_mark_skipped(idx: usize) {
    let word = idx / 64;
    if word >= MIRRORED_UT_BITMAP_WORDS {
        return;
    }
    let bit = 1u64 << (idx % 64);
    unsafe {
        (*(&raw mut MIRRORED_UT_SKIP_BITMAP))[word] |= bit;
    }
}

#[inline]
fn extra_ut_is_skipped(idx: usize) -> bool {
    if idx >= 16 {
        return false;
    }
    let bit = 1u16 << idx;
    unsafe { (*(&raw const EXTRA_UT_SKIP_MASK) & bit) != 0 }
}

#[inline]
fn extra_ut_mark_skipped(idx: usize) {
    if idx >= 16 {
        return;
    }
    let bit = 1u16 << idx;
    unsafe {
        *(&raw mut EXTRA_UT_SKIP_MASK) |= bit;
    }
}

#[inline]
fn extra_ut_clear_skipped(idx: usize) {
    if idx >= 16 {
        return;
    }
    let bit = 1u16 << idx;
    unsafe {
        *(&raw mut EXTRA_UT_SKIP_MASK) &= !bit;
    }
}

#[inline]
fn cached_untyped_scan_end() -> Cap {
    unsafe {
        let cached = *(&raw const UNTYPED_SCAN_END_CACHE);
        if cached > CAP_UNTYPED_START {
            return cached;
        }
    }
    let end = untyped_scan_end();
    unsafe {
        *(&raw mut UNTYPED_SCAN_END_CACHE) = end;
    }
    end
}

/// Determine the upper bound for untyped cap scanning.
fn untyped_scan_end() -> Cap {
    let mut end: Cap = 200; // fallback
    let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
    if info.error == 0 {
        unsafe {
            let ctx = &raw const crate::__salty_ipc_ctx;
            if !(*ctx).ipc_buffer.is_null() {
                let num_slots = (*(*ctx).ipc_buffer).msg[3];
                if num_slots > CAP_UNTYPED_START && num_slots < end {
                    end = num_slots;
                }
            }
        }
    }
    if end <= CAP_UNTYPED_START {
        CAP_UNTYPED_START + 1
    } else {
        end
    }
}

// ===========================================================================
// CSpace expansion protocol helpers
// ===========================================================================

/// Ensure root_bits is populated (lazy query on first expansion).
fn ensure_root_bits(state: &mut SlotAllocState) {
    if state.root_bits == 0 {
        let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
        if info.error == 0 {
            unsafe {
                let ctx = &raw const crate::__salty_ipc_ctx;
                if !(*ctx).ipc_buffer.is_null() {
                    state.root_bits = (*(*ctx).ipc_buffer).msg[2] as u8;
                }
            }
        }
    }
}

/// Fallback: try a synchronous blocking CSpace expansion via procmgr EP.
/// Used when cspace_ntfn is unavailable or max async expansions are reached.
fn try_blocking_cspace_expand(state: &mut SlotAllocState) -> SlotResult {
    let ep = if state.procmgr_ep != 0 {
        state.procmgr_ep
    } else {
        CAP_PROCMGR_EP
    };
    match request_expand_blocking(ep) {
        Some((base, count)) => {
            if state.seg_count >= MAX_SEGMENTS {
                state.expand_state = ExpandState::Failed;
                return SlotResult::Exhausted;
            }
            let si = state.seg_count;
            state.segments[si] = Segment { base, count, next: 0 };
            state.seg_count += 1;
            state.active_seg = si;
            state.expand_state = ExpandState::Idle;
            unsafe { *(&raw mut UNTYPED_SCAN_END_CACHE) = 0; }
            update_expansion_depth(state);

            {
                let mut lb = serial::LineBuf::new();
                lb.str(b"[SLOT] cspace-expand(sync): base=");
                lb.hex(base);
                lb.str(b" count=");
                lb.hex(count);
                lb.str(b" (seg ");
                lb.hex(si as u64);
                lb.str(b")\n");
                lb.flush();
            }

            let seg = &mut state.segments[si];
            let slot = seg.base + seg.next;
            seg.next += 1;
            SlotResult::Ok(slot)
        }
        None => {
            state.expand_state = ExpandState::Failed;
            SlotResult::Exhausted
        }
    }
}

/// Perform blocking PM_EXPAND_CSPACE Call and return the new segment.
fn request_expand_blocking(ep: Cap) -> Option<(Cap, u64)> {
    unsafe {
        let mut msg = crate::types::SaltyMsg::zeroed();
        let mut reply = crate::types::SaltyMsg::zeroed();
        msg.label = POSIX_PM_EXPAND_CSPACE;
        msg.length = 1;
        msg.regs[0] = SLOT_EXPAND_BITS_DEFAULT;

        let err = ipc::call_ctx(
            &raw mut crate::__salty_ipc_ctx,
            ep,
            &raw const msg,
            &raw mut reply,
        );
        if err != 0 || reply.label != SALTY_OK || reply.length < 2 {
            return None;
        }

        let base = reply.regs[0];
        let count = reply.regs[1];
        if base == 0 || count == 0 {
            None
        } else {
            Some((base, count))
        }
    }
}

/// Cache the expanded CSpace depth used by depth-aware invoke helpers.
fn update_expansion_depth(state: &mut SlotAllocState) {
    if state.root_bits == 0 {
        let info = invoke::cnode_get_info(CAP_SELF_CSPACE);
        if info.error == 0 {
            unsafe {
                let ctx = &raw const crate::__salty_ipc_ctx;
                if !(*ctx).ipc_buffer.is_null() {
                    state.root_bits = (*(*ctx).ipc_buffer).msg[2] as u8;
                }
            }
        }
    }
    if state.root_bits > 0 {
        state.expanded_depth = state.root_bits + SLOT_EXPAND_BITS_DEFAULT as u8;
    }
}
