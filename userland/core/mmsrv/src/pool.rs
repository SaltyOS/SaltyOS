//! VSpace COW frame pool management.
//!
//! Phase 2: Pre-allocates physical frames into a lock-free SPSC ring that
//! the kernel consumes during COW fast-path. A notification ring records
//! which pool entries were used, allowing mmsrv to update tracking and
//! replenish the pool.

use crate::client::{clear_cow_bit, find_region_by_addr};
use crate::types::MmClient;
use salty::consts::*;
use salty::invoke;
use salty::serial::LineBuf;
use salty::types::Cap;

const POOL_ENTRY_COUNT: usize = 510;
const POOL_INITIAL_FILL: usize = 64;

/// CowNotifEntry layout matching kernel-side struct.
/// Virtual address >> 12, pool index, padding.
#[repr(C)]
#[derive(Clone, Copy)]
struct CowNotifEntry {
    vaddr_page: u32,
    pool_idx: u16,
    _pad: u16,
}

/// Pool state tracked per-VSpace by mmsrv.
pub(crate) struct VSpacePool {
    /// VSpace cap this pool is associated with
    pub(crate) vspace_cap: Cap,
    /// Frame cap for the CowPool shared page
    pub(crate) pool_frame: Cap,
    /// Frame cap for the CowNotifRing shared page
    pub(crate) ring_frame: Cap,
    /// Notification cap for signaling from kernel
    pub(crate) notif_cap: Cap,
    /// mmsrv-mapped pointer to the CowPool page
    pub(crate) pool_page: *mut u8,
    /// mmsrv-mapped pointer to the CowNotifRing page
    pub(crate) ring_page: *mut u8,
    /// Per-pool-slot cap tracking: pool_slot_caps[idx % 510] holds the Frame
    /// cap for the pool entry at that ring index. Used by drain_notifications
    /// to transfer ownership to region.frame_caps and by teardown to clean up.
    pub(crate) pool_slot_caps: *mut Cap,
    /// Number of entries currently in the pool
    pub(crate) fill_count: u16,
    /// Whether this pool is active
    pub(crate) active: bool,
}

impl VSpacePool {
    pub(crate) const fn zeroed() -> Self {
        VSpacePool {
            vspace_cap: 0,
            pool_frame: 0,
            ring_frame: 0,
            notif_cap: 0,
            pool_page: core::ptr::null_mut(),
            ring_page: core::ptr::null_mut(),
            pool_slot_caps: core::ptr::null_mut(),
            fill_count: 0,
            active: false,
        }
    }
}

/// Maximum number of VSpace pools mmsrv can track.
const MAX_POOLS: usize = 32;

/// Global pool table.
static mut POOLS: [VSpacePool; MAX_POOLS] = {
    const P: VSpacePool = VSpacePool::zeroed();
    [P; MAX_POOLS]
};

/// Map a VSpace cap to its pool slot (by linear search).
pub(crate) unsafe fn find_pool_by_vspace(vspace_cap: Cap) -> *mut VSpacePool {
    unsafe {
        let pools = &raw mut POOLS;
        for i in 0..MAX_POOLS {
            if (*pools)[i].active && (*pools)[i].vspace_cap == vspace_cap {
                return &raw mut (*pools)[i];
            }
        }
        core::ptr::null_mut()
    }
}

/// Find an available pool slot.
unsafe fn find_free_pool() -> *mut VSpacePool {
    unsafe {
        let pools = &raw mut POOLS;
        for i in 0..MAX_POOLS {
            if !(*pools)[i].active {
                return &raw mut (*pools)[i];
            }
        }
        core::ptr::null_mut()
    }
}

/// Initialize a COW frame pool for a client's VSpace.
///
/// 1. Retypes 2 Frame caps (pool page + ring page)
/// 2. Maps both into mmsrv's own VSpace
/// 3. Retypes POOL_INITIAL_FILL Frame caps for pool entries
/// 4. Calls vspace_set_cow_pool and vspace_set_cow_notif
///
/// Returns true on success.
pub(crate) unsafe fn init_pool(client: *mut MmClient) -> bool {
    unsafe {
        // Deduplicate: if a pool already exists for this VSpace (e.g. refork),
        // reuse it. The existing pool entries are free frames, not bound to
        // specific COW pages, so the normal drain/replenish cycle handles any
        // stale state.
        let existing = find_pool_by_vspace((*client).vspace_cap);
        if !existing.is_null() && (*existing).active {
            return true;
        }

        let pool_slot = find_free_pool();
        if pool_slot.is_null() {
            super::puts(b"[MMSRV] pool: no free pool slots\n");
            return false;
        }

        // Allocate pool page frame
        let pool_frame = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => return false,
        };
        if super::retype_any(OBJ_FRAME, 0, pool_frame) != 0 {
            return false;
        }

        // Allocate ring page frame
        let ring_frame = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
                return false;
            }
        };
        if super::retype_any(OBJ_FRAME, 0, ring_frame) != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            return false;
        }

        // Use the shared aggregation notification (bound to mmsrv's TCB).
        // All pools share one notification — consumed by bound-notification
        // wakeup in the server loop.
        let notif_cap = super::cow_agg_ntfn();
        if notif_cap == 0 {
            super::puts(b"[MMSRV] pool: no aggregation notification\n");
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            return false;
        }

        // Map the pool Frame cap into mmsrv's own VSpace.
        // Must map the SAME physical frame the kernel will use, not a fresh one.
        let pool_page = super::self_map_frame(pool_frame);
        if pool_page.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            return false;
        }

        // Map the ring Frame cap into mmsrv's own VSpace.
        let ring_page = super::self_map_frame(ring_frame);
        if ring_page.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            return false;
        }

        // Allocate pool_slot_caps tracking array (1 page = 512 u64 entries >= 510)
        let slot_caps_page = super::self_mmap(1);
        if slot_caps_page.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            return false;
        }
        let pool_slot_caps = slot_caps_page as *mut Cap;

        // Allocate a temporary CNode to hold the initial frame caps.
        // We need a CNode with at least POOL_INITIAL_FILL slots.
        // CNode size_bits=7 gives 128 slots (>= 64).
        let temp_cnode = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
                invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
                return false;
            }
        };
        if super::retype_any(OBJ_CNODE, 7, temp_cnode) != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            return false;
        }

        // Retype POOL_INITIAL_FILL frame caps and copy them into the temp CNode.
        // Use cnode_copy so originals stay in mmsrv's CSpace (refcount=2).
        // When the temp CNode is deleted, only the copies are dropped (refcount→1).
        let mut filled: usize = 0;
        for i in 0..POOL_INITIAL_FILL {
            let slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };
            if super::retype_any(OBJ_FRAME, 0, slot) != 0 {
                break;
            }
            // Copy the frame cap into the temp CNode at slot i
            let err = invoke::cnode_copy(
                super::CAP_SELF_CSPACE, slot,
                temp_cnode, i as u64,
                0,
            );
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
                break;
            }
            // Track in pool_slot_caps by ring index
            *pool_slot_caps.add(i) = slot;
            filled += 1;
        }

        if filled == 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
            return false;
        }

        let vspace_cap = (*client).vspace_cap;

        // Tell kernel about the notification ring FIRST. If this succeeds but
        // pool setup fails below, the kernel has cow_notif_phys set but
        // cow_pool_phys==0 — the fast-path's first check returns Ok(false),
        // so the ring is never used. Harmless, and overwritten on next init.
        let err = invoke::vspace_set_cow_notif(vspace_cap, ring_frame, notif_cap);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] pool: set_cow_notif failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            for i in 0..filled {
                invoke::cnode_delete(temp_cnode, i as u64);
            }
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
            return false;
        }

        // Tell kernel about the pool (notif already set)
        let err = invoke::vspace_set_cow_pool(vspace_cap, pool_frame, temp_cnode, filled as u64);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] pool: set_cow_pool failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            for i in 0..filled {
                invoke::cnode_delete(temp_cnode, i as u64);
            }
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
            return false;
        }

        // Record pool state
        (*pool_slot).vspace_cap = vspace_cap;
        (*pool_slot).pool_frame = pool_frame;
        (*pool_slot).ring_frame = ring_frame;
        (*pool_slot).notif_cap = 0; // shared notification — pool does not own it
        (*pool_slot).pool_page = pool_page;
        (*pool_slot).ring_page = ring_page;
        (*pool_slot).pool_slot_caps = pool_slot_caps;
        (*pool_slot).fill_count = filled as u16;
        (*pool_slot).active = true;

        // Delete temp CNode. The kernel read phys_addrs from the copies;
        // destroying the CNode drops the copies (refcount→1), originals
        // in mmsrv's CSpace stay valid.
        invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);

        {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] pool: initialized for vspace_cap=");
            lb.hex(vspace_cap);
            lb.str(b" fill=");
            lb.hex(filled as u64);
            lb.str(b"\n");
            lb.flush();
        }

        true
    }
}

/// Drain notification ring entries for a given client.
/// Reads consumed-pool-entry records from the ring page, clears COW bits
/// in the corresponding client regions, transfers Frame caps from
/// pool_slot_caps to region.frame_caps.
///
/// Returns `(drained_count, completed)`:
/// - `drained_count`: number of entries successfully processed.
/// - `completed`: `true` if all pending entries were consumed (head == tail),
///   `false` if the loop broke early (e.g. OOM growing frame_caps).
///   Callers should suppress replenish on partial drain to avoid overwriting
///   preserved caps for entries that will be retried.
pub(crate) unsafe fn drain_notifications(client: *mut MmClient, pool: *mut VSpacePool) -> (usize, bool) {
    unsafe {
        if !(*pool).active || (*pool).ring_page.is_null() {
            return (0, true);
        }

        // The ring page has the CowNotifRing layout:
        //   head: u32 (kernel writes, mmsrv reads)
        //   tail: u32 (mmsrv writes, kernel reads)
        //   entries: [CowNotifEntry; 510]
        let ring_base = (*pool).ring_page;
        let head_ptr = ring_base as *const u32;
        let tail_ptr = ring_base.add(4) as *mut u32;
        let entries_base = ring_base.add(8) as *const CowNotifEntry;

        // SAFETY: ring_page points to a valid mapped page with CowNotifRing layout.
        let head = core::ptr::read_volatile(head_ptr);
        let tail = core::ptr::read_volatile(tail_ptr);

        if head == tail {
            return (0, true);
        }

        let mut drained: usize = 0;
        let mut current_tail = tail;
        while current_tail != head {
            let ring_idx = (current_tail % POOL_ENTRY_COUNT as u32) as usize;
            // SAFETY: ring_idx < POOL_ENTRY_COUNT, entries_base is valid.
            let entry = core::ptr::read_volatile(entries_base.add(ring_idx));

            let vaddr = (entry.vaddr_page as u64) << 12;

            // Find the region containing this vaddr and clear its COW bit
            let region = find_region_by_addr(client, vaddr);
            if region.is_null() {
                // Region gone (munmap/deregister) — delete orphaned pool cap
                let pool_idx = entry.pool_idx as usize;
                let slot_idx = pool_idx % POOL_ENTRY_COUNT;
                if !(*pool).pool_slot_caps.is_null() {
                    let cap = *(*pool).pool_slot_caps.add(slot_idx);
                    if cap != 0 {
                        invoke::cnode_delete(super::CAP_SELF_CSPACE, cap);
                        *(*pool).pool_slot_caps.add(slot_idx) = 0;
                    }
                }
                current_tail = current_tail.wrapping_add(1);
                drained += 1;
                continue;
            }

            let page_idx = ((vaddr - (*region).base) / 4096) as usize;
            clear_cow_bit(region, page_idx);

            // Transfer the pool's Frame cap to region.frame_caps so that
            // munmap/deregister can clean up pool-resolved pages.
            let pool_idx = entry.pool_idx as usize;
            let slot_idx = pool_idx % POOL_ENTRY_COUNT;
            if !(*pool).pool_slot_caps.is_null() {
                let cap = *(*pool).pool_slot_caps.add(slot_idx);
                if cap != 0 {
                    // Grow frame_caps if needed
                    if page_idx >= (*region).frame_cap_capacity as usize {
                        let old_cap = (*region).frame_cap_capacity as usize;
                        let required = page_idx + 1;
                        let growth = if old_cap < 128 {
                            if old_cap == 0 { 8 } else { old_cap }
                        } else if old_cap < 1024 {
                            old_cap / 2
                        } else {
                            256
                        };
                        let new_cap = core::cmp::max(required, old_cap + growth);
                        let new_fcaps = super::grow_frame_cap_array(
                            (*region).frame_caps,
                            old_cap,
                            new_cap,
                        );
                        if !new_fcaps.is_null() {
                            (*region).frame_caps = new_fcaps;
                            (*region).frame_cap_capacity = new_cap as u16;
                        } else {
                            // Growth failed — stop draining. Cap stays in pool_slot_caps;
                            // tail is not advanced past this entry, so next drain retries.
                            break;
                        }
                    }

                    if page_idx < (*region).frame_cap_capacity as usize
                        && !(*region).frame_caps.is_null()
                    {
                        let old = *(*region).frame_caps.add(page_idx);
                        if old != 0 {
                            invoke::cnode_delete(super::CAP_SELF_CSPACE, old);
                        }
                        *(*region).frame_caps.add(page_idx) = cap;
                        *(*pool).pool_slot_caps.add(slot_idx) = 0;

                        // Update frame_count high water mark
                        let needed = (page_idx + 1) as u16;
                        if needed > (*region).frame_count {
                            (*region).frame_count = needed;
                        }
                    }
                }
            }

            current_tail = current_tail.wrapping_add(1);
            drained += 1;
        }

        // Update tail to mark entries as consumed
        // SAFETY: tail_ptr is valid and mmsrv is the sole writer of tail.
        core::ptr::write_volatile(tail_ptr, current_tail);

        let completed = current_tail == head;
        (drained, completed)
    }
}

/// Replenish consumed pool entries with freshly retyped frames.
/// Allocates new frames and calls VSPACE_REPLENISH_COW_POOL.
pub(crate) unsafe fn replenish_pool(client: *mut MmClient, pool: *mut VSpacePool) {
    unsafe {
        if !(*pool).active || (*pool).pool_page.is_null() {
            return;
        }

        // Read current pool head/tail to figure out how many entries are free.
        // head and tail are monotonic u16 values (mod 2^16), not bounded to
        // 0..510. Use wrapping subtraction for correct occupancy.
        let pool_base = (*pool).pool_page;
        let head_ptr = pool_base as *const u16;
        let tail_ptr = pool_base.add(2) as *const u16;

        // SAFETY: pool_page points to a valid mapped page with CowPool layout.
        let head_raw = core::ptr::read_volatile(head_ptr);
        let tail_raw = core::ptr::read_volatile(tail_ptr);

        let used = tail_raw.wrapping_sub(head_raw) as usize;
        if used >= POOL_ENTRY_COUNT {
            return;
        }
        let free = POOL_ENTRY_COUNT - used - 1; // -1 to avoid head==tail ambiguity

        if free == 0 {
            return;
        }

        // Replenish up to POOL_INITIAL_FILL entries at a time
        let replenish_count = core::cmp::min(free, POOL_INITIAL_FILL);

        // Allocate a temp CNode for the new frames (size_bits=7 -> 128 slots)
        let temp_cnode = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => return,
        };
        if super::retype_any(OBJ_CNODE, 7, temp_cnode) != 0 {
            return;
        }

        let mut filled: usize = 0;
        for i in 0..replenish_count {
            let slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };
            if super::retype_any(OBJ_FRAME, 0, slot) != 0 {
                break;
            }
            // Copy into temp CNode; original stays in mmsrv's CSpace.
            let err = invoke::cnode_copy(
                super::CAP_SELF_CSPACE, slot,
                temp_cnode, i as u64,
                0,
            );
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
                break;
            }
            // Track in pool_slot_caps at the ring index this entry will occupy.
            // The kernel appends at current tail, so entry i lands at (tail + i) % 510.
            if !(*pool).pool_slot_caps.is_null() {
                let ring_idx = (tail_raw.wrapping_add(i as u16) as usize) % POOL_ENTRY_COUNT;
                let existing = *(*pool).pool_slot_caps.add(ring_idx);
                if existing != 0 {
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, existing);
                }
                *(*pool).pool_slot_caps.add(ring_idx) = slot;
            }
            filled += 1;
        }

        if filled > 0 {
            let vspace_cap = (*client).vspace_cap;
            let err = invoke::vspace_replenish_cow_pool(vspace_cap, temp_cnode, 0, filled as u64);
            if err != 0 {
                let mut lb = LineBuf::new();
                lb.str(b"[MMSRV] pool: replenish failed err=");
                lb.hex(err as u64);
                lb.str(b"\n");
                lb.flush();
                // Clean up originals in mmsrv's CSpace on failure
                for i in 0..filled {
                    if !(*pool).pool_slot_caps.is_null() {
                        let ring_idx = (tail_raw.wrapping_add(i as u16) as usize) % POOL_ENTRY_COUNT;
                        let cap = *(*pool).pool_slot_caps.add(ring_idx);
                        if cap != 0 {
                            invoke::cnode_delete(super::CAP_SELF_CSPACE, cap);
                            *(*pool).pool_slot_caps.add(ring_idx) = 0;
                        }
                    }
                }
                // Clean up temp CNode contents
                for i in 0..filled {
                    invoke::cnode_delete(temp_cnode, i as u64);
                }
            }
        }

        // Delete temp CNode (drops copies, originals stay at refcount=1)
        invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
    }
}

/// Tear down a VSpace pool, cleaning up all associated capabilities.
/// Called from handle_mm_deregister before deleting the client's VSpace cap.
pub(crate) unsafe fn teardown_pool(vspace_cap: Cap) {
    unsafe {
        let pool = find_pool_by_vspace(vspace_cap);
        if pool.is_null() || !(*pool).active {
            return;
        }

        // Delete unconsumed pool entry Frame caps
        if !(*pool).pool_slot_caps.is_null() {
            for i in 0..POOL_ENTRY_COUNT {
                let cap = *(*pool).pool_slot_caps.add(i);
                if cap != 0 {
                    invoke::cnode_delete(super::CAP_SELF_CSPACE, cap);
                }
            }
        }

        // Delete pool infrastructure caps
        if (*pool).pool_frame != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, (*pool).pool_frame);
        }
        if (*pool).ring_frame != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, (*pool).ring_frame);
        }
        if (*pool).notif_cap != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, (*pool).notif_cap);
        }

        *pool = VSpacePool::zeroed();
    }
}
