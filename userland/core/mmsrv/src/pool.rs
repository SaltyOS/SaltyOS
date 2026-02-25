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
    /// mmsrv-side tracking: pool slot -> frame cap (used for cleanup)
    pub(crate) frame_caps: [Cap; POOL_INITIAL_FILL],
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
            frame_caps: [0; POOL_INITIAL_FILL],
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

        // Allocate notification for kernel -> mmsrv signaling
        let notif_cap = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
                invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
                return false;
            }
        };
        if super::retype_any(OBJ_NOTIFICATION, 0, notif_cap) != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            return false;
        }

        // Map pool page into mmsrv's own VSpace
        let pool_page = super::self_mmap(1);
        if pool_page.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
            return false;
        }

        // Map ring page into mmsrv's own VSpace
        let ring_page = super::self_mmap(1);
        if ring_page.is_null() {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
            return false;
        }

        // Allocate a temporary CNode to hold the initial frame caps.
        // We need a CNode with at least POOL_INITIAL_FILL slots.
        // CNode size_bits=7 gives 128 slots (>= 64).
        let temp_cnode = match salty::slot_alloc::slot_alloc() {
            Some(s) => s,
            None => {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
                invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
                invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
                return false;
            }
        };
        if super::retype_any(OBJ_CNODE, 7, temp_cnode) != 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
            return false;
        }

        // Retype POOL_INITIAL_FILL frame caps into the temp CNode
        let mut filled: usize = 0;
        let mut frame_caps = [0u64; POOL_INITIAL_FILL];
        for i in 0..POOL_INITIAL_FILL {
            let slot = match salty::slot_alloc::slot_alloc() {
                Some(s) => s,
                None => break,
            };
            if super::retype_any(OBJ_FRAME, 0, slot) != 0 {
                break;
            }
            // Move the frame cap into the temp CNode at slot i
            let err = invoke::cnode_move(
                temp_cnode, i as u64,
                super::CAP_SELF_CSPACE, slot,
            );
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
                break;
            }
            frame_caps[i] = slot;
            filled += 1;
        }

        if filled == 0 {
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
            return false;
        }

        let vspace_cap = (*client).vspace_cap;

        // Tell kernel about the pool
        let err = invoke::vspace_set_cow_pool(vspace_cap, pool_frame, temp_cnode, filled as u64);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] pool: set_cow_pool failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            // Clean up temp CNode contents
            for i in 0..filled {
                invoke::cnode_delete(temp_cnode, i as u64);
            }
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
            return false;
        }

        // Tell kernel about the notification ring
        let err = invoke::vspace_set_cow_notif(vspace_cap, ring_frame, notif_cap);
        if err != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[MMSRV] pool: set_cow_notif failed err=");
            lb.hex(err as u64);
            lb.str(b"\n");
            lb.flush();
            invoke::cnode_delete(super::CAP_SELF_CSPACE, pool_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, ring_frame);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, notif_cap);
            invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
            return false;
        }

        // Record pool state
        (*pool_slot).vspace_cap = vspace_cap;
        (*pool_slot).pool_frame = pool_frame;
        (*pool_slot).ring_frame = ring_frame;
        (*pool_slot).notif_cap = notif_cap;
        (*pool_slot).pool_page = pool_page;
        (*pool_slot).ring_page = ring_page;
        (*pool_slot).frame_caps = frame_caps;
        (*pool_slot).fill_count = filled as u16;
        (*pool_slot).active = true;

        // Clean up temp CNode (caps have been consumed by the kernel)
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
/// in the corresponding client regions, and returns the number of entries drained.
pub(crate) unsafe fn drain_notifications(client: *mut MmClient, pool: *mut VSpacePool) -> usize {
    unsafe {
        if !(*pool).active || (*pool).ring_page.is_null() {
            return 0;
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
            return 0;
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
            if !region.is_null() {
                let page_idx = ((vaddr - (*region).base) / 4096) as usize;
                clear_cow_bit(region, page_idx);
            }

            current_tail = current_tail.wrapping_add(1);
            drained += 1;
        }

        // Update tail to mark entries as consumed
        // SAFETY: tail_ptr is valid and mmsrv is the sole writer of tail.
        core::ptr::write_volatile(tail_ptr, current_tail);

        drained
    }
}

/// Replenish consumed pool entries with freshly retyped frames.
/// Allocates new frames and calls VSPACE_REPLENISH_COW_POOL.
pub(crate) unsafe fn replenish_pool(client: *mut MmClient, pool: *mut VSpacePool) {
    unsafe {
        if !(*pool).active || (*pool).pool_page.is_null() {
            return;
        }

        // Read current pool head/tail to figure out how many entries are free
        let pool_base = (*pool).pool_page;
        let head_ptr = pool_base as *const u16;
        let tail_ptr = pool_base.add(2) as *const u16;

        // SAFETY: pool_page points to a valid mapped page with CowPool layout.
        let head = core::ptr::read_volatile(head_ptr) as usize;
        let tail = core::ptr::read_volatile(tail_ptr) as usize;

        // Available space in the ring
        let used = if tail >= head { tail - head } else { POOL_ENTRY_COUNT - head + tail };
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
            let err = invoke::cnode_move(temp_cnode, i as u64, super::CAP_SELF_CSPACE, slot);
            if err != 0 {
                invoke::cnode_delete(super::CAP_SELF_CSPACE, slot);
                break;
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
                // Clean up temp CNode contents on failure
                for i in 0..filled {
                    invoke::cnode_delete(temp_cnode, i as u64);
                }
            }
        }

        invoke::cnode_delete(super::CAP_SELF_CSPACE, temp_cnode);
    }
}
