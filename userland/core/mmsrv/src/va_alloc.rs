//! Virtual-address gap allocator and overlap-detection helpers.
//!
//! Every auto-placement path (`MM_MMAP`, `MM_ALLOC_PRIVATE_REGION`,
//! `MM_FILE_MMAP`, `MM_SHM_MAP`, stack alloc, prefault, initrd /
//! bootinfo copy, …) routes through `find_free_va_gap` so that a
//! client's regions + reservations + global exclusion zones are honoured
//! uniformly. Fixed mappings consult `range_overlaps_mapping` /
//! `range_overlaps_reservation` instead.
//!
//! The merged interval stream is built by dual-cursor walking the two
//! `BaseSortedIndex` instances (regions and reservations) in lockstep
//! with a static global-exclusion list. Each interval is yielded in
//! ascending base order; consecutive overlapping or touching intervals
//! are coalesced. The allocator scans the stream from `hint`, takes the
//! first gap of `len` bytes (after `align` rounding), and falls back to
//! a single wrap when the tail is exhausted.
//!
//! Linear scan is fine at per-client interval counts of <128.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use crate::client::ClientVm;
use crate::region::{RegionId, ReservationId};
use trona_server::slab::{BaseSortedIndex, SlabId};

/// One past the highest user virtual address (canonical 48-bit user
/// half); the allocator never returns a VA at or above it.
pub(crate) const USER_VA_TOP: u64 = 1u64 << 47;

/// Smallest user VA the allocator will ever return. The page below
/// this stays unmapped as a deterministic null guard.
pub(crate) const USER_MIN_VA: u64 = 0x1000;

/// Single non-empty interval in the merged stream.
#[derive(Clone, Copy)]
struct Interval {
    base: u64,
    end: u64,
}

impl Interval {
    fn from_base_len(base: u64, length: u64) -> Option<Self> {
        let end = base.checked_add(length)?;
        if end <= base {
            return None;
        }
        Some(Self { base, end })
    }
}

/// Static global exclusion intervals. Identical for every client.
fn global_exclusions() -> [Interval; 2] {
    [
        Interval {
            base: 0,
            end: USER_MIN_VA,
        },
        Interval {
            base: USER_VA_TOP,
            end: u64::MAX,
        },
    ]
}

/// Result alias: the chosen VA, or `None` if no gap fit inside
/// `search_bounds` after one wrap.
pub(crate) type GapResult = Option<u64>;

/// Find a free `[base, base + len)` interval inside `search_bounds`,
/// avoiding mappings, reservations, and global exclusions.
///
/// `align` must be a power of two and at least 4096. `hint` is a
/// preferred starting point; the scan rounds it up to `align` and walks
/// forward. On reaching `search_bounds.end` it wraps once back to
/// `search_bounds.start` and continues up to (but not past) the original
/// `hint`.
///
/// `except_reservation` lets sub-allocation inside a containing
/// reservation succeed: the named reservation is dropped from the
/// occupied-interval stream so the search can fit inside its body.
///
/// # Safety
///
/// Single-threaded server invariant.
pub(crate) unsafe fn find_free_va_gap(
    vm: &ClientVm,
    len: u64,
    align: u64,
    hint: u64,
    search_bounds: core::ops::Range<u64>,
    except_reservation: Option<ReservationId>,
) -> GapResult {
    unsafe {
        if len == 0 || align < 4096 || !align.is_power_of_two() {
            return None;
        }
        let lo = align_up(search_bounds.start.max(USER_MIN_VA), align)?;
        let hi = align_down(search_bounds.end.min(USER_VA_TOP), align);
        if hi <= lo || hi - lo < len {
            return None;
        }
        let want_start = align_up(hint.max(lo), align)?;
        let start = want_start.min(hi.saturating_sub(len));
        if let Some(found) = scan_interval(vm, len, align, start, hi, except_reservation) {
            return Some(found);
        }
        if start > lo {
            if let Some(found) = scan_interval(vm, len, align, lo, start, except_reservation) {
                return Some(found);
            }
        }
        None
    }
}

unsafe fn scan_interval(
    vm: &ClientVm,
    len: u64,
    align: u64,
    range_start: u64,
    range_end: u64,
    except_reservation: Option<ReservationId>,
) -> GapResult {
    unsafe {
        if range_end <= range_start || range_end - range_start < len {
            return None;
        }
        let mut walker = IntervalWalker::new(vm, except_reservation);
        let mut cursor = range_start;
        loop {
            // Drop intervals that end at or before the cursor.
            while let Some(iv) = walker.peek() {
                if iv.end <= cursor {
                    walker.advance();
                    continue;
                }
                break;
            }
            // Skip intervals that already overlap the cursor.
            while let Some(iv) = walker.peek() {
                if iv.base <= cursor && iv.end > cursor {
                    let aligned = align_up(iv.end, align)?;
                    if aligned >= range_end {
                        return None;
                    }
                    cursor = aligned;
                    walker.advance();
                    continue;
                }
                break;
            }
            if cursor >= range_end {
                return None;
            }
            let gap_end = match walker.peek() {
                Some(iv) => iv.base.min(range_end),
                None => range_end,
            };
            if gap_end > cursor && gap_end - cursor >= len {
                return Some(cursor);
            }
            // Step past the obstacle and try again.
            match walker.peek() {
                Some(iv) => {
                    let aligned = align_up(iv.end, align)?;
                    if aligned >= range_end {
                        return None;
                    }
                    cursor = aligned;
                    walker.advance();
                }
                None => return None,
            }
        }
    }
}

/// Merged dual-cursor walker over `regions_index` + `reservations_index`
/// + the static global exclusions. Yields intervals in ascending base
/// order, coalesces touching/overlapping intervals.
struct IntervalWalker {
    regions: IndexCursor,
    reservations: IndexCursor,
    globals: GlobalCursor,
    cached: Option<Interval>,
}

impl IntervalWalker {
    unsafe fn new(vm: &ClientVm, except_reservation: Option<ReservationId>) -> Self {
        let except_slot = except_reservation.map(|r| r.idx());
        unsafe {
            Self {
                regions: IndexCursor::new(vm.regions_index(), None),
                reservations: IndexCursor::new(vm.reservations_index(), except_slot),
                globals: GlobalCursor::new(),
                cached: None,
            }
        }
    }

    fn peek(&mut self) -> Option<Interval> {
        if self.cached.is_some() {
            return self.cached;
        }
        self.cached = self.pull_next();
        self.cached
    }

    fn advance(&mut self) {
        self.cached = None;
    }

    fn pull_next(&mut self) -> Option<Interval> {
        let mut current = self.take_smallest()?;
        loop {
            match self.peek_smallest() {
                Some(iv) if iv.base <= current.end => {
                    current.end = current.end.max(iv.end);
                    self.consume_taken(iv);
                }
                _ => break,
            }
        }
        Some(current)
    }

    fn peek_smallest(&self) -> Option<Interval> {
        smallest_three(
            self.regions.peek(),
            self.reservations.peek(),
            self.globals.peek(),
        )
    }

    fn take_smallest(&mut self) -> Option<Interval> {
        let pick = self.peek_smallest()?;
        self.consume_taken(pick);
        Some(pick)
    }

    fn consume_taken(&mut self, taken: Interval) {
        if matches_head(self.regions.peek(), taken) {
            self.regions.advance();
            return;
        }
        if matches_head(self.reservations.peek(), taken) {
            self.reservations.advance();
            return;
        }
        if matches_head(self.globals.peek(), taken) {
            self.globals.advance();
        }
    }
}

fn matches_head(head: Option<Interval>, taken: Interval) -> bool {
    match head {
        Some(h) => h.base == taken.base && h.end == taken.end,
        None => false,
    }
}

fn smallest_three(
    a: Option<Interval>,
    b: Option<Interval>,
    c: Option<Interval>,
) -> Option<Interval> {
    let mut best: Option<Interval> = None;
    for opt in [a, b, c].iter().copied() {
        if let Some(iv) = opt {
            best = match best {
                Some(cur) if cur.base <= iv.base => Some(cur),
                _ => Some(iv),
            };
        }
    }
    best
}

struct IndexCursor {
    index: *const BaseSortedIndex,
    pos: u32,
    except_slot: Option<u32>,
}

impl IndexCursor {
    unsafe fn new(index: *const BaseSortedIndex, except_slot: Option<u32>) -> Self {
        Self {
            index,
            pos: 0,
            except_slot,
        }
    }

    fn peek(&self) -> Option<Interval> {
        unsafe {
            let mut p = self.pos;
            loop {
                let entry = (*self.index).at(p)?;
                if Some(entry.slot) == self.except_slot || entry.length == 0 {
                    // Zero-length entries (e.g. degenerate guard
                    // reservations registered with `guard_pages == 0`
                    // for back-link parity) carry no occupied bytes
                    // and must not stop the walker — skipping them
                    // here keeps later entries reachable.
                    p += 1;
                    continue;
                }
                return Interval::from_base_len(entry.base, entry.length);
            }
        }
    }

    fn advance(&mut self) {
        // Skip exempt entries on advance so peek/advance stay in
        // sync.
        unsafe {
            self.pos += 1;
            while let Some(entry) = (*self.index).at(self.pos) {
                if Some(entry.slot) == self.except_slot || entry.length == 0 {
                    self.pos += 1;
                    continue;
                }
                break;
            }
        }
    }
}

struct GlobalCursor {
    intervals: [Interval; 2],
    pos: u8,
}

impl GlobalCursor {
    fn new() -> Self {
        Self {
            intervals: global_exclusions(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<Interval> {
        if (self.pos as usize) >= self.intervals.len() {
            return None;
        }
        Some(self.intervals[self.pos as usize])
    }

    fn advance(&mut self) {
        self.pos += 1;
    }
}

// ---------------------------------------------------------------------------
// Overlap-detection helpers
// ---------------------------------------------------------------------------

/// Return the first `RegionId` whose mapping overlaps
/// `[base, base + length)`, or `None`.
///
/// # Safety
///
/// Single-threaded server invariant.
pub(crate) unsafe fn range_overlaps_mapping(
    vm: &ClientVm,
    base: u64,
    length: u64,
) -> Option<RegionId> {
    unsafe {
        let slot = vm.regions_index().first_overlap(base, length)?;
        let epoch = vm.region_generation_at(slot);
        if epoch == 0 {
            return None;
        }
        Some(RegionId::from_slab(SlabId { idx: slot, epoch }))
    }
}

/// Return the first `ReservationId` whose reserved range overlaps
/// `[base, base + length)`, optionally skipping `except`.
///
/// # Safety
///
/// Single-threaded server invariant.
pub(crate) unsafe fn range_overlaps_reservation(
    vm: &ClientVm,
    base: u64,
    length: u64,
    except: Option<ReservationId>,
) -> Option<ReservationId> {
    unsafe {
        let mut start = base;
        let end = base.checked_add(length)?;
        loop {
            if start >= end {
                return None;
            }
            let remaining = end - start;
            let slot = vm.reservations_index().first_overlap(start, remaining)?;
            let epoch = vm.reservation_generation_at(slot);
            if epoch == 0 {
                return None;
            }
            let id = ReservationId::from_slab(SlabId { idx: slot, epoch });
            if Some(id) != except {
                return Some(id);
            }
            // Skip past the matched reservation and retry.
            let r = match vm.reservation(id) {
                Some(r) => r,
                None => return None,
            };
            let after_end = r.base.saturating_add(r.length);
            if after_end >= end {
                return None;
            }
            start = after_end;
        }
    }
}

// ---------------------------------------------------------------------------
// Alignment helpers
// ---------------------------------------------------------------------------

fn align_up(v: u64, align: u64) -> Option<u64> {
    let mask = align - 1;
    v.checked_add(mask).map(|sum| sum & !mask)
}

fn align_down(v: u64, align: u64) -> u64 {
    v & !(align - 1)
}
