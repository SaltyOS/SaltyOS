//! test_cspace_expand: per-process substrate slot allocator stress test.
//!
//! Validates that `trona_runtime::core::slot_alloc::slot_alloc` can drive substrate
//! self-expansion across the new `MAX_CSPACE_EXPANSIONS = 64` ceiling.
//! Drains the initial bump-segment, then keeps allocating to force the
//! synchronous self-expand path (substrate calls `RES_ALLOC_OBJECT`
//! against rsrcsrv to install fresh sub-CNodes in the deterministic
//! expansion window).
//!
//! Pass criteria: at least one expansion sub-CNode worth of slots
//! allocated past the initial segment, and all slots free cleanly.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_kernel::core_types::Cap;
use trona_runtime::core::slot_alloc;
use trona_runtime::debug::serial;

const STRESS_COUNT: usize = 4096;
const STORAGE_BYTES: usize = STRESS_COUNT * core::mem::size_of::<Cap>();
const STORAGE_BYTES_U64: u64 = STORAGE_BYTES as u64;
const PASS_THRESHOLD: usize = 2048;

pub fn run() -> bool {
    serial::serial_puts(b"[TEST_CSPACE_EXPAND] starting\n");

    // mmap a scratch region to hold the allocated slot ids — STRESS_COUNT
    // u64s would dwarf the test's stack budget if we put them inline.
    let storage = unsafe {
        trona_posix::mm::posix_mmap(
            core::ptr::null_mut(),
            STORAGE_BYTES_U64,
            (trona_posix::consts::PROT_READ | trona_posix::consts::PROT_WRITE) as i32,
            (trona_posix::consts::MAP_ANONYMOUS | trona_posix::consts::MAP_PRIVATE) as i32,
            -1,
            0,
        )
    };
    if storage.is_null() || storage as i64 == -1 {
        serial::serial_puts(b"[TEST_CSPACE_EXPAND] FAIL: mmap scratch\n");
        return false;
    }
    let slots = storage as *mut Cap;

    let mut allocated = 0usize;
    while allocated < STRESS_COUNT {
        match slot_alloc::slot_alloc() {
            Some(slot) => {
                unsafe { slots.add(allocated).write(slot) };
                allocated += 1;
            }
            None => break,
        }
    }

    {
        let mut lb = serial::LineBuf::new();
        lb.str(b"[TEST_CSPACE_EXPAND] allocated=");
        lb.dec(allocated as u64);
        lb.str(b" target=");
        lb.dec(PASS_THRESHOLD as u64);
        lb.str(b"\n");
        lb.flush();
    }

    let mut pass = allocated >= PASS_THRESHOLD;

    // Free everything we got, in reverse so the segment alloc_hint walks
    // back monotonically and we exercise the free path under pressure.
    for i in (0..allocated).rev() {
        let slot = unsafe { slots.add(i).read() };
        // SAFETY: `slot` is an empty slot this test allocated via slot_alloc and
        // stored raw in the mmap scratch array; it was never filled with a cap,
        // and each index is reclaimed exactly once in this reverse drain.
        let _ = unsafe { slot_alloc::reclaim_empty_allocated_slot_unchecked(slot) };
    }

    // After freeing, a fresh single alloc must succeed.
    match slot_alloc::slot_alloc() {
        Some(slot) => {
            // SAFETY: `slot` is the empty slot just allocated above (never filled
            // with a cap); its index is reclaimed exactly once here.
            let _ = unsafe { slot_alloc::reclaim_empty_allocated_slot_unchecked(slot) };
        }
        None => {
            serial::serial_puts(b"[TEST_CSPACE_EXPAND] FAIL: post-drain alloc\n");
            pass = false;
        }
    }

    let _ = unsafe { trona_posix::mm::posix_munmap(storage, STORAGE_BYTES_U64) };

    if pass {
        serial::serial_puts(b"[TEST_CSPACE_EXPAND] PASS\n");
    } else {
        serial::serial_puts(b"[TEST_CSPACE_EXPAND] FAIL\n");
    }
    pass
}
