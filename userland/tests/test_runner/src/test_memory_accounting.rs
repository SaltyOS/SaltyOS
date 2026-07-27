//! Memory accounting smoke test.
//!
//! Exercises the kernel snapshot API (`SYS_SYSMEMINFO`) and the per-tag
//! reconciliation invariant: every tracked frame must be accounted for
//! in exactly one of `free`, `untyped_reserved`, or the typed owner
//! buckets. If the invariant breaks the PMM 3-state wiring is wrong.
//!
//! SPDX-License-Identifier: GPL-2.0-only

use trona_protocol::init::TronaSysMemInfo;
use trona_runtime::debug::serial;

pub fn run() -> bool {
    let mut snap = TronaSysMemInfo::default();
    let err = trona_kernel::syscall::system_get_meminfo(
        trona_runtime::client::caps::system_info_cap().addr(),
        &raw mut snap,
    );
    if err != 0 {
        serial::serial_puts(b"[test_memory_accounting] system_get_meminfo failed\n");
        return false;
    }
    if snap.pages_total == 0 {
        serial::serial_puts(b"[test_memory_accounting] pages_total == 0\n");
        return false;
    }
    if snap.page_size != 4096 {
        serial::serial_puts(b"[test_memory_accounting] page_size != 4096\n");
        return false;
    }

    // Sum every tagged frame population. With the PMM 3-state invariant
    // this must equal `pages_total` — any shortfall means some PMM path
    // transitioned a frame without updating the per-tag counters.
    let typed = snap.pages_mo_data
        + snap.pages_mo_meta
        + snap.pages_page_cache
        + snap.pages_kernel_pagetable
        + snap.pages_kernel_stack
        + snap.pages_kernel_slab
        + snap.pages_emergency_reserve;
    let accounted = snap.pages_free + snap.pages_untyped_reserved + typed;
    if accounted != snap.pages_total {
        serial::serial_puts(b"[test_memory_accounting] accounting mismatch: ");
        let mut lb = serial::LineBuf::new();
        lb.str(b"total=");
        lb.dec(snap.pages_total);
        lb.str(b" accounted=");
        lb.dec(accounted);
        lb.str(b"\n");
        lb.flush();
        return false;
    }

    // pages_mo_data sub-kinds should also sum consistently.
    let mo_sum = snap.pages_anon_private + snap.pages_anon_shared + snap.pages_file;
    // Note: CoW child pages are tracked separately but not surfaced in
    // this struct. Accept the sub-sum to be ≤ pages_mo_data.
    if mo_sum > snap.pages_mo_data {
        serial::serial_puts(b"[test_memory_accounting] mo-kind overflow\n");
        return false;
    }

    serial::serial_puts(b"[test_memory_accounting] PASS\n");
    true
}
