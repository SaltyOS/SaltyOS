// SPDX-License-Identifier: GPL-2.0-only
//
//! init's fixed CSpace slot map.
//!
//! init runs at PID 1 with kernel-installed boot caps. The kernel writes
//! the system-cap set, the boot untyped seed, and a few well-known
//! frame caps into specific slot positions before jumping to `main`.
//! Everything else (per-spawn request MPs, fault MPs, runtime worker
//! scratch) is allocated dynamically through
//! `trona_runtime::core::slot_alloc::slot_alloc_or_idle` from `INTERNAL_BASE`
//! upwards.
//!
//! These constants are the only hard-coded positions in init's CSpace.
//! Every other slot is dispensed by the allocator at runtime.

// ---------------------------------------------------------------------------
// Kernel-fixed positions. Set by `kernite/src/init.rs` before init runs.
// ---------------------------------------------------------------------------

pub const SLOT_SELF_TCB: u64 = 0;
pub const SLOT_SELF_VSPACE: u64 = 1;
pub const SLOT_SELF_CSPACE: u64 = 2;

/// Kernel writes the system cap set into 0x03..=0x07 (KernelRng / Clock /
/// SystemControl / SystemInfo / KernelDebug). init reads these via
/// `trona_runtime::client::caps::*` getters; the allocator is told to skip 0x03..=0x07
/// during slot vending.
pub const SLOT_SYSCAP_KERNEL_RNG: u64 = 0x03;
pub const SLOT_SYSCAP_CLOCK: u64 = 0x04;
pub const SLOT_SYSCAP_SYSTEM_CONTROL: u64 = 0x05;
pub const SLOT_SYSCAP_SYSTEM_INFO: u64 = 0x06;
pub const SLOT_SYSCAP_KERNEL_DEBUG: u64 = 0x07;

/// Initial untyped seed handed to init by the kernel — the entire
/// boot-time RAM root the bootloader carved off. init's first task is
/// to split this into four chunks (init-private / namesrv-quota /
/// rsrcsrv-untyped / mmsrv-untyped). Living at slot 16 matches the
/// generic `CAP_UNTYPED_START` convention every spawned process
/// inherits.
pub const SLOT_BOOT_UNTYPED: u64 = 16;

/// Initrd FRAME chunk the bootloader passes through. init reads CPIO
/// entries (`.service` files, every userland ELF/PE) from the initrd
/// MO mapped at this address.
pub const SLOT_INITRD_UNTYPED: u64 = 17;

/// Framebuffer raw FRAME for `dispdrv`. init shares this with `dispdrv`
/// when spawning it — kernel never touches the FB after handoff.
pub const SLOT_FB_UNTYPED: u64 = 18;

/// PCI ECAM IO_PORT cap. init shares this with `pcidrv`.
pub const SLOT_PCI_IOPORT: u64 = 19;

/// COM1 IO_PORT cap. init shares this with `console`.
pub const SLOT_COM1_IOPORT: u64 = 20;

/// COM1 IRQ handler cap. init shares with `console`.
pub const SLOT_COM1_IRQ: u64 = 21;

/// Keyboard IO_PORT cap. init shares with `posix_ttysrv`.
pub const SLOT_KBD_IOPORT: u64 = 22;

/// Keyboard IRQ handler cap. init shares with `posix_ttysrv`.
pub const SLOT_KBD_IRQ: u64 = 23;

/// DEVICE_CONTROL cap. init shares with trusted device-discovery
/// services that mint IoPort, device-Untyped, and IRQ-handler caps.
pub const SLOT_DEVICE_CONTROL: u64 = 24;

/// Boot ExecAuthority cap (kernel-installed at PID1 boot). The sole authority
/// for `mo_mark_executable` — PID1 confers EXECUTE on borrowed-frames boot
/// images with it, then MOVEs it to `ldsrv` at the Stage-1 handoff.
pub const SLOT_EXEC_AUTHORITY: u64 = 25;

// ---------------------------------------------------------------------------
// Init-installed positions. Set by `boot::install_kernel_caps` after
// kernel handoff but before any allocator activity.
// ---------------------------------------------------------------------------

/// Retired fixed slot. Kept reserved so the rest of init's fixed
/// layout does not move.
pub const SLOT_RESERVED_32: u64 = 32;

/// Bootinfo snapshot frame cap. init populates a 4 KiB FRAME with the
/// bootloader's TLV bootinfo and shares it (read-only) with anyone
/// who calls `INIT_GET_BOOTINFO_FRAME`. Per-call clones are minted
/// from this master.
pub const SLOT_BOOTINFO_FRAME: u64 = 33;

/// Control EQ master cap. The owner thread sleeps on EQ_WAIT against
/// this cap; per-client request MP / per-TCB-exit / control_timer /
/// worker_completion Watches all enqueue records here.
pub const SLOT_CONTROL_EQ: u64 = 34;

/// worker_completion EQ — lifecycle worker TCBs post results here
/// when they finish a long-running step (loader stage of SPAWN, fork
/// VSPACE preparation, etc.). The owner thread Watches it on the
/// control EQ.
pub const SLOT_WORKER_COMPLETION_EQ: u64 = 35;

/// Permanent slot init's self-expansion path reuses as the destination
/// for `OBJ_CNODE` retypes. `reserve_expand_temp_slot` adopts it once;
/// `cnode_move` empties it after each install. Outside the allocator's
/// registered segments so freeing via `slot_free` would corrupt it —
/// `boot::stage_a_read_kernel_handoff` registers it in the skip range.
pub const SLOT_SELF_EXPAND_TEMP: u64 = 256;

/// control Timer cap. init uses this for spawn timeouts, itimer
/// expiry, and waitpid backoff.
pub const SLOT_CONTROL_TIMER: u64 = 36;

/// Master service-EP MP — the privileged endpoint mmsrv uses to
/// reach init for `INIT_REPORT_FAULT` and other admin-tier labels.
/// init holds the recv side; the send side is delivered to each core
/// service at spawn via the cap-table under `ROLE_INIT_CONTROL`, badged
/// with that service's `INIT_BADGE_FROM_*` so init authenticates the
/// originator of inbound server→init messages.
pub const SLOT_MASTER_SERVICE_MP_CORE: u64 = 37;
pub const SLOT_MASTER_SERVICE_MP_SEND: u64 = 38;
pub const SLOT_MASTER_SERVICE_MP_RECV: u64 = 39;

/// Three Watch caps the supervisor reactor arms on the control EQ at
/// boot — one for `master_service_mp_recv`'s STATE_READABLE, one for
/// `control_timer`'s STATE_TIMED_OUT, one for
/// `worker_completion_eq`'s STATE_READABLE. Cookies 0/1/2.
pub const SLOT_CONTROL_EQ_WATCH_SERVICE_MP: u64 = 40;
pub const SLOT_CONTROL_EQ_WATCH_TIMER: u64 = 41;
pub const SLOT_CONTROL_EQ_WATCH_WORKER: u64 = 42;

/// recv-scratch CNode slot — kernel writes received caps from
/// per-client MP_READ here. arm helpers write the `(cnode_cap, slot,
/// depth)` triple into `IpcBuffer.recv_*` before each EQ_WAIT round.
pub const SLOT_RECV_SCRATCH_BASE: u64 = 64;
/// Length of the recv-scratch window (carries up to 6 capabilities per
/// inbound MP_READ; matches `KERNITE_MP_MAX_CAP_TRANSFER`).
pub const SLOT_RECV_SCRATCH_LEN: u64 = 6;

/// First slot the dynamic allocator (`slot_alloc`) is allowed to vend.
/// `slot_alloc::install_skip_range` is called at startup with [0, 71]
/// reserved.
pub const INTERNAL_BASE: u64 = 72;

// ---------------------------------------------------------------------------
// CSpace size sanity. init's CNode is sized for 4096 slots (12 bits).
// Process-table headroom (per-process per-client request MP recv +
// per-TCB fault MP recv + per-process signal MP send) lives in the
// allocator-managed region above `INTERNAL_BASE`.
// ---------------------------------------------------------------------------

pub const CSPACE_SIZE_BITS: u32 = 12;
pub const CSPACE_SIZE: u64 = 1 << CSPACE_SIZE_BITS; // 4096

/// Reservation marker the allocator uses when it expands into a fresh
/// CNode page. Matches `MAX_CSPACE_EXPANSIONS` in
/// `trona_runtime::core::server_consts`.
pub const CSPACE_EXPAND_BASE: u64 = CSPACE_SIZE;

// ---------------------------------------------------------------------------
// VSpace anchors. Init reserves a single user VA for transient FRAME
// staging — cap-table builder frames, ELF segment staging buffers, etc.
// owner-thread-only, no concurrent reuse.
// ---------------------------------------------------------------------------

/// Scratch VA for transient FRAME mappings. Sits well above ELF code
/// / RTLD / heap and well below `STACK_TOP_ANCHOR` (`USER_VA_TOP -
/// 0x0800_0000`), so it cannot collide with init's own image or stack.
pub const SCRATCH_FRAME_VA: u64 = 0x0000_0010_0000_0000;

pub fn assert_fixed_slot_layout() {
    debug_assert_eq!(SLOT_SELF_TCB, uapi::KERNITE_CAP_SELF_TCB as u64);
    debug_assert_eq!(SLOT_SELF_VSPACE, uapi::KERNITE_CAP_SELF_VSPACE as u64);
    debug_assert_eq!(SLOT_SELF_CSPACE, uapi::KERNITE_CAP_SELF_CSPACE as u64);
    debug_assert_eq!(SLOT_SYSCAP_KERNEL_RNG, 3);
    debug_assert_eq!(SLOT_SYSCAP_CLOCK, SLOT_SYSCAP_KERNEL_RNG + 1);
    debug_assert_eq!(SLOT_SYSCAP_SYSTEM_CONTROL, SLOT_SYSCAP_CLOCK + 1);
    debug_assert_eq!(SLOT_SYSCAP_SYSTEM_INFO, SLOT_SYSCAP_SYSTEM_CONTROL + 1);
    debug_assert_eq!(SLOT_SYSCAP_KERNEL_DEBUG, SLOT_SYSCAP_SYSTEM_INFO + 1);
    debug_assert_eq!(SLOT_BOOT_UNTYPED, 16);
    debug_assert_eq!(SLOT_INITRD_UNTYPED, SLOT_BOOT_UNTYPED + 1);
    debug_assert_eq!(SLOT_FB_UNTYPED, SLOT_INITRD_UNTYPED + 1);
    debug_assert_eq!(SLOT_PCI_IOPORT, SLOT_FB_UNTYPED + 1);
    debug_assert_eq!(SLOT_COM1_IOPORT, SLOT_PCI_IOPORT + 1);
    debug_assert_eq!(SLOT_COM1_IRQ, SLOT_COM1_IOPORT + 1);
    debug_assert_eq!(SLOT_KBD_IOPORT, SLOT_COM1_IRQ + 1);
    debug_assert_eq!(SLOT_KBD_IRQ, SLOT_KBD_IOPORT + 1);
    debug_assert_eq!(SLOT_DEVICE_CONTROL, SLOT_KBD_IRQ + 1);
    debug_assert_eq!(SLOT_EXEC_AUTHORITY, SLOT_DEVICE_CONTROL + 1);
    debug_assert!(SLOT_RECV_SCRATCH_BASE + SLOT_RECV_SCRATCH_LEN <= INTERNAL_BASE);
    debug_assert!(INTERNAL_BASE < CSPACE_SIZE);
    debug_assert_eq!(CSPACE_SIZE, 1u64 << CSPACE_SIZE_BITS);
    debug_assert_eq!(CSPACE_EXPAND_BASE, CSPACE_SIZE);
}
