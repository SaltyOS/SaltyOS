// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyOS VFS server.
//!
//! # Topology
//!
//! - **Frontend** (client-facing): single master service-EP
//!   MP_CORE, each client minted with its `client_id` in the lower
//!   32 bit of the send-cap badge by namesrv. Owner reactor's main
//!   fan-in cookie kind `0`.
//! - **Backend** (saltyfs / netsrv / posix_ttysrv / blkdrv):
//!   per-mount-instance MP_CORE pair (vfs holds send + callback
//!   recv), Watch over each backend's callback recv on the same
//!   owner EQ. Cookie kind `1`.
//! - **Pager** (kernel → vfs): vfs retypes its own `OBJ_PAGER` cap,
//!   binds it to `owner_eq` via `PAGER_BIND_EQ`, and hands a cap
//!   copy to mmsrv via `MM_REGISTER_VFS_PAGER` at boot. Every
//!   `MM_FILE_MMAP` then attaches this pager to a freshly-retyped
//!   MO; absent-page faults fire `EVENT_TYPE_PAGER_REQUEST` events
//!   directly into `owner_eq` (mmsrv off the fault path). Cookie
//!   kind `2`.
//! - **Timer**: owner-private timer cap on the same EQ for page-
//!   cache writeback / poll expiry. Cookie kind `3`.
//!
//! Owner thread is the sole `VfsState` mutator. Blocking or
//! long-running backend work stays behind backend-session RPCs and
//! resumes through owner-owned `PendingOp` completion.

#![no_std]
#![no_main]

extern crate trona_kernel;
extern crate trona_protocol;
extern crate trona_runtime;
extern crate trona_server;
extern crate uapi;

pub(crate) mod arena;
pub(crate) mod boot;
pub(crate) mod core;
pub(crate) mod fs;
pub(crate) mod ipc;
pub(crate) mod ops;
pub(crate) mod owner;
pub(crate) mod personality;
pub(crate) mod server;

#[inline]
pub(crate) fn ipc_ctx() -> *mut trona_kernel::core_types::IpcContext {
    trona_runtime::current_ipc_ctx()
}

#[unsafe(no_mangle)]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8, _envp: *const *const u8) -> i32 {
    unsafe {
        // 1. Allocate the `VfsState` backing storage. The struct
        //    is too large for a static initialiser (it carries
        //    every Arena's segment-list head plus a few large
        //    inline tables) so we map a fresh anon region from
        //    mmsrv and pin the state at its base.
        let bytes = ::core::mem::size_of::<owner::VfsState>();
        let pages = (bytes + 4095) / 4096;
        let raw = server::mem::map_anon((pages * 4096) as u64);
        if raw.is_null() || raw == usize::MAX as *mut u8 {
            trona_runtime::debug::serial::serial_puts(b"[VFS] state alloc failed\n");
            return 1;
        }
        ::core::ptr::write_bytes(raw, 0, pages * 4096);
        let state_ptr = raw as *mut owner::VfsState;

        // 2. Drive the in-place arena / cookie-table / reactor
        //    construction. Failure here means the boot-time
        //    untyped budget was undersized; retry is not
        //    meaningful so we surface a non-zero exit.
        if !boot::init_state_in_place(state_ptr) {
            trona_runtime::debug::serial::serial_puts(b"[VFS] state init failed\n");
            return 1;
        }
        let state = &mut *state_ptr;

        // 3. Retype vfs's `OBJ_PAGER`, bind it to the owner EQ,
        //    and hand a cap copy to mmsrv. Subsequent
        //    `MM_FILE_MMAP` calls attach this pager to freshly
        //    retyped MOs; the kernel routes file-backed faults to
        //    the owner reactor as `EVENT_TYPE_PAGER_REQUEST` events.
        if !boot::register_pager_with_mmsrv(state) {
            trona_runtime::debug::serial::serial_puts(b"[VFS] mmsrv pager register failed\n");
            return 1;
        }

        // 4. Bootstrap the initrd-backed read-only root so the
        //    early-spawned services see a working filesystem
        //    before saltyfs takes over via `pivot_root` later.
        if !boot::bootstrap_initrd_root(state) {
            trona_runtime::debug::serial::serial_puts(b"[VFS] initrd bootstrap failed\n");
            return 1;
        }

        // 4b. Unpack the initrd CPIO into the ramfs root (Linux
        //     initramfs model) so /bin and friends are populated
        //     before the pseudo-filesystems mount over the skeleton.
        if !boot::extract_initrd(state) {
            trona_runtime::debug::serial::serial_puts(b"[VFS] initrd extraction failed\n");
            return 1;
        }

        if !boot::bootstrap_pseudo_mounts(state) {
            trona_runtime::debug::serial::serial_puts(b"[VFS] pseudo-fs bootstrap failed\n");
            return 1;
        }

        // 5. Publish vfs's master service-EP send to namesrv with
        //    `BADGE_AS_CALLER` only after the pager and initrd root
        //    are ready. Init treats namesrv publication as service
        //    readiness for dependency scheduling.
        if !boot::register_with_namesrv(state) {
            trona_runtime::debug::serial::serial_puts(b"[VFS] namesrv register failed\n");
            return 1;
        }

        // 6. Hand control to the owner reactor. The function never
        //    returns; the `0` below is purely to satisfy the C ABI
        //    in the unlikely event the reactor ever does.
        owner::reactor::run(state);
    }
}
