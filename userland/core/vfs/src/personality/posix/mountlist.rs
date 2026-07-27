// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_MOUNT_LIST` — enumerate the active mount table.
//!
//! Backs BSD `getmntinfo(3)` / `getfsstat(2)` and Linux
//! `getmntent(3)`. Each active mount is rendered into a
//! [`TronaMountInfo`] record (the `f_mntonname` path, fstype
//! string, mount flags, and a `statvfs` snapshot) and written into
//! the caller's per-process bulk SHM region — the same transport
//! `VFS_READ` uses, since a 312-byte record exceeds the inline
//! reply registers. The reply carries only the written count and
//! the total available, so a caller can size its buffer and refill.
//!
//! Wire:
//! - Request: `regs[0]` = max entries to fill. `0` is count-only
//!   (no SHM access; the reply still reports `available`), backing
//!   the first pass of `getfsstat(NULL, 0, ...)`.
//! - Reply: `regs[0]` = entries written into the SHM region (offset
//!   0, packed 312 B each), `regs[1]` = total active mounts.
//!
//! fstype comes from [`MountKind::as_fs_name`], not the backend's
//! `statfs` — service backends (Inet/Pty/Fb) have no working
//! `statfs`. A per-mount `statfs` failure degrades that one entry's
//! `statvfs` to zero rather than aborting the whole request. The
//! option string is rendered client-side from `flags` (the
//! internal `MNT_*` constants live in basaltc), so this handler
//! leaves `opts` empty and only fills the authoritative fields.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::file::VStatfs;
use crate::core::mount::MountHandle;
use crate::core::vop_context::OwnerMountCtx;
use crate::owner::VfsState;
use crate::owner::client_shm::slice_in_region;
use crate::personality::wire::{send_error_reply, send_ok_reply};
use crate::server::types::ClientHandle;
use trona_posix::types::{
    TRONA_MOUNT_INFO_FS_TYPE_LEN, TRONA_MOUNT_INFO_PATH_LEN, TRONA_MOUNT_LIST_MAX_ENTRIES,
    TronaMountInfo, TronaStatvfs,
};

const RECORD_BYTES: usize = ::core::mem::size_of::<TronaMountInfo>();

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let want = msg.regs[0] as usize;

        // Count-only fast path: report the total without touching
        // SHM. A caller (e.g. `getmntinfo`) uses this to size its
        // buffer before the fill call.
        if want == 0 {
            let available = active_mount_count(state);
            send_ok_reply(reply_lease, &[0, available as u64]);
            return;
        }

        // Resolve the caller's bulk SHM region. The client registers
        // it lazily (`ensure_bulk_shm`) before the fill call, so an
        // absent region is a hard error here.
        let region_h = match state.clients.get(client) {
            Some(c) => c.bulk_shm,
            None => {
                send_error_reply(reply_lease, VfsError::Io);
                return;
            }
        };
        let (region_base, region_bytes) = match state.client_shm_regions.get(region_h) {
            Some(r) if !r.is_empty() && r.owner_client == client => {
                match slice_in_region(r, 0, r.bytes) {
                    Some(p) => (p, r.bytes),
                    None => {
                        send_error_reply(reply_lease, VfsError::Io);
                        return;
                    }
                }
            }
            _ => {
                send_error_reply(reply_lease, VfsError::Io);
                return;
            }
        };

        let region_cap = (region_bytes as usize) / RECORD_BYTES;
        let cap = want.min(region_cap).min(TRONA_MOUNT_LIST_MAX_ENTRIES);

        // Snapshot up to `cap` mount handles and the full count in a
        // single pass — `for_each_active` borrows `state.mounts`, so
        // the blocking `statfs` calls must run afterwards over the
        // snapshot, not inside the closure.
        let mut handles = [MountHandle::INVALID; TRONA_MOUNT_LIST_MAX_ENTRIES];
        let mut available: usize = 0;
        let mut collected: usize = 0;
        state.mounts.for_each_active(|mh, _m| {
            available += 1;
            if collected < cap {
                handles[collected] = mh;
                collected += 1;
            }
            true
        });

        for idx in 0..collected {
            let mh = handles[idx];
            let mut rec = TronaMountInfo::zeroed();

            // Authoritative mount fields. Scoped so the immutable
            // borrow drops before `statfs` re-borrows `state` mutably.
            let vfsops_ptr = {
                let Some(m) = state.mounts.get(mh) else {
                    continue;
                };
                rec.mount_id = m.fs_instance_id.0;
                rec.flags = m.mount_flags as u32;
                let fs = m.kind.as_fs_name();
                let fl = fs.len().min(TRONA_MOUNT_INFO_FS_TYPE_LEN);
                rec.fs_type[..fl].copy_from_slice(&fs[..fl]);
                rec.fs_type_len = fl as u8;
                let path = m.mount_path_slice();
                let pl = path.len().min(TRONA_MOUNT_INFO_PATH_LEN);
                rec.mount_path[..pl].copy_from_slice(&path[..pl]);
                rec.mount_path_len = pl as u8;
                m.vfsops
            };

            // Per-mount statfs (synchronous; blocks on a backend RPC
            // for saltyfs). Service backends return `NotSup`; degrade
            // that entry's statvfs to zero rather than failing the
            // list.
            let mut vstat = VStatfs::zeroed();
            if !vfsops_ptr.is_null() {
                if let Some(mut mctx) = OwnerMountCtx::from_state(state, mh) {
                    if ((*vfsops_ptr).statfs)(&mut mctx, &raw mut vstat).is_err() {
                        vstat = VStatfs::zeroed();
                    }
                }
            }
            rec.statvfs = vstatfs_to_trona(&vstat);

            // SAFETY: `region_base` is vfs's mapping of the client's
            // bulk SHM region; `cap <= region_bytes / RECORD_BYTES`
            // bounds every slot, and the region lives in a separate
            // mmap untouched by the `statfs` borrow above. `rec` is a
            // 312-byte `#[repr(C)]` POD with no overlap.
            let dst = region_base.add(idx * RECORD_BYTES);
            ::core::ptr::copy_nonoverlapping((&raw const rec) as *const u8, dst, RECORD_BYTES);
        }

        send_ok_reply(reply_lease, &[collected as u64, available as u64]);
    }
}

/// Count active mounts without snapshotting handles.
fn active_mount_count(state: &VfsState) -> usize {
    let mut n = 0usize;
    state.mounts.for_each_active(|_mh, _m| {
        n += 1;
        true
    });
    n
}

/// Project the VFS-internal [`VStatfs`] onto the wire
/// [`TronaStatvfs`], matching the field mapping the `VFS_STATVFS`
/// reply uses.
fn vstatfs_to_trona(s: &VStatfs) -> TronaStatvfs {
    TronaStatvfs {
        f_bsize: s.bsize as u64,
        f_frsize: s.frsize as u64,
        f_blocks: s.blocks,
        f_bfree: s.bfree,
        f_bavail: s.bavail,
        f_files: s.files,
        f_ffree: s.ffree,
        f_favail: s.favail,
        f_fsid: s.fsid,
        f_flag: s.flag as u64,
        f_namemax: s.namemax as u64,
    }
}
