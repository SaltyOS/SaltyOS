// SPDX-License-Identifier: GPL-2.0-only
//! SaltyFS-private description of a parked RPC.
//!
//! Each outstanding saltyfs `BACKEND_*` request the VFS owner has fired
//! via `send_ctx` carries a matching [`SaltyfsOpKind`] stamped into a
//! generic [`PendingKindPayload`] on the `PendingOp` arena entry. The
//! payload stays opaque in the generic pending / session / fileops
//! layers; only this module and the saltyfs completion router interpret
//! its bytes.
//!
//! Variants store only VFS-stable primitives: inode numbers, inline
//! name buffers, and descriptor-shaped protocol values
//! ([`TransferDescriptor`]). No handles, pointers, or borrowed slices.
//!
//! # Packing contract
//!
//! [`SaltyfsOpKind::pack`] and [`SaltyfsOpKind::unpack`] use a simple
//! bytewise copy into / out of the fixed-size payload buffer. A
//! compile-time assertion below bounds `sizeof::<SaltyfsOpKind>()` so
//! growing a variant without adjusting the generic payload size
//! surfaces as a build error rather than a silent truncation.
//!
//! The pending arena entry is `#[repr(C)]` and the payload's backing
//! storage is a `[u64; _]`, so the unpack direction is UB-safe
//! provided the bytes were produced by a matching `pack` call (the
//! generic layer never mutates the payload between pack and unpack).

use trona_kernel::core_types::Cap;
use trona_protocol::posix::TransferDescriptor;

use crate::owner::pending::{PENDING_KIND_PAYLOAD_BYTES, PendingKindPayload, WALK_NAME_MAX};
use crate::vfs_core::mount::MountHandle;

/// Which saltyfs RPC is parked.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) enum SaltyfsOpKind {
    /// `BACKEND_STAT { ino }`.
    Stat { ino: u64 },
    /// `BACKEND_GETINFO`.
    GetInfo,
    /// `BACKEND_LOOKUP { parent_ino, name }`.
    Lookup {
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_READLINK { ino }`.
    Readlink { ino: u64 },
    /// `BACKEND_GETXATTR { ino, name_len, name }`. The name bytes are
    /// copied inline (mirroring the `Lookup` / `RemoveXattr` sizing) so
    /// the deferred-issue drain can replay the request after the SHM
    /// claim frees — without the inline copy the name would need to
    /// ride in the VFS↔saltyfs SHM region, which is the very lock the
    /// parked caller is waiting on.
    XattrGet {
        ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_LISTXATTR { ino }`.
    ListXattr { ino: u64 },
    /// `BACKEND_READ { ino, file_offset, transfer }`.
    Read {
        ino: u64,
        file_offset: u64,
        transfer: TransferDescriptor,
    },
    /// `BACKEND_READDIR { dir_ino, cookie, shm_offset, buf_bytes }`.
    Readdir {
        dir_ino: u64,
        cookie: u64,
        shm_offset: u64,
        buf_bytes: u64,
    },
    /// `BACKEND_SETATTR { ino, mask, mode, uid, gid, atime, mtime, size }`.
    /// `mask` is a bitwise OR of `trona_protocol::SETATTR_MASK_*` flags
    /// selecting which fields to apply; non-selected fields carry 0 on
    /// the wire and are ignored by the server.
    SetAttr {
        ino: u64,
        mask: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        atime: u64,
        mtime: u64,
        size: u64,
    },
    /// `BACKEND_SETXATTR { ino, name_len, value_len, flags, name,
    /// value }`. On the wire the name + value bytes ride in the
    /// VFS↔saltyfs SHM region at offset 0 (layout:
    /// `name[name_len] || value[value_len]`). The inline `name` / `value`
    /// buffers on this op-kind exist for the deferred-issue drain path:
    /// when an async setxattr parks because the SHM region is held by a
    /// prior xattr / readdir op, the drain replays the memcpy into SHM
    /// before firing `send_ctx`. The POSIX dispatch layer caps
    /// `name_len + value_len ≤ 224` (see `dispatch_setxattr`); the
    /// inline buffers here match [`WALK_NAME_MAX`] so neither side
    /// truncates. The completion is a plain ack — no attribute
    /// snapshot.
    SetXattr {
        ino: u64,
        name: [u8; WALK_NAME_MAX],
        value: [u8; WALK_NAME_MAX],
        name_len: u8,
        value_len: u16,
        flags: u32,
    },
    /// `BACKEND_REMOVEXATTR { ino, name_len, name }`. The name bytes
    /// fit inline because POSIX-spec xattr name maxes at 255 and the
    /// RPC payload already budgets for 144; we mirror the
    /// `Lookup.name` sizing so the opaque payload stays bounded.
    RemoveXattr {
        ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_CREATE { parent_ino, name, mode, uid, gid }`. Reply
    /// carries the new inode's id + full stat snapshot so the
    /// completion handler can materialise the child vnode.
    Create {
        parent_ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_MKDIR { parent_ino, name, mode, uid, gid }`. Same
    /// reply shape as Create.
    Mkdir {
        parent_ino: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_SYMLINK { parent_ino, name, target, uid, gid }`.
    /// Wire layout mirrors [`crate::fs::saltyfs_client::mutate_rpc`]'s
    /// sync V2 encoding: both `name` (≤ 56 bytes in V2) and `target`
    /// (≤ 64 bytes) ride as fixed-slot MR payload, **not** via the
    /// VFS↔saltyfs SHM region — so the deferred-issue drain must
    /// rebuild both payloads from this opaque record without any
    /// SHM dependency. Storing `target` inline keeps the replay
    /// self-contained.
    /// Reply shape matches Create/Mkdir.
    Symlink {
        parent_ino: u64,
        uid: u32,
        gid: u32,
        name: [u8; WALK_NAME_MAX],
        target: [u8; 64],
        name_len: u8,
        target_len: u8,
    },
    /// `BACKEND_UNLINK { parent_ino, name }`. Plain ack completion.
    Unlink {
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_RMDIR { parent_ino, name }`. Plain ack completion.
    Rmdir {
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_LINK { target_ino, parent_ino, name }`. Plain ack.
    Link {
        target_ino: u64,
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_RENAME { old_parent_ino, old_name, new_parent_ino,
    /// new_name }`. Plain ack. Names fit inline; cross-mount rename
    /// is rejected pre-issue with EXDEV so a saltyfs Rename kind is
    /// always intra-mount.
    Rename {
        old_parent_ino: u64,
        new_parent_ino: u64,
        old_name: [u8; WALK_NAME_MAX],
        new_name: [u8; WALK_NAME_MAX],
        old_name_len: u8,
        new_name_len: u8,
    },
    /// `BACKEND_TRUNCATE { ino, new_size }`. Plain ack.
    Truncate { ino: u64, new_size: u64 },
    /// `BACKEND_OPEN_SESSION`. The mount slot has been reserved and
    /// its generic fields populated; the backend reply carries session
    /// identity + root node + feature bits. `mh` identifies the mount
    /// arena slot to finalise on completion; `fs_cap` is the backend
    /// endpoint capability for SHM / subsequent RPCs.
    OpenSession { mh: MountHandle, fs_cap: Cap },
}

const _: () = assert!(
    core::mem::size_of::<SaltyfsOpKind>() <= PENDING_KIND_PAYLOAD_BYTES,
    "SaltyfsOpKind outgrew PendingKindPayload — bump PENDING_KIND_PAYLOAD_WORDS",
);

impl SaltyfsOpKind {
    /// Serialise into a [`PendingKindPayload`] for arena storage.
    /// Bytewise-stable across `pack` / `unpack` round trips on the
    /// same binary; the payload is not meant to migrate between
    /// incompatible builds.
    #[inline]
    pub(crate) fn pack(&self) -> PendingKindPayload {
        let mut payload = PendingKindPayload::zeroed();
        // SAFETY: `PENDING_KIND_PAYLOAD_BYTES` is bounded ≥ the struct
        // size by the `const _` assertion above; `payload` is fresh
        // and contains no initialised interior references.
        unsafe {
            let src = self as *const Self as *const u8;
            let dst = payload.words.as_mut_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, core::mem::size_of::<Self>());
        }
        payload
    }

    /// Deserialise a [`PendingKindPayload`] previously produced by
    /// [`SaltyfsOpKind::pack`].
    ///
    /// # Safety
    ///
    /// The caller must ensure `payload` was produced by a `pack` call
    /// on the current binary. The generic pending layer carries
    /// payloads opaquely between pack and unpack, so in-process
    /// callers satisfy this by construction.
    #[inline]
    pub(crate) unsafe fn unpack(payload: &PendingKindPayload) -> Self {
        unsafe {
            let mut out = core::mem::MaybeUninit::<Self>::uninit();
            let src = payload.words.as_ptr() as *const u8;
            let dst = out.as_mut_ptr() as *mut u8;
            core::ptr::copy_nonoverlapping(src, dst, core::mem::size_of::<Self>());
            out.assume_init()
        }
    }
}
