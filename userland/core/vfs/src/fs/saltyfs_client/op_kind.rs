// SPDX-License-Identifier: GPL-2.0-only
//
//! SaltyFS-private description of a parked RPC.
//!
//! Each outstanding saltyfs `BACKEND_*` request the VFS owner has
//! fired via `mp_write_ctx` carries a matching [`SaltyfsOpKind`]
//! stamped into the generic [`PendingKindPayload`] on the
//! `PendingOp` arena entry. The payload stays opaque in the
//! generic pending / session / posix layers; only this module
//! and the saltyfs completion router interpret its bytes.
//!
//! Variants store only VFS-stable primitives: inode numbers,
//! inline name buffers, and descriptor-shaped protocol values
//! ([`TransferDescriptor`]). No handles, pointers, or borrowed
//! slices.
//!
//! # Packing contract
//!
//! [`SaltyfsOpKind::pack`] / [`SaltyfsOpKind::unpack`] use a simple
//! bytewise copy into / out of the fixed-size payload buffer. A
//! compile-time assertion below bounds `sizeof::<SaltyfsOpKind>()`
//! so growing a variant without adjusting the generic payload size
//! surfaces as a build error rather than a silent truncation.

use crate::ipc::protocol::backend::TransferDescriptor;
use crate::owner::pending::{PENDING_KIND_PAYLOAD_BYTES, PendingKindPayload, WALK_NAME_MAX};

const SIGNED_63_MAX: u64 = (1u64 << 63) - 1;

/// Which saltyfs RPC is parked.
#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) enum SaltyfsOpKind {
    /// `BACKEND_STAT { ino }`.
    Stat { ino: u64 },
    /// `BACKEND_LOOKUP { parent_ino, name }`.
    Lookup {
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_READLINK { ino }`.
    Readlink { ino: u64 },
    /// `BACKEND_GETXATTR { ino, name_len, name }`. Name is copied
    /// inline so the deferred-issue drain can replay the request
    /// after the SHM claim frees — without the inline copy the
    /// name would have to ride in the shared SHM region, the very
    /// lock the parked caller is waiting on.
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
    /// `BACKEND_WRITE { ino, file_offset, transfer }`. Mirror of
    /// `Read` — the payload rides via `transfer` (inline regs / SHM
    /// ring sub-region / per-RPC MemoryObject) and the completion
    /// handler harvests `bytes_written` from the reply and surfaces
    /// it back to the original caller via the PendingOp's saved
    /// reply lease.
    ///
    /// `transfer.offset` (when `kind == TRANSFER_KIND_SHM`) carries
    /// the byte offset of the leased SHM ring slot — completion
    /// frees the slot via `MountData::ring_free(offset / SALTYFS_RING_SLOT_BYTES)`.
    /// MO transfers self-clean inside `saltyfs_ipc_write_issue`
    /// (send-then-drop), so no per-op state is carried for that
    /// kind.
    Write {
        ino: u64,
        file_offset: u64,
        transfer: TransferDescriptor,
    },
    /// `BACKEND_FSYNC { ino, seq, flags }`. `flags` carries the
    /// fdatasync vs fsync discriminator; `0` is the conservative
    /// "flush data + metadata" default. `seq` is the backend
    /// incarnation of `ino`, retained so dependency-held fsync
    /// ops can be issued after their write predecessors settle.
    Fsync { ino: u64, seq: u32, flags: u32 },
    /// `BACKEND_READDIR { dir_ino, cookie, shm_offset, buf_bytes }`.
    Readdir {
        dir_ino: u64,
        cookie: u64,
        shm_offset: u64,
        buf_bytes: u64,
    },
    /// `BACKEND_SETATTR { ino, mask, mode, uid, gid, atime, mtime,
    /// size }`. `mask` is a bitwise-OR of `SETATTR_MASK_*` flags
    /// selecting which fields to apply; non-selected fields carry
    /// 0 on the wire and are ignored by the server.
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
    /// value }`. Name + value bytes ride in the per-mount-instance
    /// SHM region at offset 0 (`name[name_len] ||
    /// value[value_len]`). The inline copies on this op-kind exist
    /// for the deferred-issue drain path: when an async setxattr
    /// parks because the SHM region is held, the drain replays
    /// the memcpy into SHM before firing the IPC.
    SetXattr {
        ino: u64,
        name: [u8; WALK_NAME_MAX],
        value: [u8; WALK_NAME_MAX],
        name_len: u8,
        value_len: u16,
        flags: u32,
    },
    /// `BACKEND_REMOVEXATTR { ino, name_len, name }`.
    RemoveXattr {
        ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_CREATE { parent_ino, name, mode, uid, gid }`.
    /// Reply carries the new inode's id + full stat snapshot so
    /// the completion handler can materialise the child vnode.
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
    /// Both `name` and `target` ride as fixed-slot MR payload, not
    /// via the SHM region — so the deferred-issue drain rebuilds
    /// both payloads from this opaque record without any SHM
    /// dependency.
    Symlink {
        parent_ino: u64,
        uid: u32,
        gid: u32,
        name: [u8; WALK_NAME_MAX],
        target: [u8; 64],
        name_len: u8,
        target_len: u8,
    },
    /// `BACKEND_UNLINK { parent_ino, name }`.
    Unlink {
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_RMDIR { parent_ino, name }`.
    Rmdir {
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_LINK { target_ino, parent_ino, name }`.
    Link {
        target_ino: u64,
        parent_ino: u64,
        name: [u8; WALK_NAME_MAX],
        name_len: u8,
    },
    /// `BACKEND_RENAME { old_parent_ino, old_name, new_parent_ino,
    /// new_name }`. Cross-mount rename is rejected pre-issue with
    /// `EXDEV`, so `Rename` is always intra-mount.
    Rename {
        old_parent_ino: u64,
        new_parent_ino: u64,
        old_name: [u8; WALK_NAME_MAX],
        new_name: [u8; WALK_NAME_MAX],
        old_name_len: u8,
        new_name_len: u8,
    },
    /// `BACKEND_TRUNCATE { ino, new_size }`.
    Truncate { ino: u64, new_size: u64 },
}

const _: () = assert!(
    ::core::mem::size_of::<SaltyfsOpKind>() <= PENDING_KIND_PAYLOAD_BYTES,
    "SaltyfsOpKind outgrew PendingKindPayload — bump PENDING_KIND_PAYLOAD_WORDS",
);

impl SaltyfsOpKind {
    /// Serialise into a [`PendingKindPayload`] for arena storage.
    /// Bytewise-stable across `pack` / `unpack` round trips on the
    /// same binary; not designed to migrate between incompatible
    /// builds.
    #[inline]
    pub(crate) fn pack(&self) -> PendingKindPayload {
        let mut payload = PendingKindPayload::zeroed();
        // SAFETY: `PENDING_KIND_PAYLOAD_BYTES` is bounded ≥ the
        // struct size by the `const _` assertion above; `payload`
        // is fresh and contains no initialised interior references.
        unsafe {
            let src = self as *const Self as *const u8;
            let dst = payload.words.as_mut_ptr() as *mut u8;
            ::core::ptr::copy_nonoverlapping(src, dst, ::core::mem::size_of::<Self>());
        }
        payload
    }

    /// Deserialise a [`PendingKindPayload`] previously produced by
    /// [`SaltyfsOpKind::pack`].
    ///
    /// # Safety
    ///
    /// `payload` must have been produced by a `pack` call on the
    /// current binary — the generic pending layer carries
    /// payloads opaquely between pack and unpack, so in-process
    /// callers satisfy this by construction.
    #[inline]
    pub(crate) unsafe fn unpack(payload: &PendingKindPayload) -> Self {
        unsafe {
            let mut out = ::core::mem::MaybeUninit::<Self>::uninit();
            let src = payload.words.as_ptr() as *const u8;
            let dst = out.as_mut_ptr() as *mut u8;
            ::core::ptr::copy_nonoverlapping(src, dst, ::core::mem::size_of::<Self>());
            out.assume_init()
        }
    }

    /// Validate the request snapshot before a backend completion
    /// consumes it. `PendingKindPayload` is an opaque byte record in
    /// the generic session layer; this check keeps a stale or
    /// malformed payload from driving the saltyfs completion router
    /// down the wrong projection path.
    pub(crate) fn validate_completion_envelope(&self) -> bool {
        match self {
            SaltyfsOpKind::Stat { ino }
            | SaltyfsOpKind::Readlink { ino }
            | SaltyfsOpKind::ListXattr { ino }
            | SaltyfsOpKind::Truncate { ino, .. } => *ino != 0,
            SaltyfsOpKind::Lookup {
                parent_ino,
                name,
                name_len,
            } => *parent_ino != 0 && valid_name(name, *name_len),
            SaltyfsOpKind::XattrGet {
                ino,
                name,
                name_len,
            }
            | SaltyfsOpKind::RemoveXattr {
                ino,
                name,
                name_len,
            } => *ino != 0 && valid_xattr_name(name, *name_len),
            SaltyfsOpKind::Read {
                ino,
                file_offset,
                transfer,
            }
            | SaltyfsOpKind::Write {
                ino,
                file_offset,
                transfer,
            } => *ino != 0 && *file_offset <= SIGNED_63_MAX && valid_transfer(*transfer),
            SaltyfsOpKind::Fsync { ino, seq, flags } => {
                *ino != 0 && *seq != u32::MAX && (*flags & !1) == 0
            }
            SaltyfsOpKind::Readdir {
                dir_ino,
                cookie,
                shm_offset,
                buf_bytes,
            } => {
                *dir_ino != 0
                    && *cookie <= i64::MAX as u64
                    && (*shm_offset & 0xFFF) == 0
                    && *buf_bytes != 0
            }
            SaltyfsOpKind::SetAttr {
                ino,
                mask,
                mode,
                uid,
                gid,
                atime,
                mtime,
                size,
            } => {
                const KNOWN_SETATTR_MASK: u32 = trona_protocol::vfs::backend::SETATTR_MASK_MODE
                    | trona_protocol::vfs::backend::SETATTR_MASK_UID
                    | trona_protocol::vfs::backend::SETATTR_MASK_GID
                    | trona_protocol::vfs::backend::SETATTR_MASK_ATIME
                    | trona_protocol::vfs::backend::SETATTR_MASK_MTIME
                    | trona_protocol::vfs::backend::SETATTR_MASK_SIZE;
                let mode_ok = (*mask & trona_protocol::vfs::backend::SETATTR_MASK_MODE) == 0
                    || (*mode & !0o7777) == 0;
                let owner_ok = ((*mask & trona_protocol::vfs::backend::SETATTR_MASK_UID) == 0
                    || *uid != u32::MAX)
                    && ((*mask & trona_protocol::vfs::backend::SETATTR_MASK_GID) == 0
                        || *gid != u32::MAX);
                *ino != 0
                    && *mask != 0
                    && (*mask & !KNOWN_SETATTR_MASK) == 0
                    && mode_ok
                    && owner_ok
                    && *atime <= SIGNED_63_MAX
                    && *mtime <= SIGNED_63_MAX
                    && *size <= SIGNED_63_MAX
            }
            SaltyfsOpKind::SetXattr {
                ino,
                name,
                value,
                name_len,
                value_len,
                flags,
            } => {
                const KNOWN_XATTR_FLAGS: u32 =
                    crate::core::vop::XATTR_CREATE | crate::core::vop::XATTR_REPLACE;
                *ino != 0
                    && valid_xattr_name(name, *name_len)
                    && usize::from(*value_len) <= value.len()
                    && (*flags & !KNOWN_XATTR_FLAGS) == 0
                    && (*flags & KNOWN_XATTR_FLAGS) != KNOWN_XATTR_FLAGS
            }
            SaltyfsOpKind::Create {
                parent_ino,
                mode,
                uid,
                gid,
                name,
                name_len,
            }
            | SaltyfsOpKind::Mkdir {
                parent_ino,
                mode,
                uid,
                gid,
                name,
                name_len,
            } => {
                *parent_ino != 0
                    && (*mode & !0o7777) == 0
                    && *uid != u32::MAX
                    && *gid != u32::MAX
                    && valid_name(name, *name_len)
            }
            SaltyfsOpKind::Symlink {
                parent_ino,
                uid,
                gid,
                name,
                target,
                name_len,
                target_len,
            } => {
                *parent_ino != 0
                    && *uid != u32::MAX
                    && *gid != u32::MAX
                    && valid_name(name, *name_len)
                    && valid_symlink_target(target, *target_len)
            }
            SaltyfsOpKind::Unlink {
                parent_ino,
                name,
                name_len,
            }
            | SaltyfsOpKind::Rmdir {
                parent_ino,
                name,
                name_len,
            } => *parent_ino != 0 && valid_name(name, *name_len),
            SaltyfsOpKind::Link {
                target_ino,
                parent_ino,
                name,
                name_len,
            } => *target_ino != 0 && *parent_ino != 0 && valid_name(name, *name_len),
            SaltyfsOpKind::Rename {
                old_parent_ino,
                new_parent_ino,
                old_name,
                new_name,
                old_name_len,
                new_name_len,
            } => {
                *old_parent_ino != 0
                    && *new_parent_ino != 0
                    && valid_name(old_name, *old_name_len)
                    && valid_name(new_name, *new_name_len)
            }
        }
    }
}

fn valid_name(name: &[u8; WALK_NAME_MAX], len: u8) -> bool {
    let n = usize::from(len);
    n != 0 && n <= name.len() && !name[..n].iter().any(|b| *b == 0)
}

fn valid_xattr_name(name: &[u8; WALK_NAME_MAX], len: u8) -> bool {
    valid_name(name, len)
}

fn valid_symlink_target(target: &[u8; 64], len: u8) -> bool {
    let n = usize::from(len);
    n != 0 && n <= target.len() && !target[..n].iter().any(|b| *b == 0)
}

fn valid_transfer(transfer: TransferDescriptor) -> bool {
    if transfer.flags != 0 {
        return false;
    }
    match transfer.kind {
        trona_protocol::vfs::backend::TRANSFER_KIND_INLINE
        | trona_protocol::vfs::backend::TRANSFER_KIND_MO => transfer.offset == 0,
        trona_protocol::vfs::backend::TRANSFER_KIND_SHM => true,
        _ => false,
    }
}
