// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX leaf-attribute mutation entries —
//! `VFS_CHMOD` / `VFS_FCHMOD` / `VFS_CHOWN` / `VFS_FCHOWN` /
//! `VFS_UTIMES` / `VFS_FUTIMES` / `VFS_TRUNCATE`.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::{AckReplyIntent, SetAttrKind};
use crate::owner::VfsState;
use crate::owner::pending::WALK_PATH_MAX;
use crate::server::types::ClientHandle;

/// `VFS_CHMOD` — `regs[0]=anchor_fd`, `regs[1]=mode`,
/// `regs[2]=flags` (`AT_SYMLINK_NOFOLLOW`), `regs[3]=path_len`,
/// `regs[4..]=path`. Serves both `chmod` and `fchmodat`.
pub(crate) unsafe fn handle_chmod(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
        let mode = msg.regs[1] as u32;
        let follow = (msg.regs[2] as u32 & AT_SYMLINK_NOFOLLOW) == 0;
        dispatch_path_setattr_with_path_words(
            state,
            client,
            msg,
            SetAttrKind::Mode { mode },
            /* path_len_idx = */ 3,
            /* path_words_start = */ 4,
            follow,
            reply_lease,
        );
    }
}

/// `VFS_FCHMOD` — `regs[0]=fd`, `regs[1]=mode`.
pub(crate) unsafe fn handle_fchmod(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let mode = msg.regs[1] as u32;
        let Some(vnode_h) = resolve_fd_vnode(state, client, fd) else {
            super::reply::emit_error(reply_lease, VfsError::BadF);
            return;
        };
        crate::ops::set_attr::do_setattr_for_vnode(
            state,
            client,
            vnode_h,
            SetAttrKind::Mode { mode },
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

/// `VFS_CHOWN` — `regs[0]=anchor_fd`, `regs[1]=uid`,
/// `regs[2]=gid`, `regs[3]=flags` (`AT_SYMLINK_NOFOLLOW`),
/// `regs[4]=path_len`, `regs[5..]=path`. Serves `chown` / `lchown` /
/// `fchownat`. `uid==u32::MAX` / `gid==u32::MAX` mean "do not change".
pub(crate) unsafe fn handle_chown(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
        let uid = msg.regs[1] as u32;
        let gid = msg.regs[2] as u32;
        let follow = (msg.regs[3] as u32 & AT_SYMLINK_NOFOLLOW) == 0;
        let kind = SetAttrKind::Owner {
            uid: if uid == u32::MAX { None } else { Some(uid) },
            gid: if gid == u32::MAX { None } else { Some(gid) },
        };
        dispatch_path_setattr_with_path_words(
            state,
            client,
            msg,
            kind,
            /* path_len_idx = */ 4,
            /* path_words_start = */ 5,
            follow,
            reply_lease,
        );
    }
}

/// `VFS_FCHOWN` — `regs[0]=fd`, `regs[1]=uid`, `regs[2]=gid`.
pub(crate) unsafe fn handle_fchown(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let uid = msg.regs[1] as u32;
        let gid = msg.regs[2] as u32;
        let Some(vnode_h) = resolve_fd_vnode(state, client, fd) else {
            super::reply::emit_error(reply_lease, VfsError::BadF);
            return;
        };
        let kind = SetAttrKind::Owner {
            uid: if uid == u32::MAX { None } else { Some(uid) },
            gid: if gid == u32::MAX { None } else { Some(gid) },
        };
        crate::ops::set_attr::do_setattr_for_vnode(
            state,
            client,
            vnode_h,
            kind,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

/// `VFS_UTIMES` / `VFS_UTIMENSAT` — `regs[0]=anchor_fd`,
/// `regs[1]=flags`, `regs[2]=atime_ns`, `regs[3]=mtime_ns`,
/// `regs[4]=path_len`, `regs[5..]=path`. `0` ns means "do not
/// touch".
pub(crate) unsafe fn handle_utimes(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let flags = msg.regs[1] as u32;
        let atime = msg.regs[2];
        let mtime = msg.regs[3];
        let kind = SetAttrKind::Times {
            atime_nanos: if atime == 0 { None } else { Some(atime) },
            mtime_nanos: if mtime == 0 { None } else { Some(mtime) },
        };
        const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
        let follow = (flags & AT_SYMLINK_NOFOLLOW) == 0;
        dispatch_path_setattr_with_path_words(
            state,
            client,
            msg,
            kind,
            /* path_len_idx = */ 4,
            /* path_words_start = */ 5,
            follow,
            reply_lease,
        );
    }
}

/// `VFS_FUTIMES` — `regs[0]=fd`, `regs[1]=atime_ns`, `regs[2]=mtime_ns`.
pub(crate) unsafe fn handle_futimes(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let atime = msg.regs[1];
        let mtime = msg.regs[2];
        let Some(vnode_h) = resolve_fd_vnode(state, client, fd) else {
            super::reply::emit_error(reply_lease, VfsError::BadF);
            return;
        };
        let kind = SetAttrKind::Times {
            atime_nanos: if atime == 0 { None } else { Some(atime) },
            mtime_nanos: if mtime == 0 { None } else { Some(mtime) },
        };
        crate::ops::set_attr::do_setattr_for_vnode(
            state,
            client,
            vnode_h,
            kind,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

/// `VFS_TRUNCATE` (path-based) — `regs[0]=anchor_fd`,
/// `regs[1]=new_size`, `regs[2]=path_len`, `regs[3..]=path`.
pub(crate) unsafe fn handle_truncate(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let new_size = msg.regs[1];
        let path_len = msg.regs[2] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        let mut path_buf = [0u8; WALK_PATH_MAX];
        super::wire::decode_path_bytes(msg, 3, path_len, &mut path_buf);
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        crate::ops::set_attr::do_truncate_path_from_bytes(
            state,
            client,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            new_size,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

unsafe fn dispatch_path_setattr(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    kind: SetAttrKind,
    follow_leaf: bool,
    reply_lease: ReplyLease,
) {
    unsafe {
        dispatch_path_setattr_with_path_words(
            state,
            client,
            msg,
            kind,
            /* path_len_idx = */ 2,
            /* path_words_start = */ 3,
            follow_leaf,
            reply_lease,
        );
    }
}

unsafe fn dispatch_path_setattr_with_path_words(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    kind: SetAttrKind,
    path_len_idx: usize,
    path_words_start: usize,
    follow_leaf: bool,
    reply_lease: ReplyLease,
) {
    unsafe {
        let anchor_fd = msg.regs[0] as i32;
        let path_len = msg.regs[path_len_idx] as usize;
        if path_len == 0 || path_len > WALK_PATH_MAX {
            super::reply::emit_error(reply_lease, VfsError::Inval);
            return;
        }
        let mut path_buf = [0u8; WALK_PATH_MAX];
        super::wire::decode_path_bytes(msg, path_words_start, path_len, &mut path_buf);
        let anchor_vkey = crate::ops::anchor::resolve_dirfd_vkey(state, client, anchor_fd);
        crate::ops::set_attr::do_setattr_from_bytes(
            state,
            client,
            anchor_vkey,
            &path_buf[..path_len],
            path_len,
            kind,
            follow_leaf,
            AckReplyIntent::PosixAck,
            reply_lease,
        );
    }
}

unsafe fn resolve_fd_vnode(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Option<crate::core::vnode::VnodeHandle> {
    if fd < 0 {
        return None;
    }
    let open_h = state.open_object_at(client, fd as usize)?;
    state.open_objects.get(open_h).map(|obj| obj.vnode)
}
