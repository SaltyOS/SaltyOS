// SPDX-License-Identifier: GPL-2.0-only
//
//! Directory enumeration logic helper. POSIX `getdents` /
//! `getdents64`, and Win32 directory queries. Both fan into the
//! same `data.readdir` vop; the reply emitter projects the
//! personality-neutral entries onto the requested record layout.

use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::core::outcome::{Parked, Ready};
use crate::ops::ReadDirReplyIntent;
use crate::owner::VfsState;
use crate::owner::resume::{FsResume, Resume};
use crate::personality::reply::{READDIR_FIRST_ENTRY_NAME_MAX, ReaddirReplyData};
use crate::server::open_object::OpenObjectFlags;
use crate::server::types::ClientHandle;

/// Drive the `data.readdir` vop on `fd`. The worker-io readdir
/// bridge returns one entry per call for owner-local filesystems
/// and parks on `FsResume::BulkReaddirStage` for backend-backed
/// mounts such as saltyfs.
pub(crate) unsafe fn do_readdir_from_fd(
    state: &mut VfsState,
    client: ClientHandle,
    fd: i32,
    cookie: u64,
    reply_intent: ReadDirReplyIntent,
    reply_lease: ReplyLease,
) {
    unsafe {
        if fd < 0 {
            emit_dir_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        }
        let Some(open_h) = state.open_object_at(client, fd as usize) else {
            emit_dir_error(reply_lease, reply_intent, VfsError::BadF);
            return;
        };
        let (vnode_h, open_cursor) = match state.open_objects.get(open_h) {
            Some(obj) if (obj.flags & OpenObjectFlags::O_DIRECTORY) != 0 => (obj.vnode, obj.offset),
            Some(_) => {
                emit_dir_error(reply_lease, reply_intent, VfsError::NotDir);
                return;
            }
            None => {
                emit_dir_error(reply_lease, reply_intent, VfsError::BadF);
                return;
            }
        };
        let start_cursor = if cookie == 0 { open_cursor } else { cookie };
        let (vkey, fs_id) = match state.vnodes.get(vnode_h) {
            Some(vnode) => {
                let fs_id = state
                    .mounts
                    .get(vnode.mount)
                    .map(|m| m.fs_instance_id)
                    .unwrap_or(crate::core::identity::FsInstanceId::INVALID);
                (vnode.key, fs_id)
            }
            None => {
                emit_dir_error(reply_lease, reply_intent, VfsError::Io);
                return;
            }
        };

        let Some(ctx_owner) = crate::core::vop_context::OwnerVopCtx::from_state(state, vnode_h)
        else {
            emit_dir_error(reply_lease, reply_intent, VfsError::Io);
            return;
        };
        let ops = (*ctx_owner.vnode).ops;
        if ops.is_null() {
            emit_dir_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }
        if ((*ops).data.readdir as usize) == 0 {
            emit_dir_error(reply_lease, reply_intent, VfsError::Io);
            return;
        }

        let data_ctx = ctx_owner.data_ctx().with_open_object(open_h);
        let mut next_cursor = start_cursor;
        let mut first = ReaddirReplyData {
            next_cursor: start_cursor,
            entries_written: 0,
            bytes_written: 0,
            first_entry_ino: 0,
            first_entry_dtype: 0,
            first_entry_name_len: 0,
            first_entry_name: [0u8; READDIR_FIRST_ENTRY_NAME_MAX],
        };
        let mut emit = |ino: u64,
                        name: *const u8,
                        name_len: u8,
                        dtype: u8,
                        _attr: &crate::core::file::VAttr|
         -> bool {
            if first.entries_written == 0 {
                let copy_len = (name_len as usize).min(READDIR_FIRST_ENTRY_NAME_MAX);
                first.first_entry_ino = ino;
                first.first_entry_dtype = dtype;
                first.first_entry_name_len = copy_len;
                for i in 0..copy_len {
                    first.first_entry_name[i] = *name.add(i);
                }
                first.entries_written = 1;
                first.bytes_written = copy_len as u32;
            }
            false
        };

        match ((*ops).data.readdir)(&data_ctx, &mut next_cursor, &mut emit) {
            Ok(Ready(())) => {
                first.next_cursor = next_cursor;
                if let Some(obj) = state.open_objects.get_mut(open_h) {
                    obj.offset = next_cursor;
                }
                crate::personality::reply::emit_readdir_batch(reply_lease, reply_intent, Ok(first));
            }
            Ok(Parked(handle)) => {
                // procfs `/proc` readdir parks on an init `LIST_PIDS` query
                // (`Resume::Init`); the init machine emits the dirent at
                // finalize. Backend dirs are not init ops and fall through
                // to the normal `BulkReaddirStage` park.
                match crate::owner::init_rpc::attach_lease_if_init(state, handle, reply_lease) {
                    Ok(()) => {}
                    Err(reply_lease) => {
                        let badge = state
                            .clients
                            .get(client)
                            .map(|c| c.client_badge)
                            .unwrap_or(0);
                        if let Err(Some(reply_lease)) = state.stamp_resume_ctx(
                            handle,
                            badge,
                            Some(reply_lease),
                            Resume::Fs(FsResume::BulkReaddirStage {
                                client,
                                dir_vkey: vkey,
                                fs_id,
                                fd,
                                open_handle: open_h,
                                start_cursor,
                                reply: reply_intent,
                            }),
                        ) {
                            emit_dir_error(reply_lease, reply_intent, VfsError::Busy);
                        }
                    }
                }
            }
            Err(e) => {
                emit_dir_error(reply_lease, reply_intent, e);
            }
        }
    }
}

unsafe fn emit_dir_error(reply_lease: ReplyLease, intent: ReadDirReplyIntent, err: VfsError) {
    unsafe {
        crate::personality::reply::emit_dir(reply_lease, intent, Err(err));
    }
}
