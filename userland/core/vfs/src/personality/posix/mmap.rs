// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_GET_BACKING_MO` — file-backed pager MO accessor.
//!
//! mmap straddles two memory layers:
//!
//! 1. **mmsrv** owns the address-space machinery — VSpace mappings,
//!    page allocation, COW, MAP_SHARED region tables.
//! 2. **vfs** owns the file backing — the bytes a `mmap(fd, ..)` call
//!    sees at any given offset, the dirty-page writeback path, and
//!    the page cache.
//!
//! Cleanslate split (Pager-cap edition): clients run a two-step
//! `mmap` flow:
//!
//! * `VFS_GET_BACKING_MO(fd, offset, length)` — vfs returns the
//!   pager-attached MO cap it has registered with mmsrv (vfs miss
//!   issues `MM_FILE_MMAP` to mmsrv internally to retype the MO and
//!   attach the pager).
//! * `MM_MMAP(kind=MMAP_KIND_MO, caps[0]=mo_cap, hint, length, prot,
//!   flags, mo_offset)` — client lands the MO in its own vspace via
//!   its per-client mmsrv MP.
//!
//! Anonymous mmap (`fd == -1` or `MAP_ANONYMOUS`) goes the opposite
//! way: clients call `MM_MMAP(kind=ANON, ...)` directly against
//! mmsrv and never touch vfs.
//!
//! There is no `VFS_MMAP` broker label any more — vfs is not a
//! cross-client broker for mmsrv self-tier traffic. Brokering would
//! require either an admin-tier mmsrv label (cross-client mapping)
//! or delegation of the caller's mmsrv send cap (and the cap has
//! no label-level attenuation, so delegation grants more than
//! `mmap`-class authority). The two-step flow keeps each layer's
//! authority self-contained.
//!
//! ## Wire layout
//!
//! `VFS_GET_BACKING_MO`:
//! - `regs[0]` = `fd`.
//! - `regs[1]` = `offset` (informational; the MO covers the full
//!   file — vfs uses the offset to decide whether to register a
//!   fresh page-cache window).
//! - `regs[2]` = `length` (informational; same).
//!
//! Reply: `caps[0] = backing_cap`,
//! `regs[VFS_BACKING_MO_REPLY_REG_SIZE] = backing_size`,
//! `regs[VFS_BACKING_MO_REPLY_REG_OFFSET] = mo_offset`,
//! `regs[VFS_BACKING_MO_REPLY_REG_MMAP_KIND] = mmap_kind`,
//! `regs[VFS_BACKING_MO_REPLY_REG_BACKING_ID] = mo_id`,
//! `regs[VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH] = backing_length`.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::core::vnode::{VnodeHandle, VnodeKind};
use crate::owner::VfsState;
use crate::personality::wire::send_reply_err_for_client;
use crate::server::open_object::OpenObjectKind;
use crate::server::types::ClientHandle;
use trona_protocol::vfs::public::{
    VFS_BACKING_MO_REPLY_REG_BACKING_ID, VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH,
    VFS_BACKING_MO_REPLY_REG_COUNT, VFS_BACKING_MO_REPLY_REG_MMAP_KIND,
    VFS_BACKING_MO_REPLY_REG_OFFSET, VFS_BACKING_MO_REPLY_REG_SIZE, VFS_GET_BACKING_MO,
};

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match msg.label {
            VFS_GET_BACKING_MO => handle_get_backing_mo(state, client, msg, reply_lease),
            _ => send_reply_err_for_client(state, client, reply_lease, VfsError::Inval),
        }
    }
}

unsafe fn handle_get_backing_mo(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        if msg.length < 3 {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        let fd = match i32::try_from(msg.regs[0]) {
            Ok(v) => v,
            Err(_) => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::BadF);
                return;
            }
        };
        let offset = msg.regs[1];
        let length = msg.regs[2];
        if length == 0 {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }

        // POSIX shm fds carry no vnode — the size lives in `ShmData` and the
        // backing is a vfs-owned anonymous MO with no pager. Serve that MO
        // cap directly instead of resolving a vnode (the vnode/pager path
        // does not apply). Mirrors the shm branch in `do_truncate_fd`.
        if let Some(open_h) = state.open_object_at(client, fd as usize) {
            let shm_aux = state
                .open_objects
                .get(open_h)
                .filter(|o| o.kind == OpenObjectKind::Shm)
                .map(|o| o.personality_aux);
            if let Some(aux_slot) = shm_aux {
                reply_get_backing_mo_shm(state, client, aux_slot, offset, reply_lease);
                return;
            }
        }

        let vh = match resolve_fd_vnode(state, client, fd) {
            Ok(h) => h,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };
        if crate::personality::posix::device::fb_target_for_vnode(state, vh) {
            match crate::personality::posix::device::issue_fb_get_backing(state, vh) {
                Ok(handle) => {
                    let client_badge = state
                        .clients
                        .get(client)
                        .map(|c| c.client_badge)
                        .unwrap_or(0);
                    crate::personality::posix::device::stamp_fb_resume(
                        state,
                        handle,
                        vh,
                        crate::owner::fb_completion::FBRESUME_OP_GET_BACKING_MO,
                        0,
                        reply_lease,
                        client_badge,
                    );
                }
                Err(e) => send_reply_err_for_client(state, client, reply_lease, e),
            }
            return;
        }
        let backing = match crate::owner::mm_ipc::ensure_backing_mo_for_vnode(state, vh) {
            Ok(info) => info,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        let mut out = TronaMsg::default();
        out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
        let mo_offset = match offset.checked_sub(backing.file_offset) {
            Some(v) => v,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
        };
        out.regs[VFS_BACKING_MO_REPLY_REG_SIZE] = backing.size;
        out.regs[VFS_BACKING_MO_REPLY_REG_OFFSET] = mo_offset;
        out.regs[VFS_BACKING_MO_REPLY_REG_MMAP_KIND] = trona_protocol::mm::MMAP_KIND_MO;
        out.regs[VFS_BACKING_MO_REPLY_REG_BACKING_ID] = backing.mo_id;
        out.regs[VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH] = backing.length;
        out.length = VFS_BACKING_MO_REPLY_REG_COUNT;
        // vfs keeps `backing.mo_cap` as the file's pager MO; the client maps
        // from a disposable, non-executable copy. A mapped file MO is data,
        // never a code source — executable code is conferred only through
        // ldsrv. (The pager MO carries no EXECUTE after K1 anyway, so the
        // explicit strip is defense-in-depth.)
        let cap = match trona_runtime::core::slot_alloc::dup_for_transfer_with_rights(
            trona_runtime::core::slot_alloc::resolved_cap_ref(backing.mo_cap),
            (uapi::KERNITE_RIGHT_ALL & !uapi::KERNITE_RIGHT_EXECUTE) as u64,
        ) {
            Some(c) => c,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                return;
            }
        };
        crate::owner::op::reply_send_with_cap(reply_lease, &out, cap);
    }
}

/// `VFS_GET_BACKING_MO` for a POSIX shm fd. shm carries no vnode: the
/// backing is a vfs-owned anonymous MO recorded in `ShmData`. Hand the
/// client a disposable copy of that MO cap with `mmap_kind=MMAP_KIND_MO`
/// and `mo_offset=offset` (the MO is the whole object, so `file_offset`
/// is 0). `size` / `backing_length` / `backing_id` are informational for
/// the client — it maps through the MO cap alone — but are filled from
/// `ShmData` rather than left as garbage.
fn reply_get_backing_mo_shm(
    state: &mut VfsState,
    client: ClientHandle,
    aux_slot: u32,
    offset: u64,
    reply_lease: trona_server::ReplyLease,
) {
    let Some(shm_h) = state.shm_data.handle_from_slot(aux_slot) else {
        send_reply_err_for_client(state, client, reply_lease, VfsError::BadF);
        return;
    };
    let shm_info = state
        .shm_data
        .get(shm_h)
        .map(|s| (s.mo_cap.as_raw(), s.size));
    let (mo_raw, size) = match shm_info {
        Some(v) => v,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::BadF);
            return;
        }
    };
    if mo_raw == 0 {
        send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
        return;
    }
    let page_bytes = uapi::KERNITE_PAGE_BYTES as u64;
    let backing_length = size.div_ceil(page_bytes).max(1) * page_bytes;

    let mut out = TronaMsg::default();
    out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
    out.regs[VFS_BACKING_MO_REPLY_REG_SIZE] = size;
    out.regs[VFS_BACKING_MO_REPLY_REG_OFFSET] = offset;
    out.regs[VFS_BACKING_MO_REPLY_REG_MMAP_KIND] = trona_protocol::mm::MMAP_KIND_SHM_MO;
    out.regs[VFS_BACKING_MO_REPLY_REG_BACKING_ID] = aux_slot as u64;
    out.regs[VFS_BACKING_MO_REPLY_REG_BACKING_LENGTH] = backing_length;
    out.length = VFS_BACKING_MO_REPLY_REG_COUNT;

    // The shm MO copy is non-executable (shm is data; see the file path above).
    let cap = match trona_runtime::core::slot_alloc::dup_for_transfer_with_rights(
        trona_runtime::core::slot_alloc::resolved_cap_ref(mo_raw),
        (uapi::KERNITE_RIGHT_ALL & !uapi::KERNITE_RIGHT_EXECUTE) as u64,
    ) {
        Some(c) => c,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    crate::owner::op::reply_send_with_cap(reply_lease, &out, cap);
}

fn resolve_fd_vnode(
    state: &VfsState,
    client: ClientHandle,
    fd: i32,
) -> Result<VnodeHandle, VfsError> {
    if fd < 0 {
        return Err(VfsError::BadF);
    }
    let cli = state.clients.get(client).ok_or(VfsError::Io)?;
    let fd_idx = u32::try_from(fd).map_err(|_| VfsError::BadF)?;
    let oh = cli.slot_table.lookup(fd_idx).ok_or(VfsError::BadF)?;
    let obj = state.open_objects.get(oh).ok_or(VfsError::BadF)?;
    if !obj.vnode.is_valid() {
        return Err(VfsError::BadF);
    }
    let kind = state
        .vnodes
        .get(obj.vnode)
        .map(|v| v.kind)
        .unwrap_or(VnodeKind::Empty);
    match kind {
        VnodeKind::Regular | VnodeKind::CharDev => Ok(obj.vnode),
        VnodeKind::Directory => Err(VfsError::IsDir),
        _ => Err(VfsError::Inval),
    }
}
