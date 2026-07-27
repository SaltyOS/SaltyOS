// SPDX-License-Identifier: GPL-2.0-only
//
//! POSIX shared memory — `VFS_SHM_OPEN` / `VFS_SHM_UNLINK`.
//!
//! POSIX `shm_open` / `shm_unlink` lives in a flat namespace
//! distinct from the regular filesystem tree (`/dev/shm` is the
//! conventional mount point on Linux but the lookup goes through
//! a vfs-internal table rather than the directory walker —
//! `shm_unlink` removes the name without traversing a parent
//! directory and `shm_open` does not honour `..` or symlinks).
//!
//! The backing storage is an mmsrv file-backed `MemoryObject`. vfs
//! holds the MO cap; subsequent `mmap(fd, ...)` calls hand the cap
//! through to the caller via `VFS_GET_BACKING_MO`. Refcount tracks
//! the open-side count plus the name-table entry — the [`ShmData`]
//! slot is reclaimed only when both reach zero, so a process that
//! holds an open fd survives an `shm_unlink` against the same name
//! exactly the way POSIX requires.
//!
//! Wire layout matches `VFS_OPEN` (scalar args in the low registers,
//! then the `pack_path`-encoded name):
//! - `VFS_SHM_OPEN`: `regs[0]` = `flags` (`O_CREAT`, `O_EXCL`,
//!   `O_RDONLY`, ...); `regs[1]` = `mode` (recorded, not enforced);
//!   `regs[2]` = `size_hint` (only consulted with `O_CREAT`; `shm_open`
//!   itself passes 0 and `ftruncate` sets the size); `regs[3]` =
//!   `name_len`; `regs[4..]` = name bytes (<= 32). `O_CREAT` folds the
//!   create path into this label — there is no separate create label.
//! - `VFS_SHM_UNLINK`: `regs[0]` = `name_len`; `regs[1..]` = name bytes.
//!
//! Reply: `VFS_SHM_OPEN` replies `regs[0] = fd`, `regs[1] =
//! current_size`. `VFS_SHM_UNLINK` replies with no payload on success.

use trona_kernel::core_types::TronaMsg;

use crate::arena::handle::Handle;
use crate::core::error::VfsError;
use crate::core::shm::ShmData;
use crate::owner::VfsState;
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::open_object::{OpenObject, OpenObjectAccess, OpenObjectFlags, OpenObjectKind};
use crate::server::types::ClientHandle;
use trona_protocol::vfs::public::{VFS_SHM_OPEN, VFS_SHM_UNLINK};

const SHM_NAME_INLINE_MAX: usize = 32;

const O_RDONLY: u64 = 0;
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_ACCMODE: u64 = 3;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        match msg.label {
            // O_CREAT folds into the open path (no separate create label),
            // matching VFS_OPEN. handle_open dispatches to the create routine
            // on the O_CREAT flag.
            VFS_SHM_OPEN => handle_open(state, client, msg, reply_lease),
            VFS_SHM_UNLINK => handle_unlink(state, client, msg, reply_lease),
            _ => send_reply_err_for_client(state, client, reply_lease, VfsError::Inval),
        }
    }
}

unsafe fn handle_create(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let flags = msg.regs[0];
        let _mode = msg.regs[1] as u32;
        let size_hint = msg.regs[2];
        let (name, name_len) = match decode_name(msg, 3) {
            Some(n) => n,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
        };
        let exclusive = (flags & O_EXCL) != 0;
        let acc_mode = flags & O_ACCMODE;

        if let Some(_existing) = lookup_by_name(state, &name[..name_len]) {
            if exclusive {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Exist);
                return;
            }
            // Fall through to open path semantics.
            return finish_open(state, client, &name[..name_len], acc_mode, reply_lease);
        }

        // Allocate the descriptor + retype the backing MO.
        let shm_h = match state.shm_data.alloc() {
            Some(h) => h,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                return;
            }
        };
        let mo_cap = match retype_backing_mo(state, size_hint) {
            Ok(cap) => cap,
            Err(e) => {
                state.shm_data.release(shm_h);
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };
        if let Some(s) = state.shm_data.get_mut(shm_h) {
            *s = ShmData::zeroed();
            s.active = 1;
            s.size = size_hint;
            s.mo_cap = trona_runtime::core::slot_alloc::OwnedCap::adopt_received(mo_cap);
            s.refcount = 1; // name-table entry holds the first reference
        }
        if !register_name(state, &name[..name_len], shm_h) {
            // s.mo_cap was just adopted — take it back out before release
            // so the arena slot Drop is a no-op, then release the raw cap.
            if let Some(s) = state.shm_data.get_mut(shm_h) {
                let taken = core::mem::replace(
                    &mut s.mo_cap,
                    trona_runtime::core::slot_alloc::OwnedCap::null(),
                );
                drop(taken);
            }
            // mo_cap was moved into OwnedCap above; Drop fires once
            // via the `taken` drop. Release the arena slot once.
            state.shm_data.release(shm_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }

        finish_open(state, client, &name[..name_len], acc_mode, reply_lease);
    }
}

unsafe fn handle_open(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let flags = msg.regs[0];
        // O_CREAT folds into the open path (matching VFS_OPEN): there is no
        // separate create label, so a create request lands here and is
        // dispatched to the create routine by the flag.
        if (flags & O_CREAT) != 0 {
            return handle_create(state, client, msg, reply_lease);
        }
        let (name, name_len) = match decode_name(msg, 3) {
            Some(n) => n,
            None => {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
        };
        let acc_mode = flags & O_ACCMODE;
        finish_open(state, client, &name[..name_len], acc_mode, reply_lease);
    }
}

unsafe fn handle_unlink(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    let (name, name_len) = match decode_name(msg, 0) {
        Some(n) => n,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
    };
    let shm_h = match unregister_name(state, &name[..name_len]) {
        Some(h) => h,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoEnt);
            return;
        }
    };
    // Drop the name-table reference. If no fds still pin it, the
    // descriptor and MO are reclaimed inline.
    let mut release_now = false;
    if let Some(s) = state.shm_data.get_mut(shm_h) {
        s.refcount = s.refcount.saturating_sub(1);
        release_now = s.refcount == 0;
    }
    if release_now {
        // Extract the cap via mem::replace so the arena slot Drop is a
        // no-op; then fire the single release below.
        let mo_cap_owned = state.shm_data.get_mut(shm_h).and_then(|s| {
            Some(core::mem::replace(
                &mut s.mo_cap,
                trona_runtime::core::slot_alloc::OwnedCap::null(),
            ))
        });
        drop(mo_cap_owned);
        state.shm_data.release(shm_h);
    }
    send_reply_ok_for_client(state, client, reply_lease, &[]);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Decode a `pack_path`-encoded name: `regs[offset]` = byte length,
/// `regs[offset + 1..]` = name bytes. `offset` is 3 for the open/create
/// path (after `flags`/`mode`/`size_hint`) and 0 for unlink.
fn decode_name(msg: &TronaMsg, offset: usize) -> Option<([u8; SHM_NAME_INLINE_MAX], usize)> {
    let name_len = msg.regs[offset] as usize;
    if name_len == 0 || name_len > SHM_NAME_INLINE_MAX {
        return None;
    }
    let mut name = [0u8; SHM_NAME_INLINE_MAX];
    let src = (&raw const msg.regs[offset + 1]) as *const u8;
    for i in 0..name_len {
        name[i] = unsafe { *src.add(i) };
    }
    Some((name, name_len))
}

/// vfs maintains a small inline name → ShmData mapping. The table
/// lives in the shm arena's slot metadata (slot index = the
/// 8-byte-aligned name hash mod arena cap), with linear probing on
/// collision. For now use a linear scan of every active slot; the
/// expected number of named SHM objects per system is < 32 so the
/// scan cost stays trivial.
fn lookup_by_name(state: &VfsState, name: &[u8]) -> Option<Handle<ShmData>> {
    let mut found = None;
    state.shm_data.for_each_active(|h, s| {
        if s.active != 0 && shm_name_matches(state, h, name) {
            found = Some(h);
            false
        } else {
            true
        }
    });
    found
}

fn shm_name_matches(state: &VfsState, h: Handle<ShmData>, name: &[u8]) -> bool {
    if let Some(entry) = state.shm_name_table_lookup(h) {
        entry == name
    } else {
        false
    }
}

fn register_name(state: &mut VfsState, name: &[u8], h: Handle<ShmData>) -> bool {
    state.shm_name_table_insert(name, h)
}

fn unregister_name(state: &mut VfsState, name: &[u8]) -> Option<Handle<ShmData>> {
    state.shm_name_table_remove(name)
}

fn retype_backing_mo(state: &VfsState, size: u64) -> Result<u64, VfsError> {
    // POSIX `shm_open(O_CREAT)` makes a zero-length object; `ftruncate` sets
    // the real size. mmsrv requires a >= 1-page MO, so a zero-length shm is
    // backed by a single page (the logical size recorded in `ShmData` stays
    // whatever the caller asked for).
    let mo_bytes = if size == 0 {
        uapi::KERNITE_PAGE_BYTES as u64
    } else {
        size
    };
    // Hand the request to mmsrv: `MM_MO_CREATE` returns an MO cap
    // backed by fresh anonymous memory. The cap becomes vfs's
    // owning reference; future mmap calls share-map it into client
    // vspaces.
    unsafe { crate::owner::mm_ipc::mmsrv_mo_create(state, mo_bytes, 0) }
}

unsafe fn finish_open(
    state: &mut VfsState,
    client: ClientHandle,
    name: &[u8],
    acc_mode: u64,
    reply_lease: trona_server::ReplyLease,
) {
    let shm_h = match lookup_by_name(state, name) {
        Some(h) => h,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoEnt);
            return;
        }
    };
    let size = state.shm_data.get(shm_h).map(|s| s.size).unwrap_or(0);

    let obj_h = match state.open_objects.alloc() {
        Some(h) => h,
        None => {
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    if let Some(obj) = state.open_objects.get_mut(obj_h) {
        *obj = OpenObject::EMPTY;
        obj.refcount = 1;
        obj.kind = OpenObjectKind::Shm;
        obj.personality_aux = shm_h.slot();
        let mut f = 0u8;
        if acc_mode == O_RDONLY || acc_mode == O_RDWR {
            f |= OpenObjectFlags::READABLE;
        }
        if acc_mode == O_WRONLY || acc_mode == O_RDWR {
            f |= OpenObjectFlags::WRITABLE;
        }
        obj.flags = f;
        let mut access = 0u8;
        if acc_mode == O_RDONLY || acc_mode == O_RDWR {
            access |= OpenObjectAccess::READ;
        }
        if acc_mode == O_WRONLY || acc_mode == O_RDWR {
            access |= OpenObjectAccess::WRITE;
        }
        obj.access = access;
        obj.share = crate::ops::SharePolicy::permissive().bits();
    }
    if let Some(s) = state.shm_data.get_mut(shm_h) {
        s.refcount = s.refcount.saturating_add(1);
    }

    let cli = match state.clients.get_mut(client) {
        Some(c) => c,
        None => {
            drop_shm_open_ref(state, shm_h);
            state.open_objects.release(obj_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::Io);
            return;
        }
    };
    let fd = match cli.slot_table.find_first_empty_from(0) {
        Ok(f) => f,
        Err(_) => {
            drop_shm_open_ref(state, shm_h);
            state.open_objects.release(obj_h);
            send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
            return;
        }
    };
    if cli.slot_table.set(fd, obj_h).is_err() {
        drop_shm_open_ref(state, shm_h);
        state.open_objects.release(obj_h);
        send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
        return;
    }

    send_reply_ok_for_client(state, client, reply_lease, &[fd as u64, size]);
}

pub(crate) fn drop_shm_open_ref(state: &mut VfsState, shm_h: Handle<ShmData>) {
    let mut should_release = false;
    let mut mo_cap_owned = None;
    if let Some(s) = state.shm_data.get_mut(shm_h) {
        s.refcount = s.refcount.saturating_sub(1);
        if s.refcount == 0 {
            // Extract the cap before zeroing so Drop fires exactly once.
            mo_cap_owned = Some(core::mem::replace(
                &mut s.mo_cap,
                trona_runtime::core::slot_alloc::OwnedCap::null(),
            ));
            s.active = 0;
            s.size = 0;
            should_release = true;
        }
    }
    // Drop the OwnedCap (fires delete_and_free) before releasing
    // the arena slot so the MO remains valid while mmsrv processes any
    // in-flight page requests against it.
    drop(mo_cap_owned);
    if should_release {
        let _ = state.shm_data.release(shm_h);
    }
}
