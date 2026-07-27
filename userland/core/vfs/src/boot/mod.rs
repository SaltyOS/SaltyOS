// SPDX-License-Identifier: GPL-2.0-only
//
//! Boot-time bootstrap glue.
//!
//! Owns the initrd-rooted ramfs setup, the namesrv / mmsrv
//! handshake, and the deferred-pivot hooks used when on-disk root
//! setup parks behind the filesystem daemon.
//!
//! The entry points exposed from `main.rs` are:
//!
//!   * [`init_state_in_place`] — drives the in-place arena / cookie
//!     table / reactor construction on a freshly mapped
//!     `VfsState` page.
//!   * [`register_with_namesrv`] — publishes vfs's client-facing
//!     service endpoint to namesrv with the `BADGE_AS_CALLER` flag.
//!   * [`register_pager_with_mmsrv`] — retypes vfs's `OBJ_PAGER`,
//!     binds it to the owner EQ, and ships a cap copy to mmsrv so
//!     subsequent `MM_FILE_MMAP` calls can attach this pager to
//!     freshly retyped MOs (kernel-routed page faults).
//!   * [`bootstrap_initrd_root`] — mounts the initrd-backed
//!     read-only ramfs at `/` and seeds the global mount namespace.

pub(crate) mod late_mount;

use crate::owner::VfsState;
use trona_kernel::core_types::{Cap, CapRef};
use trona_protocol::common::TRONA_OK;
use trona_runtime::core::slot_alloc::{OwnedCap, resolved_cap_ref};

/// Initialise a freshly zero-filled `VfsState` in-place.
/// Returns `false` if any arena / cookie-table allocation fails.
pub(crate) unsafe fn init_state_in_place(state_ptr: *mut VfsState) -> bool {
    unsafe {
        match VfsState::init_into(state_ptr) {
            Ok(()) => {
                let state = &mut *state_ptr;
                if !install_owner_reactor_plumbing(state) {
                    return false;
                }
                crate::fs::sysctlfs::tree::init_tree();
                crate::fs::sysctlfs::providers::init_providers();
                true
            }
            Err(_) => false,
        }
    }
}

fn copy_cap_for_transfer(src: Cap) -> Cap {
    if src == 0 {
        return 0;
    }
    let Some(dst) = trona_runtime::core::slot_alloc::alloc_slot() else {
        return 0;
    };
    let err = trona_kernel::invoke::cnode_copy_ref(
        CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
        resolved_cap_ref(src),
        CapRef::flat(uapi::KERNITE_CAP_SELF_CSPACE as u64),
        resolved_cap_ref(dst.addr()),
        uapi::KERNITE_RIGHT_ALL as u64,
    );
    if err != 0 {
        // copy failed: `dst` (OwnedSlot) Drop frees the empty slot.
        return 0;
    }
    dst.into_raw()
}

/// # Safety
/// `slot` is a transient transfer slot the caller solely owns (0 = no-op). On
/// `syscall_err != 0` the cap stayed and is torn down + freed; otherwise the
/// transfer moved it out and only the empty index is reclaimed.
unsafe fn finish_transfer_slot(slot: Cap, syscall_err: i32) {
    if slot == 0 {
        return;
    }
    if syscall_err != 0 {
        // SAFETY: the transfer failed so `slot` still holds its cap and is solely
        // owned here per this fn's `# Safety`.
        unsafe { trona_runtime::core::slot_alloc::delete_and_free(slot) };
    } else {
        // The syscall moved the cap out of `slot`, leaving it empty.
        // SAFETY: on success the transfer moved the cap out, so the slot is
        // empty; it was allocated by copy_cap_for_transfer and freed once here.
        unsafe {
            trona_runtime::core::slot_alloc::reclaim_empty_allocated_slot_unchecked(slot);
        }
    }
}

fn ensure_mmsrv_writeback_channel(state: &mut VfsState) -> Option<Cap> {
    use crate::ipc::cookie::{KIND_MMSRV_WRITEBACK, encode_cookie};

    if let Some(mp) = state.mmsrv_writeback_mp.as_ref() {
        return mp.send().map(|s| s.addr()).filter(|addr| *addr != 0);
    }
    if state.owner_eq.as_raw() == 0 {
        return None;
    }

    let mut mp = match trona_runtime::core::slot_alloc::alloc_mp_pair_owned() {
        Ok(pair) => pair,
        Err(_) => return None,
    };
    let watch = match trona_runtime::core::slot_alloc::alloc_object_owned(
        uapi::KERNITE_OBJ_WATCH as u64,
        0,
    ) {
        Ok(watch) => watch,
        Err(_) => {
            let _ = mp.release_in_place();
            return None;
        }
    };
    let recv_addr = mp.recv().map(|r| r.addr()).unwrap_or(0);
    let send_addr = mp.send().map(|s| s.addr()).unwrap_or(0);
    let watch_addr = watch.borrow().map(|r| r.addr()).unwrap_or(0);
    if recv_addr == 0 || send_addr == 0 || watch_addr == 0 {
        let _ = watch.release();
        let _ = mp.release_in_place();
        return None;
    }

    let cookie = encode_cookie(KIND_MMSRV_WRITEBACK, 0, 0);
    let err = trona_kernel::invoke::watch_register(
        resolved_cap_ref(watch_addr),
        resolved_cap_ref(recv_addr),
        state.owner_eq.borrow(),
        uapi::KERNITE_STATE_READABLE as u64,
        cookie,
    );
    if err != 0 {
        let _ = trona_kernel::invoke::watch_cancel(resolved_cap_ref(watch_addr));
        let _ = watch.release();
        let _ = mp.release_in_place();
        return None;
    }

    state.mmsrv_writeback_mp = Some(mp);
    state.mmsrv_writeback_watch_cap = Some(watch);
    state.mmsrv_writeback_cookie = cookie;
    Some(send_addr)
}

fn install_owner_reactor_plumbing(state: &mut VfsState) -> bool {
    use crate::ipc::cookie::{KIND_FRONTEND, KIND_INIT_REPLY, encode_cookie};

    if state.owner_eq.as_raw() != 0 {
        return true;
    }
    let service_ep_recv = trona_runtime::client::caps::service_recv_ep().addr();
    if service_ep_recv == 0 {
        return false;
    }
    let owner_eq = match trona_runtime::core::slot_alloc::alloc_object(
        uapi::KERNITE_OBJ_EVENT_QUEUE as u64,
        0,
    ) {
        Ok(cap) => cap,
        Err(_) => return false,
    };
    let frontend_watch =
        match trona_runtime::core::slot_alloc::alloc_object(uapi::KERNITE_OBJ_WATCH as u64, 0) {
            Ok(cap) => cap,
            Err(_) => {
                // SAFETY: owner_eq is the EQ cap from alloc_object above, solely
                // owned here; freed once on this frontend-watch-alloc failure.
                unsafe { trona_runtime::core::slot_alloc::delete_and_free(owner_eq) };
                return false;
            }
        };
    let frontend_cookie = encode_cookie(KIND_FRONTEND, 0, 0);
    let err = trona_kernel::invoke::watch_register(
        resolved_cap_ref(frontend_watch),
        CapRef::flat(service_ep_recv),
        resolved_cap_ref(owner_eq),
        uapi::KERNITE_STATE_READABLE as u64,
        frontend_cookie,
    );
    if err != 0 {
        // SAFETY: frontend_watch + owner_eq are alloc_object caps above, each
        // solely owned here; freed once on this watch_register failure.
        unsafe {
            trona_runtime::core::slot_alloc::delete_and_free(frontend_watch);
            trona_runtime::core::slot_alloc::delete_and_free(owner_eq);
        }
        return false;
    }

    // SAFETY: owner_eq / frontend_watch are the alloc_object caps above, each
    // now solely owned by the VfsState field adopting it.
    state.owner_eq = unsafe { OwnedCap::adopt_received(owner_eq) };
    state.service_ep_recv = service_ep_recv;
    state.frontend_watch_cap = unsafe { OwnedCap::adopt_received(frontend_watch) };
    state.frontend_cookie = frontend_cookie;

    // Arm the init-reply Watch. VFS issues async procfs / sysctl / ctty
    // queries to init via non-blocking `mp_write` and reads the replies
    // here: init echoes the kernel txid and its reply-marked `MP_WRITE`
    // re-asserts `STATE_READABLE` on `init_ep`'s recv side, which this
    // Watch routes to `owner_eq` under a `KIND_INIT_REPLY` cookie.
    // Best-effort — if `init_ep` is absent or the Watch alloc/register
    // fails, async init queries cannot run, but boot (which never reads
    // /proc) is unaffected; the field stays 0 and callers fall back.
    let init_ep = trona_runtime::client::caps::init_ep().addr();
    if init_ep != 0 {
        if let Ok(init_watch) =
            trona_runtime::core::slot_alloc::alloc_object(uapi::KERNITE_OBJ_WATCH as u64, 0)
        {
            let init_cookie = encode_cookie(KIND_INIT_REPLY, 0, 0);
            let err = trona_kernel::invoke::watch_register(
                resolved_cap_ref(init_watch),
                CapRef::flat(init_ep),
                resolved_cap_ref(state.owner_eq.as_raw()),
                uapi::KERNITE_STATE_READABLE as u64,
                init_cookie,
            );
            if err == 0 {
                state.init_ep_cap = init_ep;
                // SAFETY: init_watch is the alloc_object cap above, now
                // solely owned by the adopting VfsState field.
                state.init_watch_cap = unsafe { OwnedCap::adopt_received(init_watch) };
                state.init_cookie = init_cookie;
            } else {
                // SAFETY: init_watch is the alloc_object cap above, solely
                // owned here; freed once on register failure.
                unsafe { trona_runtime::core::slot_alloc::delete_and_free(init_watch) };
            }
        }
    }
    true
}

/// Publish vfs's client-facing service endpoint to namesrv with the
/// `BADGE_AS_CALLER` flag so consumer LOOKUPs receive a copy minted
/// with their own `client_id` in the badge.
pub(crate) unsafe fn register_with_namesrv(state: &mut VfsState) -> bool {
    use trona_kernel::core_types::TronaMsg;

    const NAMESRV_REGISTER: u64 = 0x200;
    const ENTRY_FLAG_BADGE_AS_CALLER: u64 = 1 << 0;
    const REGISTER_FLAGS_REG: usize = 31;

    if state.namesrv_registered {
        return true;
    }

    let Some(publish_ep) = trona_runtime::client::caps::service_client_ep_for_transfer() else {
        return false;
    };

    let mut req = TronaMsg::default();
    req.label = NAMESRV_REGISTER;
    let name = b"vfs";
    let dst = (&raw mut req.regs[1]) as *mut u8;
    for (i, &b) in name.iter().enumerate() {
        unsafe {
            *dst.add(i) = b;
        }
    }
    req.regs[0] = name.len() as u64;
    req.regs[REGISTER_FLAGS_REG] = ENTRY_FLAG_BADGE_AS_CALLER;
    req.length = 32;

    // SAFETY: The service client endpoint cap is a live cap from the
    // bootstrap table, and slot 0 is the outbound cap position consumed by
    // NAMESRV_REGISTER.
    unsafe {
        trona_kernel::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, publish_ep.slot());
    }

    let mut reply = TronaMsg::default();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            crate::ipc_ctx(),
            trona_runtime::client::caps::namesrv_ep().addr(),
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    // `publish_ep` (TransferCap) reclaims its slot on drop whether the send
    // moved the cap out to namesrv (success) or left it in place (failure).
    drop(publish_ep);
    if err == 0 && reply.label == TRONA_OK {
        state.namesrv_registered = true;
        true
    } else {
        false
    }
}

/// Retype vfs's `OBJ_PAGER`, bind it to the owner EQ, and hand a
/// cap copy to mmsrv via `MM_REGISTER_VFS_PAGER`. From this point
/// on every `MM_FILE_MMAP` invokes `MO_ATTACH_PAGER(mo_cap,
/// vfs_pager_cap)` so the kernel routes file-backed page faults
/// directly to the owner reactor as
/// `KERNITE_EVENT_TYPE_PAGER_REQUEST` events. The bound cap stays
/// in `VfsState.pager_cap` for the rest of the process lifetime.
pub(crate) unsafe fn register_pager_with_mmsrv(state: &mut VfsState) -> bool {
    use trona_kernel::core_types::TronaMsg;
    use trona_protocol::mm::MM_REGISTER_VFS_PAGER;

    let mmsrv_ep = trona_runtime::client::caps::mmsrv_ep().addr();
    if mmsrv_ep == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv pager register: missing mmsrv ep\n");
        });
        return false;
    }
    // SAFETY: Boot runs on the single VFS owner thread before pager events can
    // race this state; the function initializes the process-global pager cap.
    let pager_cap = match crate::owner::pager_rpc::ensure_pager_session(state) {
        Ok(cap) => cap,
        Err(_) => return false,
    };
    let writeback_send_cap = match ensure_mmsrv_writeback_channel(state) {
        Some(cap) => cap,
        None => {
            trona_runtime::uerror!(|_lb| {
                _lb.str(b"[VFS] mmsrv pager register: writeback channel failed\n");
            });
            return false;
        }
    };

    let mut req = TronaMsg::default();
    req.label = MM_REGISTER_VFS_PAGER;
    req.length = 0;
    let pager_transfer = copy_cap_for_transfer(pager_cap);
    if pager_transfer == 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv pager register: pager cap copy failed\n");
        });
        return false;
    }
    let writeback_transfer = copy_cap_for_transfer(writeback_send_cap);
    if writeback_transfer == 0 {
        // SAFETY: pager_transfer is the disposable copy minted above and has
        // not been sent yet; delete it on this local failure.
        unsafe { finish_transfer_slot(pager_transfer, -1) };
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv pager register: writeback cap copy failed\n");
        });
        return false;
    }

    // SAFETY: MessagePipe cap transfer moves the source CSpace entry, so send
    // disposable copies and keep VFS's retained pager/writeback caps live.
    unsafe {
        trona_kernel::ipc::clear_send_caps_ctx(crate::ipc_ctx());
        trona_kernel::ipc::set_send_cap_ctx(crate::ipc_ctx(), 0, pager_transfer);
        trona_kernel::ipc::set_send_cap_ctx(crate::ipc_ctx(), 1, writeback_transfer);
    }

    let mut reply = TronaMsg::default();
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            crate::ipc_ctx(),
            mmsrv_ep,
            &raw const req,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    unsafe {
        trona_kernel::ipc::clear_send_caps_ctx(crate::ipc_ctx());
    }
    // SAFETY: transfer slots are the disposable copies copy_cap_for_transfer
    // minted above, solely owned here.
    unsafe {
        finish_transfer_slot(pager_transfer, err);
        finish_transfer_slot(writeback_transfer, err);
    }
    if err != 0 {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv pager register call failed err=");
            _lb.hex(err as u64);
            _lb.str(b"\n");
        });
        return false;
    }
    if reply.label != trona_protocol::common::TRONA_OK {
        trona_runtime::uerror!(|_lb| {
            _lb.str(b"[VFS] mmsrv pager register reply label=");
            _lb.hex(reply.label);
            _lb.str(b"\n");
        });
        return false;
    }
    state.mmsrv_pager_registered = true;
    true
}

/// Bootstrap the initrd-backed read-only ramfs at `/`. Driven by
/// the same [`crate::core::mount`] tree as any later mount
/// — the only difference is that the root mount has no covered
/// vnode (`covered_key = NONE`).
pub(crate) unsafe fn bootstrap_initrd_root(state: &mut VfsState) -> bool {
    use crate::core::mount::{Mount, MountKind};

    let vfsops_ptr: *const crate::core::vop::VfsOps = &crate::fs::ramfs::RAMFS_VFSOPS;
    let mount_h = match state.mounts.alloc() {
        Some(h) => h,
        None => return false,
    };
    let fs_id = state.next_fs_instance_id();
    if let Some(m) = state.mounts.get_mut(mount_h) {
        *m = Mount::EMPTY;
        m.kind = MountKind::Initrd;
        m.fs_instance_id = fs_id;
        m.vfsops = vfsops_ptr;
        m.set_mount_path(b"/");
    }

    let root_vh = unsafe {
        let mut mctx = match crate::core::vop_context::OwnerMountCtx::from_state(state, mount_h) {
            Some(c) => c,
            None => {
                state.mounts.release(mount_h);
                return false;
            }
        };
        match ((*vfsops_ptr).mount)(&mut mctx) {
            Ok(h) => h,
            Err(_) => {
                state.mounts.release(mount_h);
                return false;
            }
        }
    };
    if let Some(m) = state.mounts.get_mut(mount_h) {
        m.root = root_vh;
    }
    state.root_mount = mount_h;

    if let Err(_) = unsafe {
        crate::core::mount_ctl::finalize_mount_tail(
            state,
            mount_h,
            crate::core::vnode::VnodeHandle::INVALID,
            fs_id,
        )
    } {
        state.mounts.release(mount_h);
        return false;
    }
    true
}

const BOOTSTRAP_ROOT_DIRS: &[(&[u8], u32)] = &[
    (b"bin", 0o755),
    (b"sbin", 0o755),
    (b"lib", 0o755),
    (b"usr", 0o755),
    (b"etc", 0o755),
    (b"var", 0o755),
    (b"tmp", 0o1777),
    (b"dev", 0o755),
    (b"proc", 0o555),
    (b"sys", 0o555),
    (b"home", 0o755),
    (b"root", 0o700),
    (b"mnt", 0o755),
    (b"pipe", 0o755),
    (b"initramfs", 0o555),
    (b"newroot", 0o755),
];

const BOOTSTRAP_PSEUDO_MOUNTS: &[(&[u8], crate::core::mount::MountKind, u64)] = &[
    (b"dev", crate::core::mount::MountKind::Devfs, 0),
    (
        b"proc",
        crate::core::mount::MountKind::Procfs,
        (trona_protocol::posix::MNT_NODEV
            | trona_protocol::posix::MNT_NOEXEC
            | trona_protocol::posix::MNT_NOSUID) as u64,
    ),
    (b"tmp", crate::core::mount::MountKind::Tmpfs, 0),
    (
        b"sys",
        crate::core::mount::MountKind::Sysctlfs,
        (trona_protocol::posix::MNT_NODEV
            | trona_protocol::posix::MNT_NOEXEC
            | trona_protocol::posix::MNT_NOSUID) as u64,
    ),
    (b"pipe", crate::core::mount::MountKind::Pipefs, 0),
];

unsafe fn root_vnode(state: &VfsState) -> Option<crate::core::vnode::VnodeHandle> {
    state.mounts.get(state.root_mount).map(|m| m.root)
}

unsafe fn lookup_root_child(
    state: &mut VfsState,
    root_vh: crate::core::vnode::VnodeHandle,
    name: &[u8],
) -> Result<Option<crate::core::vnode::VnodeHandle>, crate::core::error::VfsError> {
    use crate::core::outcome::Ready;
    let mut ctx = unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, root_vh) }
        .ok_or(crate::core::error::VfsError::Io)?;
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return Err(crate::core::error::VfsError::Io);
    }
    match unsafe { ((*ops).meta.lookup)(&mut ctx, name.as_ptr(), name.len() as u8) } {
        Ok(Ready(vh)) if vh.is_valid() => Ok(Some(vh)),
        Ok(Ready(_)) | Err(crate::core::error::VfsError::NoEnt) => Ok(None),
        Ok(_) => Err(crate::core::error::VfsError::Busy),
        Err(e) => Err(e),
    }
}

unsafe fn ensure_root_dir(
    state: &mut VfsState,
    root_vh: crate::core::vnode::VnodeHandle,
    name: &[u8],
    mode: u32,
) -> Result<crate::core::vnode::VnodeHandle, crate::core::error::VfsError> {
    use crate::core::outcome::Ready;
    use crate::core::vnode::VnodeKind;

    if let Some(vh) = unsafe { lookup_root_child(state, root_vh, name)? } {
        let vnode = state
            .vnodes
            .get(vh)
            .ok_or(crate::core::error::VfsError::Io)?;
        if vnode.kind == VnodeKind::Directory {
            return Ok(vh);
        }
        return Err(crate::core::error::VfsError::NotDir);
    }

    let mut ctx = unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, root_vh) }
        .ok_or(crate::core::error::VfsError::Io)?;
    let ops = unsafe { (*ctx.vnode).ops };
    if ops.is_null() {
        return Err(crate::core::error::VfsError::Io);
    }
    let cred = crate::core::cred::VfsCred::root();
    match unsafe {
        ((*ops).meta.mkdir)(
            &mut ctx,
            name.as_ptr(),
            name.len() as u8,
            mode,
            &raw const cred,
        )
    } {
        Ok(Ready(vh)) if vh.is_valid() => Ok(vh),
        Ok(_) => Err(crate::core::error::VfsError::Busy),
        Err(e) => Err(e),
    }
}

// =======================================================================
// initrd CPIO extraction
//
// Populate the ramfs root from the bootloader-loaded initrd archive
// (the Linux initramfs model: unpack the cpio into the rootfs at boot).
// The initrd is a pseudo-device untyped granted by init via the
// `initrd_untyped.cap` requirement; it is mapped read-only and zero-copy
// with `VSPACE_MAP_DEVICE` (no retype, no zeroing), parsed, copied into
// ramfs, and the transient mapping is then dropped.
// =======================================================================

/// Transient VA for the initrd device mapping during extraction.
/// Sits in the free gap between the mmsrv-managed mmap window (which
/// tops out at 0x4000_0000) and the rtld shared-library / main-image
/// region (`0x4000_xxxx_xxxx`, where libtrona/libc load) — the same
/// low-VA band dispdrv maps the framebuffer device into, so it is
/// known mappable and unoccupied. Unmapped before `extract_initrd`
/// returns. (The pager-scratch base overlaps the rtld region and must
/// not be reused here.)
const INITRD_MAP_VA: u64 = 0x0000_0000_5000_0000;
/// Upper bound on the device-extent probe (256 MiB) — a backstop against
/// a malformed device limit, far above any real initrd.
const INITRD_MAP_MAX_PAGES: u64 = 65536;

/// Map the initrd pseudo-device untyped read-only into our address
/// space, discovering its exact page extent against the kernel's device
/// limit. Overshoot is rejected cleanly (maps zero), so probe forward in
/// 64-page chunks, then page-by-page for the tail. Returns the number of
/// pages mapped (0 on failure).
fn map_initrd_window(initrd_ut: Cap) -> u64 {
    let vs = CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64);
    let flags = uapi::KERNITE_PAGE_FLAG_USER as u64; // read-only, cached
    const CHUNK: u64 = 64;
    let mut pages: u64 = 0;
    while pages + CHUNK <= INITRD_MAP_MAX_PAGES {
        let (err, mapped) = trona_kernel::invoke::vspace_map_device_range(
            vs,
            resolved_cap_ref(initrd_ut),
            pages * 4096,
            INITRD_MAP_VA + pages * 4096,
            CHUNK,
            flags,
        );
        if err != 0 {
            break;
        }
        pages += mapped;
        if mapped != CHUNK {
            break;
        }
    }
    while pages < INITRD_MAP_MAX_PAGES {
        let (err, mapped) = trona_kernel::invoke::vspace_map_device_range(
            vs,
            resolved_cap_ref(initrd_ut),
            pages * 4096,
            INITRD_MAP_VA + pages * 4096,
            1,
            flags,
        );
        if err != 0 {
            break;
        }
        pages += mapped;
        if mapped != 1 {
            break;
        }
    }
    pages
}

/// Drop the transient initrd mapping installed by `map_initrd_window`.
fn unmap_initrd_window(pages: u64) {
    let vs = CapRef::flat(uapi::KERNITE_CAP_SELF_VSPACE as u64);
    for i in 0..pages {
        let _ = trona_kernel::invoke::vspace_unmap(vs, INITRD_MAP_VA + i * 4096);
    }
}

/// Walk `path` from `root_vh`, creating each directory component if
/// absent (idempotent), and return the final directory's vnode.
unsafe fn ensure_dir_path(
    state: &mut VfsState,
    root_vh: crate::core::vnode::VnodeHandle,
    path: &[u8],
    mode: u32,
) -> Option<crate::core::vnode::VnodeHandle> {
    let mut cur = root_vh;
    for comp in path.split(|&b| b == b'/') {
        if comp.is_empty() || (comp.len() == 1 && comp[0] == b'.') {
            continue;
        }
        if comp.len() > 255 {
            return None;
        }
        cur = unsafe { ensure_root_dir(state, cur, comp, mode) }.ok()?;
    }
    Some(cur)
}

/// Create the regular file `name` under `parent_vh` and write `data`
/// into it, looping until the full payload is committed. Returns false
/// on any failure.
unsafe fn create_file_with_data(
    state: &mut VfsState,
    parent_vh: crate::core::vnode::VnodeHandle,
    name: &[u8],
    mode: u32,
    data: *const u8,
    data_len: u64,
) -> bool {
    use crate::core::outcome::Ready;
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let cred = crate::core::cred::VfsCred::root();

    let file_vh = {
        let Some(mut pctx) =
            (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, parent_vh) })
        else {
            return false;
        };
        let ops = unsafe { (*pctx.vnode).ops };
        if ops.is_null() {
            return false;
        }
        match unsafe {
            ((*ops).meta.create)(
                &mut pctx,
                name.as_ptr(),
                name.len() as u8,
                mode,
                &raw const cred,
            )
        } {
            Ok(Ready(vh)) if vh.is_valid() => vh,
            _ => return false,
        }
    };

    if data_len == 0 {
        return true;
    }

    let Some(wctx) = (unsafe { crate::core::vop_context::OwnerVopCtx::from_state(state, file_vh) })
    else {
        return false;
    };
    let ops = unsafe { (*wctx.vnode).ops };
    if ops.is_null() {
        return false;
    }
    let dctx = unsafe { wctx.data_ctx() };
    let mut off: u64 = 0;
    while off < data_len {
        match unsafe { ((*ops).data.write)(&dctx, off, data.add(off as usize), data_len - off) } {
            Ok(Ready(n)) if n > 0 => off += n,
            _ => return false,
        }
    }
    true
}

/// Extract the initrd CPIO archive into the ramfs root. Fail-loud: a
/// half-populated root is worse than a clean abort, so any error returns
/// false (a fatal boot condition for the caller).
pub(crate) unsafe fn extract_initrd(state: &mut VfsState) -> bool {
    // POSIX `st_mode` type bits as carried in the CPIO newc header.
    const S_IFMT: u32 = 0o170000;
    const S_IFDIR: u32 = 0o040000;
    const S_IFREG: u32 = 0o100000;

    let initrd_ut = trona_runtime::client::caps::initrd_untyped().addr();
    if initrd_ut == 0 {
        trona_runtime::debug::serial::serial_puts(b"[VFS] initrd_untyped cap not granted\n");
        return false;
    }

    let pages = map_initrd_window(initrd_ut);
    if pages == 0 {
        trona_runtime::debug::serial::serial_puts(b"[VFS] initrd device map failed\n");
        return false;
    }
    let mapped_bytes = (pages * 4096) as usize;

    let Some(root_vh) = (unsafe { root_vnode(state) }) else {
        unmap_initrd_window(pages);
        return false;
    };

    let mut iter = unsafe {
        trona_loader::common::cpio::CpioIter::new(INITRD_MAP_VA as *const u8, mapped_bytes)
    };
    let mut ok = true;
    while let Some(e) = iter.next_entry_ext() {
        // Normalize: strip leading slashes so each path is rooted at `/`.
        let mut name = unsafe { core::slice::from_raw_parts(e.name, e.name_len) };
        while let [b'/', rest @ ..] = name {
            name = rest;
        }
        if name.is_empty() || (name.len() == 1 && name[0] == b'.') {
            continue;
        }
        let perm = e.mode & 0o7777;
        match e.mode & S_IFMT {
            S_IFDIR => {
                if unsafe { ensure_dir_path(state, root_vh, name, perm) }.is_none() {
                    ok = false;
                    break;
                }
            }
            S_IFREG => {
                let (parent, leaf) = match name.iter().rposition(|&b| b == b'/') {
                    Some(i) => (&name[..i], &name[i + 1..]),
                    None => (&name[..0], name),
                };
                if leaf.is_empty() {
                    continue;
                }
                let parent_vh = if parent.is_empty() {
                    root_vh
                } else {
                    match unsafe { ensure_dir_path(state, root_vh, parent, 0o755) } {
                        Some(h) => h,
                        None => {
                            ok = false;
                            break;
                        }
                    }
                };
                if !unsafe {
                    create_file_with_data(state, parent_vh, leaf, perm, e.data, e.data_len as u64)
                } {
                    ok = false;
                    break;
                }
            }
            // Symlink / device / fifo entries do not occur in the initrd
            // image; ignore any that ever appear rather than failing the
            // whole extraction.
            _ => {}
        }
    }

    unmap_initrd_window(pages);
    ok
}

pub(crate) unsafe fn bootstrap_pseudo_mounts(state: &mut VfsState) -> bool {
    let Some(root_vh) = (unsafe { root_vnode(state) }) else {
        return false;
    };
    if !root_vh.is_valid() {
        return false;
    }
    for (name, mode) in BOOTSTRAP_ROOT_DIRS {
        if unsafe { ensure_root_dir(state, root_vh, name, *mode) }.is_err() {
            return false;
        }
    }
    for (name, kind, flags) in BOOTSTRAP_PSEUDO_MOUNTS {
        let target_vh = match unsafe { ensure_root_dir(state, root_vh, name, 0o755) } {
            Ok(vh) => vh,
            Err(_) => return false,
        };
        // Absolute mount-point path "/<name>" for `f_mntonname`.
        let mut abs_path = [0u8; crate::core::mount::MOUNT_PATH_MAX];
        abs_path[0] = b'/';
        let n = name.len().min(abs_path.len() - 1);
        abs_path[1..1 + n].copy_from_slice(&name[..n]);
        if unsafe {
            crate::fs::mount::mount_inmemory_boot(
                state,
                target_vh,
                *kind,
                *flags,
                &abs_path[..1 + n],
            )
        }
        .is_err()
        {
            return false;
        }
    }
    true
}
