// SPDX-License-Identifier: GPL-2.0-only
//
//! `VFS_REGISTER_BULK_SHM` / `VFS_RELEASE_BULK_SHM` — per-client
//! bulk-transfer SHM region lifecycle.
//!
//! The handler drives mmsrv through two sync round-trips:
//!
//! 1. `MM_SHM_CREATE(name, size)` — backing MO allocation, returning
//!    `(shm_idx; caps=[shm_cap])`.
//! 2. `MM_SHM_MAP(shm_idx; caps=[shm_cap])` — map the region into
//!    vfs's own VSpace.
//!
//! The reply returns `caps=[shm_cap]` to the client; the client maps
//! its own view by calling its self-tier mmsrv endpoint. On any
//! partial failure the helper rolls back vfs's mapping / cap / SHM
//! registry entry before replying.
//!
//! ## Wire layout — `VFS_REGISTER_BULK_SHM`
//!
//! - `regs[0] = bytes (u64)` — requested size (mmsrv rounds up to
//!   page granularity; capped at [`BULK_SHM_MAX_BYTES`]).
//!
//! ## Reply
//!
//! - `regs[0] = bytes (u64)` — the region size after mmsrv's page
//!   rounding.
//! - `regs[1] = shm_idx (u64)` — mmsrv-side SHM slot id.
//! - `regs[2] = token (u64)` — opaque VFS region token echoed on
//!   `VFS_RELEASE_BULK_SHM`.
//! - `caps[0] = shm_cap` — capability authorizing the client's
//!   self-tier `MM_SHM_MAP`.
//!
//! ## Wire layout — `VFS_RELEASE_BULK_SHM`
//!
//! - `regs[0] = token (u64)` — must match the previously-issued
//!   VFS token. Reply is empty OK.

use trona_kernel::core_types::TronaMsg;

use crate::core::error::VfsError;
use crate::owner::VfsState;
use trona_runtime::core::slot_alloc::OwnedCap;

use crate::owner::client_shm::{
    BULK_SHM_MAX_BYTES, BULK_SHM_PAGE_BYTES, ClientShmHandle, ClientShmRegion, mmsrv_munmap,
    mmsrv_shm_create, mmsrv_shm_destroy, mmsrv_shm_map,
};
use crate::personality::wire::{send_reply_err_for_client, send_reply_ok_for_client};
use crate::server::types::ClientHandle;

pub(crate) unsafe fn handle_register(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let bytes_req = msg.regs[0];
        if bytes_req == 0 || bytes_req > BULK_SHM_MAX_BYTES {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
            return;
        }
        // If the client already has a live region, refuse rather
        // than silently allocating a second one — POSIX shm_open
        // semantics expect explicit unmap before re-registration.
        let existing = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm)
            .unwrap_or(ClientShmHandle::INVALID);
        if state.client_shm_regions.is_alive(existing) {
            send_reply_err_for_client(state, client, reply_lease, VfsError::Busy);
            return;
        }
        let pages = (bytes_req + BULK_SHM_PAGE_BYTES - 1) / BULK_SHM_PAGE_BYTES;
        let region_bytes = pages * BULK_SHM_PAGE_BYTES;
        let shm_id = state.next_shm_id;
        state.next_shm_id = state.next_shm_id.wrapping_add(1);

        // -- (1) MM_SHM_CREATE -----------------------------------
        let (shm_idx, shm_cap) = match mmsrv_shm_create(state, shm_id, region_bytes) {
            Ok(v) => v,
            Err(e) => {
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        // vfs keeps `shm_cap` (stored on the region for release); mmsrv
        // and the client each receive a disposable copy, since the
        // kernel moves a staged cap out of vfs's CSpace on transfer.
        // Mint the client's copy up front so every failure path below
        // drops it (RAII) without bespoke cleanup.
        // Wrap `shm_cap` into OwnedCap immediately so every failure path
        // below drops it without explicit `delete_and_free` calls.
        let shm_cap_owned = OwnedCap::adopt_received(shm_cap);

        let client_cap =
            match trona_runtime::core::slot_alloc::dup_for_transfer(shm_cap_owned.borrow()) {
                Some(c) => c,
                None => {
                    // shm_cap_owned drops here — fires delete_and_free.
                    drop(shm_cap_owned);
                    let _ = mmsrv_shm_destroy(shm_idx);
                    send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                    return;
                }
            };

        // -- (2) MM_SHM_MAP into vfs's own VSpace ----------------
        let map_cap =
            match trona_runtime::core::slot_alloc::dup_for_transfer(shm_cap_owned.borrow()) {
                Some(c) => c,
                None => {
                    drop(shm_cap_owned);
                    let _ = mmsrv_shm_destroy(shm_idx);
                    send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                    return;
                }
            };
        let vfs_va = match mmsrv_shm_map(shm_idx, map_cap, region_bytes) {
            Ok(va) => va,
            Err(e) => {
                drop(shm_cap_owned);
                let _ = mmsrv_shm_destroy(shm_idx);
                send_reply_err_for_client(state, client, reply_lease, e);
                return;
            }
        };

        // -- (3) Allocate the arena slot and stash bookkeeping ---
        let region_h = match state.client_shm_regions.alloc() {
            Some(h) => h,
            None => {
                let _ = mmsrv_munmap(vfs_va, region_bytes);
                drop(shm_cap_owned);
                let _ = mmsrv_shm_destroy(shm_idx);
                send_reply_err_for_client(state, client, reply_lease, VfsError::NoMem);
                return;
            }
        };
        if let Some(slot) = state.client_shm_regions.get_mut(region_h) {
            *slot = ClientShmRegion {
                shm_idx,
                shm_cap: Some(shm_cap_owned),
                vfs_va,
                bytes: region_bytes,
                owner_client: client,
            };
        }
        if let Some(cli) = state.clients.get_mut(client) {
            cli.bulk_shm = region_h;
        }

        // -- (4) Reply. The client maps its own view from `client_cap`;
        //    vfs keeps `shm_cap` on the region for release.
        let mut out = TronaMsg::default();
        out.label = trona_protocol::vfs::public::VFS_PUBLIC_REPLY_OK;
        out.length = 3;
        out.regs[0] = region_bytes;
        out.regs[1] = shm_idx;
        out.regs[2] = (u64::from(region_h.epoch()) << 32) | u64::from(region_h.slot());
        crate::owner::op::reply_send_with_cap(reply_lease, &out, client_cap);
    }
}

pub(crate) unsafe fn handle_release(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        let token = msg.regs[0];
        let region_h = state
            .clients
            .get(client)
            .map(|c| c.bulk_shm)
            .unwrap_or(ClientShmHandle::INVALID);
        let expected_token = (u64::from(region_h.epoch()) << 32) | u64::from(region_h.slot());
        let (vfs_va, bytes, shm_idx, shm_cap) = {
            let Some(region) = state.client_shm_regions.get_mut(region_h) else {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            };
            if token != expected_token {
                send_reply_err_for_client(state, client, reply_lease, VfsError::Inval);
                return;
            }
            (
                region.vfs_va,
                region.bytes,
                region.shm_idx,
                core::mem::replace(&mut region.shm_cap, None),
            )
        };
        let _ = mmsrv_munmap(vfs_va, bytes);
        drop(shm_cap);
        let _ = mmsrv_shm_destroy(shm_idx);
        if let Some(cli) = state.clients.get_mut(client) {
            cli.bulk_shm = ClientShmHandle::INVALID;
        }
        let _ = state.client_shm_regions.release(region_h);
        send_reply_ok_for_client(state, client, reply_lease, &[]);
    }
}
