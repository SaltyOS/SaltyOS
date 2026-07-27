// SPDX-License-Identifier: GPL-2.0-only
//! Win32 client sidecar lifecycle.
//!
//! The neutral owner state stores the sidecar table, but Win32
//! semantics live here: first NT-label contact seeds current-drive
//! state, fork/clone copies it, client teardown drops it, and path
//! entries fetch a drive table plus per-drive CWD anchors.

use crate::core::identity::VnodeKey;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

pub(crate) fn seed_client_state(state: &mut VfsState, client: ClientHandle) {
    let root_vkey = root_vkey(state).unwrap_or(VnodeKey::NONE);
    let _ = state.win32_cwd.ensure_seeded(client, root_vkey);
}

pub(crate) fn clone_client_state(state: &mut VfsState, src: ClientHandle, dst: ClientHandle) {
    let root_vkey = root_vkey(state).unwrap_or(VnodeKey::NONE);
    let _ = state.win32_cwd.clone_from(src, dst, root_vkey);
}

pub(crate) fn drop_client_state(state: &mut VfsState, client: ClientHandle) {
    state.win32_cwd.deregister(client);
}

pub(crate) fn path_context_for_client(
    state: &VfsState,
    client: ClientHandle,
) -> (
    super::drives::DriveTable,
    [VnodeKey; super::drives::DRIVE_LETTER_COUNT],
) {
    let mut drives = super::drives::DriveTable::default_table();
    let mut drive_cwds = [VnodeKey::NONE; super::drives::DRIVE_LETTER_COUNT];
    if let Some(entry) = state.win32_cwd.get(client) {
        drives.current_drive = entry.current_drive.min(25);
        for (drive_idx, slot) in drive_cwds.iter_mut().enumerate() {
            if let Some(vkey) = state.win32_cwd.drive_cwd_vkey(client, drive_idx) {
                *slot = vkey;
            }
        }
    }
    (drives, drive_cwds)
}

fn root_vkey(state: &VfsState) -> Option<VnodeKey> {
    if state.root_mount.is_valid() {
        if let Some(mount) = state.mounts.get(state.root_mount) {
            if let Some(root) = state.vnodes.get(mount.root) {
                return Some(root.key);
            }
        }
    }
    let mut found = None;
    state.mounts.for_each_active(|_h, mount| {
        if !mount.covered_key.is_valid() {
            if let Some(root) = state.vnodes.get(mount.root) {
                found = Some(root.key);
                return false;
            }
        }
        true
    });
    found
}
