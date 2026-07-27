// SPDX-License-Identifier: GPL-2.0-only
//! Win32 per-client current-drive and per-drive cwd sidecar.
//!
//! The neutral `ClientState` carries only the POSIX-style cwd anchor.
//! Win32 needs per-drive cwd state (`C:foo` vs `D:foo`), so that state
//! lives here keyed by `ClientHandle`.

use crate::server::types::ClientHandle;
use crate::vfs_core::namei::PathAnchor;

pub(crate) const MAX_WIN32_CLIENTS: usize = 64;

#[derive(Clone, Copy)]
#[repr(C)]
pub(crate) struct Win32CwdEntry {
    pub(crate) client: ClientHandle,
    pub(crate) current_drive: u8,
    _pad: [u8; 7],
    pub(crate) drive_cwd: [PathAnchor; 26],
}

impl Win32CwdEntry {
    const fn empty() -> Self {
        Win32CwdEntry {
            client: ClientHandle::INVALID,
            current_drive: 0,
            _pad: [0; 7],
            drive_cwd: [PathAnchor::INVALID; 26],
        }
    }
}

#[repr(C)]
pub(crate) struct Win32CwdTable {
    entries: [Win32CwdEntry; MAX_WIN32_CLIENTS],
}

impl Win32CwdTable {
    pub(crate) const fn zeroed() -> Self {
        Win32CwdTable {
            entries: [Win32CwdEntry::empty(); MAX_WIN32_CLIENTS],
        }
    }

    pub(crate) fn register(&mut self, client: ClientHandle) -> Result<(), ()> {
        if !client.is_valid() {
            return Err(());
        }
        if self.find_slot(client).is_some() {
            return Ok(());
        }
        for slot in self.entries.iter_mut() {
            if !slot.client.is_valid() {
                *slot = Win32CwdEntry::empty();
                slot.client = client;
                return Ok(());
            }
        }
        Err(())
    }

    pub(crate) fn ensure_seeded(
        &mut self,
        client: ClientHandle,
        root_anchor: PathAnchor,
    ) -> Result<(), ()> {
        self.register(client)?;
        let Some(slot) = self.get_mut(client) else {
            return Err(());
        };
        let blank = slot.drive_cwd.iter().all(|anchor| !anchor.is_valid());
        if blank {
            slot.current_drive = 2;
        }
        if root_anchor.is_valid() {
            if !slot.drive_cwd[2].is_valid() {
                slot.drive_cwd[2] = root_anchor;
            }
            if !slot.drive_cwd[25].is_valid() {
                slot.drive_cwd[25] = root_anchor;
            }
        }
        Ok(())
    }

    pub(crate) fn clone_from(
        &mut self,
        src: ClientHandle,
        dst: ClientHandle,
        root_anchor: PathAnchor,
    ) -> Result<(), ()> {
        self.ensure_seeded(dst, root_anchor)?;
        let src_slot = match self.get(src) {
            Some(slot) => *slot,
            None => return Ok(()),
        };
        let Some(dst_slot) = self.get_mut(dst) else {
            return Err(());
        };
        *dst_slot = src_slot;
        dst_slot.client = dst;
        Ok(())
    }

    pub(crate) fn deregister(&mut self, client: ClientHandle) {
        if let Some(idx) = self.find_slot(client) {
            self.entries[idx] = Win32CwdEntry::empty();
        }
    }

    pub(crate) fn get(&self, client: ClientHandle) -> Option<&Win32CwdEntry> {
        self.find_slot(client).map(|idx| &self.entries[idx])
    }

    pub(crate) fn get_mut(&mut self, client: ClientHandle) -> Option<&mut Win32CwdEntry> {
        let idx = self.find_slot(client)?;
        Some(&mut self.entries[idx])
    }

    pub(crate) fn drive_cwd_anchor(
        &self,
        client: ClientHandle,
        drive_index: usize,
    ) -> Option<PathAnchor> {
        if drive_index >= 26 {
            return None;
        }
        let slot = self.get(client)?;
        let anchor = slot.drive_cwd[drive_index];
        if !anchor.is_valid() {
            None
        } else {
            Some(anchor)
        }
    }

    pub(crate) fn set_drive_cwd(
        &mut self,
        client: ClientHandle,
        drive_index: usize,
        anchor: PathAnchor,
    ) -> Result<(), ()> {
        if drive_index >= 26 {
            return Err(());
        }
        let Some(slot) = self.get_mut(client) else {
            return Err(());
        };
        slot.current_drive = drive_index as u8;
        slot.drive_cwd[drive_index] = anchor;
        Ok(())
    }

    #[inline]
    fn find_slot(&self, client: ClientHandle) -> Option<usize> {
        if !client.is_valid() {
            return None;
        }
        for (idx, slot) in self.entries.iter().enumerate() {
            if slot.client == client {
                return Some(idx);
            }
        }
        None
    }
}

unsafe impl Sync for Win32CwdTable {}
