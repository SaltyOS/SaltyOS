// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 per-open HANDLE state.
//!
//! Generic `OpenObject` owns the open-file-description state that
//! every personality shares. NT-specific access masks and mode bits
//! live here so the generic table does not import Win32 policy.

use crate::arena::handle::Handle;
use crate::owner::VfsState;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct Win32HandleState {
    /// Granted access captured at open/create time.
    pub granted_access: u32,
    /// Raw FILE_SHARE_* mask captured from the NT wire.
    pub share_access: u32,
    /// Raw CreateOptions mask captured from the NT wire.
    pub create_options: u32,
    /// Reserved for OBJ_* / DuplicateObject handle flags.
    pub handle_flags: u32,
}

impl Win32HandleState {
    pub(crate) const EMPTY: Self = Self {
        granted_access: 0,
        share_access: 0,
        create_options: 0,
        handle_flags: 0,
    };
}

pub(crate) fn install(
    state: &mut VfsState,
    granted_access: u32,
    share_access: u32,
    create_options: u32,
) -> Option<Handle<Win32HandleState>> {
    let handle = state.win32_handle_states.alloc()?;
    if let Some(slot) = state.win32_handle_states.get_mut(handle) {
        *slot = Win32HandleState {
            granted_access,
            share_access,
            create_options,
            handle_flags: 0,
        };
    }
    Some(handle)
}

pub(crate) fn get_by_slot(state: &VfsState, slot: u32) -> Option<&Win32HandleState> {
    let handle = state.win32_handle_states.handle_from_slot(slot)?;
    state.win32_handle_states.get(handle)
}

pub(crate) fn release_by_slot(state: &mut VfsState, slot: u32) {
    let Some(handle) = state.win32_handle_states.handle_from_slot(slot) else {
        return;
    };
    state.win32_handle_states.release(handle);
}
