// SPDX-License-Identifier: GPL-2.0-only
//! Code-MemoryObject acquisition for the mmsrv-backed image loader.
//!
//! A run staged through mmsrv's `STAGE_FLAG_PROVIDED_MO` mode needs an
//! execute-bearing (`R-X`) code MO to attenuate from. Before the Stage-1 handoff
//! init still holds the boot `ExecAuthority` and mints one directly over the
//! initrd bytes; afterwards `ldsrv` is the sole EXECUTE authority, so init
//! resolves the code MO through it — a program main by conferring EXECUTE on a
//! READ backing it wraps over the initrd bytes (`resolve_main`), a shared library
//! by soname from `ldsrv`'s cache (`resolve_library_at` against init's own
//! `state.caps.ldsrv_client_ep`, looked up through namesrv).

use trona_kernel::core_types::{Cap, TronaMsg};
use trona_protocol::namesrv::NAMESRV_LOOKUP;
use trona_runtime::core::slot_alloc::{OwnedCap, alloc_slot};

use crate::supervisor::SupervisorState;
use crate::supervisor::ldsrv_adopt::mint_borrowed;

/// What a code MO is being acquired for — selects the post-handoff resolve path.
pub enum CodeSource<'a> {
    /// A program main image. Post-handoff its bytes are wrapped in a READ backing
    /// and conferred through `resolve_main` (init's private exec-control MP).
    Main { bytes: &'a [u8] },
    /// A shared library / interpreter, resolved post-handoff from `ldsrv`'s cache
    /// by `name` (its soname). `bytes` back the pre-handoff direct mint.
    Library { name: &'a [u8], bytes: &'a [u8] },
}

impl CodeSource<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            CodeSource::Main { bytes } => bytes,
            CodeSource::Library { bytes, .. } => bytes,
        }
    }
}

/// Acquire an `R-X` code MO for `source`, owned by the caller.
///
/// Pre-handoff (`exec_authority_held`): mint a borrowed-frames `R-X` MO directly
/// over the initrd bytes. Post-handoff: resolve through `ldsrv` — a main by
/// `resolve_main` over a READ backing init wraps (ldsrv confers EXECUTE +
/// content-digest-dedups to the adopted MO), a library by
/// `resolve_library_at` against init's cached `state.caps.ldsrv_client_ep`.
pub fn get_code_mo(state: &mut SupervisorState, source: CodeSource<'_>) -> Result<OwnedCap, i32> {
    let initrd_va = state.caps.initrd_va;
    if state.exec_authority_held {
        // Pre-handoff: init is still the EXECUTE authority — mint the R-X view
        // directly (same path the boot group and the adopt sender use).
        return mint_borrowed(state, initrd_va, source.bytes(), true);
    }

    match source {
        CodeSource::Main { bytes } => {
            // Wrap the initrd bytes in a READ borrowed-frames backing (no
            // EXECUTE, no authority needed) and let ldsrv confer EXECUTE. `size`
            // is the exact byte length so ldsrv's content digest matches the
            // adopted object and dedups to it — a page-aligned length would miss.
            let backing = mint_borrowed(state, initrd_va, bytes, false)?;
            let control_ep = state
                .ldsrv_exec_control_send
                .as_ref()
                .map(|c| c.as_raw())
                .unwrap_or(0);
            let resolved = unsafe {
                trona_runtime::client::ldsrv::resolve_main(
                    control_ep,
                    backing.into_transfer(),
                    bytes.len() as u64,
                    0,
                )
            }
            .map_err(|e| e as i32)?;
            Ok(resolved.code_mo)
        }
        CodeSource::Library { name, .. } => {
            // Post-handoff: route through init's own cached `ldsrv` EP rather
            // than `trona_runtime::client::ldsrv::resolve_library`. The runtime
            // helper lazy-resolves via `__trona_cap_ldsrv_ep`, which the kernel
            // never installs for PID 1 (`ldsrv` does not exist at init's
            // startup, so `ROLE_LDSRV_CLIENT` is absent from init's startup
            // cap-table). PID 1 is the supervisor: its own
            // `state.caps.namesrv_client_mp` is the authoritative namesrv EP,
            // and the resolved ldsrv EP is cached in
            // `state.caps.ldsrv_client_ep` on first use.
            let ldsrv_ep = init_ldsrv_client_ep(state)?;
            let resolved =
                unsafe { trona_runtime::client::ldsrv::resolve_library_at(ldsrv_ep, name) }
                    .map_err(|e| e as i32)?;
            Ok(resolved.code_mo)
        }
    }
}

/// Look up ldsrv's client-facing service EP through namesrv, caching the
/// per-caller copy in `state.caps.ldsrv_client_ep`. Init owns this cap (it
/// does not flow through `install_well_known_caps`) because the runtime
/// weak-symbol path is permanently dead for PID 1 — see the
/// `Library { name, .. }` arm of [`get_code_mo`].
///
/// Returns the raw slot address of the cached cap, ready to hand to
/// [`trona_runtime::client::ldsrv::resolve_library_at`]. Errors:
/// `KERNITE_ERR_OUT_OF_MEMORY` on slot exhaustion, or the namesrv reply
/// label on a refused lookup (typically `KERNITE_ERR_NOT_FOUND` until ldsrv
/// registers).
pub(super) fn init_ldsrv_client_ep(state: &mut SupervisorState) -> Result<u64, i32> {
    if let Some(cap) = state.caps.ldsrv_client_ep.as_ref() {
        return Ok(cap.as_raw());
    }

    let namesrv_ep = state
        .caps
        .namesrv_client_mp
        .as_ref()
        .map(|c| c.as_raw())
        .unwrap_or(0);
    if namesrv_ep == 0 {
        return Err(uapi::KERNITE_ERR_NOT_FOUND as i32);
    }

    let dest = alloc_slot().ok_or(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32)?;

    let ipc_ctx = trona_runtime::current_ipc_ctx();
    if ipc_ctx.is_null() {
        return Err(uapi::KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let saved = unsafe { trona_kernel::ipc::get_receive_slot_path_ctx(ipc_ctx) };
    unsafe {
        trona_runtime::core::ipc_ext::set_receive_slot_ctx(
            ipc_ctx,
            uapi::KERNITE_CAP_SELF_CSPACE as Cap,
            dest.addr(),
            0,
        );
    }

    let mut msg = TronaMsg::zeroed();
    msg.label = NAMESRV_LOOKUP;
    pack_name_lookup(&mut msg, b"ldsrv");

    let mut reply = TronaMsg::zeroed();
    unsafe { trona_kernel::ipc::clear_send_caps_ctx(ipc_ctx) };
    let err = unsafe {
        trona_kernel::ipc::mp_call_ctx(
            ipc_ctx,
            namesrv_ep,
            &raw const msg,
            &raw mut reply,
            trona_kernel::ipc::IPC_TIMEOUT_BLOCK_FOREVER,
        )
    };
    unsafe {
        trona_kernel::ipc::set_receive_slot_path_ctx(ipc_ctx, saved.0, saved.1, saved.2, saved.3);
    }
    if err != 0 {
        return Err(err as i32);
    }
    if reply.label != trona_protocol::common::TRONA_OK as u64 {
        return Err(reply.label as i32);
    }

    let cap = unsafe { dest.assume_filled() };
    let raw = cap.as_raw();
    state.caps.ldsrv_client_ep = Some(cap);
    Ok(raw)
}

/// Pack a service name into a `NAMESRV_LOOKUP` request register block: byte
/// length at `regs[0]`, name bytes 8-per-word starting at `regs[1]`. Matches
/// `userland/core/namesrv/src/wire.rs::NAMESRV_LOOKUP` and the lazy-resolve
/// helper in `lib/trona/runtime/src/client/lazy_resolve.rs`.
fn pack_name_lookup(msg: &mut TronaMsg, name: &[u8]) {
    const MAX_NAME_BYTES: usize = 64;
    let len = name.len().min(MAX_NAME_BYTES);
    msg.regs[0] = len as u64;
    let mut written = 0;
    let mut word_idx = 1;
    while written < len && word_idx < msg.regs.len() {
        let mut word = [0u8; 8];
        let chunk = (len - written).min(8);
        word[..chunk].copy_from_slice(&name[written..written + chunk]);
        msg.regs[word_idx] = u64::from_le_bytes(word);
        written += chunk;
        word_idx += 1;
    }
    msg.length = word_idx as u64;
}
