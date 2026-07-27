// SPDX-License-Identifier: GPL-2.0-only
//
//! Win32 label-range dispatch entry — `0x540..=0x57F`.
//!
//! Owner-reactor's frontend `kind=0` branch delegates here when
//! the client's personality is `Win32`. The Win32 wire is
//! NT-shaped: `NtCreateFile`, `NtReadFile`, `NtWriteFile`,
//! `NtClose`, `NtQueryInformationFile`, `NtSetInformationFile`,
//! `NtDeviceIoControlFile`. Each label decodes its own
//! `ObjectAttributes` / `IO_STATUS_BLOCK` payload through the
//! per-label NT entry under `personality::win32::*`, which lands
//! on the personality-neutral `ops::*` helpers and emits the
//! NTSTATUS reply through `personality::reply::*`.
//!
//! Each of the 28 NT labels is matched explicitly so a wire
//! audit can read the dispatch table and confirm which calls are
//! routed and which still surface `STATUS_NOT_SUPPORTED`.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::owner::VfsState;
use crate::personality::wire::send_ntstatus_reply;
use crate::server::types::ClientHandle;
use trona_protocol::win32::{
    WIN32_NT_CLOSE, WIN32_NT_CREATE_FILE, WIN32_NT_CREATE_MAILSLOT_FILE,
    WIN32_NT_CREATE_NAMED_PIPE_FILE, WIN32_NT_CREATE_PIPE, WIN32_NT_CREATE_SECTION,
    WIN32_NT_CREATE_SYMBOLIC_LINK_OBJECT, WIN32_NT_DELETE_FILE, WIN32_NT_DEVICE_IO_CONTROL_FILE,
    WIN32_NT_DUPLICATE_OBJECT, WIN32_NT_FLUSH_BUFFERS_FILE, WIN32_NT_LOCK_FILE,
    WIN32_NT_MAP_VIEW_OF_SECTION, WIN32_NT_OPEN_FILE, WIN32_NT_OPEN_SECTION,
    WIN32_NT_QUERY_ATTRIBUTES_FILE, WIN32_NT_QUERY_DIRECTORY_FILE,
    WIN32_NT_QUERY_FULL_ATTRIBUTES_FILE, WIN32_NT_QUERY_INFORMATION_FILE,
    WIN32_NT_QUERY_SECURITY_OBJECT, WIN32_NT_QUERY_VOLUME_INFORMATION_FILE, WIN32_NT_READ_FILE,
    WIN32_NT_RENAME_FILE, WIN32_NT_SET_INFORMATION_FILE, WIN32_NT_SET_SECURITY_OBJECT,
    WIN32_NT_SET_VOLUME_INFORMATION_FILE, WIN32_NT_UNLOCK_FILE, WIN32_NT_UNMAP_VIEW_OF_SECTION,
    WIN32_NT_WRITE_FILE,
};

/// Dispatch a frontend RPC whose label landed in the Win32 range.
/// Resolves the per-label handler explicitly so the routing table
/// can be audited statically. Each handler decodes its own NT
/// argument layout off `msg`, performs drive-letter + path
/// canonicalization (`super::path` / `super::drives`), then walks
/// the resulting absolute path through `core::namei_async`
/// before producing an NTSTATUS reply via `send_ntstatus_reply`.
pub(crate) unsafe fn dispatch(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    match msg.label {
        WIN32_NT_CLOSE => unsafe { super::close::handle(state, client, msg, reply_lease) },
        WIN32_NT_DUPLICATE_OBJECT => unsafe {
            super::duplicate::handle(state, client, msg, reply_lease)
        },
        WIN32_NT_READ_FILE => unsafe {
            super::io::handle_nt_read_file(state, client, msg, reply_lease)
        },
        WIN32_NT_WRITE_FILE => unsafe {
            super::io::handle_nt_write_file(state, client, msg, reply_lease)
        },
        WIN32_NT_FLUSH_BUFFERS_FILE => unsafe {
            super::io::handle_nt_flush_buffers_file(state, client, msg, reply_lease)
        },
        // NtDeleteFile maps to `UnlinkKind::Either` — Windows
        // accepts both files and directories on the public
        // surface; the kernel rejects when a directory is
        // non-empty via filesystem policy.
        WIN32_NT_DELETE_FILE => unsafe {
            super::unlink::handle_nt_delete_file(state, client, msg, reply_lease)
        },
        WIN32_NT_RENAME_FILE => unsafe {
            super::rename::handle_nt_rename_file(state, client, msg, reply_lease)
        },
        WIN32_NT_QUERY_SECURITY_OBJECT => unsafe {
            super::security::handle_nt_query_security_object(state, client, msg, reply_lease)
        },
        WIN32_NT_SET_SECURITY_OBJECT => unsafe {
            super::security::handle_nt_set_security_object(state, client, msg, reply_lease)
        },
        WIN32_NT_QUERY_INFORMATION_FILE => unsafe {
            super::attr::handle_nt_query_information_file(state, client, msg, reply_lease)
        },
        WIN32_NT_QUERY_ATTRIBUTES_FILE => unsafe {
            super::attr::handle_nt_query_attributes_file(state, client, msg, reply_lease)
        },
        WIN32_NT_QUERY_FULL_ATTRIBUTES_FILE => unsafe {
            super::attr::handle_nt_query_full_attributes_file(state, client, msg, reply_lease)
        },
        WIN32_NT_QUERY_DIRECTORY_FILE => unsafe {
            super::dir::handle_nt_query_directory_file(state, client, msg, reply_lease)
        },
        WIN32_NT_DEVICE_IO_CONTROL_FILE => unsafe {
            super::device_io_control::handle(state, client, msg, reply_lease)
        },
        WIN32_NT_QUERY_VOLUME_INFORMATION_FILE => unsafe {
            super::statvfs::handle(state, client, msg, reply_lease)
        },
        WIN32_NT_LOCK_FILE => unsafe {
            super::lock::handle_nt_lock_file(state, client, msg, reply_lease)
        },
        WIN32_NT_UNLOCK_FILE => unsafe {
            super::lock::handle_nt_unlock_file(state, client, msg, reply_lease)
        },

        WIN32_NT_CREATE_FILE => unsafe {
            super::open::handle_nt_create_file(state, client, msg, reply_lease)
        },
        WIN32_NT_OPEN_FILE => unsafe {
            super::open::handle_nt_open_file(state, client, msg, reply_lease)
        },
        // NtSetInformationFile dispatches by `InformationClass`.
        // Position / EOF (14 / 20) reach the I/O slice directly;
        // the other classes (Rename=10, Disposition=13, Basic=4)
        // land with the mutation slice.
        WIN32_NT_SET_INFORMATION_FILE => unsafe {
            let info_class = (msg.regs[1] & 0xFFFF_FFFF) as u32;
            const FILE_POSITION_INFORMATION: u32 = 14;
            const FILE_END_OF_FILE_INFORMATION: u32 = 20;
            match info_class {
                FILE_POSITION_INFORMATION | FILE_END_OF_FILE_INFORMATION => {
                    let _handled = super::io::handle_nt_set_information_file_io(
                        state, client, msg, info_class, reply_lease,
                    );
                }
                _ => super::set_information::handle(state, client, msg, reply_lease),
            }
        },
        WIN32_NT_CREATE_PIPE => unsafe {
            super::create_pipe::handle(state, client, msg, reply_lease)
        },
        WIN32_NT_CREATE_NAMED_PIPE_FILE => unsafe {
            super::create_leaf::handle_nt_create_named_pipe_file(state, client, msg, reply_lease)
        },
        WIN32_NT_CREATE_SYMBOLIC_LINK_OBJECT => unsafe {
            super::create_leaf::handle_nt_create_symbolic_link_object(state, client, msg, reply_lease)
        },
        WIN32_NT_CREATE_SECTION => unsafe {
            super::create_section::handle(state, client, msg, reply_lease)
        },

        // NtSetVolumeInformationFile labels a mounted volume —
        // saltyos exposes no equivalent (mount labels are
        // immutable post-mount).
        WIN32_NT_SET_VOLUME_INFORMATION_FILE
        // NtCreateMailslotFile — saltyos has no mailslot
        // primitive (Win32-only IPC channel). The
        // win32-on-saltyos compat path will eventually map this
        // to a netsrv `AF_UNIX` datagram socket; until that
        // adapter lands, the NT request returns NOT_SUPPORTED.
        | WIN32_NT_CREATE_MAILSLOT_FILE
        // NtOpenSection / NtMapViewOfSection / NtUnmapViewOfSection
        // are client-side calls in the saltyos model — the client
        // calls its own mmsrv directly via `MM_MMAP(kind=MO)` /
        // `MM_MUNMAP` once it holds the section's `mo_cap` (the
        // basaltc shim translates between NT section HANDLE ↔
        // mmsrv MO cap). vfs is not on this path; callers that
        // somehow reach the vfs wire here surface NOT_SUPPORTED so
        // the dispatch shape stays observable.
        | WIN32_NT_OPEN_SECTION
        | WIN32_NT_MAP_VIEW_OF_SECTION
        | WIN32_NT_UNMAP_VIEW_OF_SECTION => send_ntstatus_reply(reply_lease, VfsError::NotSup),
        _ => send_ntstatus_reply(reply_lease, VfsError::NotSup),
    }
}

// NtDuplicateObject body lives in `super::duplicate`.
// NtCreateFile / NtOpenFile bodies live in `super::open`.
// NtSetInformationFile body lives in `super::set_information` —
// FilePosition / FileEndOfFile sub-classes are handled in
// `super::io` before this dispatcher; the rest land in
// `super::set_information::handle`.
// NtQueryInformationFile / NtQueryAttributesFile /
// NtQueryFullAttributesFile bodies live in `super::attr`.
