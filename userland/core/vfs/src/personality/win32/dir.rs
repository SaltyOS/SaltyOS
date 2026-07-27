// SPDX-License-Identifier: GPL-2.0-only
//
//! NT `NtQueryDirectoryFile` entry.
//!
//! Wire layout (`WIN32_NT_QUERY_DIRECTORY_FILE = 0x547`):
//! ```text
//!   byte 0..4    FileHandle           (i32 fd)
//!   byte 4..8    Length               (u32, caller buffer cap)
//!   byte 8..12   FileInformationClass (u32)
//!   byte 12..16  ReturnSingleEntry    (u32, bool)
//!   byte 16..24  StartCookie          (u64)
//! ```

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::core::error::VfsError;
use crate::ops::ReadDirReplyIntent;
use crate::owner::VfsState;
use crate::server::types::ClientHandle;

const FILE_DIRECTORY_INFORMATION: u32 = 1;
const FILE_FULL_DIRECTORY_INFORMATION: u32 = 2;
const FILE_BOTH_DIRECTORY_INFORMATION: u32 = 3;
const FILE_NAMES_INFORMATION: u32 = 12;
const FILE_ID_BOTH_DIRECTORY_INFORMATION: u32 = 37;
const FILE_ID_FULL_DIRECTORY_INFORMATION: u32 = 38;

pub(crate) unsafe fn handle_nt_query_directory_file(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = (msg.regs[0] & 0xFFFF_FFFF) as i32;
        let info_class = (msg.regs[1] & 0xFFFF_FFFF) as u32;
        let cookie = msg.regs[2];

        let reply_intent = match info_class {
            FILE_DIRECTORY_INFORMATION => ReadDirReplyIntent::NtFileDirectoryInformation,
            FILE_FULL_DIRECTORY_INFORMATION => ReadDirReplyIntent::NtFileFullDirectoryInformation,
            FILE_BOTH_DIRECTORY_INFORMATION => ReadDirReplyIntent::NtFileBothDirectoryInformation,
            FILE_NAMES_INFORMATION => ReadDirReplyIntent::NtFileNamesInformation,
            FILE_ID_BOTH_DIRECTORY_INFORMATION => {
                ReadDirReplyIntent::NtFileIdBothDirectoryInformation
            }
            FILE_ID_FULL_DIRECTORY_INFORMATION => {
                ReadDirReplyIntent::NtFileIdFullDirectoryInformation
            }
            _ => {
                super::reply::emit_ntstatus_error(reply_lease, VfsError::Inval);
                return;
            }
        };

        crate::ops::dir::do_readdir_from_fd(state, client, fd, cookie, reply_intent, reply_lease);
    }
}
