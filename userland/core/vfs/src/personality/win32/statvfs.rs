// SPDX-License-Identifier: GPL-2.0-only
//
//! `NtQueryVolumeInformationFile` entry — produces
//! `FILE_FS_VOLUME_INFORMATION` / `FILE_FS_SIZE_INFORMATION` /
//! `FILE_FS_ATTRIBUTE_INFORMATION` over the neutral statfs helper.

use trona_kernel::core_types::TronaMsg;
use trona_server::ReplyLease;

use crate::ops::StatfsReplyIntent;
use crate::owner::VfsState;
use crate::personality::reply::emit_statfs;
use crate::server::types::ClientHandle;

const FILE_FS_VOLUME_INFORMATION: u32 = 1;
const FILE_FS_SIZE_INFORMATION: u32 = 3;
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
const FILE_FS_ATTRIBUTE_INFORMATION: u32 = 5;

pub(crate) unsafe fn handle(
    state: &mut VfsState,
    client: ClientHandle,
    msg: &TronaMsg,
    reply_lease: ReplyLease,
) {
    unsafe {
        let fd = msg.regs[0] as i32;
        let intent = match msg.regs[1] as u32 {
            FILE_FS_VOLUME_INFORMATION => StatfsReplyIntent::NtFileFsVolumeInformation,
            FILE_FS_SIZE_INFORMATION => StatfsReplyIntent::NtFileFsSizeInformation,
            FILE_FS_DEVICE_INFORMATION => StatfsReplyIntent::NtFileFsDeviceInformation,
            FILE_FS_ATTRIBUTE_INFORMATION => StatfsReplyIntent::NtFileFsAttributeInformation,
            _ => {
                emit_statfs(
                    reply_lease,
                    StatfsReplyIntent::NtFileFsVolumeInformation,
                    Err(crate::core::error::VfsError::Inval),
                );
                return;
            }
        };
        let result = crate::ops::statfs::do_statfs_from_fd(state, client, fd);
        emit_statfs(reply_lease, intent, result);
    }
}
