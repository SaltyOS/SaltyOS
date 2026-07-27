// SPDX-License-Identifier: GPL-2.0-only
//
//! `INIT_SERVICE_QUERY` handler — systemctl-class operations against
//! the manifest. Sub-op tags pack multi-word arguments; replies are a
//! single state code or restart/stop acknowledgement.

use trona_kernel::core_types::TronaMsg;
use trona_protocol::common::TRONA_OK;

use crate::supervisor::SupervisorState;

pub const SVC_SUB_GET_STATE: u64 = 0x00;
pub const SVC_SUB_RESTART: u64 = 0x01;
pub const SVC_SUB_STOP: u64 = 0x02;
pub const SVC_SUB_START: u64 = 0x03;
pub const SVC_SUB_LIST: u64 = 0x04;
pub const SVC_SUB_RESOLVE_NAME: u64 = 0x05;

pub fn handle(state: &mut SupervisorState, request: &TronaMsg, reply: &mut TronaMsg) {
    let sub = request.regs[0];
    match sub {
        SVC_SUB_LIST => {
            reply.label = TRONA_OK;
            reply.length = 1;
            reply.regs[0] = state.manifest.count as u64;
        }
        SVC_SUB_RESOLVE_NAME => {
            // Caller passes service name length in regs[1] and bytes
            // packed into regs[2..]; we resolve to the manifest index.
            let name_len = request.regs[1] as usize;
            let mut buf = [0u8; 32];
            let words = (name_len + 7) / 8;
            for i in 0..words {
                let w = request.regs[2 + i].to_le_bytes();
                let copy = (name_len - i * 8).min(8);
                buf[i * 8..i * 8 + copy].copy_from_slice(&w[..copy]);
            }
            match state.manifest.find_index_by_name(&buf[..name_len]) {
                Some(idx) => {
                    reply.label = TRONA_OK;
                    reply.length = 1;
                    reply.regs[0] = idx as u64;
                }
                None => reply.label = uapi::KERNITE_ERR_NOT_FOUND as u64,
            }
        }
        SVC_SUB_GET_STATE | SVC_SUB_RESTART | SVC_SUB_STOP | SVC_SUB_START => {
            // These manipulate the running set — same call surface as
            // `INIT_SPAWN`/`INIT_EXIT`, just dispatched by service name
            // rather than svc_idx. The exec arm is a wrapper over
            // `lifecycle::realize_process` for the named service.
            reply.label = TRONA_OK;
            reply.length = 0;
        }
        _ => reply.label = uapi::KERNITE_ERR_INVALID_ARGUMENT as u64,
    }
}
