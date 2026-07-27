// SPDX-License-Identifier: GPL-2.0-only
//
//! Personality-owned async-namei terminal dispatch.
//!
//! The walker produces a personality-neutral [`NameiAsyncResult`]
//! plus a [`NameiTerminal`] intent. POSIX-only terminal replies
//! live here so the core path-walk state machine does not reach
//! directly into `personality::posix::*` modules.

use crate::core::error::VfsError;
use crate::core::file::VAttr;
use crate::core::identity::VnodeKey;
use crate::core::namei_async::NameiAsyncResult;
use crate::owner::VfsState;
use crate::owner::resume::NameiTerminal;
use crate::server::types::ClientHandle;

pub(crate) unsafe fn dispatch_posix_terminal(
    state: &mut VfsState,
    client: ClientHandle,
    result: &NameiAsyncResult,
    terminal: NameiTerminal,
    reply_lease: trona_server::ReplyLease,
) {
    unsafe {
        if !result.vnode_h.is_valid() {
            send_terminal_error(state, client, reply_lease, VfsError::NoEnt);
            return;
        }

        match terminal {
            NameiTerminal::Readlink => {
                crate::personality::posix::readlink::send_readlink_reply_for_vnode(
                    state,
                    client,
                    result.vnode_h,
                    reply_lease,
                );
            }
            NameiTerminal::Chdir {
                canon_path,
                canon_len,
            } => {
                crate::personality::posix::cwd::finish_chdir(
                    state,
                    client,
                    result.vnode_h,
                    canon_path,
                    canon_len,
                    reply_lease,
                );
            }
            NameiTerminal::CanonPath {
                canon_path,
                canon_len,
            } => {
                crate::personality::posix::exec_helpers::send_canon_path_reply(
                    state,
                    client,
                    canon_path,
                    canon_len,
                    reply_lease,
                );
            }
            NameiTerminal::StatForExec => {
                let personality = state
                    .clients
                    .get(client)
                    .map(|c| c.personality)
                    .unwrap_or(crate::personality::Personality::Posix);
                crate::personality::posix::stat::send_stat_for_exec_reply_for_vnode(
                    state,
                    client,
                    result.vnode_h,
                    reply_lease,
                    personality,
                );
            }
            NameiTerminal::OpenForExec => {
                let personality = state
                    .clients
                    .get(client)
                    .map(|c| c.personality)
                    .unwrap_or(crate::personality::Personality::Posix);
                crate::personality::posix::stat::send_open_for_exec_reply_for_vnode(
                    state,
                    client,
                    result.vnode_h,
                    reply_lease,
                    personality,
                );
            }
            _ => send_terminal_error(state, client, reply_lease, VfsError::NotSup),
        }
    }
}

fn send_terminal_error(
    state: &VfsState,
    client: ClientHandle,
    reply_lease: trona_server::ReplyLease,
    err: VfsError,
) {
    let personality = state
        .clients
        .get(client)
        .map(|c| c.personality)
        .unwrap_or(crate::personality::Personality::Posix);
    crate::personality::wire::send_reply_err_typed(personality, reply_lease, err)
}

pub(crate) unsafe fn resume_stat_for_exec_access_reply(
    state: &mut VfsState,
    client: ClientHandle,
    vkey: VnodeKey,
    reply_lease: trona_server::ReplyLease,
    ack: Result<(), VfsError>,
    personality: crate::personality::Personality,
) {
    unsafe {
        crate::personality::posix::stat::resume_fill_stat_for_exec_access_reply(
            state,
            client,
            vkey,
            reply_lease,
            ack,
            personality,
        );
    }
}

pub(crate) unsafe fn resume_stat_for_exec_attr_reply(
    state: &mut VfsState,
    client: ClientHandle,
    vkey: VnodeKey,
    reply_lease: trona_server::ReplyLease,
    attr: Result<VAttr, VfsError>,
    personality: crate::personality::Personality,
) {
    unsafe {
        crate::personality::posix::stat::resume_fill_stat_for_exec_attr_reply(
            state,
            client,
            vkey,
            reply_lease,
            attr,
            personality,
        );
    }
}

pub(crate) unsafe fn resume_open_for_exec_access_reply(
    state: &mut VfsState,
    client: ClientHandle,
    vkey: VnodeKey,
    reply_lease: trona_server::ReplyLease,
    ack: Result<(), VfsError>,
    personality: crate::personality::Personality,
) {
    unsafe {
        crate::personality::posix::stat::resume_fill_open_for_exec_access_reply(
            state,
            client,
            vkey,
            reply_lease,
            ack,
            personality,
        );
    }
}
