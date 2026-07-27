// SPDX-License-Identifier: GPL-2.0-only
//
//! `PendingSubs` — ring of parked LOOKUP / SUBSCRIBE callers. Each
//! entry pairs a target name with the reply MessagePipe endpoint slot
//! and transaction id to use for the eventual `reply-marked MP_WRITE`,
//! plus the deadline (for `LOOKUP_TIMEOUT`).

use crate::wire::MAX_NAME_BYTES;
use trona_server::MpReplyTarget;

pub const PENDING_SUBS_RING: usize = 32;

pub const KIND_LOOKUP: u8 = 0;
pub const KIND_LOOKUP_TIMEOUT: u8 = 1;
pub const KIND_SUBSCRIBE: u8 = 2;

#[derive(Clone, Copy)]
pub struct PendingSub {
    pub name: [u8; MAX_NAME_BYTES],
    pub name_len: u8,
    pub kind: u8,
    pub reply_target: MpReplyTarget,
    pub deadline_ns: u64,
    pub subscriber_tcb: u32,
    pub cookie: u64,
    pub active: u8,
}

impl PendingSub {
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_BYTES],
            name_len: 0,
            kind: 0,
            reply_target: MpReplyTarget::none(),
            deadline_ns: 0,
            subscriber_tcb: 0,
            cookie: 0,
            active: 0,
        }
    }

    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

pub struct PendingSubs {
    entries: [PendingSub; PENDING_SUBS_RING],
}

impl PendingSubs {
    pub const fn new() -> Self {
        Self {
            entries: [PendingSub::empty(); PENDING_SUBS_RING],
        }
    }

    pub fn push(
        &mut self,
        name: &[u8],
        kind: u8,
        reply_target: MpReplyTarget,
        deadline_ns: u64,
        subscriber_tcb: u32,
        cookie: u64,
    ) -> Option<usize> {
        for (idx, entry) in self.entries.iter_mut().enumerate() {
            if entry.active != 0 {
                continue;
            }
            entry.name_len = name.len() as u8;
            entry.name[..name.len()].copy_from_slice(name);
            entry.kind = kind;
            entry.reply_target = reply_target;
            entry.deadline_ns = deadline_ns;
            entry.subscriber_tcb = subscriber_tcb;
            entry.cookie = cookie;
            entry.active = 1;
            return Some(idx);
        }
        None
    }

    pub fn entry(&self, idx: usize) -> &PendingSub {
        &self.entries[idx]
    }

    pub fn vacate(&mut self, idx: usize) {
        self.entries[idx].active = 0;
    }

    /// Earliest deadline among `LOOKUP_TIMEOUT` parks (for arming the
    /// park Timer). Returns `None` when no timed park is queued.
    pub fn earliest_deadline_ns(&self) -> Option<u64> {
        let mut best: Option<u64> = None;
        for entry in self.entries.iter() {
            if entry.active == 0 || entry.kind != KIND_LOOKUP_TIMEOUT {
                continue;
            }
            best = Some(match best {
                Some(prev) if prev <= entry.deadline_ns => prev,
                _ => entry.deadline_ns,
            });
        }
        best
    }
}
