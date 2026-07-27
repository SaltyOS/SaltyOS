// SPDX-License-Identifier: GPL-2.0-only
//! `EventRecord` — wire format delivered from `EventQueue::wait/poll`.
//!
//! Layout mirrors `kernite_event_record` in
//! `kernite/include/uapi/event.h` field-for-field. `kind`
//! discriminates between state-flag / IRQ / Timer / pipe / user /
//! overflow records; `status` carries OK / cancelled / peer-closed /
//! object-closed / dropped. `cookie` and the `payload*` fields are
//! caller-supplied at watch-registration / produce time and round-trip
//! back unmodified. `object_id`, `state_set`, and `state_seen` are
//! kernel-populated for state-bearing producers.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EventRecord {
    pub kind: u32,
    pub status: u32,
    pub cookie: u64,
    pub object_id: u64,
    pub state_set: u64,
    pub state_seen: u64,
    pub payload0: u64,
    pub payload1: u64,
    pub payload2: u64,
}

impl EventRecord {
    pub const fn empty() -> Self {
        Self {
            kind: 0,
            status: 0,
            cookie: 0,
            object_id: 0,
            state_set: 0,
            state_seen: 0,
            payload0: 0,
            payload1: 0,
            payload2: 0,
        }
    }
}
