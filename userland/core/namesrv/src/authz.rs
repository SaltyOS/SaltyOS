// SPDX-License-Identifier: GPL-2.0-only
//
//! Badge-based authorization for namesrv labels. namesrv is a
//! single-master broker — caller identity comes from the minted badge
//! on the invoked cap, propagated by the kernel into `MpRecord.badge`.
//!
//! Wire layout (64 bits):
//!
//! ```text
//!   bit 63-62: class — 00=query, 01=publisher, 11=admin
//!   bit 61-48: reserved (= 0)
//!   bit 47-32: policy_id (16 bits) — stable per-service id from the
//!              service manifest; survives restarts.
//!   bit 31-0:  client_id (32 bits) — caller process identity, used
//!              both for routing (every label) and as the OwnerTable
//!              key (publisher class). For publisher caps, init mints
//!              the badge with the publisher process's main TCB
//!              `trace_id` packed into this field; conceptually that
//!              value is the caller's `client_id` so we keep one name
//!              for it across the wire.
//! ```

use trona_server::badge::{
    BADGE_CLASS_ADMIN, BADGE_CLASS_PUBLISHER, BADGE_CLASS_QUERY, class_bits, client_id_of,
    policy_id_of,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeClass {
    Query,
    Publisher,
    Admin,
}

#[derive(Debug, Clone, Copy)]
pub struct BadgeFields {
    pub class: BadgeClass,
    pub policy_id: u32,
    /// Caller's `client_id` (badge low 32 bits). For publisher caps
    /// this doubles as the OwnerTable key (publisher process identity)
    /// because init mints the publisher cap with the publisher's main
    /// TCB trace_id packed in here, and that value is the caller's
    /// per-process `client_id`.
    pub client_id: u32,
}

impl BadgeFields {
    /// Parse a raw badge value. Returns `None` if the class bits
    /// indicate a reserved combination (`0b10`).
    pub fn parse(badge: u64) -> Option<Self> {
        let class = match class_bits(badge) {
            BADGE_CLASS_QUERY => BadgeClass::Query,
            BADGE_CLASS_PUBLISHER => BadgeClass::Publisher,
            BADGE_CLASS_ADMIN => BadgeClass::Admin,
            _ => return None,
        };
        Some(Self {
            class,
            policy_id: policy_id_of(badge),
            client_id: client_id_of(badge),
        })
    }
}
