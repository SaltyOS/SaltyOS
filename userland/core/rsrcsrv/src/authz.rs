// SPDX-License-Identifier: GPL-2.0-only
//
//! Badge-based authorization for rsrcsrv labels. rsrcsrv is a single-master
//! retype broker — caller identity comes from the minted badge on the
//! invoked cap, propagated by the kernel into `MpRecord.badge`.
//!
//! Wire layout matches `trona_server::badge` (see that module's docs);
//! the class bit assignment used here is:
//!
//! ```text
//!   00 (Client) — regular per-process retype caller. namesrv mints
//!                 per-caller service caps with this class when an
//!                 entry uses `BADGE_AS_CALLER`; quota / OwnerTable
//!                 entries are keyed by `client_id`.
//!   01 (Client) — accepted for compatibility with explicit publisher
//!                 class caps.
//!   11 (Admin)  — privileged caller (init at namesrv-spawn time).
//!                 Bypasses quota checks; quota-management labels
//!                 require this class.
//! ```
//!
//! `client_id` (badge low 32 bits) is the OwnerTable key for the Client
//! class; it replaces the previous opaque 64-bit badge so the per-owner
//! tracking is consistent with namesrv's publisher table.

use trona_server::badge::{
    BADGE_CLASS_ADMIN, BADGE_CLASS_PUBLISHER, BADGE_CLASS_QUERY, class_bits, client_id_of,
    policy_id_of,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeClass {
    Client,
    Admin,
}

#[derive(Debug, Clone, Copy)]
pub struct BadgeFields {
    pub class: BadgeClass,
    pub policy_id: u32,
    /// Caller's `client_id` (badge low 32 bits). Doubles as the
    /// OwnerTable key — every retype admit / release / drop_owner uses
    /// this u32 (NOT the raw badge u64).
    pub client_id: u32,
}

impl BadgeFields {
    /// Parse a raw badge value. Returns `None` if the class bits
    /// indicate a reserved combination (`0b10`).
    pub fn parse(badge: u64) -> Option<Self> {
        let class = match class_bits(badge) {
            BADGE_CLASS_QUERY | BADGE_CLASS_PUBLISHER => BadgeClass::Client,
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
