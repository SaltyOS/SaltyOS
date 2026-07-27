// SPDX-License-Identifier: GPL-2.0-only
//
//! Per-backend filesystem clients. Each module bridges a concrete
//! backend to the generic vnode / personality layers. Synthetic
//! filesystems own their on-mount state directly via `Mount.data`;
//! session-backed drivers use `BackendSessionSlot` plus their own
//! per-mount client state.

pub(crate) mod devfs;
pub(crate) mod metrics;
pub(crate) mod mount;
pub(crate) mod pipefs;
pub(crate) mod procfs;
pub(crate) mod ramfs;
pub(crate) mod saltyfs_client;
pub(crate) mod sysctlfs;
pub(crate) mod tmpfs;
