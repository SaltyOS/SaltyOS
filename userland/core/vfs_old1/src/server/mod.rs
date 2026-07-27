// SPDX-License-Identifier: GPL-2.0-only
//! VFS-private server helpers.

pub(crate) mod client;
pub(crate) mod epoll_object;
pub(crate) mod fifo_object;
pub(crate) mod mem;
pub(crate) mod mo;
pub(crate) mod open_file;
pub(crate) mod pipe_object;
pub(crate) mod proc_object;
pub(crate) mod shm_object;
pub(crate) mod sysctl_object;
pub(crate) mod types;
pub(crate) mod unix_socket_object;
