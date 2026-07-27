// SPDX-License-Identifier: GPL-2.0-only
//! VFS bootstrap — Vnode-native boot sequence.
//!
//! The single entry point is [`init_boot_env`], which performs the full
//! multi-stage bootstrap:
//!
//! 1. Register builtin filesystem types (ramfs, devfs, procfs, tmpfs, sysctlfs).
//! 2. Mount ramfs as the root filesystem and set `ROOT_MOUNT`.
//! 3. Create the FHS directory scaffold on ramfs root.
//! 4. Seed `/etc` configuration files (passwd, shadow, group, etc.).
//! 5. Extract CPIO initrd into `/initramfs`.
//! 6. Mount devfs on `/dev`.
//! 7. Mount procfs on `/proc`.
//! 8. Mount tmpfs on `/tmp`.
//! 9. Mount sysctlfs on `/sys`.

pub(crate) mod bootstrap;
pub(crate) mod fstab;
pub(crate) mod late_mount;
pub(crate) mod pivot_root;

pub(crate) use bootstrap::init_boot_env;

pub(crate) use bootstrap::BOOT_CRED;
