//! Personality metadata and provider registry shared by spawn/exec paths.
//! SPDX-License-Identifier: GPL-2.0-only

pub(crate) mod posix;
mod win32;

use trona_kernel::core_types::{Cap, TronaMsg};
use trona_kernel::ipc;

use crate::base::proc_table::{
    COMPLETION_EVENT_CONTINUED, COMPLETION_EVENT_EXITED, COMPLETION_EVENT_STOPPED, SUBSYS_POSIX,
    SUBSYS_WIN32,
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    BuiltIn,
    External,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PersonalityKind {
    Posix,
    Win32,
}

#[derive(Clone, Copy)]
pub struct PersonalityDescriptor {
    pub kind: PersonalityKind,
    pub subsystem_id: u8,
    pub provider_kind: ProviderKind,
    pub vfs_subsystem_id: Option<u8>,
    pub ops: &'static PersonalityOps,
}

pub struct PersonalityOps {
    pub install_bootstrap_cap: unsafe fn(PersonalityKind, Cap, Option<u64>, u64) -> bool,
    pub register_vfs_client: unsafe fn(PersonalityKind, u32) -> bool,
    pub pre_teardown: unsafe fn(PersonalityKind, u64),
    pub post_teardown: unsafe fn(PersonalityKind, u64),
    pub register_provider_cap: unsafe fn(PersonalityKind, Cap) -> Result<(), ()>,
    pub observes_completion_event: fn(PersonalityKind, u8) -> bool,
}

unsafe fn install_bootstrap_cap_builtin(
    _kind: PersonalityKind,
    _child_cn: Cap,
    _dst_slot: Option<u64>,
    _badge: u64,
) -> bool {
    true
}

unsafe fn install_bootstrap_cap_external(
    kind: PersonalityKind,
    child_cn: Cap,
    dst_slot: Option<u64>,
    badge: u64,
) -> bool {
    unsafe {
        let Some(dst_slot) = dst_slot else {
            return true;
        };

        let provider_cap = kind.provider_cap();
        if provider_cap == 0 {
            return false;
        }

        let _ = trona_kernel::invoke::cnode_delete(child_cn, dst_slot);
        trona_kernel::invoke::cnode_mint(
            crate::CAP_SELF_CSPACE,
            provider_cap,
            child_cn,
            dst_slot,
            badge,
        ) == 0
    }
}

unsafe fn register_vfs_client_builtin(_kind: PersonalityKind, _pid: u32) -> bool {
    true
}

unsafe fn register_vfs_client_win32(kind: PersonalityKind, pid: u32) -> bool {
    unsafe {
        let Some(vfs_subsystem_id) = kind.descriptor().vfs_subsystem_id else {
            return true;
        };

        let mut vfs_msg = TronaMsg::zeroed();
        let mut vfs_reply = TronaMsg::zeroed();
        vfs_msg.label = trona_protocol::vfs::public::VFS_CLIENT_REGISTER;
        vfs_msg.length = 2;
        vfs_msg.regs[0] = pid as u64;
        vfs_msg.regs[1] = vfs_subsystem_id as u64;
        let err = ipc::call_ctx(
            crate::ipc_ctx(),
            crate::base::cap_helpers::vfs_provider_ep(),
            &raw const vfs_msg,
            &raw mut vfs_reply,
        );
        err == 0 && vfs_reply.label == crate::TRONA_OK
    }
}

unsafe fn pre_teardown_common(_kind: PersonalityKind, _badge: u64) {}

unsafe fn post_teardown_common(_kind: PersonalityKind, badge: u64) {
    if !crate::base::vfs_notify::enqueue_client_exit(badge) {
        trona_runtime::uwarn!(|_lb| {
            _lb.str(b"[PROCMGR] VFS client-exit queue full badge=");
            _lb.hex(badge);
            _lb.str(b"\n");
        });
    }
}

unsafe fn register_provider_cap_builtin(_kind: PersonalityKind, _cap: Cap) -> Result<(), ()> {
    Err(())
}

fn observes_completion_event_posix(_kind: PersonalityKind, event_kind: u8) -> bool {
    matches!(
        event_kind,
        COMPLETION_EVENT_EXITED | COMPLETION_EVENT_STOPPED | COMPLETION_EVENT_CONTINUED
    )
}

fn observes_completion_event_win32(_kind: PersonalityKind, event_kind: u8) -> bool {
    matches!(event_kind, COMPLETION_EVENT_EXITED)
}

unsafe fn register_provider_cap_external(kind: PersonalityKind, cap: Cap) -> Result<(), ()> {
    unsafe {
        let slot = &raw mut PROVIDER_CAPS[kind.index()];
        if *slot != 0 {
            trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, *slot);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(*slot);
        }
        *slot = cap;
        Ok(())
    }
}

static POSIX_OPS: PersonalityOps = PersonalityOps {
    install_bootstrap_cap: install_bootstrap_cap_builtin,
    register_vfs_client: register_vfs_client_builtin,
    pre_teardown: pre_teardown_common,
    post_teardown: post_teardown_common,
    register_provider_cap: register_provider_cap_builtin,
    observes_completion_event: observes_completion_event_posix,
};

static WIN32_OPS: PersonalityOps = PersonalityOps {
    install_bootstrap_cap: install_bootstrap_cap_external,
    register_vfs_client: register_vfs_client_win32,
    pre_teardown: pre_teardown_common,
    post_teardown: post_teardown_common,
    register_provider_cap: register_provider_cap_external,
    observes_completion_event: observes_completion_event_win32,
};

static DESCRIPTORS: [PersonalityDescriptor; 2] = [
    PersonalityDescriptor {
        kind: PersonalityKind::Posix,
        subsystem_id: SUBSYS_POSIX,
        provider_kind: ProviderKind::BuiltIn,
        vfs_subsystem_id: None,
        ops: &POSIX_OPS,
    },
    PersonalityDescriptor {
        kind: PersonalityKind::Win32,
        subsystem_id: SUBSYS_WIN32,
        provider_kind: ProviderKind::External,
        vfs_subsystem_id: Some(SUBSYS_WIN32),
        ops: &WIN32_OPS,
    },
];

static mut PROVIDER_CAPS: [Cap; 2] = [0; 2];

impl PersonalityKind {
    const fn index(self) -> usize {
        match self {
            PersonalityKind::Posix => 0,
            PersonalityKind::Win32 => 1,
        }
    }

    pub const fn from_subsystem_id(subsystem_id: u8) -> Self {
        match subsystem_id {
            SUBSYS_WIN32 => PersonalityKind::Win32,
            _ => PersonalityKind::Posix,
        }
    }

    pub const fn descriptor(self) -> PersonalityDescriptor {
        DESCRIPTORS[self.index()]
    }

    pub const fn subsystem_id(self) -> u8 {
        self.descriptor().subsystem_id
    }

    pub unsafe fn register_vfs_client(self, pid: u32) -> bool {
        unsafe { (self.descriptor().ops.register_vfs_client)(self, pid) }
    }

    pub unsafe fn pre_teardown(self, badge: u64) {
        unsafe { (self.descriptor().ops.pre_teardown)(self, badge) }
    }

    pub unsafe fn post_teardown(self, badge: u64) {
        unsafe { (self.descriptor().ops.post_teardown)(self, badge) }
    }

    pub unsafe fn install_bootstrap_cap(
        self,
        child_cn: Cap,
        dst_slot: Option<u64>,
        badge: u64,
    ) -> bool {
        unsafe { (self.descriptor().ops.install_bootstrap_cap)(self, child_cn, dst_slot, badge) }
    }

    pub unsafe fn provider_cap(self) -> Cap {
        unsafe { PROVIDER_CAPS[self.index()] }
    }

    pub unsafe fn register_provider_cap(self, cap: Cap) -> Result<(), ()> {
        unsafe { (self.descriptor().ops.register_provider_cap)(self, cap) }
    }

    pub fn observes_completion_event(self, event_kind: u8) -> bool {
        (self.descriptor().ops.observes_completion_event)(self, event_kind)
    }

    pub unsafe fn prepare_runtime(
        self,
        pid: u32,
        child_cn: Cap,
        dst_slot: Option<u64>,
        badge: u64,
    ) -> bool {
        unsafe {
            self.install_bootstrap_cap(child_cn, dst_slot, badge) && self.register_vfs_client(pid)
        }
    }
}

pub unsafe fn handle_register_provider(msg: &TronaMsg, reply: &mut TronaMsg) {
    unsafe {
        let kind = PersonalityKind::from_subsystem_id(msg.regs[0] as u8);
        let scratch = crate::CAP_RECV_SCRATCH;

        let perm = match (&mut *(&raw mut crate::ALLOCATOR)).alloc_single_slot() {
            Some(s) => s,
            None => {
                reply.label = crate::TRONA_OUT_OF_MEMORY;
                return;
            }
        };

        let err = trona_kernel::invoke::cnode_move(
            crate::CAP_SELF_CSPACE,
            perm,
            crate::CAP_SELF_CSPACE,
            scratch,
        );
        if err != 0 {
            let _ = trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, scratch);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(perm);
            reply.label = trona_protocol::posix::TRONA_INVALID_CAPABILITY;
            return;
        }

        if kind.register_provider_cap(perm).is_err() {
            trona_kernel::invoke::cnode_delete(crate::CAP_SELF_CSPACE, perm);
            (&mut *(&raw mut crate::ALLOCATOR)).free_single_slot(perm);
            reply.label = crate::TRONA_INVALID_ARGUMENT;
            return;
        }

        reply.label = crate::TRONA_OK;
    }
}
