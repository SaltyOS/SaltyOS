// SPDX-License-Identifier: GPL-2.0-only
//! System Call Handler
//!
//! Capability invocation dispatch.

mod cap;
mod cspace;
mod dispatch;
mod event;
mod exec_authority;
pub(crate) mod fastpath;
mod invoke;
mod ioport;
mod misc;
mod mo;
mod pager;
mod pipe;
mod sc;
mod support;
mod system;
mod tcb;
mod types;
mod vspace;

use crate::cap::{CNode, CapRights, Capability, FrameObject, ObjectType};
use crate::mm::{CAP_LOCK, phys_to_virt, restore_irq, save_irq_disable};
use crate::sched::class::{
    SCHED_CLASS_DEADLINE, SCHED_CLASS_FAIR, SCHED_CLASS_IDLE, SCHED_CLASS_RT_FIFO,
};
use crate::sched::scheduler::DeferredReleaseList;
use crate::sched::thread::{SchedContext, Tcb};
use crate::task::state::ThreadState;
pub(crate) use cspace::{
    lookup_cnode_root, lookup_invoke_target_locked, lookup_typed_cap_locked,
    resolve_cnode_copy_request, resolve_cnode_move_request, resolve_cnode_write_request,
    resolve_untyped_reset_request, resolve_untyped_retype_request,
};
#[allow(unused_imports)]
pub use dispatch::syscall_handle_rust;
pub(crate) use support::{
    copy_to_current_ipc_words, current_ipc_buffer_base, read_current_ipc_word,
    syscall_error_from_cap_error, syscall_error_from_vspace_error, validate_capability,
    write_current_ipc_word,
};
pub use types::{Syscall, SyscallError, SyscallResult, msg_info};
