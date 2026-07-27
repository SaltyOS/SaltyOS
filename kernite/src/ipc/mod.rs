// SPDX-License-Identifier: GPL-2.0-only
//! IPC Subsystem
//!
//! Hosts the synchronous and bulk IPC primitives — `MessagePipe`
//! (record + cap-carrier transfer with `MP_CALL` / `reply-marked MP_WRITE` on the
//! pipe endpoint), `DataPipe` (bytes ring), `Futex`, and per-task
//! `Fault` pipes.
//!

pub mod data_pipe;
pub mod fault;
pub mod futex;
pub mod message_pipe;
pub mod transfer;

/// IPC Buffer layout (mapped into user VSpace, shared between kernel and user)
///
/// Mirrors `kernite_ipc_buffer` in `kernite/include/uapi/ipc.h` 1:1.
/// The `msg[]` array is overlaid by userland as `struct trona_msg`:
///   msg[0] = label, msg[1] = length, msg[2..33] = regs[0..31]
/// So 34 slots = 2 header + 32 message registers.
///
/// Total size: 4096 bytes (one page).
#[repr(C)]
pub struct IpcBuffer {
    /// trona_msg overlay: [label, length, regs[0..31]]
    pub msg: [u64; 34], // 0x000: 272 bytes
    /// Badge received from sender.
    pub badge: u64, // 0x110: 8 bytes
    /// MP record flags surfaced from the inbound `kernite_mp_record`
    /// (`KERNITE_MP_FLAG_*`). Distinct from `badge` so the sender's
    /// tag is not entangled with the kernel-set call/reply bits.
    pub mp_flags: u64, // 0x118: 8 bytes
    /// Capability slots — sender-side CSpace indices the sender wants
    /// to transfer; on the receiver side, the kernel-installed
    /// receive-side slot indices.
    pub caps: [u64; 4], // 0x120: 32 bytes
    /// CNode for receiving transferred capabilities.
    pub receive_cnode: u64, // 0x140: 8 bytes
    /// Starting slot index in receive CNode.
    pub receive_index: u64, // 0x148: 8 bytes
    /// CSpace depth for resolving `receive_cnode`.
    pub receive_depth: u64, // 0x150: 8 bytes
    /// MessagePipe call transaction id. Inbound reads publish it;
    /// replies echo it so the kernel can wake the matching caller.
    pub mp_txid: u64, // 0x158: 8 bytes
    /// Reserved / extended payload area. `reserved[0]` carries the
    /// receive-slot depth for nested cap delivery; remaining words
    /// are syscall-specific.
    pub reserved: [u64; 468], // 0x160: 3744 bytes
}

// Compile-time assertion: IpcBuffer matches the UAPI page-sized layout.
const _: () = assert!(core::mem::size_of::<IpcBuffer>() == uapi::KERNITE_IPC_BUFFER_SIZE as usize);
