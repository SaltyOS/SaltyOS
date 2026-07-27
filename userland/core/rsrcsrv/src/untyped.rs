// SPDX-License-Identifier: GPL-2.0-only
//
//! Untyped pool — fixed-size freelist of `KERNITE_OBJ_UNTYPED` chunks.
//!
//! Each chunk records its cap, log2 size, and live child count. Retype
//! picks a chunk via forward+wrap scan starting at a per-class hint;
//! exhaustion runs a drain-and-reset pass over chunks with
//! `children_live == 0`.

use trona_kernel::syscall;
use uapi::{KERNITE_ERR_OUT_OF_MEMORY, KERNITE_INV_UNTYPED_RESET, KERNITE_INV_UNTYPED_RETYPE};

pub const MAX_CHUNKS: usize = 32;

#[derive(Clone, Copy)]
pub struct UntypedChunk {
    pub cap: u64,
    pub size_bits: u8,
    pub children_live: u32,
    pub last_alloc_idx: u32,
    pub active: u8,
    /// Set when a retype advanced this chunk's watermark since the last
    /// successful `UNTYPED_RESET`. A drained chunk (`children_live == 0`)
    /// only becomes reusable space once a reset actually succeeds; until
    /// then the kernel watermark is still advanced. The kernel refuses
    /// `UNTYPED_RESET` with `HasChildren` while any object carved from the
    /// chunk is still referenced elsewhere (an in-flight reaper entry, a
    /// peer's cap copy, a bound MP-pair side), so tracking this lets
    /// reclaim retry the refused chunks instead of mistaking a refused
    /// reset for reclaimed space.
    pub dirty: u8,
}

impl UntypedChunk {
    const fn empty() -> Self {
        Self {
            cap: 0,
            size_bits: 0,
            children_live: 0,
            last_alloc_idx: 0,
            active: 0,
            dirty: 0,
        }
    }
}

pub struct FreeList {
    chunks: [UntypedChunk; MAX_CHUNKS],
    used: usize,
}

#[derive(Clone, Copy)]
pub struct RetypeFailure {
    pub last_error: u64,
}

impl RetypeFailure {
    pub fn reply_error(self) -> u64 {
        if self.last_error == 0 {
            KERNITE_ERR_OUT_OF_MEMORY as u64
        } else {
            self.last_error
        }
    }
}

impl FreeList {
    pub const fn new() -> Self {
        Self {
            chunks: [UntypedChunk::empty(); MAX_CHUNKS],
            used: 0,
        }
    }

    pub fn used(&self) -> usize {
        self.used
    }

    pub fn adopt(&mut self, cap: u64, size_bits: u8) -> bool {
        for chunk in self.chunks.iter_mut() {
            if chunk.active == 0 {
                chunk.cap = cap;
                chunk.size_bits = size_bits;
                chunk.children_live = 0;
                chunk.last_alloc_idx = 0;
                chunk.active = 1;
                self.used += 1;
                return true;
            }
        }
        false
    }

    /// Try to retype `target_type` (size `target_size_bits`) into
    /// `dest_slot` from any active chunk that can fit it. Returns the
    /// chunk index on success or `None` on failure. Client-facing paths
    /// should use [`try_retype_detailed`] so the kernel's exact error
    /// label is not lost.
    pub fn try_retype(
        &mut self,
        target_type: u64,
        target_size_bits: u64,
        dest_slot: u64,
    ) -> Option<usize> {
        self.try_retype_detailed(target_type, target_size_bits, dest_slot)
            .ok()
    }

    /// Detailed variant of [`try_retype`] for client-facing RPC paths.
    /// Propagating the kernel's last `UNTYPED_RETYPE` error keeps ABI
    /// mismatches (for example a new object type missing from the kernel
    /// switch) from being misreported as generic pool exhaustion.
    pub fn try_retype_detailed(
        &mut self,
        target_type: u64,
        target_size_bits: u64,
        dest_slot: u64,
    ) -> Result<usize, RetypeFailure> {
        let mut last_error = KERNITE_ERR_OUT_OF_MEMORY as u64;
        for pass in 0..2 {
            for idx in 0..MAX_CHUNKS {
                let chunk = &self.chunks[idx];
                if chunk.active == 0 {
                    continue;
                }
                if (chunk.size_bits as u64) < target_size_bits {
                    continue;
                }
                let r = syscall::invoke(
                    chunk.cap,
                    KERNITE_INV_UNTYPED_RETYPE as u64,
                    target_type,
                    target_size_bits,
                    dest_slot,
                    0,
                );
                if r.error == 0 {
                    self.chunks[idx].children_live += 1;
                    self.chunks[idx].dirty = 1;
                    return Ok(idx);
                }
                last_error = r.error as u64;
            }
            if pass == 0 {
                self.drain_and_reset();
            }
        }
        Err(RetypeFailure { last_error })
    }

    /// Reset every chunk that has drained (`children_live == 0`) and still
    /// carries an advanced watermark (`dirty`). The kernel refuses
    /// `UNTYPED_RESET` with `HasChildren` while any object carved from the
    /// chunk is still referenced elsewhere — an in-flight reaper entry, a
    /// peer's cap copy, or a bound MP-pair side whose binder has not been
    /// revoked yet. `dirty` is cleared only on a *successful* reset, so a
    /// refused reset leaves the chunk marked for retry on the next reclaim
    /// rather than being silently treated as reclaimed space. Called on
    /// retype failure and at the end of every batched teardown.
    pub fn drain_and_reset(&mut self) {
        for chunk in self.chunks.iter_mut() {
            if chunk.active == 0 || chunk.children_live != 0 || chunk.dirty == 0 {
                continue;
            }
            let r = syscall::invoke(chunk.cap, KERNITE_INV_UNTYPED_RESET as u64, 0, 0, 0, 0);
            if r.error == 0 {
                chunk.last_alloc_idx = 0;
                chunk.dirty = 0;
            }
        }
    }

    /// Decrement the live-children count after a FREE / OWNER_EXITED revoke
    /// against a single chunk. This does NOT reset the chunk: a chunk is
    /// only safe to reset once *every* object carved from it is fully dead,
    /// which in a batched teardown (owner exit, MP pair) is only true after
    /// all sibling revokes have completed and the reaper has run. Resetting
    /// mid-loop — while a bound MP-pair side or a not-yet-reaped peer cap
    /// still references the chunk — is refused by the kernel with
    /// `HasChildren`. Callers run [`drain_and_reset`] once after the whole
    /// teardown batch so the reset lands cleanly.
    pub fn release_one(&mut self, chunk_idx: usize) {
        if chunk_idx >= MAX_CHUNKS {
            return;
        }
        let chunk = &mut self.chunks[chunk_idx];
        if chunk.active == 0 || chunk.children_live == 0 {
            return;
        }
        chunk.children_live -= 1;
    }
}
