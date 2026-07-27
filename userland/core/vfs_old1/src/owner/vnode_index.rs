// SPDX-License-Identifier: GPL-2.0-only
//! Fixed-capacity stable-vnode lookup index.
//!
//! `VnodeKey` is the structural identity used by path anchors and mounted
//! filesystem nodes. The owner keeps one lightweight open-addressed table so
//! `vnode_by_key()` does not have to linearly scan every live vnode.

use crate::server::mem;
use crate::vfs_core::identity::{FsInstanceId, VnodeKey};
use crate::vfs_core::vnode::VnodeHandle;

const SLOT_EMPTY: u8 = 0;
const SLOT_FULL: u8 = 1;
const SLOT_TOMBSTONE: u8 = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct VnodeKeyIndexSlot {
    key: VnodeKey,
    vnode: VnodeHandle,
    state: u8,
    _pad0: [u8; 7],
}

impl VnodeKeyIndexSlot {
    const fn zeroed() -> Self {
        VnodeKeyIndexSlot {
            key: VnodeKey::INVALID,
            vnode: VnodeHandle::INVALID,
            state: SLOT_EMPTY,
            _pad0: [0; 7],
        }
    }
}

pub(crate) struct VnodeKeyIndex {
    slots: *mut VnodeKeyIndexSlot,
    cap: u32,
    alloc_bytes: u64,
}

impl VnodeKeyIndex {
    pub(crate) fn new(cap: u32) -> Option<Self> {
        if cap < 8 || !cap.is_power_of_two() {
            return None;
        }

        let bytes = (cap as usize) * core::mem::size_of::<VnodeKeyIndexSlot>();
        let alloc_bytes = ((bytes + 4095) & !4095) as u64;
        let ptr = unsafe { mem::map_anon(alloc_bytes) } as *mut VnodeKeyIndexSlot;
        if ptr.is_null() || ptr == usize::MAX as *mut VnodeKeyIndexSlot {
            return None;
        }

        for idx in 0..cap as usize {
            unsafe {
                *ptr.add(idx) = VnodeKeyIndexSlot::zeroed();
            }
        }

        Some(VnodeKeyIndex {
            slots: ptr,
            cap,
            alloc_bytes,
        })
    }

    #[inline]
    pub(crate) fn key_is_indexable(key: VnodeKey) -> bool {
        key.fs_instance_id != FsInstanceId::INVALID
            && key.backend_id != trona_protocol::BackendNodeId::INVALID
    }

    #[inline]
    fn hash(key: VnodeKey) -> u64 {
        let mut x = key.fs_instance_id.0;
        x ^= key.backend_id.ino.rotate_left(17);
        x ^= (key.backend_id.seq as u64).wrapping_mul(0x9E37_79B1);
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51afd7ed558ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
        x ^ (x >> 33)
    }

    pub(crate) fn lookup(&self, key: VnodeKey) -> Option<VnodeHandle> {
        if !Self::key_is_indexable(key) {
            return None;
        }

        let mask = (self.cap - 1) as usize;
        let mut idx = (Self::hash(key) as usize) & mask;
        for _ in 0..self.cap {
            let slot = unsafe { &*self.slots.add(idx) };
            match slot.state {
                SLOT_EMPTY => return None,
                SLOT_FULL if slot.key == key => return Some(slot.vnode),
                _ => {
                    idx = (idx + 1) & mask;
                }
            }
        }
        None
    }

    pub(crate) fn insert(&self, key: VnodeKey, vnode: VnodeHandle) -> bool {
        if !Self::key_is_indexable(key) || !vnode.is_valid() {
            return false;
        }

        let mask = (self.cap - 1) as usize;
        let mut idx = (Self::hash(key) as usize) & mask;
        let mut first_tombstone = usize::MAX;
        for _ in 0..self.cap {
            let slot = unsafe { &mut *self.slots.add(idx) };
            match slot.state {
                SLOT_EMPTY => {
                    let target = if first_tombstone != usize::MAX {
                        unsafe { &mut *self.slots.add(first_tombstone) }
                    } else {
                        slot
                    };
                    target.key = key;
                    target.vnode = vnode;
                    target.state = SLOT_FULL;
                    return true;
                }
                SLOT_TOMBSTONE => {
                    if first_tombstone == usize::MAX {
                        first_tombstone = idx;
                    }
                }
                SLOT_FULL if slot.key == key => {
                    slot.vnode = vnode;
                    return true;
                }
                _ => {}
            }
            idx = (idx + 1) & mask;
        }

        if first_tombstone != usize::MAX {
            let target = unsafe { &mut *self.slots.add(first_tombstone) };
            target.key = key;
            target.vnode = vnode;
            target.state = SLOT_FULL;
            return true;
        }
        false
    }

    pub(crate) fn remove(&self, key: VnodeKey, vnode: Option<VnodeHandle>) -> bool {
        if !Self::key_is_indexable(key) {
            return false;
        }

        let mask = (self.cap - 1) as usize;
        let mut idx = (Self::hash(key) as usize) & mask;
        for _ in 0..self.cap {
            let slot = unsafe { &mut *self.slots.add(idx) };
            match slot.state {
                SLOT_EMPTY => return false,
                SLOT_FULL if slot.key == key => {
                    if vnode.map(|expected| slot.vnode == expected).unwrap_or(true) {
                        slot.key = VnodeKey::INVALID;
                        slot.vnode = VnodeHandle::INVALID;
                        slot.state = SLOT_TOMBSTONE;
                        return true;
                    }
                }
                _ => {}
            }
            idx = (idx + 1) & mask;
        }
        false
    }
}

impl Drop for VnodeKeyIndex {
    fn drop(&mut self) {
        if !self.slots.is_null() && self.alloc_bytes != 0 {
            let _ = unsafe { mem::unmap(self.slots as *mut u8, self.alloc_bytes) };
        }
    }
}

unsafe impl Send for VnodeKeyIndex {}
