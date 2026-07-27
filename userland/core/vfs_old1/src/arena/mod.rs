// SPDX-License-Identifier: GPL-2.0-only
//! `Arena<T>` — non-moving, epoch-counted slab allocator.
//!
//! Vnodes, mounts, and mount namespaces live in owner-owned slabs. The
//! slabs do not move, so handle resolution is stable for the lifetime of
//! an object; the epoch prevents stale handles from matching after reuse.

pub(crate) mod handle;

pub(crate) use handle::Handle;

const FREE_LIST_END: u32 = u32::MAX;

#[repr(C)]
#[derive(Clone, Copy)]
struct SlotMeta {
    epoch: u32,
    in_use: u8,
    _pad: [u8; 3],
    next_free: u32,
}

/// Fixed-capacity, non-moving slab.
///
/// The early namespace core does not need segmented growth: the number of
/// live mounts and structural vnodes is modest, and non-moving storage is
/// the property that matters for handle stability.
pub(crate) struct Arena<T> {
    data: *mut T,
    meta: *mut SlotMeta,
    cap: u32,
    free_head: u32,
    free_count: u32,
}

impl<T> Arena<T> {
    /// Allocate a new slab with `cap` slots.
    pub(crate) fn new(cap: u32) -> Option<Self> {
        if cap == 0 {
            return None;
        }

        let data_bytes = (cap as usize) * core::mem::size_of::<T>();
        let meta_bytes = (cap as usize) * core::mem::size_of::<SlotMeta>();
        let data_alloc = (data_bytes + 4095) & !4095;
        let meta_alloc = (meta_bytes + 4095) & !4095;

        let data_ptr = unsafe { crate::server::mem::map_anon(data_alloc as u64) };
        if data_ptr.is_null() || data_ptr == usize::MAX as *mut u8 {
            return None;
        }

        let meta_ptr = unsafe { crate::server::mem::map_anon(meta_alloc as u64) };
        if meta_ptr.is_null() || meta_ptr == usize::MAX as *mut u8 {
            unsafe {
                crate::server::mem::unmap(data_ptr, data_alloc as u64);
            }
            return None;
        }

        let meta = meta_ptr as *mut SlotMeta;
        for idx in 0..cap {
            unsafe {
                let slot = &mut *meta.add(idx as usize);
                slot.epoch = 1;
                slot.in_use = 0;
                slot.next_free = if idx + 1 < cap {
                    idx + 1
                } else {
                    FREE_LIST_END
                };
            }
        }

        Some(Arena {
            data: data_ptr as *mut T,
            meta,
            cap,
            free_head: 0,
            free_count: cap,
        })
    }

    /// Allocate one slot and zero-fill its storage.
    pub(crate) fn alloc(&mut self) -> Option<Handle<T>> {
        if self.free_count == 0 || self.free_head == FREE_LIST_END {
            return None;
        }

        let slot_idx = self.free_head;
        let meta = unsafe { &mut *self.meta.add(slot_idx as usize) };
        self.free_head = meta.next_free;
        self.free_count -= 1;

        meta.in_use = 1;
        meta.next_free = FREE_LIST_END;
        unsafe {
            core::ptr::write_bytes(self.data.add(slot_idx as usize), 0, 1);
        }

        Some(Handle::new(slot_idx, meta.epoch))
    }

    /// Number of live slots.
    #[inline]
    pub(crate) fn len(&self) -> u32 {
        self.cap.saturating_sub(self.free_count)
    }

    /// Total slot capacity.
    #[inline]
    pub(crate) fn capacity(&self) -> u32 {
        self.cap
    }

    /// Resolve a live handle to a shared reference.
    pub(crate) fn get(&self, handle: Handle<T>) -> Option<&T> {
        if !handle.is_valid() || handle.slot() >= self.cap {
            return None;
        }

        let meta = unsafe { &*self.meta.add(handle.slot() as usize) };
        if meta.epoch != handle.epoch() || meta.in_use == 0 {
            return None;
        }

        Some(unsafe { &*self.data.add(handle.slot() as usize) })
    }

    /// Resolve a live handle to an exclusive reference.
    pub(crate) fn get_mut(&mut self, handle: Handle<T>) -> Option<&mut T> {
        if !handle.is_valid() || handle.slot() >= self.cap {
            return None;
        }

        let meta = unsafe { &*self.meta.add(handle.slot() as usize) };
        if meta.epoch != handle.epoch() || meta.in_use == 0 {
            return None;
        }

        Some(unsafe { &mut *self.data.add(handle.slot() as usize) })
    }

    /// Release one live slot back to the free list.
    pub(crate) fn release(&mut self, handle: Handle<T>) -> bool {
        if !handle.is_valid() || handle.slot() >= self.cap {
            return false;
        }

        let slot_idx = handle.slot() as usize;
        let meta = unsafe { &mut *self.meta.add(slot_idx) };
        if meta.epoch != handle.epoch() || meta.in_use == 0 {
            return false;
        }

        meta.in_use = 0;
        meta.epoch = meta.epoch.wrapping_add(1);
        if meta.epoch == 0 {
            meta.epoch = 1;
        }
        meta.next_free = self.free_head;
        self.free_head = handle.slot();
        self.free_count = self.free_count.saturating_add(1);
        true
    }

    /// Iterate every active slot until the callback returns `false`.
    pub(crate) fn for_each_active<F>(&self, mut f: F)
    where
        F: FnMut(Handle<T>, &T) -> bool,
    {
        for slot_idx in 0..self.cap {
            let meta = unsafe { &*self.meta.add(slot_idx as usize) };
            if meta.in_use == 0 {
                continue;
            }

            let handle = Handle::new(slot_idx, meta.epoch);
            let value = unsafe { &*self.data.add(slot_idx as usize) };
            if !f(handle, value) {
                return;
            }
        }
    }
}

unsafe impl<T: Send> Send for Arena<T> {}
