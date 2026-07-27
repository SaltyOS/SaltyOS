// SPDX-License-Identifier: GPL-2.0-only
//
//! Stage-B bootstrap untyped sizing.
//!
//! The pre-mmsrv core services are loaded by init's direct loader, so
//! their ELF/DSO image frames and early kernel objects must fit in
//! boot-time untyped chunks. This module measures the current initrd
//! images and simulates the kernel's untyped carve accounting before
//! Stage B splits the boot untyped.

use trona_server::event_loop::CookieEntry;
use uapi::{
    KERNITE_CNODE_DEFAULT_SIZE_BITS, KERNITE_CNODE_HEADER_BYTES, KERNITE_CNODE_MAX_SIZE_BITS,
    KERNITE_CNODE_MIN_SIZE_BITS, KERNITE_CNODE_SLOT_BYTES, KERNITE_ERR_INVALID_ARGUMENT,
    KERNITE_ERR_OUT_OF_MEMORY, KERNITE_EVENT_QUEUE_BYTES, KERNITE_MESSAGE_PIPE_BYTES,
    KERNITE_MESSAGE_PIPE_CORE_BYTES, KERNITE_OBJ_CNODE, KERNITE_OBJ_EVENT_QUEUE, KERNITE_OBJ_FRAME,
    KERNITE_OBJ_MESSAGE_PIPE, KERNITE_OBJ_MESSAGE_PIPE_CORE, KERNITE_OBJ_SCHED_CONTEXT,
    KERNITE_OBJ_TCB, KERNITE_OBJ_TIMER, KERNITE_OBJ_UNTYPED, KERNITE_OBJ_VSPACE, KERNITE_OBJ_WATCH,
    KERNITE_PAGE_BYTES, KERNITE_SCHED_CONTEXT_BYTES, KERNITE_TCB_BYTES, KERNITE_TIMER_BYTES,
    KERNITE_VSPACE_BYTES, KERNITE_WATCH_BYTES,
};

use crate::supervisor::SupervisorState;
use crate::supervisor::boot_core::CORE_STACK_PAGES;
use crate::supervisor::loader::{cpio, dso, elf};
use crate::supervisor::manifest::MAX_SERVICES;
use crate::supervisor::state::InitTarget;
use crate::supervisor::untyped_split::BootUntypedPlan;

const CNODE_ALIGN_BYTES: u64 = 8;
const MAX_CLASSES_PER_SOURCE: usize = 16;

const NAMESRV_BOOT_ALLOCATOR_MIN_BYTES: u64 = 1 << 20;
const RSRCSRV_AUTHORITY_TARGET_SIZE_BITS: u64 = 25;

/// Size of init's dedicated slab page-backing untyped pool, carved from
/// `init_private` at boot. Backs the PID table / lifecycle / extras
/// slabs; 4 MiB holds tens of thousands of process records once the
/// fixed 512-entry table cap is gone, and the slab free list keeps live
/// use far below the ceiling.
pub const INIT_SLAB_POOL_SIZE_BITS: u64 = 22;

const INIT_COOKIE_BOOT_RECORDS: u64 = MAX_SERVICES as u64 + 8;
const SEGMENT_HEADER_UPPER_BYTES: u64 = 64;
const SEGMENT_INITIAL_CAP: u64 = 64;

/// Build the concrete Stage-B split plan from the current initrd.
pub fn plan_boot_untyped_split(state: &SupervisorState) -> Result<BootUntypedPlan, i32> {
    let namesrv_image_pages = direct_image_frame_pages(state, b"/bin/namesrv")?;
    let rsrcsrv_image_pages = direct_image_frame_pages(state, b"/bin/rsrcsrv")?;
    let mmsrv_image_pages = direct_image_frame_pages(state, b"/bin/mmsrv")?;

    let namesrv_plumbing_bytes = namesrv_plumbing_bytes(namesrv_image_pages)?;
    let namesrv_plumbing_size_bits = size_bits_for_bytes(namesrv_plumbing_bytes)?;
    let namesrv_boot_size_bits = size_bits_for_bytes(NAMESRV_BOOT_ALLOCATOR_MIN_BYTES)?;
    let namesrv_quota_size_bits =
        enclosing_untyped_bits(namesrv_plumbing_size_bits, namesrv_boot_size_bits)?;

    let mut init_private = CarveBudget::new();
    carve_init_support(&mut init_private)?;
    carve_rsrcsrv_boot(&mut init_private, rsrcsrv_image_pages)?;
    carve_mmsrv_boot(&mut init_private, mmsrv_image_pages)?;
    carve_init_slab_pool(&mut init_private)?;

    Ok(BootUntypedPlan {
        init_private_size_bits: size_bits_for_bytes(init_private.bytes())?,
        namesrv_quota_size_bits,
        namesrv_plumbing_size_bits,
        namesrv_boot_size_bits,
        rsrcsrv_quota_target_size_bits: RSRCSRV_AUTHORITY_TARGET_SIZE_BITS,
    })
}

fn direct_image_frame_pages(state: &SupervisorState, binary_name: &[u8]) -> Result<u64, i32> {
    let image_bytes =
        cpio::find_file(state, binary_name).ok_or(uapi::KERNITE_ERR_NOT_FOUND as i32)?;
    let main_image = elf::parse(image_bytes)?;
    let closure = dso::resolve(state, &main_image, binary_name, false)?;
    dso::direct_map_frame_pages(&closure)
}

fn namesrv_plumbing_bytes(image_pages: u64) -> Result<u64, i32> {
    let mut budget = CarveBudget::new();
    carve_core_plumbing(&mut budget)?;
    budget.carve(KERNITE_OBJ_EVENT_QUEUE, 8, 1)?;
    carve_mp_pairs(&mut budget, 1)?;
    budget.carve(KERNITE_OBJ_TIMER, 0, 1)?;
    budget.carve(KERNITE_OBJ_WATCH, 0, 16)?;
    budget.carve(KERNITE_OBJ_FRAME, 12, image_pages)?;
    Ok(budget.bytes())
}

fn carve_init_support(budget: &mut CarveBudget) -> Result<(), i32> {
    budget.carve(KERNITE_OBJ_FRAME, 0, 1)?;
    budget.carve(KERNITE_OBJ_EVENT_QUEUE, 0, 2)?;
    budget.carve(KERNITE_OBJ_TIMER, 0, 1)?;
    carve_mp_pairs(budget, 1)?;
    budget.carve(KERNITE_OBJ_WATCH, 0, 3)?;
    budget.carve(KERNITE_OBJ_FRAME, 12, init_cookie_table_pages()?)?;
    carve_mp_pairs(budget, 1)?;
    budget.carve(KERNITE_OBJ_WATCH, 0, 1)
}

/// Reserve init's dedicated slab page-backing pool inside `init_private`
/// so [`split`](crate::supervisor::untyped_split::split) sizes the chunk
/// large enough for boot to sub-carve [`INIT_SLAB_POOL_SIZE_BITS`] of
/// untyped for `state.frames`.
fn carve_init_slab_pool(budget: &mut CarveBudget) -> Result<(), i32> {
    budget.carve(KERNITE_OBJ_UNTYPED, INIT_SLAB_POOL_SIZE_BITS, 1)
}

fn carve_rsrcsrv_boot(budget: &mut CarveBudget, image_pages: u64) -> Result<(), i32> {
    carve_core_plumbing(budget)?;
    carve_mp_pairs(budget, 1)?;
    budget.carve(KERNITE_OBJ_EVENT_QUEUE, 4, 1)?;
    budget.carve(KERNITE_OBJ_FRAME, 12, image_pages)
}

fn carve_mmsrv_boot(budget: &mut CarveBudget, image_pages: u64) -> Result<(), i32> {
    carve_core_plumbing(budget)?;
    carve_mp_pairs(budget, 1)?;
    budget.carve(KERNITE_OBJ_EVENT_QUEUE, 6, 1)?;
    budget.carve(KERNITE_OBJ_EVENT_QUEUE, 8, 1)?;
    carve_mp_pairs(budget, 1)?;
    budget.carve(KERNITE_OBJ_TCB, 0, 1)?;
    budget.carve(KERNITE_OBJ_SCHED_CONTEXT, 0, 1)?;
    budget.carve(KERNITE_OBJ_FRAME, 12, 16)?;
    budget.carve(KERNITE_OBJ_FRAME, 12, image_pages)
}

fn carve_core_plumbing(budget: &mut CarveBudget) -> Result<(), i32> {
    budget.carve(KERNITE_OBJ_TCB, 0, 1)?;
    budget.carve(KERNITE_OBJ_VSPACE, 0, 1)?;
    budget.carve(KERNITE_OBJ_CNODE, 12, 1)?;
    budget.carve(KERNITE_OBJ_SCHED_CONTEXT, 0, 1)?;
    budget.carve(KERNITE_OBJ_FRAME, 12, 2 + CORE_STACK_PAGES as u64)
}

fn carve_mp_pairs(budget: &mut CarveBudget, count: u64) -> Result<(), i32> {
    budget.carve(KERNITE_OBJ_MESSAGE_PIPE_CORE, 0, count)?;
    budget.carve(KERNITE_OBJ_MESSAGE_PIPE, 0, count * 2)
}

fn init_cookie_table_pages() -> Result<u64, i32> {
    let mut remaining = INIT_COOKIE_BOOT_RECORDS;
    let mut cap = SEGMENT_INITIAL_CAP;
    let mut pages = 0u64;
    while remaining > 0 {
        let used = core::cmp::min(remaining, cap);
        let entry_bytes = (core::mem::size_of::<CookieEntry<InitTarget>>() as u64).checked_mul(cap);
        let segment_bytes = entry_bytes
            .and_then(|bytes| bytes.checked_add(SEGMENT_HEADER_UPPER_BYTES))
            .ok_or(KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        pages = pages
            .checked_add(page_count(segment_bytes)?)
            .ok_or(KERNITE_ERR_INVALID_ARGUMENT as i32)?;
        remaining -= used;
        cap = cap
            .checked_mul(2)
            .ok_or(KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    }
    Ok(pages)
}

fn enclosing_untyped_bits(first_bits: u64, second_bits: u64) -> Result<u64, i32> {
    let mut budget = CarveBudget::new();
    budget.carve(KERNITE_OBJ_UNTYPED, first_bits, 1)?;
    budget.carve(KERNITE_OBJ_UNTYPED, second_bits, 1)?;
    size_bits_for_bytes(budget.bytes())
}

fn size_bits_for_bytes(bytes: u64) -> Result<u64, i32> {
    let bytes = core::cmp::max(bytes, KERNITE_PAGE_BYTES);
    if bytes > (1u64 << 47) {
        return Err(KERNITE_ERR_OUT_OF_MEMORY as i32);
    }
    let bits = if bytes <= 1 {
        0
    } else {
        64 - (bytes - 1).leading_zeros() as u64
    };
    Ok(core::cmp::max(bits, 12))
}

fn page_count(bytes: u64) -> Result<u64, i32> {
    let rounded = align_up(bytes, KERNITE_PAGE_BYTES)?;
    Ok(rounded / KERNITE_PAGE_BYTES)
}

struct CarveBudget {
    watermark: u64,
    class_sizes: [u64; MAX_CLASSES_PER_SOURCE],
    class_count: usize,
}

impl CarveBudget {
    const fn new() -> Self {
        Self {
            watermark: 0,
            class_sizes: [0; MAX_CLASSES_PER_SOURCE],
            class_count: 0,
        }
    }

    fn bytes(&self) -> u64 {
        self.watermark
    }

    fn carve(&mut self, obj_type: u64, size_bits: u64, count: u64) -> Result<(), i32> {
        if count == 0 {
            return Ok(());
        }
        let bytes = object_alloc_bytes(obj_type, size_bits)?;
        let align = object_align(obj_type, bytes);
        self.register_class(bytes)?;
        for _ in 0..count {
            let start = align_up(self.watermark, align)?;
            self.watermark = start
                .checked_add(bytes)
                .ok_or(KERNITE_ERR_OUT_OF_MEMORY as i32)?;
        }
        Ok(())
    }

    fn register_class(&mut self, bytes: u64) -> Result<(), i32> {
        if bytes == 0 {
            return Ok(());
        }
        for i in 0..self.class_count {
            if self.class_sizes[i] == bytes {
                return Ok(());
            }
        }
        if self.class_count >= MAX_CLASSES_PER_SOURCE {
            return Err(KERNITE_ERR_OUT_OF_MEMORY as i32);
        }
        self.class_sizes[self.class_count] = bytes;
        self.class_count += 1;
        Ok(())
    }
}

fn object_align(obj_type: u64, bytes: u64) -> u64 {
    if bytes == 0 {
        1
    } else if obj_type == KERNITE_OBJ_CNODE {
        CNODE_ALIGN_BYTES
    } else if obj_type == KERNITE_OBJ_VSPACE {
        KERNITE_PAGE_BYTES
    } else {
        bytes
    }
}

fn object_alloc_bytes(obj_type: u64, size_bits: u64) -> Result<u64, i32> {
    match obj_type {
        KERNITE_OBJ_UNTYPED => checked_shift(size_bits, 12, 47),
        KERNITE_OBJ_FRAME => {
            let effective = if size_bits == 0 { 12 } else { size_bits };
            checked_shift(effective, 12, 30)
        }
        KERNITE_OBJ_TCB => Ok(KERNITE_TCB_BYTES),
        KERNITE_OBJ_CNODE => cnode_alloc_bytes(size_bits),
        KERNITE_OBJ_VSPACE => Ok(KERNITE_VSPACE_BYTES),
        KERNITE_OBJ_SCHED_CONTEXT => Ok(KERNITE_SCHED_CONTEXT_BYTES),
        KERNITE_OBJ_EVENT_QUEUE => Ok(KERNITE_EVENT_QUEUE_BYTES),
        KERNITE_OBJ_WATCH => Ok(KERNITE_WATCH_BYTES),
        KERNITE_OBJ_MESSAGE_PIPE => Ok(KERNITE_MESSAGE_PIPE_BYTES),
        KERNITE_OBJ_MESSAGE_PIPE_CORE => Ok(KERNITE_MESSAGE_PIPE_CORE_BYTES),
        KERNITE_OBJ_TIMER => Ok(KERNITE_TIMER_BYTES),
        _ => Err(KERNITE_ERR_INVALID_ARGUMENT as i32),
    }
}

fn cnode_alloc_bytes(size_bits: u64) -> Result<u64, i32> {
    let bits = if size_bits == 0 {
        KERNITE_CNODE_DEFAULT_SIZE_BITS
    } else {
        size_bits
    };
    if bits < KERNITE_CNODE_MIN_SIZE_BITS || bits > KERNITE_CNODE_MAX_SIZE_BITS {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    let slots = 1u64
        .checked_shl(bits as u32)
        .ok_or(KERNITE_ERR_INVALID_ARGUMENT as i32)?;
    KERNITE_CNODE_SLOT_BYTES
        .checked_mul(slots)
        .and_then(|bytes| bytes.checked_add(KERNITE_CNODE_HEADER_BYTES))
        .ok_or(KERNITE_ERR_INVALID_ARGUMENT as i32)
}

fn checked_shift(bits: u64, min: u64, max: u64) -> Result<u64, i32> {
    if bits < min || bits > max {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    1u64.checked_shl(bits as u32)
        .ok_or(KERNITE_ERR_INVALID_ARGUMENT as i32)
}

fn align_up(value: u64, align: u64) -> Result<u64, i32> {
    if align == 0 {
        return Err(KERNITE_ERR_INVALID_ARGUMENT as i32);
    }
    let rem = value % align;
    if rem == 0 {
        Ok(value)
    } else {
        value
            .checked_add(align - rem)
            .ok_or(KERNITE_ERR_OUT_OF_MEMORY as i32)
    }
}
