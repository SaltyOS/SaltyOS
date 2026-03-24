// SPDX-License-Identifier: GPL-2.0-only
//! Block I/O request handlers and dispatch logic.

use besalt::consts::*;
use besalt::serial::LineBuf;
use besalt::types::*;

use crate::virtio::*;
use crate::{puts, CAPACITY_SECTORS, VIRTIO_INITIALIZED, USING_MODERN_TRANSPORT, VQUEUE_BASE};
use crate::{QUEUE_SIZE, AVAIL_IDX, LAST_USED_IDX, QUEUE_AVAIL_OFF, QUEUE_USED_OFF};
use crate::{SHM_VADDR, SHM_SIZE, SECTOR_SIZE, BLK_SHM_ID};

/// Read ISR status (transport-aware).
fn read_isr() -> u8 {
    if unsafe { *(&raw const USING_MODERN_TRANSPORT) } {
        crate::virtio_modern::modern_isr_read()
    } else {
        bar_read8(VIRTIO_ISR_STATUS)
    }
}

pub(crate) fn clear_pending_irq() {
    if unsafe { *(&raw const VIRTIO_INITIALIZED) } {
        let _ = read_isr();
    }
}

/// Notify queue 0 (transport-aware).
fn transport_notify_queue() {
    if unsafe { *(&raw const USING_MODERN_TRANSPORT) } {
        crate::virtio_modern::modern_notify_queue();
    } else {
        bar_write16(VIRTIO_QUEUE_NOTIFY, 0);
    }
}

pub(crate) fn handle_read(msg: &BesaltMsg) -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();

    if !unsafe { *(&raw const VIRTIO_INITIALIZED) } {
        reply.label = BESALT_INVALID_OPERATION;
        return reply;
    }

    let start_sector = msg.regs[0];
    let count = msg.regs[1];
    let shm_offset = msg.regs[2];

    // Limit to 8 sectors (4KB) per request
    let actual_count = if count > 8 { 8 } else { count };
    let byte_count = actual_count * 512;

    if actual_count == 0 {
        reply.label = BESALT_INVALID_ARGUMENT;
        return reply;
    }

    if shm_offset + byte_count > SHM_SIZE {
        reply.label = BESALT_OUT_OF_RANGE;
        return reply;
    }

    unsafe {
        let qsz = *(&raw const QUEUE_SIZE);
        let vq_base = *(&raw const VQUEUE_BASE);
        let avail_off = *(&raw const QUEUE_AVAIL_OFF);
        let used_off = *(&raw const QUEUE_USED_OFF);

        // Drain any stale completions from previously timed-out requests.
        // After a timeout, LAST_USED_IDX may lag behind the actual used.idx
        // because the device completed the request after we gave up polling.
        let used_base = (vq_base + used_off) as *const u16;
        let cur_used = core::ptr::read_volatile(used_base.add(1));
        if cur_used != *(&raw const LAST_USED_IDX) {
            *(&raw mut LAST_USED_IDX) = cur_used;
            let _ = read_isr();
        }

        // Get physical addresses for DMA
        let data_vaddr = SHM_VADDR + shm_offset;
        let data_phys = vaddr_to_phys(data_vaddr);
        if data_phys == 0 {
            reply.label = BESALT_BAD_ADDRESS;
            return reply;
        }

        // Set up request header
        let hdr = &raw mut REQ_HEADER;
        (*hdr).req_type = 0; // VIRTIO_BLK_T_IN (read)
        (*hdr).reserved = 0;
        (*hdr).sector = start_sector;
        let hdr_phys = vaddr_to_phys(hdr as u64);
        if hdr_phys == 0 {
            reply.label = BESALT_BAD_ADDRESS;
            return reply;
        }

        // Set up status byte
        *(&raw mut REQ_STATUS) = 0xFF;
        let status_phys = vaddr_to_phys(&raw const REQ_STATUS as u64);
        if status_phys == 0 {
            reply.label = BESALT_BAD_ADDRESS;
            return reply;
        }

        // Set up 3 descriptors
        let desc_base = vq_base as *mut VirtqDesc;

        // Desc 0: request header (device-readable)
        (*desc_base.add(0)).addr = hdr_phys;
        (*desc_base.add(0)).len = 16; // sizeof VirtioBlkReqHeader
        (*desc_base.add(0)).flags = VRING_DESC_F_NEXT;
        (*desc_base.add(0)).next = 1;

        // Desc 1: data buffer (device-writable)
        (*desc_base.add(1)).addr = data_phys;
        (*desc_base.add(1)).len = byte_count as u32;
        (*desc_base.add(1)).flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        (*desc_base.add(1)).next = 2;

        // Desc 2: status byte (device-writable)
        (*desc_base.add(2)).addr = status_phys;
        (*desc_base.add(2)).len = 1;
        (*desc_base.add(2)).flags = VRING_DESC_F_WRITE;
        (*desc_base.add(2)).next = 0;

        // Add to available ring
        let avail_base = (vq_base + avail_off) as *mut u16;
        // avail.flags at offset 0
        // avail.idx at offset 1
        // avail.ring[i] at offset 2+i
        let avail_idx = *(&raw const AVAIL_IDX);
        let ring_idx = (avail_idx % qsz) as usize;
        *avail_base.add(2 + ring_idx) = 0; // descriptor chain head = 0
        // Memory barrier (compiler fence)
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        *avail_base.add(1) = avail_idx.wrapping_add(1);
        *(&raw mut AVAIL_IDX) = avail_idx.wrapping_add(1);

        // Kick the device
        transport_notify_queue();

        // Poll for completion
        let used_base = (vq_base + used_off) as *const u16;
        // used.flags at offset 0
        // used.idx at offset 1
        let last_used = *(&raw const LAST_USED_IDX);
        let mut spin_count = 0u32;
        loop {
            let used_idx = core::ptr::read_volatile(used_base.add(1));
            if used_idx != last_used {
                *(&raw mut LAST_USED_IDX) = used_idx;
                break;
            }
            spin_count += 1;
            if spin_count > 100_000_000 {
                puts(b"[blkdrv] virtio read timeout\n");
                let _ = read_isr();
                reply.label = BESALT_BUSY;
                return reply;
            }
        }

        // Ensure DMA-written data is visible before reading status/data.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        // Clear device ISR to deassert the shared IRQ line.
        // Without this, the virtio-blk device keeps IRQ 11 asserted,
        // interfering with other devices sharing the same IRQ (e.g. virtio-net).
        let _ = read_isr();

        // Check status
        let status = *(&raw const REQ_STATUS);
        if status != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[blkdrv] read error status=");
            lb.dec(status as u64);
            lb.putc(b'\n');
            lb.flush();
            reply.label = BESALT_INVALID_OPERATION;
            return reply;
        }
    }

    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = byte_count;
    reply
}

pub(crate) fn handle_write(msg: &BesaltMsg) -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();

    if !unsafe { *(&raw const VIRTIO_INITIALIZED) } {
        reply.label = BESALT_INVALID_OPERATION;
        return reply;
    }

    let start_sector = msg.regs[0];
    let count = msg.regs[1];
    let shm_offset = msg.regs[2];

    // Limit to 8 sectors (4KB) per request
    let actual_count = if count > 8 { 8 } else { count };
    let byte_count = actual_count * 512;

    if actual_count == 0 {
        reply.label = BESALT_INVALID_ARGUMENT;
        return reply;
    }

    if shm_offset + byte_count > SHM_SIZE {
        reply.label = BESALT_OUT_OF_RANGE;
        return reply;
    }

    unsafe {
        let qsz = *(&raw const QUEUE_SIZE);
        let vq_base = *(&raw const VQUEUE_BASE);
        let avail_off = *(&raw const QUEUE_AVAIL_OFF);
        let used_off = *(&raw const QUEUE_USED_OFF);

        // Drain any stale completions from previously timed-out requests.
        let used_base = (vq_base + used_off) as *const u16;
        let cur_used = core::ptr::read_volatile(used_base.add(1));
        if cur_used != *(&raw const LAST_USED_IDX) {
            *(&raw mut LAST_USED_IDX) = cur_used;
            let _ = read_isr();
        }

        // Get physical addresses for DMA
        let data_vaddr = SHM_VADDR + shm_offset;
        let data_phys = vaddr_to_phys(data_vaddr);
        if data_phys == 0 {
            reply.label = BESALT_BAD_ADDRESS;
            return reply;
        }

        // Set up request header
        let hdr = &raw mut REQ_HEADER;
        (*hdr).req_type = 1; // VIRTIO_BLK_T_OUT (write)
        (*hdr).reserved = 0;
        (*hdr).sector = start_sector;
        let hdr_phys = vaddr_to_phys(hdr as u64);
        if hdr_phys == 0 {
            reply.label = BESALT_BAD_ADDRESS;
            return reply;
        }

        // Set up status byte
        *(&raw mut REQ_STATUS) = 0xFF;
        let status_phys = vaddr_to_phys(&raw const REQ_STATUS as u64);
        if status_phys == 0 {
            reply.label = BESALT_BAD_ADDRESS;
            return reply;
        }

        // Set up 3 descriptors
        let desc_base = vq_base as *mut VirtqDesc;

        // Desc 0: request header (device-readable)
        (*desc_base.add(0)).addr = hdr_phys;
        (*desc_base.add(0)).len = 16; // sizeof VirtioBlkReqHeader
        (*desc_base.add(0)).flags = VRING_DESC_F_NEXT;
        (*desc_base.add(0)).next = 1;

        // Desc 1: data buffer (device-readable for write — NO VRING_DESC_F_WRITE)
        (*desc_base.add(1)).addr = data_phys;
        (*desc_base.add(1)).len = byte_count as u32;
        (*desc_base.add(1)).flags = VRING_DESC_F_NEXT;
        (*desc_base.add(1)).next = 2;

        // Desc 2: status byte (device-writable)
        (*desc_base.add(2)).addr = status_phys;
        (*desc_base.add(2)).len = 1;
        (*desc_base.add(2)).flags = VRING_DESC_F_WRITE;
        (*desc_base.add(2)).next = 0;

        // Add to available ring
        let avail_base = (vq_base + avail_off) as *mut u16;
        let avail_idx = *(&raw const AVAIL_IDX);
        let ring_idx = (avail_idx % qsz) as usize;
        *avail_base.add(2 + ring_idx) = 0; // descriptor chain head = 0
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        *avail_base.add(1) = avail_idx.wrapping_add(1);
        *(&raw mut AVAIL_IDX) = avail_idx.wrapping_add(1);

        // Kick the device
        transport_notify_queue();

        // Poll for completion
        let used_base = (vq_base + used_off) as *const u16;
        let last_used = *(&raw const LAST_USED_IDX);
        let mut spin_count = 0u32;
        loop {
            let used_idx = core::ptr::read_volatile(used_base.add(1));
            if used_idx != last_used {
                *(&raw mut LAST_USED_IDX) = used_idx;
                break;
            }
            spin_count += 1;
            if spin_count > 100_000_000 {
                puts(b"[blkdrv] virtio write timeout\n");
                let _ = read_isr();
                reply.label = BESALT_BUSY;
                return reply;
            }
        }

        // Ensure DMA-written data is visible before reading status/data.
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);

        // Clear device ISR to deassert the shared IRQ line.
        let _ = read_isr();

        // Check status
        let status = *(&raw const REQ_STATUS);
        if status != 0 {
            let mut lb = LineBuf::new();
            lb.str(b"[blkdrv] write error status=");
            lb.dec(status as u64);
            lb.putc(b'\n');
            lb.flush();
            reply.label = BESALT_INVALID_OPERATION;
            return reply;
        }
    }

    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = byte_count;
    reply
}

pub(crate) fn handle_get_info() -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();
    reply.label = 0;
    reply.length = 2;
    reply.regs[0] = unsafe { *(&raw const CAPACITY_SECTORS) };
    reply.regs[1] = SECTOR_SIZE as u64;
    reply
}

pub(crate) fn handle_get_shm_id() -> BesaltMsg {
    let mut reply = BesaltMsg::zeroed();
    reply.label = 0;
    reply.length = 1;
    reply.regs[0] = BLK_SHM_ID;
    reply
}
