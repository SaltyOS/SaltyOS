use trona::types::Cap;

pub(crate) const MAX_UT_SOURCES: usize = 32;

#[derive(Clone, Copy)]
pub(crate) struct UntypedSource {
    pub(crate) cap: Cap,
    pub(crate) active: bool,
}

impl UntypedSource {
    pub(crate) const fn empty() -> Self {
        UntypedSource {
            cap: 0,
            active: false,
        }
    }
}

pub(crate) const REGION_HEAP: u8 = 0;
pub(crate) const REGION_MMAP: u8 = 1;
pub(crate) const REGION_SPAWN: u8 = 2;
pub(crate) const REGION_SHARED_RO: u8 = 3;
pub(crate) const REGION_FILE_SHARED: u8 = 4;
pub(crate) const REGION_INITIAL_CAP: usize = 8;

#[derive(Clone, Copy)]
pub(crate) struct MmRegion {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) prot: u8,
    pub(crate) region_type: u8,
    pub(crate) active: bool,
    pub(crate) lazy: bool,
    pub(crate) mo_cap: Cap,
    /// Page offset within the MO for this region's base address.
    /// Used for per-segment shared lib mappings where multiple regions
    /// share one MO at different offsets.
    pub(crate) mo_offset: u32,
    pub(crate) backing_kind: u8,
    pub(crate) backing_writeback: u8,
    pub(crate) _pad: [u8; 2],
    pub(crate) backing_id0: u64,
    pub(crate) backing_id1: u64,
    pub(crate) backing_file_offset: u64,
    pub(crate) backing_file_size: u64,
}

impl MmRegion {
    pub(crate) const fn zeroed() -> Self {
        MmRegion {
            base: 0,
            length: 0,
            prot: 0,
            region_type: 0,
            active: false,
            lazy: false,
            mo_cap: 0,
            mo_offset: 0,
            backing_kind: 0,
            backing_writeback: 0,
            _pad: [0; 2],
            backing_id0: 0,
            backing_id1: 0,
            backing_file_offset: 0,
            backing_file_size: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct MmClient {
    pub(crate) badge: u64,
    pub(crate) pid: u32,
    pub(crate) active: bool,
    /// Cap slot in mmsrv's CSpace holding the client's VSpace cap.
    pub(crate) vspace_cap: Cap,
    pub(crate) heap_base: u64,
    pub(crate) heap_current: u64,
    pub(crate) mmap_next: u64,
    pub(crate) regions: *mut MmRegion,
    pub(crate) region_count: usize,
    pub(crate) region_cap: usize,
}

impl MmClient {
    pub(crate) const fn zeroed() -> Self {
        MmClient {
            badge: 0,
            pid: 0,
            active: false,
            vspace_cap: 0,
            heap_base: 0,
            heap_current: 0,
            mmap_next: 0,
            regions: core::ptr::null_mut(),
            region_count: 0,
            region_cap: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ShmObject {
    pub(crate) id: u64,
    pub(crate) active: bool,
    pub(crate) page_count: u32,
    pub(crate) frame_caps: *mut Cap,
    pub(crate) frame_cap_capacity: u32,
}

impl ShmObject {
    pub(crate) const fn zeroed() -> Self {
        ShmObject {
            id: 0,
            active: false,
            page_count: 0,
            frame_caps: core::ptr::null_mut(),
            frame_cap_capacity: 0,
        }
    }
}
