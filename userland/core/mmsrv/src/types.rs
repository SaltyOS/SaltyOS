use besalt::types::Cap;

pub(crate) const MAX_UT_SOURCES: usize = 12;

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
pub(crate) const REGION_INITIAL_CAP: usize = 8;
pub(crate) const HEAP_INITIAL_FRAME_CAP: usize = 64;

#[derive(Clone, Copy)]
pub(crate) struct MmRegion {
    pub(crate) base: u64,
    pub(crate) length: u64,
    pub(crate) prot: u8,
    pub(crate) region_type: u8,
    pub(crate) active: bool,
    pub(crate) lazy: bool,
    pub(crate) frame_caps: *mut Cap,
    pub(crate) frame_count: u16,
    pub(crate) frame_cap_capacity: u16,
    pub(crate) cow_bitmap: *mut u64,     // 1 bit per page; set = COW-inherited, no frame cap
    pub(crate) cow_bitmap_words: u16,    // number of u64 words in bitmap
    pub(crate) cow_inherited: bool,      // set during fork; immune to mprotect changes
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
            frame_caps: core::ptr::null_mut(),
            frame_count: 0,
            frame_cap_capacity: 0,
            cow_bitmap: core::ptr::null_mut(),
            cow_bitmap_words: 0,
            cow_inherited: false,
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
    pub(crate) page_count: u16,
    pub(crate) frame_caps: *mut Cap,
    pub(crate) frame_cap_capacity: u16,
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
