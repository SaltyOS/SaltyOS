//! UEFI Bootloader for SaltyOS
//!
//! Loads kernel/initrd/bootcore and hands off to bootcore for paging setup.

#![no_std]
#![no_main]

use uefi::prelude::*;
use uefi::Identify;
use uefi::proto::media::fs::SimpleFileSystem;
use uefi::proto::media::file::{File, FileAttribute, FileMode};
use uefi::table::boot::{AllocateType, MemoryType, SearchType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::FileInfo;
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat as GopPixelFormat};
use saltyos_ska::{BootInfo, BootFlags, PhysAddr, MemoryEntry, MemoryType as SkaMemoryType};
use saltyos_bootloader_core::{BootContext, BootHandoff};
use saltyos_ska::{ExtraHeader, EXTRA_KIND_MEM_RESERVED};
use saltyos_bootloader_common::{
    PT_LOAD, parse_elf_header, get_program_headers,
    find_load_vaddr_range, find_dynamic_segment,
    layout::{KERNEL_PHYS_BASE, BOOTCORE_PHYS_BASE},
};

use core::mem::size_of;

/// Maximum memory map entries
const MAX_MEMORY_MAP_ENTRIES: usize = 128;

/// Kernel load addresses
// Defined in bootloader_common::layout

/// Identity map size for bootloader + kernel staging
const IDENTITY_MAP_GIB: usize = 4;


/// Static memory map storage
#[repr(C, align(16))]
pub struct AlignedMemoryMapStorage {
    data: [u8; 16 * 1024],
}

static mut MEMORY_MAP_STORAGE: AlignedMemoryMapStorage = AlignedMemoryMapStorage { data: [0; 16 * 1024] };

/// Static memory map entries
static mut MEMORY_MAP_ENTRIES: [MemoryEntry; MAX_MEMORY_MAP_ENTRIES] = [MemoryEntry {
    base: PhysAddr::new(0),
    length: 0,
    mem_type: SkaMemoryType::Usable,
    acpi_attrs: 0,
}; MAX_MEMORY_MAP_ENTRIES];

#[entry]
fn main(_image_handle: Handle, mut system_table: SystemTable<Boot>) -> Status {
    uefi_services::init(&mut system_table).unwrap();

    // Print banner
    {
        let stdout = system_table.stdout();
        let _ = stdout.output_string(cstr16!("SaltyOS UEFI Bootloader (PIE)\r\n"));
        let _ = stdout.output_string(cstr16!("===========================\r\n\r\n"));
    }

    // Get loaded image
    let boot_services = system_table.boot_services();
    let loaded_image = boot_services
        .open_protocol_exclusive::<LoadedImage>(_image_handle)
        .expect("Failed to open LoadedImage protocol");
    let device = loaded_image.device().expect("No device handle");
    drop(loaded_image);

    // Open filesystem
    let mut fs = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(device)
        .expect("Failed to open SimpleFileSystem");
    let mut root = fs.open_volume().expect("Failed to open volume");

    // Open kernel.elf
    let kernel_filename = cstr16!("kernel.elf");
    let bootcore_filename = cstr16!("bootcore.elf");
    let initrd_filename = cstr16!("initrd.img");
    let mut kernel_file = root
        .open(kernel_filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open kernel.elf")
        .into_regular_file()
        .expect("Not a regular file");

    // Get kernel file size
    let mut info_buf = [0u8; 256];
    let info: &mut FileInfo = kernel_file.get_info(&mut info_buf).expect("Failed to get file info");
    let kernel_size = info.file_size();
    let _ = info;

    // Get bootcore file size
    let mut bootcore_file = root
        .open(bootcore_filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open bootcore.elf")
        .into_regular_file()
        .expect("Not a regular file");
    let info: &mut FileInfo = bootcore_file
        .get_info(&mut info_buf)
        .expect("Failed to get bootcore file info");
    let bootcore_size = info.file_size();
    let _ = info;

    // Get initrd file size
    let mut initrd_file = root
        .open(initrd_filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open initrd.img")
        .into_regular_file()
        .expect("Not a regular file");
    let info: &mut FileInfo = initrd_file
        .get_info(&mut info_buf)
        .expect("Failed to get initrd file info");
    let initrd_size = info.file_size();
    let _ = info;

    // Drop file handles and print status
    drop(kernel_file);
    drop(bootcore_file);
    drop(initrd_file);
    drop(root);
    drop(fs);

    // Get stdout for status messages (need to drop boot_services first to avoid borrow issues)
    {
        let stdout = system_table.stdout();
        let _ = stdout.output_string(cstr16!("Loading kernel...\r\n"));
    }

    // Allocate memory for kernel ELF data
    let boot_services = system_table.boot_services();
    let kernel_pages = (kernel_size as usize + 4095) / 4096;
    let kernel_data_ptr = boot_services
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, kernel_pages)
        .expect("Failed to allocate memory for kernel");

    let kernel_data = unsafe {
        core::slice::from_raw_parts_mut(kernel_data_ptr as *mut u8, kernel_size as usize)
    };

    // Allocate memory for bootcore ELF data
    let bootcore_pages = (bootcore_size as usize + 4095) / 4096;
    let bootcore_data_ptr = boot_services
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, bootcore_pages)
        .expect("Failed to allocate memory for bootcore");

    let bootcore_data = unsafe {
        core::slice::from_raw_parts_mut(bootcore_data_ptr as *mut u8, bootcore_size as usize)
    };

    // Allocate memory for initrd data
    let initrd_pages = (initrd_size as usize + 4095) / 4096;
    let initrd_data_ptr = boot_services
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, initrd_pages)
        .expect("Failed to allocate memory for initrd");
    let initrd_data = unsafe {
        core::slice::from_raw_parts_mut(initrd_data_ptr as *mut u8, initrd_size as usize)
    };

    // Reopen file and read kernel/initrd
    let loaded_image = boot_services
        .open_protocol_exclusive::<LoadedImage>(_image_handle)
        .expect("Failed to open LoadedImage protocol");
    let device = loaded_image.device().expect("No device handle");
    drop(loaded_image);

    let mut fs = boot_services
        .open_protocol_exclusive::<SimpleFileSystem>(device)
        .expect("Failed to open SimpleFileSystem");
    let mut root = fs.open_volume().expect("Failed to open volume");
    let mut kernel_file = root
        .open(kernel_filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open kernel.elf")
        .into_regular_file()
        .expect("Not a regular file");

    kernel_file
        .read(kernel_data)
        .expect("Failed to read kernel file");
    drop(kernel_file);

    let mut bootcore_file = root
        .open(bootcore_filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open bootcore.elf")
        .into_regular_file()
        .expect("Not a regular file");
    bootcore_file
        .read(bootcore_data)
        .expect("Failed to read bootcore file");
    drop(bootcore_file);

    let mut initrd_file = root
        .open(initrd_filename, FileMode::Read, FileAttribute::empty())
        .expect("Failed to open initrd.img")
        .into_regular_file()
        .expect("Not a regular file");
    initrd_file
        .read(initrd_data)
        .expect("Failed to read initrd file");
    drop(initrd_file);
    drop(root);
    drop(fs);

    // Parse kernel ELF
    let elf_header = parse_elf_header(kernel_data)
        .expect("Invalid ELF header");
    let phdrs = get_program_headers(kernel_data, elf_header);

    // Parse bootcore ELF
    let bootcore_elf_header = parse_elf_header(bootcore_data)
        .expect("Invalid bootcore ELF header");
    let bootcore_phdrs = get_program_headers(bootcore_data, bootcore_elf_header);
    let (bootcore_vaddr_base, bootcore_vaddr_end) = find_load_vaddr_range(bootcore_phdrs)
        .expect("No PT_LOAD segments found in bootcore");

    // Compute kernel image bounds (link-time VAs)
    let (vaddr_base, vaddr_end) = find_load_vaddr_range(phdrs)
        .expect("No PT_LOAD segments found");

    // Allocate kernel image at a fixed physical base
    let image_size = (vaddr_end - vaddr_base) as usize;
    let image_pages = (image_size + 4095) / 4096;
    let kernel_phys_base = KERNEL_PHYS_BASE;

    boot_services
        .allocate_pages(
            AllocateType::Address(kernel_phys_base),
            MemoryType::LOADER_DATA,
            image_pages,
        )
        .expect("Failed to allocate kernel image");

    // Load segments into KERNEL_PHYS_BASE + (p_vaddr - vaddr_base)
    let mut dyn_phys: u64 = 0;
    let mut dyn_size: u64 = 0;
    if let Some((dyn_vaddr, dyn_memsz)) = find_dynamic_segment(phdrs) {
        dyn_phys = kernel_phys_base + (dyn_vaddr - vaddr_base);
        dyn_size = dyn_memsz;
    }
    for phdr in phdrs {
        if phdr.p_type == PT_LOAD {
            let dest_addr = kernel_phys_base + (phdr.p_vaddr - vaddr_base);
            let src_data = unsafe {
                core::slice::from_raw_parts(
                    (kernel_data_ptr as usize + phdr.p_offset as usize) as *const u8,
                    phdr.p_filesz as usize,
                )
            };

            unsafe {
                core::ptr::copy_nonoverlapping(
                    src_data.as_ptr(),
                    dest_addr as *mut u8,
                    phdr.p_filesz as usize,
                );

                // Zero BSS
                if phdr.p_memsz > phdr.p_filesz {
                    core::ptr::write_bytes(
                        (dest_addr + phdr.p_filesz) as *mut u8,
                        0,
                        (phdr.p_memsz - phdr.p_filesz) as usize,
                    );
                }
            }
        }

    }

    // Allocate bootcore image at a fixed physical base
    let bootcore_image_size = (bootcore_vaddr_end - bootcore_vaddr_base) as usize;
    let bootcore_image_pages = (bootcore_image_size + 4095) / 4096;
    let bootcore_phys_base = BOOTCORE_PHYS_BASE;

    boot_services
        .allocate_pages(
            AllocateType::Address(bootcore_phys_base),
            MemoryType::LOADER_DATA,
            bootcore_image_pages,
        )
        .expect("Failed to allocate bootcore image");

    for phdr in bootcore_phdrs {
        if phdr.p_type == PT_LOAD {
            let dest_addr = bootcore_phys_base + (phdr.p_vaddr - bootcore_vaddr_base);
            let src_data = unsafe {
                core::slice::from_raw_parts(
                    (bootcore_data_ptr as usize + phdr.p_offset as usize) as *const u8,
                    phdr.p_filesz as usize,
                )
            };

            unsafe {
                core::ptr::copy_nonoverlapping(
                    src_data.as_ptr(),
                    dest_addr as *mut u8,
                    phdr.p_filesz as usize,
                );

                // Zero BSS
                if phdr.p_memsz > phdr.p_filesz {
                    core::ptr::write_bytes(
                        (dest_addr + phdr.p_filesz) as *mut u8,
                        0,
                        (phdr.p_memsz - phdr.p_filesz) as usize,
                    );
                }
            }
        }
    }

    let bootcore_entry = bootcore_phys_base + (bootcore_elf_header.e_entry - bootcore_vaddr_base);
    let bootcore_end = bootcore_phys_base + (bootcore_image_pages as u64 * 4096);

    let user_image_phys: u64 = 0;
    let user_image_pages: usize = 0;
    let user_stack_phys: u64 = 0;
    let user_stack_pages: usize = 0;

    // Drop boot_services and print status
    drop(boot_services);
    {
        let stdout = system_table.stdout();
        let _ = stdout.output_string(cstr16!("ELF entry point: 0x"));
        print_hex(stdout, elf_header.e_entry);
        let _ = stdout.output_string(cstr16!("\r\n"));
        let _ = stdout.output_string(cstr16!("Kernel loaded\r\n"));
    }

    // Get memory map
    let boot_services = system_table.boot_services();
    let memory_map = unsafe {
        boot_services.memory_map(
            &mut *(&raw mut MEMORY_MAP_STORAGE.data),
        ).expect("Failed to get memory map")
    };

    // Convert to SKA format
    let mut entry_count = 0usize;
    for entry in memory_map.entries().take(MAX_MEMORY_MAP_ENTRIES) {
        let ska_type = match entry.ty {
            MemoryType::CONVENTIONAL
            | MemoryType::LOADER_CODE
            | MemoryType::LOADER_DATA
            | MemoryType::BOOT_SERVICES_CODE
            | MemoryType::BOOT_SERVICES_DATA => SkaMemoryType::Usable,
            MemoryType::RESERVED => SkaMemoryType::Reserved,
            MemoryType::ACPI_RECLAIM => SkaMemoryType::AcpiReclaimable,
            MemoryType::ACPI_NON_VOLATILE => SkaMemoryType::AcpiNvs,
            MemoryType::UNUSABLE => SkaMemoryType::Unusable,
            _ => SkaMemoryType::Reserved,
        };

        unsafe {
            MEMORY_MAP_ENTRIES[entry_count] = MemoryEntry {
                base: PhysAddr::new(entry.phys_start),
                length: entry.page_count * 4096,
                mem_type: ska_type,
                acpi_attrs: 0,
            };
        }
        entry_count += 1;
    }

    // Copy memory map into low memory so the kernel can read it after paging switch
    let entries_bytes = entry_count * size_of::<MemoryEntry>();
    let entries_pages = core::cmp::max(1, (entries_bytes + 4095) / 4096);
    let memory_map_phys = boot_services
        .allocate_pages(
            AllocateType::MaxAddress(0x0000_0000_FFFF_F000),
            MemoryType::LOADER_DATA,
            entries_pages,
        )
        .expect("Failed to allocate memory map buffer");

    unsafe {
        let entries_src = core::ptr::addr_of!(MEMORY_MAP_ENTRIES) as *const MemoryEntry;
        core::ptr::copy_nonoverlapping(
            entries_src,
            memory_map_phys as *mut MemoryEntry,
            entry_count,
        );
    }

    let mut identity_map_gib = IDENTITY_MAP_GIB;
    let mem_map_end = memory_map_phys + (entries_pages as u64 * 4096);
    let needed_gib = ((mem_map_end + (1 << 30) - 1) >> 30) as usize;
    if needed_gib > identity_map_gib {
        identity_map_gib = needed_gib;
    }
    let needed_gib = ((bootcore_end + (1 << 30) - 1) >> 30) as usize;
    if needed_gib > identity_map_gib {
        identity_map_gib = needed_gib;
    }

    // Build BootInfo in low memory
    let mut ctx = BootContext::empty();
    ctx.flags |= BootFlags::UEFI;
    ctx.memory_map = PhysAddr::new(memory_map_phys);
    ctx.memory_map_entries = entry_count as u32;

    // Initrd (raw cpio)
    let initrd_end = initrd_data_ptr + initrd_size;
    let needed_gib = ((initrd_end + (1 << 30) - 1) >> 30) as usize;
    if needed_gib > identity_map_gib {
        identity_map_gib = needed_gib;
    }
    ctx.flags |= BootFlags::INITRD;
    ctx.initrd = saltyos_ska::ModuleInfo {
        address: PhysAddr::new(initrd_data_ptr),
        size: initrd_size,
        name: [0; 64],
    };

    // Populate framebuffer info if GOP is available
    if let Ok(handles) = boot_services.locate_handle_buffer(
        SearchType::ByProtocol(&GraphicsOutput::GUID),
    ) {
        if let Some(handle) = handles.first() {
            if let Ok(mut gop) = boot_services.open_protocol_exclusive::<GraphicsOutput>(*handle) {
                let mode = gop.current_mode_info();
                let mut fb = gop.frame_buffer();
                let format = match mode.pixel_format() {
                    GopPixelFormat::Rgb => saltyos_ska::PixelFormat::Rgb,
                    GopPixelFormat::Bgr => saltyos_ska::PixelFormat::Bgr,
                    _ => saltyos_ska::PixelFormat::Bgr,
                };

                let fb_addr = fb.as_mut_ptr() as u64;
                let fb_size = (mode.stride() as u64)
                    * (mode.resolution().1 as u64)
                    * 4;
                let fb_end = fb_addr + fb_size;
                let needed_gib = ((fb_end + (1 << 30) - 1) >> 30) as usize;
                if needed_gib > identity_map_gib {
                    identity_map_gib = needed_gib;
                }

                ctx.flags |= BootFlags::FRAMEBUFFER;
                ctx.framebuffer = saltyos_ska::FramebufferInfo {
                    address: PhysAddr::new(fb_addr),
                    width: mode.resolution().0 as u32,
                    height: mode.resolution().1 as u32,
                    pitch: (mode.stride() * 4) as u32,
                    format,
                    bpp: 32,
                };
            }
        }
    }

    let bootinfo_phys = boot_services
        .allocate_pages(
            AllocateType::MaxAddress(0x0000_0000_FFFF_F000),
            MemoryType::LOADER_DATA,
            1,
        )
        .expect("Failed to allocate BootInfo buffer");

    let bootinfo_ptr = bootinfo_phys as *mut BootInfo;

    // Print status
    drop(boot_services);
    {
        let stdout = system_table.stdout();
        let _ = stdout.output_string(cstr16!("Preparing bootcore handoff...\r\n"));
    }
    let boot_services = system_table.boot_services();

    // Allocate page table arena for bootcore (keep below 4 GiB for identity map)
    let pt_pages: usize = 32;
    let pt_alloc_base = boot_services
        .allocate_pages(
            AllocateType::MaxAddress(0x0000_0000_FFFF_F000),
            MemoryType::LOADER_DATA,
            pt_pages,
        )
        .expect("Failed to allocate bootcore page table arena");
    let pt_alloc_size = (pt_pages * 4096) as u64;

    // Allocate handoff buffer (low memory for identity map)
    let handoff_pages: usize = 1;
    let handoff_phys = boot_services
        .allocate_pages(
            AllocateType::MaxAddress(0x0000_0000_FFFF_F000),
            MemoryType::LOADER_DATA,
            handoff_pages,
        )
        .expect("Failed to allocate bootcore handoff buffer");
    let handoff_size = (handoff_pages * 4096) as u64;

    let handoff_end = handoff_phys + handoff_size;
    let needed_gib = ((handoff_end + (1 << 30) - 1) >> 30) as usize;
    if needed_gib > identity_map_gib {
        identity_map_gib = needed_gib;
    }

    // Build extra TLV (reserved ranges)
    let extra_count: u32 = 8;
    let extra_len = (4 + (extra_count as u64) * 16) as u32;
    let extra_total = (core::mem::size_of::<ExtraHeader>() as u32) + extra_len;
    let extra_pages = ((extra_total as usize) + 4095) / 4096;
    let extra_ptr = boot_services
        .allocate_pages(
            AllocateType::MaxAddress(0x0000_0000_FFFF_F000),
            MemoryType::LOADER_DATA,
            extra_pages,
        )
        .expect("Failed to allocate boot extra buffer");
    let extra_size = (extra_pages * 4096) as u64;

    let extra_end = extra_ptr + extra_size;
    let needed_gib = ((extra_end + (1 << 30) - 1) >> 30) as usize;
    if needed_gib > identity_map_gib {
        identity_map_gib = needed_gib;
    }

    unsafe {
        let hdr = extra_ptr as *mut ExtraHeader;
        core::ptr::write(hdr, ExtraHeader { kind: EXTRA_KIND_MEM_RESERVED, len: extra_len });
        let count_ptr = (extra_ptr + core::mem::size_of::<ExtraHeader>() as u64) as *mut u32;
        core::ptr::write(count_ptr, extra_count);
        let mut cur = (count_ptr as u64) + 4;

        let mut write_range = |base: u64, size: u64| {
            let base_ptr = cur as *mut u64;
            core::ptr::write(base_ptr, base);
            core::ptr::write(base_ptr.add(1), size);
            cur += 16;
        };

        write_range(bootinfo_phys, 4096);
        write_range(memory_map_phys, (entries_pages * 4096) as u64);
        write_range(initrd_data_ptr, initrd_size);
        write_range(kernel_phys_base, image_pages as u64 * 4096);
        write_range(bootcore_phys_base, bootcore_image_pages as u64 * 4096);
        write_range(pt_alloc_base, pt_alloc_size);
        write_range(extra_ptr, extra_size);
        write_range(handoff_phys, handoff_size);
    }

    let extra_ptr = extra_ptr as u64;
    let extra_len = extra_total as u64;

    let handoff_ptr = handoff_phys as *mut BootHandoff;
    let handoff = BootHandoff {
        boot_context: ctx,
        bootinfo_ptr,
        kernel_phys_base,
        kernel_vaddr_base: vaddr_base,
        kernel_entry: elf_header.e_entry,
        kernel_dyn_phys: dyn_phys,
        kernel_dyn_size: dyn_size,
        user_image_phys,
        user_image_pages: user_image_pages as u64,
        user_stack_phys,
        user_stack_pages: user_stack_pages as u64,
        pt_alloc_base,
        pt_alloc_size,
        identity_map_gib: identity_map_gib as u64,
        extra_ptr,
        extra_len,
    };

    unsafe {
        core::ptr::write(handoff_ptr, handoff);
    }

    // Exit boot services
    drop(boot_services);
    let (_image, _memory_map) = system_table.exit_boot_services(MemoryType::LOADER_DATA);

    let bootcore_fn: extern "sysv64" fn(*const BootHandoff) -> ! =
        unsafe { core::mem::transmute(bootcore_entry as usize) };
    unsafe {
        bootcore_fn(handoff_ptr as *const BootHandoff);
    }
}

/// Print a hex number to stdout
fn print_hex(stdout: &mut uefi::proto::console::text::Output, n: u64) {
    // UEFI cstr16! macro requires a string literal, so we output digit by digit
    let hex_chars = [
        cstr16!("0"), cstr16!("1"), cstr16!("2"), cstr16!("3"),
        cstr16!("4"), cstr16!("5"), cstr16!("6"), cstr16!("7"),
        cstr16!("8"), cstr16!("9"), cstr16!("a"), cstr16!("b"),
        cstr16!("c"), cstr16!("d"), cstr16!("e"), cstr16!("f"),
    ];

    // Output all 16 hex digits (leading zeros)
    for i in 0..16 {
        let shift = (15 - i) * 4;
        let digit = ((n >> shift) & 0xf) as usize;
        let _ = stdout.output_string(hex_chars[digit]);
    }
}
