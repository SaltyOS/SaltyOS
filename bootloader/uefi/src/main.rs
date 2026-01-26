//! UEFI Bootloader for SaltyOS
//!
//! Loads the kernel ELF file with PIE support and sets up page tables
//! for higher-half kernel execution.

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
use saltyos_bootloader_common::{
    PT_LOAD, parse_elf_header, get_program_headers, init_bootinfo,
    find_load_vaddr_range, find_dynamic_segment,
    layout::{KERNEL_PHYS_BASE, KERNEL_VIRT_BASE, USER_STACK_PAGES},
};

mod paging;

use core::mem::size_of;

/// Maximum memory map entries
const MAX_MEMORY_MAP_ENTRIES: usize = 128;

/// Kernel load addresses
// Defined in bootloader_common::layout

/// Identity map size for bootloader + kernel staging
const IDENTITY_MAP_GIB: usize = 4;

/// ELF dynamic constants
const DT_NULL: i64 = 0;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;

/// x86_64 relocation type
const R_X86_64_RELATIVE: u32 = 8;

#[repr(C)]
struct Elf64Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C)]
struct Elf64Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

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

    // Drop kernel_file and print status
    drop(kernel_file);
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

    // Reopen file and read kernel
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
    drop(root);
    drop(fs);

    // Parse ELF
    let elf_header = parse_elf_header(kernel_data)
        .expect("Invalid ELF header");
    let phdrs = get_program_headers(kernel_data, elf_header);

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
            MemoryType::CONVENTIONAL => SkaMemoryType::Usable,
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

    // Build BootInfo in low memory
    let mut bootinfo = init_bootinfo();
    bootinfo.flags |= BootFlags::UEFI;
    bootinfo.memory_map = PhysAddr::new(memory_map_phys);
    bootinfo.memory_map_entries = entry_count as u32;

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

                bootinfo.flags |= BootFlags::FRAMEBUFFER;
                bootinfo.framebuffer = Some(saltyos_ska::FramebufferInfo {
                    address: PhysAddr::new(fb_addr),
                    width: mode.resolution().0 as u32,
                    height: mode.resolution().1 as u32,
                    pitch: (mode.stride() * 4) as u32,
                    format,
                    bpp: 32,
                });
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
    unsafe {
        core::ptr::write(bootinfo_ptr, bootinfo);
    }

    // Print status
    drop(boot_services);
    {
        let stdout = system_table.stdout();
        let _ = stdout.output_string(cstr16!("Setting up page tables...\r\n"));
    }
    let boot_services = system_table.boot_services();

    // Allocate user code + stack pages
    let user_code_phys = boot_services
        .allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 1)
        .expect("Failed to allocate user code page");
    let user_stack_pages = USER_STACK_PAGES;
    let user_stack_phys = boot_services
        .allocate_pages(
            AllocateType::AnyPages,
            MemoryType::LOADER_DATA,
            user_stack_pages,
        )
        .expect("Failed to allocate user stack pages");

    // Fill user code page with a tiny syscall loop
    let user_stub: [u8; 24] = [
        0x48, 0xb8, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xbf, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0f, 0x05, 0xeb, 0xfe,
    ];
    unsafe {
        core::ptr::write_bytes(user_code_phys as *mut u8, 0, 4096);
        core::ptr::copy_nonoverlapping(
            user_stub.as_ptr(),
            user_code_phys as *mut u8,
            user_stub.len(),
        );
        core::ptr::write_bytes(
            user_stack_phys as *mut u8,
            0,
            user_stack_pages * 4096,
        );
    }

    // Create page tables for higher-half kernel + user mappings
    let pml4_addr = unsafe {
        paging::create_page_tables(
            kernel_phys_base,
            identity_map_gib,
            user_code_phys,
            user_stack_phys,
            user_stack_pages,
        )
    };

    // Exit boot services
    let (_image, _memory_map) = system_table.exit_boot_services(MemoryType::LOADER_DATA);

    // Enable paging
    unsafe {
        paging::enable_paging(pml4_addr);
    }

    // Apply RELA relocations (R_X86_64_RELATIVE) if present
    if dyn_phys != 0 && dyn_size != 0 {
        apply_relocations(dyn_phys, dyn_size, vaddr_base, kernel_phys_base);
    }

    // Jump to runtime kernel entry point
    // runtime_entry = KERNEL_VIRT_BASE + (e_entry - vaddr_base)
    let kernel_entry = KERNEL_VIRT_BASE + (elf_header.e_entry - vaddr_base);

    unsafe {
        let kernel_fn: extern "sysv64" fn(&BootInfo) -> ! =
            core::mem::transmute(kernel_entry as usize);

        kernel_fn(&*bootinfo_ptr);
    }
}

fn apply_relocations(dyn_phys: u64, dyn_size: u64, vaddr_base: u64, phys_base: u64) {
    let mut rela_ptr = 0u64;
    let mut rela_sz = 0u64;
    let mut rela_ent = 0u64;

    let mut offset = 0u64;
    while offset + size_of::<Elf64Dyn>() as u64 <= dyn_size {
        let dyn_entry = unsafe { &*(dyn_phys.wrapping_add(offset) as *const Elf64Dyn) };
        if dyn_entry.d_tag == DT_NULL {
            break;
        }
        match dyn_entry.d_tag {
            DT_RELA => rela_ptr = dyn_entry.d_val,
            DT_RELASZ => rela_sz = dyn_entry.d_val,
            DT_RELAENT => rela_ent = dyn_entry.d_val,
            _ => {}
        }
        offset += size_of::<Elf64Dyn>() as u64;
    }

    if rela_ptr == 0 || rela_sz == 0 {
        return;
    }

    if rela_ent == 0 {
        rela_ent = size_of::<Elf64Rela>() as u64;
    }

    let slide = KERNEL_VIRT_BASE.wrapping_sub(vaddr_base);
    let rela_phys = phys_base + (rela_ptr - vaddr_base);
    let count = rela_sz / rela_ent;

    for i in 0..count {
        let rela = unsafe {
            &*(rela_phys.wrapping_add(i * rela_ent) as *const Elf64Rela)
        };
        let r_type = (rela.r_info & 0xffff_ffff) as u32;
        if r_type == R_X86_64_RELATIVE {
            let reloc_phys = phys_base + (rela.r_offset - vaddr_base);
            let value = slide.wrapping_add(rela.r_addend as u64);
            unsafe {
                core::ptr::write_unaligned(reloc_phys as *mut u64, value);
            }
        }
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
