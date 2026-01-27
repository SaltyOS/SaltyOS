; ==============================================================================
; SaltyOS SKA ABI constants for BIOS bootloader (ASM)
; Keep in sync with abi/ska/src/lib.rs
; ==============================================================================

; BootInfo layout (repr(C)) - only stable fields used by BIOS
%define BOOTINFO_MAGIC_DWORD        0x00414B53  ; "SKA\0" little endian
%define BOOTINFO_VERSION            0x0001

%define BOOTINFO_OFF_MAGIC          0
%define BOOTINFO_OFF_VERSION        4
%define BOOTINFO_OFF_FLAGS          8
%define BOOTINFO_OFF_SIZE           12
%define BOOTINFO_OFF_MEMORY_MAP     16
%define BOOTINFO_OFF_MEMORY_MAP_ENT 24
%define BOOTINFO_OFF_FRAMEBUFFER    32
%define BOOTINFO_OFF_INITRD         48
%define BOOTINFO_OFF_CMDLINE        128
%define BOOTINFO_OFF_CMDLINE_LEN    136
%define BOOTINFO_OFF_RSDP           144
%define BOOTINFO_OFF_EXTRA          152
%define BOOTINFO_OFF_EXTRA_LEN      160

; BootFlags (bitflags u32)
%define BOOTFLAG_UEFI               0x01
%define BOOTFLAG_BIOS               0x02
%define BOOTFLAG_FRAMEBUFFER        0x04
%define BOOTFLAG_ACPI               0x08
%define BOOTFLAG_INITRD             0x10

; MemoryType (u32)
%define SKA_MEM_USABLE              1
%define SKA_MEM_RESERVED            2
%define SKA_MEM_ACPI_RECLAIM        3
%define SKA_MEM_ACPI_NVS            4
%define SKA_MEM_UNUSABLE            5
%define SKA_MEM_DISABLED            6
