%define KERNEL_PHYS_BASE        0x00200000
%define BOOTCORE_PHYS_BASE      0x00100000
%define KERNEL_VIRT_BASE        0xFFFFFFFF80000000

%define USER_CODE_BASE          0x0000000040000000
%define USER_STACK_BASE         0x0000000040100000
%define USER_STACK_PAGES        4
%define USER_STUB_LEN           24

%define USER_PML4_INDEX         0x00
%define USER_PDPT_INDEX         0x01
%define USER_PD_INDEX           0x00
%define USER_PT_INDEX           0x000
%define USER_STACK_PT_INDEX     0x100
