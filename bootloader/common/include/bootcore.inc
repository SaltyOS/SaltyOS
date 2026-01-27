; ==============================================================================
; Bootcore handoff layout (matches bootloader/core BootContext/BootHandoff)
; ==============================================================================

; BootContext offsets
%define BOOTCTX_OFF_FLAGS            0
%define BOOTCTX_OFF_MEMORY_MAP       8
%define BOOTCTX_OFF_MEMORY_MAP_ENT   16
%define BOOTCTX_OFF_FRAMEBUFFER      24
%define BOOTCTX_OFF_INITRD           48
%define BOOTCTX_OFF_CMDLINE          128
%define BOOTCTX_OFF_CMDLINE_LEN      136
%define BOOTCTX_OFF_RSDP             144
%define BOOTCTX_SIZE                 152

; BootHandoff offsets
%define BOOTHANDOFF_OFF_BOOTCTX          0
%define BOOTHANDOFF_OFF_BOOTINFO_PTR     152
%define BOOTHANDOFF_OFF_KERNEL_PHYS_BASE 160
%define BOOTHANDOFF_OFF_KERNEL_VADDR     168
%define BOOTHANDOFF_OFF_KERNEL_ENTRY     176
%define BOOTHANDOFF_OFF_KERNEL_DYN_PHYS  184
%define BOOTHANDOFF_OFF_KERNEL_DYN_SIZE  192
%define BOOTHANDOFF_OFF_USER_IMAGE_PHYS  200
%define BOOTHANDOFF_OFF_USER_IMAGE_PAGES 208
%define BOOTHANDOFF_OFF_USER_STACK_PHYS  216
%define BOOTHANDOFF_OFF_USER_STACK_PAGES 224
%define BOOTHANDOFF_OFF_PT_ALLOC_BASE    232
%define BOOTHANDOFF_OFF_PT_ALLOC_SIZE    240
%define BOOTHANDOFF_OFF_IDENTITY_GIB     248
%define BOOTHANDOFF_OFF_EXTRA_PTR        256
%define BOOTHANDOFF_OFF_EXTRA_LEN        264
%define BOOTHANDOFF_SIZE                 272
