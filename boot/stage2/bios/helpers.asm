; SPDX-License-Identifier: GPL-2.0-only
; -----------------------------------------------------------------------------
;  SaltyOS Stage 2 - BIOS Helpers
;  File: helpers.asm
;  Description: BIOS service wrappers with correct Long Mode <-> Real Mode switching
; -----------------------------------------------------------------------------

section .data

; -----------------------------------------------------------------------------
;  Global Variables
; -----------------------------------------------------------------------------
global boot_drive
boot_drive:     db 0

global stage3_lba
stage3_lba:     dq 129

global kernel_lba
kernel_lba:     dq 193

; Disk Address Packet (DAP)
align 4
global dap
dap:
    db 0x10             ; Size
    db 0                ; Reserved
global dap_sectors
dap_sectors:    dw 0    ; Count
global dap_offset
dap_offset:     dw 0    ; Offset
global dap_segment
dap_segment:    dw 0    ; Segment
global dap_lba_low
dap_lba_low:    dd 0    ; LBA Low
global dap_lba_high
dap_lba_high:   dd 0    ; LBA High

; Parameter Buffer
global param_buf
param_buf:
param_buf_buffer:  times 64 db 0

; Return Values
global disk_result
disk_result:    dw 0

; Context Saving
global saved_cr3
saved_cr3:      dq 0
global saved_rsp
saved_rsp:      dq 0

; Memory Map Pointers
global mmap_buffer_ptr
mmap_buffer_ptr:  dq 0
global mmap_count_value
mmap_count_value: dq 0

; VBE Data
global vbe_ctrl_info_ptr
vbe_ctrl_info_ptr: dq 0x6000
global vbe_mode_info_ptr
vbe_mode_info_ptr: dq 0x6200
global vbe_result
vbe_result:     dw 0
global vbe_mode_found
vbe_mode_found: dw 0

; External IDT Pointer from entry.asm
extern idt64_ptr

; Real Mode IDT Pointer (IVT at 0x0)
real_mode_idt:
    dw 0x3FF        ; Limit
    dd 0x00000000   ; Base

; -----------------------------------------------------------------------------
;  GDT Definitions
; -----------------------------------------------------------------------------
align 16
gdt_start:
    dq 0x0000000000000000       ; Null Descriptor
.code32:
    dq 0x00CF9A000000FFFF       ; 32-bit Code (Base=0, Limit=4GB)
.data32:
    dq 0x00CF92000000FFFF       ; 32-bit Data (Base=0, Limit=4GB)
.code16:
    dq 0x00009A000000FFFF       ; 16-bit Code (Base=0, Limit=64KB)
.data16:
    dq 0x000092000000FFFF       ; 16-bit Data (Base=0, Limit=64KB)
.code64:
    dq 0x00AF9A000000FFFF       ; 64-bit Code
.data64:
    dq 0x00AF92000000FFFF       ; 64-bit Data
gdt_end:

; GDT Pointer for Real/Protected Mode (6 bytes)
gdt_ptr32:
    dw gdt_end - gdt_start - 1
    dd gdt_start

; GDT Pointer for Long Mode (10 bytes)
gdt_ptr64:
    dw gdt_end - gdt_start - 1
    dq gdt_start

; Selectors
SEL_CODE32 equ gdt_start.code32 - gdt_start
SEL_DATA32 equ gdt_start.data32 - gdt_start
SEL_CODE16 equ gdt_start.code16 - gdt_start
SEL_DATA16 equ gdt_start.data16 - gdt_start
SEL_CODE64 equ gdt_start.code64 - gdt_start
SEL_DATA64 equ gdt_start.data64 - gdt_start

; -----------------------------------------------------------------------------
;  Code Section - 64-bit
; -----------------------------------------------------------------------------
section .text
bits 64
default rel

; -----------------------------------------------------------------------------
;  Macro: GO_TO_REAL_MODE
;  Switches from Long Mode to Real Mode AND loads Real Mode IDT
; -----------------------------------------------------------------------------
%macro GO_TO_REAL_MODE 0
    cli
    ; 1. Save 64-bit state
    mov [saved_rsp], rsp
    mov rax, cr3
    mov [saved_cr3], rax
    
    ; 2. Load 64-bit GDT pointer
    lgdt [gdt_ptr64]

    ; 3. Jump to Compatibility Mode (32-bit)
    push SEL_CODE32         ; CS
    lea rax, [%%compat_mode]
    push rax                ; RIP
    retfq

bits 32
%%compat_mode:
    mov ax, SEL_DATA32
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; 4. Disable Paging (CR0.PG = 0)
    mov eax, cr0
    and eax, ~(1 << 31)
    mov cr0, eax

    ; 5. Disable Long Mode (EFER.LME = 0)
    mov ecx, 0xC0000080
    rdmsr
    and eax, ~(1 << 8)
    wrmsr

    ; 6. Disable PAE (CR4.PAE = 0)
    mov eax, cr4
    and eax, ~(1 << 5)
    mov cr4, eax

    ; 7. Jump to 16-bit Protected Mode
    jmp SEL_CODE16:%%pm16

bits 16
%%pm16:
    mov ax, SEL_DATA16
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    ; 8. Disable Protected Mode (CR0.PE = 0)
    mov eax, cr0
    and eax, ~1
    mov cr0, eax

    ; 9. Jump to Real Mode
    jmp 0x0000:%%real_mode

%%real_mode:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x5000          ; Temp Stack
    
    ; [중요] Load Real Mode IDT (IVT)
    lidt [real_mode_idt]
    
    sti
%endmacro

; -----------------------------------------------------------------------------
;  Macro: GO_TO_LONG_MODE
;  Switches from Real Mode to Long Mode AND restores Long Mode IDT
; -----------------------------------------------------------------------------
%macro GO_TO_LONG_MODE 0
    cli
    ; 1. Load 32-bit GDT pointer (valid in Real Mode)
    lgdt [gdt_ptr32]

    ; 2. Enable Protected Mode (CR0.PE = 1)
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; 3. Jump to 32-bit PM
    jmp dword SEL_CODE32:%%pm32

bits 32
%%pm32:
    mov ax, SEL_DATA32
    mov ds, ax
    mov es, ax
    mov ss, ax

    ; 4. Enable PAE (CR4.PAE = 1)
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    ; 5. Restore CR3
    mov eax, [dword saved_cr3]
    mov cr3, eax

    ; 6. Enable Long Mode (EFER.LME = 1)
    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    ; 7. Enable Paging (CR0.PG = 1)
    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    ; 8. Jump to 64-bit Code
    jmp SEL_CODE64:%%long_mode

bits 64
%%long_mode:
    mov ax, SEL_DATA64
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    mov rsp, [saved_rsp]
    
    ; [중요] Restore Long Mode IDT
    lidt [idt64_ptr]
%endmacro

; -----------------------------------------------------------------------------
;  Function: bios_read_disk_lba
; -----------------------------------------------------------------------------
global bios_read_disk_lba
bios_read_disk_lba:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rax, rdi
    shr rax, 20
    test rax, rax
    jnz .error

    mov qword [param_buf], rdi
    mov qword [param_buf + 8], rsi
    mov qword [param_buf + 16], rdx

    ; --- Switch to Real Mode ---
    GO_TO_REAL_MODE

    ; *** CRITICAL: Explicitly tell NASM we are in 16-bit mode ***
    bits 16
    
    ; Setup DAP
    mov eax, [param_buf]
    mov ecx, eax
    shr ecx, 4
    mov [dap_segment], cx
    and ax, 0x0F
    mov [dap_offset], ax

    mov eax, [param_buf + 8]
    mov edx, [param_buf + 12]
    mov cx, [param_buf + 16]

    mov byte [dap], 0x10
    mov byte [dap + 1], 0
    mov [dap_sectors], cx
    mov [dap_lba_low], eax
    mov [dap_lba_high], edx

    mov ah, 0x42
    mov dl, [boot_drive]
    mov si, dap
    int 0x13
    jc .disk_fail

    mov ax, [dap_sectors]
    mov [disk_result], ax
    jmp .return

.disk_fail:
    mov word [disk_result], -1

.return:
    ; --- Switch back to Long Mode ---
    GO_TO_LONG_MODE

    ; *** CRITICAL: Explicitly tell NASM we are in 64-bit mode ***
    bits 64

    movsx rax, word [disk_result]
    jmp .done

.error:
    mov rax, -2

.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; -----------------------------------------------------------------------------
;  Function: bios_get_e820_map
; -----------------------------------------------------------------------------
global bios_get_e820_map
bios_get_e820_map:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov rax, rdi
    shr rax, 20
    test rax, rax
    jnz .error

    mov qword [param_buf], rdi
    mov qword [param_buf + 8], rsi

    GO_TO_REAL_MODE
    bits 16

    mov edi, [param_buf]
    mov cx, [param_buf + 16] 
    
    xor ebx, ebx
    xor bp, bp               

.loop:
    cmp bp, cx
    jae .done_e820

    mov ax, bp
    mov dx, 24
    mul dx
    mov di, [param_buf]
    add di, ax

    mov edx, 0x534D4150
    mov eax, 0xE820
    mov ecx, 24
    int 0x15
    jc .done_e820
    
    cmp eax, 0x534D4150
    jne .done_e820

    inc bp
    test ebx, ebx
    jz .done_e820
    jmp .loop

.done_e820:
    mov [param_buf + 24], bp
    
    GO_TO_LONG_MODE
    bits 64

    movzx rax, word [param_buf + 24]
    jmp .exit

.error:
    xor rax, rax
.exit:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; -----------------------------------------------------------------------------
;  Function: bios_get_vbe_framebuffer
; -----------------------------------------------------------------------------
global bios_get_vbe_framebuffer
bios_get_vbe_framebuffer:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov qword [param_buf], rdi

    GO_TO_REAL_MODE
    bits 16

    mov ax, 0x4F00
    mov di, 0x6000
    int 0x10
    cmp al, 0x4F
    jne .fail

    mov ax, [0x6000 + 16]
    mov bx, [0x6000 + 18]
    mov fs, bx
    mov si, ax

.mode_loop:
    mov cx, [fs:si]
    cmp cx, 0xFFFF
    je .fail

    mov ax, 0x4F01
    mov di, 0x6200
    int 0x10
    cmp al, 0x4F
    jne .next_mode

    mov bx, [0x6200]
    test bx, 0x80
    jz .next_mode
    test bx, 0x10
    jz .next_mode
    
    mov al, [0x6200 + 0x19]
    cmp al, 32
    je .found
    cmp al, 24
    je .found

.next_mode:
    add si, 2
    jmp .mode_loop

.found:
    mov ax, 0x4F02
    mov bx, cx
    or bx, 0x4000
    int 0x10
    cmp al, 0x4F
    jne .fail

    mov di, [param_buf]
    mov eax, [0x6200 + 28]
    mov [di], eax
    mov ax, [0x6200 + 18]
    mov [di + 8], ax
    mov ax, [0x6200 + 20]
    mov [di + 12], ax
    mov ax, [0x6200 + 16]
    mov [di + 16], ax
    mov al, [0x6200 + 25]
    mov [di + 20], al

    mov word [vbe_result], 1
    jmp .return_vbe

.fail:
    mov word [vbe_result], 0

.return_vbe:
    GO_TO_LONG_MODE
    bits 64

    movzx rax, word [vbe_result]
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

; -----------------------------------------------------------------------------
;  Simple Helpers
; -----------------------------------------------------------------------------
global bios_get_boot_drive
bios_get_boot_drive:
    movzx rax, byte [boot_drive]
    ret