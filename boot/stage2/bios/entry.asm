; SaltyOS Stage 2 - Entry Point
; SPDX-License-Identifier: GPL-2.0-only
;
; Called from MBR at 0x7E00 in real mode
; Sets up protected mode, long mode, loads Stage 3, jumps to it

[bits 16]
[org 0x7E00]

; Constants
STAGE3_LOAD_ADDR    equ 0x10000     ; 64KB - Stage 3 load address
STAGE3_LBA          equ 129         ; Stage 3 starts after Stage 2 (1 + 128 sectors)
STAGE3_SECTORS      equ 64          ; 32KB for Stage 3
KERNEL_LBA          equ 193         ; Kernel LBA (after Stage 3)

_start:
    cli
    
    ; Save boot drive from MBR (passed in DL)
    mov [boot_drive], dl

    ; Set up segments
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x7C00              ; Stack below MBR

    ; Print message
    mov si, msg_stage2
    call print16

    ; Enable A20 line
    call enable_a20

    ; Load Stage 3 to 0x10000 while still in real mode
    mov si, msg_loading_s3
    call print16
    
    ; Set up DAP for Stage 3
    mov word [dap_sectors], STAGE3_SECTORS
    mov word [dap_offset], 0x0000
    mov word [dap_segment], 0x1000      ; Segment 0x1000 = address 0x10000
    mov dword [dap_lba_low], STAGE3_LBA
    mov dword [dap_lba_high], 0
    
    mov ah, 0x42
    mov dl, [boot_drive]
    mov si, dap
    int 0x13
    jc .disk_error

    ; Load Kernel to 0x20000 temporarily (BIOS can't access >1MB directly)
    mov si, msg_loading_kernel
    call print16
    
    ; Load kernel to 0x20000 (we'll copy to 1MB in protected mode)
    mov word [dap_sectors], 64          ; Load 32KB of kernel for now
    mov word [dap_offset], 0x0000
    mov word [dap_segment], 0x2000      ; 0x20000
    mov dword [dap_lba_low], KERNEL_LBA
    mov dword [dap_lba_high], 0
    
    mov ah, 0x42
    mov dl, [boot_drive]
    mov si, dap
    int 0x13
    jc .disk_error

    mov si, msg_entering_pm
    call print16

    ; Load GDT
    lgdt [gdt_ptr]

    ; Enter protected mode
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    ; Far jump to 32-bit code
    jmp 0x08:protected_mode

.disk_error:
    mov si, msg_disk_err
    call print16
    jmp .halt

.halt:
    cli
    hlt
    jmp .halt

; Enable A20 via fast A20 gate
enable_a20:
    in al, 0x92
    or al, 2
    out 0x92, al
    ret

; Print string in real mode (SI = string)
print16:
    pusha
.loop:
    lodsb
    or al, al
    jz .done
    mov ah, 0x0E
    mov bx, 0x0007
    int 0x10
    jmp .loop
.done:
    popa
    ret

; Messages
msg_stage2:         db "S2: start", 13, 10, 0
msg_loading_s3:     db "S2: load S3", 13, 10, 0
msg_loading_kernel: db "S2: load K", 13, 10, 0
msg_entering_pm:    db "S2: PM", 13, 10, 0
msg_disk_err:       db "S2: disk err", 13, 10, 0

; Boot drive number
boot_drive: db 0

; Disk Address Packet
align 4
dap:
    db 0x10                 ; Size
    db 0                    ; Reserved
dap_sectors:    dw 0        ; Sectors to read
dap_offset:     dw 0        ; Offset
dap_segment:    dw 0        ; Segment
dap_lba_low:    dd 0        ; LBA low
dap_lba_high:   dd 0        ; LBA high

; 32-bit protected mode code
[bits 32]
protected_mode:
    ; Set up segment registers
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7C00

    ; Print character via serial (0x3F8) to show we're in PM
    mov dx, 0x3F8
    mov al, 'P'
    out dx, al

    ; NOTE: Kernel stays at 0x20000. Stage 3 will parse the ELF and
    ; load segments to their correct physical addresses (0x100000+)

    ; Set up paging for long mode
    call setup_paging

    ; Enable long mode in EFER
    mov ecx, 0xC0000080     ; EFER MSR
    rdmsr
    or eax, (1 << 8)        ; Set LME bit
    wrmsr

    ; Enable paging (enters long mode)
    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    ; Jump to 64-bit code (use 64-bit code segment 0x18)
    jmp 0x18:long_mode

; Set up identity paging for first 1GB + higher-half kernel mapping
setup_paging:
    ; Page table layout at 0x70000:
    ;   0x70000: PML4
    ;   0x71000: PDPT
    ;   0x72000: PD for identity mapping (0x0 - 1GB, 2MB pages)
    ;   0x73000: PD for higher-half (PDPT[510]: 0xFFFFFFFF80000000+)
    ;   0x74000: PT[0] for higher-half kernel code/data (4KB pages)
    ;   0x75000: PD for higher-half stack area (PDPT[509]: 0xFFFFFFFF7FC00000+)
    ;   0x76000: PT for stack area (4KB pages)
    
    ; Clear page table area (28KB = 7 pages)
    mov edi, 0x70000
    mov cr3, edi
    xor eax, eax
    mov ecx, 7168           ; 28KB in dwords
    rep stosd
    mov edi, cr3

    ; === PML4 setup ===
    ; PML4[0] -> PDPT at 0x71000 (identity mapping)
    lea eax, [edi + 0x1000]
    or eax, 3               ; Present + Writable
    mov dword [edi], eax
    
    ; PML4[511] -> same PDPT (for higher-half 0xFFFFFFFF........)
    mov dword [edi + 511*8], eax
    
    add edi, 0x1000         ; EDI = PDPT at 0x71000

    ; === PDPT setup ===
    ; PDPT[0] -> PD at 0x72000 (for identity 0x0 - 1GB)
    lea eax, [edi + 0x1000]
    or eax, 3
    mov dword [edi], eax
    
    ; PDPT[509] -> PD at 0x75000 (for stack area 0xFFFFFFFF7FC00000+)
    lea eax, [edi + 0x4000]
    or eax, 3
    mov dword [edi + 509*8], eax
    
    ; PDPT[510] -> PD at 0x73000 (for kernel 0xFFFFFFFF80000000+)
    lea eax, [edi + 0x2000]
    or eax, 3
    mov dword [edi + 510*8], eax
    
    add edi, 0x1000         ; EDI = PD at 0x72000 (identity PD)

    ; === Identity PD (0x72000): 2MB huge pages for first 1GB ===
    mov ebx, 0x00000083     ; Present + Writable + Huge (PS bit)
    mov ecx, 512
.pd_identity_loop:
    mov dword [edi], ebx
    add ebx, 0x200000       ; 2MB per entry
    add edi, 8
    loop .pd_identity_loop
    
    ; EDI now at 0x73000 (higher-half kernel PD)
    
    ; === Higher-half kernel PD (0x73000) ===
    ; PD[0] -> PT at 0x74000 (for 4KB pages at 0xFFFFFFFF80000000+)
    lea eax, [edi + 0x1000]
    or eax, 3               ; Present + Writable
    mov dword [edi], eax
    
    add edi, 0x1000         ; EDI = PT at 0x74000
    
    ; === Kernel PT (0x74000): map 0xFFFFFFFF80000000+ -> physical 0x100000+ ===
    ; Map 2MB (512 * 4KB pages)
    mov ebx, 0x00100003     ; Physical 0x100000 + Present + Writable
    mov ecx, 512
.pt_kernel_loop:
    mov dword [edi], ebx
    add ebx, 0x1000         ; 4KB per entry
    add edi, 8
    loop .pt_kernel_loop
    
    ; EDI now at 0x75000 (stack area PD)
    
    ; === Stack area PD (0x75000) for PDPT[509] ===
    ; Maps 0xFFFFFFFF7FC00000 - 0xFFFFFFFF7FFFFFFF
    ; PD[511] -> PT at 0x76000 (last 2MB of this 1GB region, where stack probing goes)
    lea eax, [edi + 0x1000]
    or eax, 3
    mov dword [edi + 511*8], eax    ; PD[511] for the last 2MB
    
    add edi, 0x1000         ; EDI = PT at 0x76000
    
    ; === Stack PT (0x76000): map physical 0x0 - 0x1FFFFF for stack probing ===
    ; This maps virtual 0xFFFFFFFF7FE00000 - 0xFFFFFFFF7FFFFFFF -> physical 0x0 - 0x1FFFFF
    ; Stack probing will touch these pages
    mov ebx, 0x00000003     ; Physical 0x0 + Present + Writable
    mov ecx, 512
.pt_stack_loop:
    mov dword [edi], ebx
    add ebx, 0x1000         ; 4KB per entry
    add edi, 8
    loop .pt_stack_loop

    ; Enable PAE
    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax

    ret

; 64-bit long mode code
[bits 64]
long_mode:
    ; Set up 64-bit data segments (use 64-bit data segment 0x20)
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; Set up stack
    mov rsp, 0x80000        ; Stack at 512KB

    ; Print 'L' to serial to show long mode
    mov dx, 0x3F8
    mov al, 'L'
    out dx, al

    ; Jump to Stage 3 at 0x10000
    mov rax, STAGE3_LOAD_ADDR
    call rax

    ; Should not return, halt if it does
.halt64:
    cli
    hlt
    jmp .halt64

; GDT for protected mode and long mode
align 16
gdt_start:
    ; Null descriptor (0x00)
    dq 0
    ; 32-bit code segment (0x08) - for protected mode
    dq 0x00CF9A000000FFFF
    ; 32-bit data segment (0x10)
    dq 0x00CF92000000FFFF
    ; 64-bit code segment (0x18) - for long mode
    dq 0x00AF9A000000FFFF
    ; 64-bit data segment (0x20)
    dq 0x00AF92000000FFFF
gdt_end:

gdt_ptr:
    dw gdt_end - gdt_start - 1
    dd gdt_start
