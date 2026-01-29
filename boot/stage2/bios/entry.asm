; SPDX-License-Identifier: GPL-2.0-only
; -----------------------------------------------------------------------------
;  SaltyOS Stage 2 - BIOS Entry Point
;  File: boot/stage2/bios/entry.asm
; -----------------------------------------------------------------------------

[bits 16]

STAGE3_LBA      equ 129
KERNEL_LBA      equ 193
PT_BASE         equ 0x70000
STACK_ADDR_16   equ 0x5000
STACK_ADDR_32   equ 0x6000
STACK_ADDR_64   equ 0x90000

extern stage2_bios_main
extern boot_drive
extern stage3_lba
extern kernel_lba

global _start
_start:
    cli
    mov al, 0xFF
    out 0x21, al
    out 0xA1, al

    mov [boot_drive], dl
    
    mov dword [stage3_lba], STAGE3_LBA
    mov dword [kernel_lba], KERNEL_LBA
    mov dword [stage3_lba + 4], 0
    mov dword [kernel_lba + 4], 0

    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, STACK_ADDR_16

    mov eax, gdt_start
    mov [gdt_ptr + 2], eax

    mov si, msg_stage2
    call print16

    call enable_a20
    jc .a20_failed

    ; Unreal Mode
    push ds
    push es
    lgdt [gdt_ptr]
    mov eax, cr0
    or al, 1
    mov cr0, eax
    mov bx, 0x10
    mov fs, bx
    and al, 0xFE
    mov cr0, eax
    pop es
    pop ds
    sti

    mov si, msg_checking_cpu
    call print16

    call check_cpu_features
    jc .cpu_unsupported

    mov si, msg_entering_pm
    call print16

    cli
    lidt [idt_ptr]
    lgdt [gdt_ptr]

    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp 0x08:protected_mode

.cpu_unsupported:
    mov si, msg_cpu_err
    call print16
    jmp halt_cpu

.a20_failed:
    mov si, msg_a20_err
    call print16
    jmp halt_cpu

; Real Mode Helpers
halt_cpu:
    cli
    hlt
    jmp halt_cpu

enable_a20:
    call a20_try_kbc
    jc a20_try_bios
    call a20_test
    jc a20_try_bios
    ret

a20_try_kbc:
    cli
    call a20_wait_cmd
    mov al, 0xAD
    out 0x64, al
    call a20_wait_cmd
    mov al, 0xD0
    out 0x64, al
    call a20_wait_data
    in al, 0x60
    push ax
    call a20_wait_cmd
    mov al, 0xD1
    out 0x64, al
    call a20_wait_cmd
    mov al, 0xDF
    out 0x60, al
    pop ax
    or al, 2
    push ax
    out 0x60, al
    call a20_wait_cmd
    mov al, 0xAE
    out 0x64, al
    pop ax
    sti
    ret

a20_wait_cmd:
    in al, 0x64
    test al, 2
    jnz a20_wait_cmd
    ret

a20_wait_data:
    in al, 0x64
    test al, 1
    jz a20_wait_data
    ret

a20_try_bios:
    in al, 0x92
    or al, 2
    and al, 0xFE
    out 0x92, al
    call a20_test
    ret

a20_test:
    pushf
    cli
    push ds
    push es
    xor ax, ax
    mov es, ax
    mov ax, 0xFFFF
    mov ds, ax
    mov di, 0x7DFE
    mov si, 0x7E0E
    mov ax, [es:di]
    push ax
    mov bx, [si]
    push bx
    mov word [es:di], 0xAA55
    mov word [si], 0x55AA
    mov ax, [es:di]
    mov bx, [si]
    pop bx
    mov [si], bx
    pop ax
    mov [es:di], ax
    pop es
    pop ds
    popf
    cmp ax, bx
    je .a20_disabled
    clc
    ret
.a20_disabled:
    stc
    ret

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

check_cpu_features:
    pushfd
    pop eax
    mov ecx, eax
    xor eax, 1 << 21
    push eax
    popfd
    pushfd
    pop eax
    push ecx
    popfd
    cmp eax, ecx
    je .no_long_mode
    mov eax, 0x80000000
    cpuid
    cmp eax, 0x80000001
    jb .no_long_mode
    mov eax, 0x80000001
    cpuid
    test edx, 1 << 29
    jz .no_long_mode
    clc
    ret
.no_long_mode:
    stc
    ret

; Data
msg_stage2:       db "S2: Start", 13, 10, 0
msg_entering_pm:  db "S2: Enter PM", 13, 10, 0
msg_checking_cpu: db "S2: Check CPU", 13, 10, 0
msg_cpu_err:      db "S2: CPU No LM", 13, 10, 0
msg_a20_err:      db "S2: A20 Fail", 13, 10, 0

; 32-bit Protected Mode
[bits 32]
protected_mode:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, STACK_ADDR_32

    mov dx, 0x3F8
    mov al, 'P'
    out dx, al

    call setup_paging

    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8)
    wrmsr

    mov eax, cr0
    or eax, (1 << 31)
    mov cr0, eax

    jmp 0x18:long_mode

setup_paging:
    mov edi, PT_BASE
    xor eax, eax
    mov ecx, 3072
    rep stosd

    mov edi, PT_BASE
    lea eax, [edi + 0x1000]
    or eax, 3
    mov dword [edi], eax
    mov dword [edi + 511*8], eax

    add edi, 0x1000
    lea eax, [edi + 0x1000]
    or eax, 3
    mov dword [edi], eax
    mov dword [edi + 510*8], eax

    add edi, 0x1000
    mov ecx, 512

    ; Entry 0: identity-map 0x0-0x1FFFFF -> 0x0-0x1FFFFF (for stage2 at 0x7E00)
    mov dword [edi], 0x83      ; 0x80 (PS) | 0x02 (RW) | 0x01 (Present), base = 0
    mov dword [edi + 4], 0
    add edi, 8

    ; Entry 1: identity-map 0x200000-0x3FFFFF -> 0x200000-0x3FFFFF
    mov dword [edi], (1 << 21) | 0x83  ; Base = 2MB
    mov dword [edi + 4], 0
    add edi, 8

    ; Entry 2: identity-map 0x400000-0x5FFFFF -> 0x400000-0x5FFFFF
    mov dword [edi], (2 << 21) | 0x83  ; Base = 4MB
    mov dword [edi + 4], 0
    add edi, 8

    ; Entry 3: identity-map 0x600000-0x7FFFFF -> 0x600000-0x7FFFFF
    mov dword [edi], (3 << 21) | 0x83  ; Base = 6MB
    mov dword [edi + 4], 0
    add edi, 8

    ; Remaining entries: start from 0x800000 (8MB)
    mov ebx, (4 << 21) | 0x83  ; Start at 8MB
    mov ecx, 508               ; 512 - 4 entries already set

.loop_pd:
    mov dword [edi], ebx
    mov dword [edi + 4], 0
    add ebx, 1 << 21           ; Add 2MB
    add edi, 8
    loop .loop_pd

    mov eax, PT_BASE
    mov cr3, eax

    mov eax, cr4
    or eax, (1 << 5)
    mov cr4, eax
    ret

; 64-bit Long Mode
[bits 64]
default rel

long_mode:
    mov ax, 0x20
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov rsp, STACK_ADDR_64

    call setup_idt64
    lidt [idt64_ptr]

    mov dx, 0x3F8
    mov al, 'L'
    out dx, al

    call stage2_bios_main

.halt64:
    cli
    hlt
    jmp .halt64

setup_idt64:
    mov rdi, idt64
    lea rsi, [isr_stub_table]
    mov ecx, 256
.loop_idt:
    lodsq
    mov word [rdi], ax
    mov word [rdi + 2], 0x18
    mov byte [rdi + 4], 0
    mov byte [rdi + 5], 0x8E
    shr rax, 16
    mov word [rdi + 6], ax
    shr rax, 16
    mov dword [rdi + 8], eax
    mov dword [rdi + 12], 0
    add rdi, 16
    dec ecx
    jnz .loop_idt
    ret

isr_common_halt:
    cli
.halt_loop:
    hlt
    jmp .halt_loop

%assign i 0
%rep 256
isr%+i:
    jmp isr_common_halt
%assign i i+1
%endrep

align 8
isr_stub_table:
%assign i 0
%rep 256
    dq isr%+i
%assign i i+1
%endrep

align 16
gdt_start:
    dq 0
    dq 0x00CF9A000000FFFF
    dq 0x00CF92000000FFFF
    dq 0x00AF9A000000FFFF
    dq 0x00AF92000000FFFF
gdt_end:
gdt_ptr:
    dw gdt_end - gdt_start - 1
    dd gdt_start

idt_ptr:
    dw 2047
    dd 0

; IDT 64-bit Storage
align 16
idt64:
    times 256 * 16 db 0

idt64_end:
global idt64_ptr
idt64_ptr:
    dw idt64_end - idt64 - 1
    dq idt64