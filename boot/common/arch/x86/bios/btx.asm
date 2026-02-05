; SPDX-License-Identifier: GPL-2.0-only
;
; SaltyOS Bootloader - BTX (Real-Mode BIOS Callback Support)
;
; Provides BIOS interrupt services from 32-bit protected mode by
; transitioning PM -> Real Mode -> PM. This replaces the former V86
; approach which was incompatible with SeaBIOS's AHCI driver (AHCI
; needs 32-bit MMIO via call32/SMM which corrupts V86 state).
;
; The BIOS handler runs in genuine real mode, so SeaBIOS can freely
; use call32(), SMM, or whatever it needs. This is the same pattern
; used by GRUB and other production bootloaders.
;
; API: v86_init(), v86int(), and the v86 register struct are unchanged.
;

[BITS 32]

; =============================================================================
; Constants
; =============================================================================

; Low-memory layout for PM <-> RM communication
REG_BUF         equ 0x0500      ; Register buffer (52 bytes)
SAVED_GDTR      equ 0x0540      ; Saved PM GDTR (6 bytes)
SAVED_IDTR      equ 0x0548      ; Saved PM IDTR (6 bytes)
SAVED_ESP       equ 0x0550      ; Saved PM ESP (4 bytes)
SAVED_SS        equ 0x0554      ; Saved PM SS (4 bytes)
RM_IDTR         equ 0x0590      ; Real-mode IDTR (6 bytes)
TRAMPOLINE      equ 0x0600      ; Real-mode trampoline destination

; GDT selectors (transition GDT)
SEL_CODE32      equ 0x08        ; 32-bit code, flat 4GB, DPL=0
SEL_DATA32      equ 0x10        ; 32-bit data, flat 4GB, DPL=0
SEL_CODE16      equ 0x18        ; 16-bit code, base=0, limit=1MB, DPL=0
SEL_DATA16      equ 0x20        ; 16-bit data, base=0, limit=1MB, DPL=0

; V86 structure offsets (must match v86.h / struct V86Regs)
V86_CTL         equ 0x00
V86_ADDR        equ 0x04
V86_EAX         equ 0x08
V86_ECX         equ 0x0C
V86_EDX         equ 0x10
V86_EBX         equ 0x14
V86_ESP         equ 0x18
V86_EBP         equ 0x1C
V86_ESI         equ 0x20
V86_EDI         equ 0x24
V86_DS          equ 0x28
V86_ES          equ 0x2C
V86_FS          equ 0x30
V86_GS          equ 0x34
V86_EFL         equ 0x38

; Register buffer offsets (at REG_BUF = 0x500)
BUF_EAX         equ 0x00
BUF_ECX         equ 0x04
BUF_EDX         equ 0x08
BUF_EBX         equ 0x0C
BUF_ESP         equ 0x10
BUF_EBP         equ 0x14
BUF_ESI         equ 0x18
BUF_EDI         equ 0x1C
BUF_DS          equ 0x20
BUF_ES          equ 0x24
BUF_FS          equ 0x28
BUF_GS          equ 0x2C
BUF_EFL         equ 0x30

; =============================================================================
; Data Section
; =============================================================================

section .data

; Global V86 register structure (exported to C)
global v86
v86:
    dd 0                    ; ctl
    dd 0                    ; addr
    dd 0                    ; eax
    dd 0                    ; ecx
    dd 0                    ; edx
    dd 0                    ; ebx
    dd 0                    ; esp
    dd 0                    ; ebp
    dd 0                    ; esi
    dd 0                    ; edi
    dd 0                    ; ds
    dd 0                    ; es
    dd 0                    ; fs
    dd 0                    ; gs
    dd 0                    ; efl

; Saved protected mode state
pm_esp:         dd 0
pm_ss:          dd 0

; =============================================================================
; BSS Section
; =============================================================================

section .bss nobits

; Transition GDT (5 entries: null, code32, data32, code16, data16)
alignb 16
trans_gdt:      resb 8 * 5
trans_gdt_end:

; GDT/IDT pointers
trans_gdtr:     resb 6
saved_gdtr:     resb 6
saved_idtr:     resb 6

; =============================================================================
; Text Section
; =============================================================================

section .text

; -----------------------------------------------------------------------------
; v86_init - Initialize BTX subsystem for real-mode BIOS callbacks
;
; Sets up the transition GDT (with 16-bit entries), writes the real-mode
; IDTR to low memory, and copies the trampoline code to 0x0600.
; -----------------------------------------------------------------------------
global v86_init
v86_init:
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi

    ; --- Set up transition GDT ---

    ; Clear GDT
    mov     edi, trans_gdt
    mov     ecx, 8 * 5
    xor     al, al
    rep     stosb

    ; Entry 0: Null (already zeroed)

    ; Entry 1 (0x08): 32-bit code - flat 4GB, DPL=0
    mov     dword [trans_gdt + 0x08], 0x0000FFFF
    mov     dword [trans_gdt + 0x0C], 0x00CF9A00

    ; Entry 2 (0x10): 32-bit data - flat 4GB, DPL=0
    mov     dword [trans_gdt + 0x10], 0x0000FFFF
    mov     dword [trans_gdt + 0x14], 0x00CF9200

    ; Entry 3 (0x18): 16-bit code - base=0, limit=0xFFFFF, byte gran, DPL=0
    mov     dword [trans_gdt + 0x18], 0x0000FFFF
    mov     dword [trans_gdt + 0x1C], 0x000F9A00

    ; Entry 4 (0x20): 16-bit data - base=0, limit=0xFFFFF, byte gran, DPL=0
    mov     dword [trans_gdt + 0x20], 0x0000FFFF
    mov     dword [trans_gdt + 0x24], 0x000F9200

    ; Load transition GDT
    mov     word [trans_gdtr], trans_gdt_end - trans_gdt - 1
    mov     dword [trans_gdtr + 2], trans_gdt
    lgdt    [trans_gdtr]

    ; Reload CS via far jump
    jmp     SEL_CODE32:.reload_cs
.reload_cs:

    ; Reload data segments
    mov     ax, SEL_DATA32
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    ; --- Write real-mode IDTR to low memory (0x0590) ---
    mov     word [RM_IDTR], 0x03FF
    mov     dword [RM_IDTR + 2], 0x00000000

    ; --- Copy trampoline to 0x0600 ---
    mov     esi, rm_trampoline
    mov     edi, TRAMPOLINE
    mov     ecx, rm_trampoline_end - rm_trampoline
    rep     movsb

    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret

; -----------------------------------------------------------------------------
; v86int - Execute BIOS interrupt via real-mode transition
;
; Reads parameters from global 'v86' structure, transitions to real mode,
; executes the interrupt, and stores results back.
; -----------------------------------------------------------------------------
global v86int
v86int:
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi
    pushfd

    cli

    ; Save current GDT and IDT
    sgdt    [saved_gdtr]
    sidt    [saved_idtr]

    ; Save PM stack
    mov     [pm_esp], esp
    mov     [pm_ss], ss

    ; Copy PM state to low memory so trampoline can restore it
    mov     eax, [saved_gdtr]
    mov     [SAVED_GDTR], eax
    mov     ax, [saved_gdtr + 4]
    mov     [SAVED_GDTR + 4], ax

    mov     eax, [saved_idtr]
    mov     [SAVED_IDTR], eax
    mov     ax, [saved_idtr + 4]
    mov     [SAVED_IDTR + 4], ax

    mov     eax, [pm_esp]
    mov     [SAVED_ESP], eax
    mov     eax, [pm_ss]
    mov     [SAVED_SS], eax

    ; Copy v86 register fields to low-memory buffer at 0x500
    mov     eax, [v86 + V86_EAX]
    mov     [REG_BUF + BUF_EAX], eax
    mov     eax, [v86 + V86_ECX]
    mov     [REG_BUF + BUF_ECX], eax
    mov     eax, [v86 + V86_EDX]
    mov     [REG_BUF + BUF_EDX], eax
    mov     eax, [v86 + V86_EBX]
    mov     [REG_BUF + BUF_EBX], eax
    mov     eax, [v86 + V86_ESP]
    mov     [REG_BUF + BUF_ESP], eax
    mov     eax, [v86 + V86_EBP]
    mov     [REG_BUF + BUF_EBP], eax
    mov     eax, [v86 + V86_ESI]
    mov     [REG_BUF + BUF_ESI], eax
    mov     eax, [v86 + V86_EDI]
    mov     [REG_BUF + BUF_EDI], eax

    mov     eax, [v86 + V86_DS]
    mov     [REG_BUF + BUF_DS], eax
    mov     eax, [v86 + V86_ES]
    mov     [REG_BUF + BUF_ES], eax
    mov     eax, [v86 + V86_FS]
    mov     [REG_BUF + BUF_FS], eax
    mov     eax, [v86 + V86_GS]
    mov     [REG_BUF + BUF_GS], eax

    ; Patch INT number in trampoline (at the copied location in low memory)
    mov     al, [v86 + V86_ADDR]
    mov     [TRAMPOLINE + (rm_int_patch - rm_trampoline) + 1], al

    ; Load transition GDT
    lgdt    [trans_gdtr]

    ; Far jump to 16-bit protected mode code
    jmp     SEL_CODE16:pm16_entry

; -----------------------------------------------------------------------------
; 16-bit protected mode bridge
; Switches from 32-bit PM to 16-bit PM, then disables PE to enter real mode.
; -----------------------------------------------------------------------------
[BITS 16]
pm16_entry:
    ; Load 16-bit data segments
    mov     ax, SEL_DATA16
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    ; Disable protected mode (clear CR0.PE)
    mov     eax, cr0
    and     al, 0xFE
    mov     cr0, eax

    ; Far jump to real-mode trampoline at 0x0600
    jmp     0x0000:TRAMPOLINE

; =============================================================================
; Real-mode trampoline (copied to 0x0600 at init time)
;
; Runs in genuine real mode. Loads registers from buffer at 0x500,
; executes the BIOS interrupt, saves results, re-enters protected mode.
; =============================================================================
rm_trampoline:
    ; Set up real-mode segments and stack
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax
    mov     sp, 0x7C00

    ; Load real-mode IVT
    lidt    [0x0590]

    ; Load GPRs from register buffer at 0x500
    mov     ecx, [0x0500 + BUF_ECX]
    mov     edx, [0x0500 + BUF_EDX]
    mov     ebx, [0x0500 + BUF_EBX]
    mov     ebp, [0x0500 + BUF_EBP]
    mov     esi, [0x0500 + BUF_ESI]
    mov     edi, [0x0500 + BUF_EDI]

    ; Load segment registers (while DS=0 for buffer access)
    mov     es, [0x0500 + BUF_ES]
    mov     fs, [0x0500 + BUF_FS]
    mov     gs, [0x0500 + BUF_GS]

    ; Push target DS value (while DS still =0)
    push    word [0x0500 + BUF_DS]

    ; Load EAX last
    mov     eax, [0x0500 + BUF_EAX]

    ; Load DS from stack
    pop     ds

    ; Execute BIOS interrupt
    sti
rm_int_patch:
    int     0x00                    ; Patched with actual INT number
    cli

    ; --- Save results ---
    ; MOV does not modify flags, so EFLAGS from BIOS call are preserved.
    ; CLI does not modify arithmetic flags (CF, ZF, SF, OF, PF).
    ;
    ; Save EAX and DS first (we need EAX as scratch and DS=0 for buffer).
    ; Use the stack (PUSH doesn't modify flags either).
    push    eax                     ; Save BIOS return EAX (4 bytes)
    push    ds                      ; Save BIOS return DS  (2 bytes)

    ; Now save EFLAGS (still pristine from BIOS call)
    pushfd                          ; Save EFLAGS (4 bytes)

    ; Set DS=0 for buffer access (MOV doesn't modify flags)
    mov     ax, 0
    mov     ds, ax

    ; Stack layout (SP grows down):
    ;   [SP+0]  = EFLAGS  (4 bytes, from pushfd)
    ;   [SP+4]  = DS      (2 bytes, from push ds)
    ;   [SP+6]  = EAX     (4 bytes, from push eax)

    ; Store EFLAGS from stack
    pop     dword [0x0500 + BUF_EFL]    ; Pop 4 bytes (pushfd result)

    ; Store DS from stack (16-bit pop; upper 16 bits of dword slot are
    ; already zero from the v86int pre-copy of the C-set segment value)
    pop     word [0x0500 + BUF_DS]      ; Pop 2 bytes

    ; Store EAX from stack
    pop     dword [0x0500 + BUF_EAX]    ; Pop 4 bytes

    ; Store remaining GPRs (still have original BIOS return values)
    mov     [0x0500 + BUF_ECX], ecx
    mov     [0x0500 + BUF_EDX], edx
    mov     [0x0500 + BUF_EBX], ebx
    mov     [0x0500 + BUF_EBP], ebp
    mov     [0x0500 + BUF_ESI], esi
    mov     [0x0500 + BUF_EDI], edi

    ; Store segment registers (16-bit stores; upper halves already zero)
    mov     [0x0500 + BUF_ES], es
    mov     [0x0500 + BUF_FS], fs
    mov     [0x0500 + BUF_GS], gs

    ; Re-enter protected mode
    lgdt    [0x0540]                ; Restore PM GDTR

    mov     eax, cr0
    or      al, 1
    mov     cr0, eax                ; Enable PE

    ; Far jump to 32-bit PM (manual encoding for 32-bit offset in 16-bit mode)
    db      0x66, 0xEA
    dd      pm32_return             ; 32-bit absolute address
    dw      SEL_CODE32              ; Selector 0x08
rm_trampoline_end:

; =============================================================================
; 32-bit PM return point
; =============================================================================
[BITS 32]
pm32_return:
    ; Reload 32-bit data segments
    mov     ax, SEL_DATA32
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ; Restore IDTR
    lidt    [SAVED_IDTR]

    ; Restore PM stack
    mov     ss, [SAVED_SS]
    mov     esp, [SAVED_ESP]

    ; Copy register buffer back to v86 struct
    mov     eax, [REG_BUF + BUF_EAX]
    mov     [v86 + V86_EAX], eax
    mov     eax, [REG_BUF + BUF_ECX]
    mov     [v86 + V86_ECX], eax
    mov     eax, [REG_BUF + BUF_EDX]
    mov     [v86 + V86_EDX], eax
    mov     eax, [REG_BUF + BUF_EBX]
    mov     [v86 + V86_EBX], eax
    mov     eax, [REG_BUF + BUF_EBP]
    mov     [v86 + V86_EBP], eax
    mov     eax, [REG_BUF + BUF_ESI]
    mov     [v86 + V86_ESI], eax
    mov     eax, [REG_BUF + BUF_EDI]
    mov     [v86 + V86_EDI], eax

    mov     eax, [REG_BUF + BUF_DS]
    mov     [v86 + V86_DS], eax
    mov     eax, [REG_BUF + BUF_ES]
    mov     [v86 + V86_ES], eax
    mov     eax, [REG_BUF + BUF_FS]
    mov     [v86 + V86_FS], eax
    mov     eax, [REG_BUF + BUF_GS]
    mov     [v86 + V86_GS], eax

    mov     eax, [REG_BUF + BUF_EFL]
    mov     [v86 + V86_EFL], eax

    ; Restore callee-saved registers and return
    popfd
    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret
