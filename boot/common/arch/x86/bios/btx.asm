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
; API: v86_init(workspace_base, workspace_size), v86int(), and the v86
; register struct are unchanged.
;

[BITS 32]

; =============================================================================
; Constants
; =============================================================================

; Low-memory workspace layout (all offsets are relative to workspace base).
REG_BUF_OFF         equ 0x000       ; Register buffer (52 bytes)
SAVED_GDTR_OFF      equ 0x040       ; Saved PM GDTR (6 bytes)
SAVED_IDTR_OFF      equ 0x048       ; Saved PM IDTR (6 bytes)
SAVED_ESP_OFF       equ 0x050       ; Saved PM ESP (4 bytes)
SAVED_SS_OFF        equ 0x054       ; Saved PM SS (4 bytes)
RM_IDTR_OFF         equ 0x090       ; Real-mode IDTR (6 bytes)
PM16_BRIDGE_OFF     equ 0x0C0       ; 16-bit PM->RM bridge destination
TRAMPOLINE_OFF      equ 0x100       ; Real-mode trampoline destination
RM_STACK_TOP_OFF    equ 0x0FF0      ; Temporary real-mode stack top
WORKSPACE_MIN_SIZE  equ 0x1000

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

; Register buffer offsets (at REG_BUF_OFF)
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

; Runtime-selected low-memory workspace metadata
ws_base:            dd 0
ws_seg:             dd 0
ws_reg_buf_ptr:     dd 0
ws_saved_gdtr_ptr:  dd 0
ws_saved_idtr_ptr:  dd 0
ws_saved_esp_ptr:   dd 0
ws_saved_ss_ptr:    dd 0
ws_rm_idtr_ptr:     dd 0
ws_pm16_ptr:        dd 0
ws_tramp_ptr:       dd 0

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
; Args (cdecl):
;   [ebp+8]  = workspace_base (physical, < 1MB, 16-byte aligned)
;   [ebp+12] = workspace_size
;
; Sets up the transition GDT and initializes runtime-selected workspace
; pointers for PM <-> RM transitions.
;
; Returns:
;   eax = 0 on success, -1 on failure
; -----------------------------------------------------------------------------
global v86_init
v86_init:
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi

    cld                             ; Ensure forward direction for string ops

    ; Validate workspace arguments.
    mov     eax, [ebp + 8]          ; workspace_base
    mov     edx, [ebp + 12]         ; workspace_size

    test    eax, 0xF                ; paragraph alignment
    jnz     .fail

    cmp     edx, WORKSPACE_MIN_SIZE
    jb      .fail

    lea     ecx, [eax + WORKSPACE_MIN_SIZE]
    cmp     ecx, eax                ; overflow check
    jb      .fail
    cmp     ecx, 0x000A0000         ; below VGA window
    ja      .fail

    ; Cache workspace metadata and pointers.
    mov     [ws_base], eax
    mov     ecx, eax
    shr     ecx, 4
    mov     [ws_seg], ecx

    lea     ecx, [eax + REG_BUF_OFF]
    mov     [ws_reg_buf_ptr], ecx
    lea     ecx, [eax + SAVED_GDTR_OFF]
    mov     [ws_saved_gdtr_ptr], ecx
    lea     ecx, [eax + SAVED_IDTR_OFF]
    mov     [ws_saved_idtr_ptr], ecx
    lea     ecx, [eax + SAVED_ESP_OFF]
    mov     [ws_saved_esp_ptr], ecx
    lea     ecx, [eax + SAVED_SS_OFF]
    mov     [ws_saved_ss_ptr], ecx
    lea     ecx, [eax + RM_IDTR_OFF]
    mov     [ws_rm_idtr_ptr], ecx
    lea     ecx, [eax + PM16_BRIDGE_OFF]
    mov     [ws_pm16_ptr], ecx
    lea     ecx, [eax + TRAMPOLINE_OFF]
    mov     [ws_tramp_ptr], ecx

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

    ; Entry 3 (0x18): 16-bit code - base=workspace, limit=0xFFFFF, byte gran
    ;
    ; GDT base encoding: bits 31:24 are implicitly zero because `and eax, 0xFF`
    ; discards them. This is correct because the workspace is required to be
    ; below 0xA0000 (< 1MB), well within the 16MB limit of this encoding.
    mov     ebx, [ws_base]
    mov     eax, ebx
    shl     eax, 16
    and     eax, 0xFFFF0000
    or      eax, 0x0000FFFF
    mov     dword [trans_gdt + 0x18], eax

    mov     eax, ebx
    shr     eax, 16
    and     eax, 0xFF
    or      eax, 0x000F9A00
    mov     dword [trans_gdt + 0x1C], eax

    ; Entry 4 (0x20): 16-bit data - base=workspace, limit=0xFFFFF, byte gran
    mov     eax, ebx
    shl     eax, 16
    and     eax, 0xFFFF0000
    or      eax, 0x0000FFFF
    mov     dword [trans_gdt + 0x20], eax

    mov     eax, ebx
    shr     eax, 16
    and     eax, 0xFF
    or      eax, 0x000F9200
    mov     dword [trans_gdt + 0x24], eax

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

    ; --- Write real-mode IDTR to workspace ---
    mov     edi, [ws_rm_idtr_ptr]
    mov     word [edi], 0x03FF
    mov     dword [edi + 2], 0x00000000

    ; --- Copy 16-bit PM bridge into workspace ---
    mov     esi, pm16_entry
    mov     edi, [ws_pm16_ptr]
    mov     ecx, pm16_entry_end - pm16_entry
    rep     movsb

    ; --- Copy trampoline into workspace ---
    mov     esi, rm_trampoline
    mov     edi, [ws_tramp_ptr]
    mov     ecx, rm_trampoline_end - rm_trampoline
    rep     movsb

    ; Patch PM16 RM jump segment with runtime workspace segment.
    mov     edi, [ws_pm16_ptr]
    mov     ax, [ws_seg]
    mov     [edi + (pm16_rm_jump - pm16_entry) + 3], ax

    xor     eax, eax
    jmp     .done

.fail:
    xor     eax, eax
    mov     [ws_base], eax
    mov     [ws_seg], eax
    mov     [ws_reg_buf_ptr], eax
    mov     [ws_saved_gdtr_ptr], eax
    mov     [ws_saved_idtr_ptr], eax
    mov     [ws_saved_esp_ptr], eax
    mov     [ws_saved_ss_ptr], eax
    mov     [ws_rm_idtr_ptr], eax
    mov     [ws_pm16_ptr], eax
    mov     [ws_tramp_ptr], eax
    mov     eax, -1

.done:
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

    ; v86_init() must run first.
    cmp     dword [ws_base], 0
    jne     .have_workspace

    ; Surface failure to callers via carry flag in v86.efl.
    mov     dword [v86 + V86_EFL], 1
    jmp     .return

.have_workspace:
    cli

    ; Save current GDT and IDT
    sgdt    [saved_gdtr]
    sidt    [saved_idtr]

    ; Save PM stack
    mov     [pm_esp], esp
    mov     [pm_ss], ss

    ; Copy PM state to workspace so trampoline can restore it
    mov     edi, [ws_saved_gdtr_ptr]
    mov     eax, [saved_gdtr]
    mov     [edi], eax
    mov     ax, [saved_gdtr + 4]
    mov     [edi + 4], ax

    mov     edi, [ws_saved_idtr_ptr]
    mov     eax, [saved_idtr]
    mov     [edi], eax
    mov     ax, [saved_idtr + 4]
    mov     [edi + 4], ax

    mov     edi, [ws_saved_esp_ptr]
    mov     eax, [pm_esp]
    mov     [edi], eax
    mov     edi, [ws_saved_ss_ptr]
    mov     eax, [pm_ss]
    mov     [edi], eax

    ; Copy v86 register fields into workspace register buffer.
    mov     edi, [ws_reg_buf_ptr]
    mov     eax, [v86 + V86_EAX]
    mov     [edi + BUF_EAX], eax
    mov     eax, [v86 + V86_ECX]
    mov     [edi + BUF_ECX], eax
    mov     eax, [v86 + V86_EDX]
    mov     [edi + BUF_EDX], eax
    mov     eax, [v86 + V86_EBX]
    mov     [edi + BUF_EBX], eax
    mov     eax, [v86 + V86_ESP]
    mov     [edi + BUF_ESP], eax
    mov     eax, [v86 + V86_EBP]
    mov     [edi + BUF_EBP], eax
    mov     eax, [v86 + V86_ESI]
    mov     [edi + BUF_ESI], eax
    mov     eax, [v86 + V86_EDI]
    mov     [edi + BUF_EDI], eax
    mov     eax, [v86 + V86_DS]
    mov     [edi + BUF_DS], eax
    mov     eax, [v86 + V86_ES]
    mov     [edi + BUF_ES], eax
    mov     eax, [v86 + V86_FS]
    mov     [edi + BUF_FS], eax
    mov     eax, [v86 + V86_GS]
    mov     [edi + BUF_GS], eax

    ; Re-copy bridge/trampoline into workspace.
    cld
    mov     esi, pm16_entry
    mov     edi, [ws_pm16_ptr]
    mov     ecx, pm16_entry_end - pm16_entry
    rep     movsb

    mov     esi, rm_trampoline
    mov     edi, [ws_tramp_ptr]
    mov     ecx, rm_trampoline_end - rm_trampoline
    rep     movsb

    ; Refresh RM IDTR (workspace may be clobbered by firmware).
    mov     edi, [ws_rm_idtr_ptr]
    mov     word [edi], 0x03FF
    mov     dword [edi + 2], 0x00000000

    ; Patch PM16 bridge jump segment with runtime workspace segment.
    mov     edi, [ws_pm16_ptr]
    mov     ax, [ws_seg]
    mov     [edi + (pm16_rm_jump - pm16_entry) + 3], ax

    ; Patch INT number in copied trampoline.
    mov     edi, [ws_tramp_ptr]
    mov     al, [v86 + V86_ADDR]
    mov     [edi + (rm_int_patch - rm_trampoline) + 1], al

    ; Load transition GDT
    lgdt    [trans_gdtr]

    ; Far jump to 16-bit bridge (descriptor base points to workspace).
    jmp     SEL_CODE16:PM16_BRIDGE_OFF

.return:
    ; Restore callee-saved registers and return
    popfd
    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret

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

    ; Far jump to real-mode trampoline in runtime-selected workspace.
    ; Segment is patched at runtime by v86_init()/v86int().
pm16_rm_jump:
    jmp     0x0000:TRAMPOLINE_OFF
pm16_entry_end:

; =============================================================================
; Real-mode trampoline (copied into workspace and refreshed each call)
;
; Runs in genuine real mode. Loads registers from workspace buffer,
; executes the BIOS interrupt, saves results, re-enters protected mode.
; =============================================================================
rm_trampoline:
    ; Set up real-mode segments and stack using workspace segment.
    push    cs
    pop     ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax
    mov     sp, RM_STACK_TOP_OFF

    ; Load real-mode IVT
    lidt    [RM_IDTR_OFF]

    ; Load GPRs from workspace register buffer.
    mov     ecx, [REG_BUF_OFF + BUF_ECX]
    mov     edx, [REG_BUF_OFF + BUF_EDX]
    mov     ebx, [REG_BUF_OFF + BUF_EBX]
    mov     ebp, [REG_BUF_OFF + BUF_EBP]
    mov     esi, [REG_BUF_OFF + BUF_ESI]
    mov     edi, [REG_BUF_OFF + BUF_EDI]

    ; Load segment registers (while DS=workspace segment for buffer access).
    mov     es, [REG_BUF_OFF + BUF_ES]
    mov     fs, [REG_BUF_OFF + BUF_FS]
    mov     gs, [REG_BUF_OFF + BUF_GS]

    ; Push target DS value.
    push    word [REG_BUF_OFF + BUF_DS]

    ; Load EAX last
    mov     eax, [REG_BUF_OFF + BUF_EAX]

    ; Load DS from stack
    pop     ds

    ; Execute BIOS interrupt with IRQs masked in this transition window.
    ; This avoids timer IRQ re-entry while PM/RM state is half-switched.
rm_int_patch:
    int     0x00                    ; Patched with actual INT number
    cli

    ; --- Save results ---
    ; MOV does not modify flags, so EFLAGS from BIOS call are preserved.
    ; CLI does not modify arithmetic flags (CF, ZF, SF, OF, PF).
    ;
    ; Save EAX and DS first (we need EAX as scratch and then restore DS
    ; to the workspace segment for buffer access).
    ; Use the stack (PUSH doesn't modify flags either).
    push    eax                     ; Save BIOS return EAX (4 bytes)
    push    ds                      ; Save BIOS return DS  (2 bytes)

    ; Now save EFLAGS (still pristine from BIOS call)
    pushfd                          ; Save EFLAGS (4 bytes)

    ; Set DS=workspace segment for buffer access (MOV doesn't modify flags)
    push    cs
    pop     ax
    mov     ds, ax

    ; Stack layout (SP grows down):
    ;   [SP+0]  = EFLAGS  (4 bytes, from pushfd)
    ;   [SP+4]  = DS      (2 bytes, from push ds)
    ;   [SP+6]  = EAX     (4 bytes, from push eax)

    ; Store EFLAGS from stack
    pop     dword [REG_BUF_OFF + BUF_EFL]    ; Pop 4 bytes (pushfd result)

    ; Store DS from stack (16-bit pop; upper 16 bits of dword slot are
    ; already zero from the v86int pre-copy of the C-set segment value)
    pop     word [REG_BUF_OFF + BUF_DS]      ; Pop 2 bytes

    ; Store EAX from stack
    pop     dword [REG_BUF_OFF + BUF_EAX]    ; Pop 4 bytes

    ; Store remaining GPRs (still have original BIOS return values)
    mov     [REG_BUF_OFF + BUF_ECX], ecx
    mov     [REG_BUF_OFF + BUF_EDX], edx
    mov     [REG_BUF_OFF + BUF_EBX], ebx
    mov     [REG_BUF_OFF + BUF_EBP], ebp
    mov     [REG_BUF_OFF + BUF_ESI], esi
    mov     [REG_BUF_OFF + BUF_EDI], edi

    ; Store segment registers (16-bit stores; upper halves already zero)
    mov     [REG_BUF_OFF + BUF_ES], es
    mov     [REG_BUF_OFF + BUF_FS], fs
    mov     [REG_BUF_OFF + BUF_GS], gs

    ; Re-enter protected mode
    lgdt    [SAVED_GDTR_OFF]        ; Restore PM GDTR
    ; Preload PM IDT before setting PE to avoid a tiny window where
    ; PE=1 but IDT still points at the real-mode IVT.
    lidt    [SAVED_IDTR_OFF]

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
    cli
    cld

    ; Reload 32-bit data segments
    mov     ax, SEL_DATA32
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    ; Restore PM stack.
    ; Preload both SS and ESP values so that `mov esp` is the very next
    ; instruction after `mov ss`, staying within the 1-instruction IRQ
    ; inhibition window. (PM IDTR was already restored by the trampoline
    ; at SAVED_IDTR_OFF before re-entering protected mode.)
    mov     ebx, [ws_saved_esp_ptr]
    mov     ebx, [ebx]             ; preload ESP value
    mov     eax, [ws_saved_ss_ptr]
    mov     ax, [eax]              ; preload SS value
    mov     ss, ax                 ; SS updated — next insn is IRQ-inhibited
    mov     esp, ebx               ; ESP set within inhibition window

    ; Copy register buffer back to v86 struct
    mov     esi, [ws_reg_buf_ptr]
    mov     eax, [esi + BUF_EAX]
    mov     [v86 + V86_EAX], eax
    mov     eax, [esi + BUF_ECX]
    mov     [v86 + V86_ECX], eax
    mov     eax, [esi + BUF_EDX]
    mov     [v86 + V86_EDX], eax
    mov     eax, [esi + BUF_EBX]
    mov     [v86 + V86_EBX], eax
    mov     eax, [esi + BUF_EBP]
    mov     [v86 + V86_EBP], eax
    mov     eax, [esi + BUF_ESI]
    mov     [v86 + V86_ESI], eax
    mov     eax, [esi + BUF_EDI]
    mov     [v86 + V86_EDI], eax

    mov     eax, [esi + BUF_DS]
    mov     [v86 + V86_DS], eax
    mov     eax, [esi + BUF_ES]
    mov     [v86 + V86_ES], eax
    mov     eax, [esi + BUF_FS]
    mov     [v86 + V86_FS], eax
    mov     eax, [esi + BUF_GS]
    mov     [v86 + V86_GS], eax

    mov     eax, [esi + BUF_EFL]
    mov     [v86 + V86_EFL], eax

    ; Restore callee-saved registers and return
    popfd
    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret
