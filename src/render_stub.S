/* parsec-zh text hooks (x86-64, Windows ABI).
 *
 * Both ImFont::RenderText and ImFont::CalcTextSizeA keep their text pointers as
 * stack arguments. For parsecd's skel DLLs (rsp == value at function entry):
 *     RenderText     text_begin = [rsp+0x38]   text_end = [rsp+0x40]
 *     CalcTextSizeA  text_begin = [rsp+0x30]   text_end = [rsp+0x38]
 * rcx is the ImFont* in both. The stubs ask the C helper for a translation and
 * for whether the (possibly translated) text needs the CJK font, then jump to
 * the MinHook-style trampoline which runs the original function body.
 */
    .intel_syntax noprefix
    .text

/* ---- shared prologue/epilogue -------------------------------------------
 * NOTE (x64 ABI): the callee's register "home"/shadow area is [rsp .. rsp+0x20)
 * at the call site. The xmm save area therefore starts at +0x20 so that a
 * callee spilling into its shadow space cannot clobber our saved xmm0/xmm1.
 * ------------------------------------------------------------------------ */
    .macro SAVEALL
    push r15
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    pushfq
    mov  r15, rsp                 /* entry rsp = r15 + 0x48 */
    sub  rsp, 0x120
    and  rsp, -16
    movups xmmword ptr [rsp + 0x20], xmm0
    movups xmmword ptr [rsp + 0x30], xmm1
    movups xmmword ptr [rsp + 0x40], xmm2
    movups xmmword ptr [rsp + 0x50], xmm3
    movups xmmword ptr [rsp + 0x60], xmm4
    movups xmmword ptr [rsp + 0x70], xmm5
    movups xmmword ptr [rsp + 0x80], xmm6
    movups xmmword ptr [rsp + 0x90], xmm7
    movups xmmword ptr [rsp + 0xa0], xmm8
    movups xmmword ptr [rsp + 0xb0], xmm9
    movups xmmword ptr [rsp + 0xc0], xmm10
    movups xmmword ptr [rsp + 0xd0], xmm11
    movups xmmword ptr [rsp + 0xe0], xmm12
    movups xmmword ptr [rsp + 0xf0], xmm13
    movups xmmword ptr [rsp + 0x100], xmm14
    movups xmmword ptr [rsp + 0x110], xmm15
    .endm

    .macro RESTOREALL
    movups xmm0,  xmmword ptr [rsp + 0x20]
    movups xmm1,  xmmword ptr [rsp + 0x30]
    movups xmm2,  xmmword ptr [rsp + 0x40]
    movups xmm3,  xmmword ptr [rsp + 0x50]
    movups xmm4,  xmmword ptr [rsp + 0x60]
    movups xmm5,  xmmword ptr [rsp + 0x70]
    movups xmm6,  xmmword ptr [rsp + 0x80]
    movups xmm7,  xmmword ptr [rsp + 0x90]
    movups xmm8,  xmmword ptr [rsp + 0xa0]
    movups xmm9,  xmmword ptr [rsp + 0xb0]
    movups xmm10, xmmword ptr [rsp + 0xc0]
    movups xmm11, xmmword ptr [rsp + 0xd0]
    movups xmm12, xmmword ptr [rsp + 0xe0]
    movups xmm13, xmmword ptr [rsp + 0xf0]
    movups xmm14, xmmword ptr [rsp + 0x100]
    movups xmm15, xmmword ptr [rsp + 0x110]
    mov  rsp, r15
    popfq
    pop  r11
    pop  r10
    pop  r9
    pop  r8
    pop  rdx
    pop  rcx
    pop  rax
    pop  r15
    .endm

/* (removed) naked_AddFont: the abandoned AddFont "replace FontData" path. It was
 * never installed, and it jumped through g_p_trampoline_font which is always
 * NULL. AddFont is now hooked with MinHook (detour_AddFont, merge mode).
 */

    .globl naked_RenderText
    .def  naked_RenderText; .scl 2; .type 32; .endef
naked_RenderText:
    SAVEALL
    /* probe: drawn size (entry xmm2, saved at rsp+0x40) vs font->FontSize (rcx+0x14) */
    movss xmm0, dword ptr [rsp + 0x40]
    movss xmm2, dword ptr [rcx + 0x14]
    movss dword ptr [rip + g_rt_last_size], xmm0
    movss dword ptr [rip + g_rt_last_fsize], xmm2
    subss xmm0, xmm2
    movss dword ptr [rip + g_rt_last_diff], xmm0
    comiss xmm0, dword ptr [rip + g_half]
    ja   .Lrtp_mis
    comiss xmm0, dword ptr [rip + g_nhalf]
    jb   .Lrtp_mis
    jmp  .Lrtp_done
.Lrtp_mis:
    inc  dword ptr [rip + g_rt_mismatch]
.Lrtp_done:
    mov  rcx, qword ptr [r15 + 0x48 + 0x38]     /* text_begin */
    mov  rdx, qword ptr [r15 + 0x48 + 0x40]     /* text_end   */
    call tr_helper
    test rax, rax
    je   1f
    cmp  dword ptr [rax + 16], 0                /* translated? */
    je   1f
    mov  r10, qword ptr [rax + 0]
    mov  qword ptr [r15 + 0x48 + 0x38], r10
    mov  r10, qword ptr [rax + 8]
    mov  qword ptr [r15 + 0x48 + 0x40], r10
1:
    /* The CJK glyphs are MERGED into the app's own font by the AddFont hook, so
       the font pointer (rcx) must stay as-is here. (Rewriting rcx before
       RESTOREALL would be useless anyway: RESTOREALL pops the saved rcx back
       over it.) */
    RESTOREALL
    jmp  qword ptr [rip + g_p_trampoline]

/* ---- ImFont::CalcTextSizeA --------------------------------------------- */
    .globl naked_CalcTextSize
    .def  naked_CalcTextSize; .scl 2; .type 32; .endef
naked_CalcTextSize:
    SAVEALL
    mov  rcx, qword ptr [r15 + 0x48 + 0x30]     /* text_begin */
    mov  rdx, qword ptr [r15 + 0x48 + 0x38]     /* text_end   */
    call tr_helper
    test rax, rax
    je   1f
    cmp  dword ptr [rax + 16], 0
    je   1f
    mov  r10, qword ptr [rax + 0]
    mov  qword ptr [r15 + 0x48 + 0x30], r10
    mov  r10, qword ptr [rax + 8]
    mov  qword ptr [r15 + 0x48 + 0x38], r10
1:
    /* Font pointer stays; CJK is merged into the app font (see render stub). */
    RESTOREALL
    jmp  qword ptr [rip + g_p_trampoline_cts]
