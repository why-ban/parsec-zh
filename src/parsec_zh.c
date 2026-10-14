// parsec-zh: runtime Chinese localization injector for Parsec (parsecd-150-104a.dll)
// Strategy:
//   * Hook ImFontAtlas::AddFont  -> merge a CJK font (system) into every text font so the
//     existing fonts can draw Chinese (no metric changes, no font switching needed).
//   * Hook ImGui::CalcTextSize   -> translate text so measurement matches drawing.
//   * Hook ImFont::RenderText    -> translate text so drawn labels are Chinese.
// Nothing on disk is modified; the signed Parsec binaries are left untouched.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

/* ---- suspend every other thread while patching (avoid racing a concurrent call) ---- */
static void res_threads(HANDLE* in, int n);
/* Open with control access so we can also relocate a thread's RIP that points
 * inside the bytes we are about to overwrite (see reloc_thread_ips). */
static int susp_threads(HANDLE* out, int cap) {
    int n = 0, overflow = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te; te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == tid) continue;
            HANDLE h = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                  FALSE, te.th32ThreadID);
            if (!h) continue;
            if (SuspendThread(h) == (DWORD)-1) { CloseHandle(h); continue; }
            if (n < cap) out[n++] = h;
            else { ResumeThread(h); CloseHandle(h); overflow = 1; }  /* never leave it suspended */
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (overflow) { res_threads(out, n); return -1; }   /* caller must abort */
    return n;
}

static void res_threads(HANDLE* in, int n) {
    for (int i = 0; i < n; i++) { ResumeThread(in[i]); CloseHandle(in[i]); }
}

/* If a suspended thread is currently executing inside [target, target+copylen),
 * retarget its RIP to the equivalent place in the trampoline before we resume.
 * Without this the thread could resume in the middle of the rewritten bytes. */
static void reloc_thread_ips(HANDLE* th, int n, void* target, int copylen, void* tramp) {
    DWORD64 t = (DWORD64)target;
    for (int i = 0; i < n; i++) {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(th[i], &ctx)) continue;
        if (ctx.Rip >= t && ctx.Rip < t + (DWORD64)copylen) {
            ctx.Rip = (DWORD64)tramp + (ctx.Rip - t);
            SetThreadContext(th[i], &ctx);
        }
    }
}
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

static void report(const char* msg);

#include "MinHook.h"
#include "hde64.h"
#include "translations.h"

// ---------------------------------------------------------------------------
// Runtime function discovery (version independent).
//
// The Parsec loader keeps changing its parsecd-<ver>.dll, so hard-coded RVAs
// go stale. Instead we locate the ImGui entry points through stable anchor
// strings and the PE exception directory:
//   * AddFont     -> assert string "font_cfg->FontData != 0 && ..."
//   * AddText     -> assert string "font->ContainerAtlas->TexID == ..."
//   * RenderText  -> the call inside AddText whose target starts mov rax,rsp
//   * CalcTextSize-> unique prologue 40 53 48 83 EC 40 4C 8B 15 (push rbx; sub rsp,40h; mov r10,[rip+x])
// ---------------------------------------------------------------------------
typedef struct { unsigned char* p; size_t n; } Blob;

static int get_section(unsigned char* base, const char* name, Blob* out) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER* sh = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sh++) {
        char nm[9]; memcpy(nm, sh->Name, 8); nm[8] = 0;
        if (strcmp(nm, name) == 0) {
            out->p = base + sh->VirtualAddress;
            out->n = sh->Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

static unsigned char* find_wide(Blob* rd, Blob* dt, const wchar_t* s) {
    size_t len = wcslen(s) * 2;
    Blob* blobs[2] = { rd, dt };
    for (int b = 0; b < 2; b++) {
        Blob* bl = blobs[b];
        if (!bl->p) continue;
        for (size_t i = 0; i + len <= bl->n; i += 2) {
            if (memcmp(bl->p + i, s, len) == 0) return bl->p + i;
        }
    }
    return NULL;
}

static unsigned char* find_ref(Blob* text, unsigned char* target) {
    for (size_t i = 0; i + 7 <= text->n; i++) {
        unsigned char b0 = text->p[i], b1 = text->p[i+1], b2 = text->p[i+2];
        if ((b0 == 0x48 || b0 == 0x4C) && (b1 == 0x8D || b1 == 0x8B) && (b2 & 0xC7) == 0x05) {
            int32_t disp = *(int32_t*)(text->p + i + 3);
            if (text->p + i + 7 + disp == target) return text->p + i;
        }
    }
    return NULL;
}

// .pdata holds RUNTIME_FUNCTION{ begin_rva, end_rva, unwind_rva }
static unsigned char* func_start(Blob* pdata, unsigned char* base, unsigned char* addr) {
    size_t count = pdata->n / 12;
    unsigned char* best = NULL;
    for (size_t i = 0; i < count; i++) {
        uint32_t b = *(uint32_t*)(pdata->p + i*12);
        uint32_t e = *(uint32_t*)(pdata->p + i*12 + 4);
        if (!b && !e) continue;
        unsigned char* s = base + b;
        unsigned char* en = base + e;
        if (s <= addr && addr < en) return s;
        if (s <= addr) best = s;   // fallback: nearest preceding
    }
    return best;
}

// --- split-function handling -------------------------------------------------
// MSVC splits some functions into several *contiguous* .pdata chunks that simply
// fall through into each other (UNWIND_INFO chaining). An anchor string usually
// lives in a later chunk, so func_start() returns a mid-function address and
// hooking there corrupts the prologue. Walk back through the contiguous chunks
// until we reach an address that is the actual target of a `call`/`jmp rel32`
// (the real entry point).
static Blob g_text_blob = {0};
static Blob g_pdata_blob = {0};

static int is_direct_target(unsigned char* t) {
    for (size_t i = 0; i + 5 <= g_text_blob.n; i++) {
        unsigned char b = g_text_blob.p[i];
        if (b == 0xE8 || b == 0xE9) {
            int32_t rel = *(int32_t*)(g_text_blob.p + i + 1);
            if (g_text_blob.p + i + 5 + rel == t) return 1;
        }
    }
    return 0;
}

static unsigned char* real_entry(Blob* pdata, unsigned char* base, unsigned char* frag) {
    unsigned char* cur = frag;
    for (int guard = 0; guard < 64 && cur; guard++) {
        if (is_direct_target(cur)) return cur;
        unsigned char* prev = NULL;
        size_t count = pdata->n / 12;
        for (size_t i = 0; i < count; i++) {
            uint32_t b = *(uint32_t*)(pdata->p + i*12);
            uint32_t e = *(uint32_t*)(pdata->p + i*12 + 4);
            if (!b && !e) continue;
            if (base + e == cur) { prev = base + b; break; }
        }
        if (!prev || prev >= cur) break;
        cur = prev;
    }
    return cur;
}

static unsigned char* g_f_addfont = NULL;
static unsigned char* g_f_rendertext = NULL;
static unsigned char* g_f_calctextsize = NULL;
static unsigned char* g_f_build = NULL;   // ImFontAtlasBuildWithStbTruetype

static void discover_functions(unsigned char* base) {
    Blob text = {0}, rdata = {0}, data = {0}, pdata = {0};
    g_f_addfont = g_f_rendertext = g_f_calctextsize = NULL;   // never reuse a stale pointer
    g_f_build = NULL;
    get_section(base, ".text", &text);
    get_section(base, ".rdata", &rdata);
    get_section(base, ".data", &data);
    get_section(base, ".pdata", &pdata);
    g_text_blob = text;
    g_pdata_blob = pdata;

    // AddFont
    unsigned char* s1 = find_wide(&rdata, &data, L"font_cfg->FontData != 0 && font_cfg->FontDataSize > 0");
    if (s1) {
        unsigned char* r = find_ref(&text, s1);
        if (r) {
            unsigned char* frag = func_start(&pdata, base, r);
            g_f_addfont = real_entry(&pdata, base, frag);   // resolve split-function entry
        }
    }

    // AddText -> RenderText
    unsigned char* s2 = find_wide(&rdata, &data, L"font->ContainerAtlas->TexID == _TextureIdStack.back()");
    if (s2) {
        unsigned char* r = find_ref(&text, s2);
        unsigned char* addtext = r ? func_start(&pdata, base, r) : NULL;
        unsigned char* addtext_end = NULL;
        if (addtext) {
            // end of AddText = end of the .pdata range that contains it
            size_t count = pdata.n / 12;
            for (size_t i = 0; i < count; i++) {
                uint32_t b = *(uint32_t*)(pdata.p + i*12);
                uint32_t e = *(uint32_t*)(pdata.p + i*12 + 4);
                unsigned char* s = base + b;
                unsigned char* en = base + e;
                if (s <= addtext && addtext < en) { addtext_end = en; break; }
            }
            // Bound the scan even when func_start() fell back to "nearest
            // preceding" (addtext outside every range): never walk past the end
            // of the mapped .text section, that would fault at install time.
            {
                unsigned char* hard_end = text.p + text.n;
                if (!addtext_end || addtext_end > hard_end) addtext_end = hard_end;
            }
            for (unsigned char* p = addtext; p + 10 < addtext_end; p++) {
                if (*p == 0xE8) {
                    int32_t rel = *(int32_t*)(p + 1);
                    unsigned char* t = p + 5 + rel;
                    if (t >= text.p && t + 7 <= text.p + text.n &&
                        t[0]==0x48 && t[1]==0x8B && t[2]==0xC4 && t[3]==0x48 && t[4]==0x89 && t[5]==0x50 && t[6]==0x10) {
                        g_f_rendertext = t;
                        break;
                    }
                }
            }
        }
    }

    // ImFont::CalcTextSizeA (unique prologue: mov rax,rsp; push rbx; push rsi; sub rsp,98h)
    static const unsigned char pat[8] = {0x48,0x8B,0xC4,0x53,0x56,0x48,0x81,0xEC};
    for (size_t i = 0; i + 12 <= text.n; i++) {
        if (memcmp(text.p + i, pat, 8) == 0 && text.p[i+8] == 0x98 && text.p[i+9] == 0x00 &&
            text.p[i+10] == 0x00 && text.p[i+11] == 0x00) {
            unsigned char* cand = text.p + i;
            unsigned char* f = func_start(&pdata, base, cand);
            if (f == cand) { g_f_calctextsize = f; break; }
        }
    }

    // ImFontAtlasBuildWithStbTruetype: unique prologue
    //   4C 8B DC 55 53 48 8D AB 38 FE FF FF 48 81 EC B8 02 00 00
    static const unsigned char bpat[20] = {0x4C,0x8B,0xDC,0x55,0x53,0x48,0x8D,0xAB,0x38,0xFE,0xFF,0xFF,0x48,0x81,0xEC,0xB8,0x02,0x00,0x00};
    for (size_t i = 0; i + 19 <= text.n; i++) {
        if (memcmp(text.p + i, bpat, 19) == 0) { g_f_build = text.p + i; break; }
    }
}


// ImFontConfig (ImGui 1.73, x64) field offsets
#define IMFC_FontData            0x00
#define IMFC_FontDataSize        0x08
#define IMFC_FontDataOwned       0x0C
#define IMFC_FontNo              0x10
#define IMFC_SizePixels          0x14
#define IMFC_OversampleH         0x18
#define IMFC_OversampleV         0x1C
#define IMFC_PixelSnapH          0x20
#define IMFC_GlyphExtraSpacing   0x24
#define IMFC_GlyphOffset         0x2C
#define IMFC_GlyphRanges         0x38
#define IMFC_GlyphMinAdvanceX    0x40
#define IMFC_GlyphMaxAdvanceX    0x44
#define IMFC_MergeMode           0x48
#define IMFC_RasterizerFlags     0x4C
#define IMFC_RasterizerMultiply  0x50
#define IMFC_EllipsisChar        0x54
#define IMFC_Name                0x56
#define IMFC_DstFont             0x80
#define IMFC_SIZE                0x88

static HMODULE         g_target = NULL;

// Referenced by the assembly RenderText stub (render_stub.S).
void* g_p_trampoline = NULL;
void* g_p_trampoline_cts = NULL;
extern unsigned char g_cfg_enable;
extern void* g_cjk_data;
extern int   g_cjk_size;
volatile int  g_cfg_hits = 0;
volatile int  g_cfg_patched = 0;
volatile unsigned g_t_attach = 0;
volatile unsigned g_t_install_start = 0;
volatile unsigned g_t_ldr_hook = 0;
volatile unsigned g_t_target_hook = 0;
volatile unsigned g_t_first_af = 0;
// Snapshots of the (distinct) font configs we substituted, for diagnostics.
typedef struct { float size; float rmult; unsigned char oh, ov, snap, owned; } CfgSnap;
CfgSnap g_snaps[24];
volatile int g_snap_n = 0;
// RenderText probe: compare the drawn size (entry xmm2) with font->FontSize
// (font+0x14). |diff| > 0.5 means the atlas glyph was rasterized at a different
// pixel size than it is drawn at -> blur. Constants are referenced from asm.
float g_half = 0.5f;
float g_nhalf = -0.5f;
volatile int   g_rt_mismatch = 0;
volatile float g_rt_last_diff = 0.0f;
volatile float g_rt_last_size = 0.0f;
volatile float g_rt_last_fsize = 0.0f;
// Set once from a dev flag at install time (never read inside the AddFont hook).
int g_osv2 = 0;
// Developer switches are DISABLED unless the process environment explicitly opts
// in (PARSEC_ZH_DEV=1). This keeps the shipped DLL from honouring stray files.
int g_dev = 0;
// Gates high-volume / user-data-bearing diagnostics (per-draw TR/RT samples, the
// MISS collector, periodic heartbeats). OFF in a normal install so we neither
// bloat the log nor write the user's host names / Peer IDs to disk; turn on with
// PARSEC_ZH_VERBOSE=1 (or PARSEC_ZH_DEV=1) when diagnosing.
int g_verbose = 0;
static int dev_flag(const char* name) {
    if (!g_dev) return 0;
    // Developer flags, if any, live next to the injected DLL -- never a hard-coded
    // build path (this repository is public, so it must not leak the author's tree).
    HMODULE self = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&dev_flag, &self);
    char p[MAX_PATH];
    if (!GetModuleFileNameA(self, p, MAX_PATH)) return 0;
    char* slash = strrchr(p, '\\');
    if (slash) slash[1] = 0; else p[0] = 0;
    size_t base = strlen(p);
    _snprintf(p + base, MAX_PATH - base, "%s", name);
    p[MAX_PATH - 1] = 0;
    return GetFileAttributesA(p) != INVALID_FILE_ATTRIBUTES;
}
static int    g_creation_hooks_removed = 0;

static char  g_dllpath[MAX_PATH] = {0};
// Kept open for the process lifetime so a parent/watcher can cheaply test
// "is this process already injected?" by the existence of its ready event.
static HANDLE g_ready_ev = NULL;

// The three process-creation hooks (CreateProcessW -> CreateProcessInternalW ->
// NtCreateUserProcess) all fire for a single create. Track child PIDs so we only
// inject once per created process.
static volatile LONG g_inj_lock = 0;
static DWORD g_inj_pid[256];
static int   g_inj_n = 0;
static int mark_injecting(DWORD pid) {
    int already = 0;
    while (InterlockedCompareExchange(&g_inj_lock, 1, 0) != 0) Sleep(0);
    for (int i = 0; i < g_inj_n; i++) if (g_inj_pid[i] == pid) { already = 1; break; }
    if (!already && g_inj_n < 256) g_inj_pid[g_inj_n++] = pid;
    InterlockedExchange(&g_inj_lock, 0);
    return already;
}

// Inject our own DLL into another process (used for Parsec's spawned UI child).
static void inject_into(HANDLE proc, const char* dllpath) {
    wchar_t wpath[MAX_PATH];
    // dllpath is ANSI (from GetModuleFileNameA). Convert with the ANSI code page,
    // not UTF-8, or a non-ASCII install path yields a broken wide path and the
    // remote LoadLibraryW silently fails -> permanently English UI.
    if (MultiByteToWideChar(CP_ACP, 0, dllpath, -1, wpath, MAX_PATH) <= 0) return;
    SIZE_T sz = (wcslen(wpath) + 1) * sizeof(wchar_t);
    void* rem = VirtualAllocEx(proc, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) return;
    if (!WriteProcessMemory(proc, rem, wpath, sz, NULL)) { VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return; }
    FARPROC llw = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (!llw) { VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return; }
    HANDLE th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)llw, rem, 0, NULL);
    if (th) {
        DWORD wr = WaitForSingleObject(th, 20000);
        CloseHandle(th);
        // Free the remote buffer ONLY after the thread is done reading the path;
        // on timeout the target may still reference it, so leak instead of UAF.
        if (wr == WAIT_OBJECT_0) VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    }

    // Do NOT let the child run until its in-DLL hooks are in place, otherwise the
    // skel loads first and its font atlas is built before AddFont is hooked. The
    // injected DLL signals a per-PID event once its LdrLoadDll hook is installed.
    DWORD pid = GetProcessId(proc);
    if (pid) {
        char name[64];
        _snprintf(name, sizeof(name), "Local\\parsec-zh-ready-%lu", (unsigned long)pid);
        HANDLE ev = NULL;
        for (int i = 0; i < 200 && !ev; i++) { ev = OpenEventA(SYNCHRONIZE, FALSE, name); if (!ev) Sleep(10); }
        if (ev) { WaitForSingleObject(ev, 8000); CloseHandle(ev); }
    }
}


// Case-insensitive substring checks used to make sure we only ever inject into a
// process whose image really lives under a Parsec directory (never an unrelated
// same-named executable somewhere else on the machine).
static int contains_ci_a(const char* hay, const char* needle) {
    size_t nl = strlen(needle);
    if (!nl) return 0;
    for (; *hay; hay++) if (_strnicmp(hay, needle, nl) == 0) return 1;
    return 0;
}
static int contains_ci_w(const wchar_t* hay, const wchar_t* needle) {
    size_t nl = wcslen(needle);
    if (!nl) return 0;
    for (; *hay; hay++) if (_wcsnicmp(hay, needle, nl) == 0) return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// translation lookup
// ---------------------------------------------------------------------------
#define TR_TABLE_SIZE 2048
static int    tr_slot[TR_TABLE_SIZE];   // index+1 into TR_* or 0
static unsigned tr_hash[TR_TABLE_SIZE];
static int    tr_ready = 0;
static int    g_dbg = 0;

static void dbglog(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    report(buf);
}

static unsigned tr_fnv(const char* s, int len) {
    unsigned h = 2166136261u;
    for (int i = 0; i < len; i++) { h ^= (unsigned char)s[i]; h *= 16777619u; }
    return h;
}

static void build_prefix_rules(void);

static void tr_init(void) {
    if (tr_ready) return;
    memset(tr_slot, 0, sizeof(tr_slot));
    int count = 0;
    for (int i = 0; i < TR_N && count < TR_TABLE_SIZE - 1; i++) {
        const char* en = TR_EN[i];
        int len = (int)strlen(en);
        unsigned h = tr_fnv(en, len);
        unsigned pos = h & (TR_TABLE_SIZE - 1);
        unsigned guard = 0;
        while (tr_slot[pos] != 0 && ++guard < TR_TABLE_SIZE) pos = (pos + 1) & (TR_TABLE_SIZE - 1);
        if (guard >= TR_TABLE_SIZE) break;          // table full: stop instead of spinning
        tr_slot[pos] = i + 1;
        tr_hash[pos] = h;
        count++;
    }
    build_prefix_rules();
    tr_ready = 1;
}

static int tr_find(const char* s, int len) {
    unsigned h = tr_fnv(s, len);
    unsigned pos = h & (TR_TABLE_SIZE - 1);
    while (tr_slot[pos] != 0) {
        if (tr_hash[pos] == h) {
            const char* en = TR_EN[tr_slot[pos] - 1];
            if ((int)strlen(en) == len && memcmp(en, s, len) == 0) return tr_slot[pos] - 1;
        }
        pos = (pos + 1) & (TR_TABLE_SIZE - 1);
    }
    return -1;
}

typedef struct { const char* begin; const char* end; int translated; int cjk; } TrOut;

// --- formatted-string rules -------------------------------------------------
// ImGui substitutes "%d/%s/..." BEFORE the text reaches us, so a dictionary key
// that still contains a placeholder can never match. We therefore split each
// such key (and its translation) into literal SEGMENTS around the placeholders
// and match the rendered text segment by segment, keeping the substituted values.
typedef struct { const char* s; int len; } SegR;
typedef struct { SegR en[6]; SegR zh[6]; int n; } FmtRule;
static FmtRule g_fmt[512];
static int g_fmt_n = 0;

static int split_fmt(const char* s, SegR* out, int maxout) {
    int n = 0;
    const char* seg = s;
    const char* p = s;
    while (*p) {
        if (*p == '%') {
            if (p[1] == '%') { p += 2; continue; }
            const char* q = p + 1;
            while (*q && strchr("-+ #0", *q)) q++;
            while (*q >= '0' && *q <= '9') q++;
            if (*q == '.') { q++; while (*q >= '0' && *q <= '9') q++; }
            while (*q && strchr("hljztL", *q)) q++;
            if (!*q) break;
            q++;
            if (n < maxout) { out[n].s = seg; out[n].len = (int)(p - seg); n++; }
            p = q; seg = q;
        } else p++;
    }
    if (n < maxout) { out[n].s = seg; out[n].len = (int)(p - seg); n++; }
    return n;
}

static void build_prefix_rules(void) {
    g_fmt_n = 0;
    for (int i = 0; i < TR_N && g_fmt_n < 512; i++) {
        if (!strchr(TR_EN[i], '%')) continue;
        SegR en[6], zh[6];
        int ne = split_fmt(TR_EN[i], en, 6);
        int nz = split_fmt(TR_ZH[i], zh, 6);
        if (ne != nz || ne < 2) continue;
        // Require at least one solid literal anchor (>=6 bytes) anywhere in the
        // pattern. The first segment may be empty, so strings like "%u Frames" or
        // "%s#%u connected." (whose leading literal is empty) can still translate
        // once ImGui has substituted the values into the rendered text.
        {
            int maxseg = 0;
            for (int k = 0; k < ne; k++) if (en[k].len > maxseg) maxseg = en[k].len;
            if (maxseg < 6) continue;      // too weak an anchor -> avoid false hits
        }
        FmtRule* R = &g_fmt[g_fmt_n];
        R->n = ne;
        for (int k = 0; k < ne; k++) { R->en[k] = en[k]; R->zh[k] = zh[k]; }
        g_fmt_n++;
    }
}

static const char* mem_find(const char* h, int hlen, const char* n, int nlen) {
    if (nlen == 0) return h;
    if (nlen > hlen) return NULL;
    for (int i = 0; i + nlen <= hlen; i++) if (h[i] == n[0] && memcmp(h + i, n, nlen) == 0) return h + i;
    return NULL;
}

// Match a rendered, already-formatted string against the segment rules.
// [pb,b) is preserved verbatim as a prefix (icon/spaces).
static int match_fmt(const char* pb, const char* b, const char* e, char* dst, int cap) {
    int blen = (int)(e - b);
    for (int i = 0; i < g_fmt_n; i++) {
        FmtRule* R = &g_fmt[i];
        if (blen < R->en[0].len || memcmp(b, R->en[0].s, R->en[0].len) != 0) continue;
        int w = 0, ok = 1;
        int prelen = (int)(b - pb);
        if (prelen + R->zh[0].len > cap) continue;
        if (prelen) memcpy(dst, pb, prelen);
        w = prelen;
        memcpy(dst + w, R->zh[0].s, R->zh[0].len); w += R->zh[0].len;
        const char* p = b + R->en[0].len;
        for (int s = 1; s < R->n && ok; s++) {
            int lastseg = (s == R->n - 1);
            if (lastseg && R->en[s].len == 0) {   // trailing literal empty: consume the rest
                int vlen = (int)(e - p);
                if (w + vlen + R->zh[s].len > cap) { ok = 0; break; }
                memcpy(dst + w, p, vlen); w += vlen;
                memcpy(dst + w, R->zh[s].s, R->zh[s].len); w += R->zh[s].len;
                p = e; break;
            }
            const char* found = mem_find(p, (int)(e - p), R->en[s].s, R->en[s].len);
            if (!found) { ok = 0; break; }
            int vlen = (int)(found - p);
            if (w + vlen + R->zh[s].len > cap) { ok = 0; break; }
            memcpy(dst + w, p, vlen); w += vlen;
            memcpy(dst + w, R->zh[s].s, R->zh[s].len); w += R->zh[s].len;
            p = found + R->en[s].len;
        }
        if (!ok) continue;
        // A rule whose first literal is empty has no leading anchor, so only accept
        // it when it consumes the ENTIRE string; otherwise it could rewrite part of
        // a longer, unrelated string (chat text, a host name, ...).
        if (R->en[0].len == 0 && p != e) continue;
        if (p < e) {                 // keep any trailing text the rule did not model
            int vlen = (int)(e - p);
            if (w + vlen > cap) continue;
            memcpy(dst + w, p, vlen); w += vlen;
        }
        return w;
    }
    return -1;
}

static int has_nonascii(const char* p, const char* e) {
    for (; p < e; p++) if ((unsigned char)*p >= 0x80) return 1;
    return 0;
}

// Translate a single segment [b,e). Returns the new byte length written to dst
// (>=0), or -1 when there is no translation.
// Matching is tried on: the exact text, then the text with surrounding spaces
// stripped (Parsec pads some literals), then the text with a leading icon
// (private-use UTF-8 char, e.g. "\uEA22  Add Friend") and its spaces stripped.
static int utf8_char_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}

// emit "prefix bytes + translation + suffix bytes"
static int emit_tr(const char* pb, const char* pe, const char* sb, const char* se,
                   int idx, char* dst, int cap) {
    const char* zh = TR_ZH[idx];
    int zhlen = (int)strlen(zh);
    int prelen = (int)(pe - pb);
    int suflen = (int)(se - sb);
    if (prelen + zhlen + suflen > cap) return -1;
    if (prelen) memcpy(dst, pb, prelen);
    memcpy(dst + prelen, zh, zhlen);
    if (suflen) memcpy(dst + prelen + zhlen, sb, suflen);
    return prelen + zhlen + suflen;
}

// Try exact match on the key range [kb,ke); the bytes [pb,kb) are kept verbatim
// as a prefix and [kb+keylen,se) as a suffix.
static int try_range(const char* pb, const char* kb, const char* ke, const char* se,
                     char* dst, int cap) {
    const char* id = NULL;
    for (const char* p = kb; p + 1 < ke; p++) if (p[0] == '#' && p[1] == '#') { id = p; break; }
    int kl = (int)((id ? id : ke) - kb);
    if (kl <= 0) return -1;
    int idx = tr_find(kb, kl);
    if (idx >= 0) return emit_tr(pb, kb, kb + kl, se, idx, dst, cap);
    return -1;
}

// Translate a single segment [b,e). Returns new byte length or -1.
// Tried on: exact, spaces-stripped, leading-icon(U+E000..)-stripped, plus the
// segment rules for strings that came from a printf-style format.
static int translate_one(const char* b, const char* e, char* dst, int cap) {
    if (!b || e <= b) return -1;
    int r = try_range(b, b, e, e, dst, cap);
    if (r >= 0) return r;
    r = match_fmt(b, b, e, dst, cap);
    if (r >= 0) return r;
    {
        const char* s = b; const char* t = e;
        while (s < t && *s == ' ') s++;
        while (t > s && t[-1] == ' ') t--;
        if (s != b || t != e) {
            r = try_range(b, s, t, e, dst, cap); if (r >= 0) return r;
            r = match_fmt(b, s, t, dst, cap);    if (r >= 0) return r;
        }
    }
    if ((unsigned char)b[0] >= 0x80) {
        const char* s = b + utf8_char_len((unsigned char)b[0]);
        while (s < e && *s == ' ') s++;
        r = try_range(b, s, e, e, dst, cap); if (r >= 0) return r;
        r = match_fmt(b, s, e, dst, cap);    if (r >= 0) return r;
    }
    return -1;
}

// Translate [begin,end). Handles NULL end and "##"/"###" label IDs, and falls
// back to translating each '\n'-separated line independently (Parsec joins
// several sentences into one rendered string, e.g. a label + its WARNING line).
static int tr_translate(const char* begin, const char* end, TrOut* out, char* buf, int bufsz) {
    if (!begin) return 0;
    if (!end) end = begin + strlen(begin);
    if (end <= begin) return 0;

    int n = translate_one(begin, end, buf, bufsz - 1);
    if (n >= 0) {
        buf[n] = 0;
        out->begin = buf;
        out->end = buf + n;
        out->translated = 1;
        out->cjk = 1;
        if (g_verbose && g_dbg < 80) {
            char k[256];
            int kn = (int)(end - begin); if (kn > 255) kn = 255;
            memcpy(k, begin, kn); k[kn] = 0;
            g_dbg++;
            dbglog("TR[%d]: [%s] -> [%s]", g_dbg, k, buf);
        }
        return 1;
    }

    // Multi-line: translate line by line.
    if (end - begin > 1 && memchr(begin, '\n', (size_t)(end - begin))) {
        int w = 0, changed = 0;
        const char* p = begin;
        while (p < end) {
            const char* nl = (const char*)memchr(p, '\n', (size_t)(end - p));
            const char* seg_end = nl ? nl : end;
            int rem = bufsz - 1 - w;
            if (rem <= 0) return 0;
            int m = translate_one(p, seg_end, buf + w, rem);
            if (m >= 0) { w += m; changed = 1; }
            else {
                int L = (int)(seg_end - p);
                if (w + L > bufsz - 1) return 0;
                memcpy(buf + w, p, L); w += L;
            }
            if (nl) { if (w >= bufsz - 1) return 0; buf[w++] = '\n'; p = nl + 1; }
            else p = end;
        }
        if (changed) {
            buf[w] = 0;
            out->begin = buf;
            out->end = buf + w;
            out->translated = 1;
            out->cjk = 1;
            return 1;
        }
    }
    return 0;
}

// Thread-local output for the asm RenderText stub.
static __thread TrOut  tls_out;
static __thread char   tls_buf[16384];

// Diagnostic: remember every distinct UI-looking string we failed to translate,
// so completeness can be checked against what the UI actually renders.
static unsigned miss_hash[2048];
static int miss_n = 0;
static void miss_note(const char* b, const char* e) {
    int len = (int)(e - b);
    if (len < 3 || len > 200) return;
    int has_alpha = 0, has_space = 0, has_pct = 0;
    for (const char* p = b; p < e; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '%') has_pct = 1;
        if (c == ' ') has_space = 1;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) has_alpha = 1;
    }
    if (!has_alpha || has_pct) return;
    if (!has_space && len < 5) return;
    unsigned h = tr_fnv(b, len);
    for (int i = 0; i < miss_n; i++) if (miss_hash[i] == h) return;
    if (miss_n >= 2048) return;
    miss_hash[miss_n++] = h;
    char line[256];
    int n = len < 200 ? len : 200;
    line[0] = 0;
    memcpy(line, "MISS: [", 7);
    memcpy(line + 7, b, n);
    line[7 + n] = ']';
    line[8 + n] = 0;
    report(line);
}

TrOut* tr_helper(const char* begin, const char* end) {
    static int logged = 0;
    static int once = 0;
    if (!once) {
        once = 1;
        char b[256];
        _snprintf(b, sizeof(b), "DIAG cfg_enable=%d hits=%d data=%p size=%d t_attach=%u t_install=%u t_ldr=%u t_target=%u t_af=%u",
                  (int)g_cfg_enable, (int)g_cfg_hits, g_cjk_data, g_cjk_size,
                  g_t_attach, g_t_install_start, g_t_ldr_hook, g_t_target_hook, g_t_first_af);
        report(b);
    }
    if (g_verbose && g_cfg_hits != logged) {
        char b[160];
        _snprintf(b, sizeof(b), "CFGSTAT hits=%d patched=%d t_install=%u t_af=%u",
                  (int)g_cfg_hits, (int)g_cfg_patched, g_t_target_hook, g_t_first_af);
        report(b);
        logged = g_cfg_hits;
    }
    tls_out.translated = 0;
    tls_out.cjk = 0;
    tls_out.begin = begin;
    tls_out.end = end;
    if (!begin) return &tls_out;
    if (!end) end = begin + strlen(begin);
    tls_out.end = end;
    if (has_nonascii(begin, end)) tls_out.cjk = 1;
    // Safety gate: only translate once the CJK font has really been substituted
    // into the atlas. If our hooks landed after the atlas was built, patch_cfg
    // never ran; translating then would draw Chinese with no glyphs ('?'), which
    // is worse than leaving English. In that case stay English.
    if (g_cfg_patched == 0) return &tls_out;
    if (g_verbose && g_dbg < 40) {
        char k[200]; int n = 0;
        const char* p = begin;
        while (p < end && *p && n < 199) k[n++] = *p++;
        k[n] = 0;
        g_dbg++;
        dbglog("RT[%d]: [%s]", g_dbg, k);
    }
    if (tr_translate(begin, end, &tls_out, tls_buf, sizeof(tls_buf))) return &tls_out;
    if (g_verbose) miss_note(begin, end);
    return &tls_out;
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// A small self-contained inline hook (absolute jump through a relay placed near
// the target) used where MinHook refuses the function prologue.
// ---------------------------------------------------------------------------
static void* near_alloc(void* target, size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t gran = si.dwAllocationGranularity ? si.dwAllocationGranularity : 0x10000;
    uintptr_t t = (uintptr_t)target;
    for (uintptr_t d = gran; d < 0x70000000ULL; d += gran) {
        void* p = VirtualAlloc((void*)(t - d), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return p;
        p = VirtualAlloc((void*)(t + d), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (p) return p;
    }
    return NULL;
}

// Emit `jmp qword ptr [rip+0]` followed by the destination address (14 bytes).
static void emit_jmp_abs(unsigned char* p, void* dest) {
    p[0] = 0xFF; p[1] = 0x25;
    *(uint32_t*)(p + 2) = 0;
    *(void**)(p + 6) = dest;
}

// Extend a requested copy length up to the next instruction boundary. Copying a
// partial instruction into the trampoline (e.g. 5 of addfont's 6 prologue bytes,
// which splits "40 53 56 57 41 54") produces a bogus REX-prefixed jump and makes
// the target execute garbage. Every overwritten byte must land on a boundary.
static int align_copylen(unsigned char* p, int min_len) {
    int len = 0;
    while (len < min_len) {
        hde64s hs;
        unsigned int l = hde64_disasm(p + len, &hs);
        if (l == 0 || (hs.flags & F_ERROR)) return -1;
        // Reject anything whose meaning depends on its location: relative branches
        // and RIP-relative memory operands would be wrong in the trampoline.
        if (hs.flags & F_RELATIVE) return -1;
        if ((hs.flags & F_MODRM) && hs.modrm_mod == 0 && hs.modrm_rm == 5) return -1;  // [rip+disp]
        len += (int)l;
        if (len > 24) return -1;
    }
    return len;
}

static int manual_hook(void* target, void* detour, int copylen, void** tramp_out) {
    // Never split an instruction: grow the overwrite length to a boundary.
    copylen = align_copylen((unsigned char*)target, copylen);
    if (copylen < 5 || copylen > 24) return 0;

    unsigned char* page = (unsigned char*)near_alloc(target, 4096);
    if (!page) return 0;
    memcpy(page, target, copylen);                       // [original bytes]
    emit_jmp_abs(page + copylen, (unsigned char*)target + copylen);  // -> target+copylen
    unsigned char* relay = page + copylen + 14;
    emit_jmp_abs(relay, detour);                         // reach a possibly distant detour

    // Publish the trampoline *before* the target starts jumping to the detour,
    // otherwise a concurrent call would run with orig == NULL.
    *tramp_out = page;
    FlushInstructionCache(GetCurrentProcess(), page, copylen + 28);

    DWORD old;
    if (!VirtualProtect(target, copylen, PAGE_EXECUTE_READWRITE, &old)) return 0;
    // The target must still be a committed page (a module may have been unloaded
    // between the protect call and the write). Bail out instead of faulting.
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(target, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) {
        VirtualProtect(target, copylen, old, &old);
        return 0;
    }
    unsigned char patch[32];
    memset(patch, 0x90, sizeof(patch));
    patch[0] = 0xE9;
    *(int32_t*)(patch + 1) = (int32_t)((unsigned char*)relay - ((unsigned char*)target + 5));
    // Freeze the other threads so no one can execute a half-written patch.
    HANDLE th[1024];
    int nth = susp_threads(th, 1024);
    if (nth < 0) { VirtualProtect(target, copylen, old, &old); return 0; }  // too many threads -> abort safely
    reloc_thread_ips(th, nth, target, copylen, page);                       // don't resume into half-written bytes
    memcpy(target, patch, copylen);
    FlushInstructionCache(GetCurrentProcess(), target, copylen);
    res_threads(th, nth);
    VirtualProtect(target, copylen, old, &old);
    return 1;
}

void* g_cjk_data = NULL;
int   g_cjk_size = 0;
unsigned char g_cfg_enable = 0;

// Build the ImFontConfig for the CJK font (static storage; called from the asm
// AddFont stub). Returns NULL when the font data is unavailable.

// Called from the asm AddFont stub. Parsec adds its fonts with a NULL glyph
// range for text fonts and a fixed range for its icon font. For text fonts we
// substitute a CJK-capable font (keeping the requested pixel size, leaving the
// icon font untouched). No second AddFont call is made, so ImGui's locked-atlas
// assertion can never be triggered.
// Called from the asm AddFont stub. It MUST NOT call into the CRT or any heavy
// API: ImGui can add fonts while the process holds the loader lock, and a file or
// heap call there crashes the app. Pure memory work only.

// ---------------------------------------------------------------------------
// AddFont detour: keep the app's ORIGINAL font (its Latin is the sharpest) and
// merely MERGE our CJK glyphs into it (ImGui MergeMode), instead of replacing
// the font data (which made Latin blurry).
// ---------------------------------------------------------------------------
typedef void* (*tAddFont)(void* atlas, const void* cfg);
static tAddFont g_orig_AddFont = NULL;

// Signals (per process) that the CJK font really got merged -> this UI is
// localized. Used by the launcher to detect a still-English client and heal it.
static HANDLE g_loc_ev = NULL;
static void mark_localized(void) {
    if (g_loc_ev) return;
    char n[64];
    _snprintf(n, sizeof(n), "Local\\parsec-zh-localized-%lu", (unsigned long)GetCurrentProcessId());
    g_loc_ev = CreateEventA(NULL, TRUE, FALSE, n);
    if (g_loc_ev) SetEvent(g_loc_ev);
}

static void* detour_AddFont(void* atlas, const void* cfgp) {
    void* font = g_orig_AddFont(atlas, cfgp);
    g_cfg_hits++;
    if (!g_cfg_enable || !font || !cfgp || !g_cjk_data || g_cjk_size <= 0) return font;
    const unsigned char* c = (const unsigned char*)cfgp;
    if (*(const void**)(c + IMFC_GlyphRanges) != NULL) return font;   /* icon font */
    if (*(float*)(c + IMFC_SizePixels) < 9.0f) return font;
    if (*(unsigned char*)(c + IMFC_MergeMode) != 0) return font;      /* our own merge call */

    /* Layout probe: if a future ImGui version moved the ImFontConfig fields, bail
       out (stay English) instead of writing a merge config into wrong offsets. */
    {
        float sz = *(float*)(c + IMFC_SizePixels);
        unsigned char oh = *(unsigned char*)(c + IMFC_OversampleH);
        unsigned char ov = *(unsigned char*)(c + IMFC_OversampleV);
        if (!(sz >= 6.0f && sz <= 200.0f) || oh < 1 || oh > 8 || ov < 1 || ov > 8) {
            if (g_cfg_enable) {
                g_cfg_enable = 0;
                report("parsec-zh: ImFontConfig layout mismatch -> font substitution disabled (English)");
            }
            return font;
        }
    }

    unsigned char mc[IMFC_SIZE];
    memcpy(mc, c, IMFC_SIZE);
    *(void**)(mc + IMFC_FontData)     = g_cjk_data;
    *(int*)(mc + IMFC_FontDataSize)   = g_cjk_size;
    *(char*)(mc + IMFC_FontDataOwned) = 0;        /* the atlas copies it */
    *(int*)(mc + IMFC_FontNo)         = 0;        /* first face of a .ttc */
    *(const unsigned short**)(mc + IMFC_GlyphRanges) =
        (*(float*)(c + IMFC_SizePixels) <= 26.0f) ? TR_GLYPH_RANGES_BROAD : TR_GLYPH_RANGES;
    *(unsigned char*)(mc + IMFC_MergeMode) = 1;
    *(void**)(mc + IMFC_DstFont) = font;          /* merge into the app's font */
    /* Sharpness: ImGui's default 3x1 oversampling is bilinearly averaged by the
       GPU and is the main source of blur; 1x1 keeps the glyph at its exact pixel
       grid. Snap advances, and slightly boost the rasterizer to firm up strokes. */
    *(unsigned char*)(mc + IMFC_OversampleH) = 1;
    *(unsigned char*)(mc + IMFC_OversampleV) = 1;
    *(unsigned char*)(mc + IMFC_PixelSnapH) = 1;
    *(float*)(mc + IMFC_RasterizerMultiply) = 1.15f;
    *(float*)(mc + IMFC_GlyphExtraSpacing) = 0.0f;

    /* diagnostics snapshot */
    {
        float sz = *(float*)(c + IMFC_SizePixels);
        int n = g_snap_n, dup = 0;
        for (int i = 0; i < n && i < 24; i++) if (g_snaps[i].size == sz) { dup = 1; break; }
        if (!dup && n < 24) { g_snaps[n].size = sz; g_snaps[n].oh = 3; g_snaps[n].ov = 1; g_snaps[n].snap = 1; g_snaps[n].rmult = 1.0f; g_snap_n = n + 1; }
    }

    void* f2 = g_orig_AddFont(atlas, mc);
    g_cfg_patched++;
    mark_localized();
    return f2 ? f2 : font;
}

// (removed) the abandoned "replace FontData" path (patch_cfg): it was never
// installed and its asm stub (naked_AddFont) jumped to a NULL trampoline.
// Only detour_AddFont (MinHook, merge mode) is used.

// ---------------------------------------------------------------------------
// child-process injection: parsecd.exe spawns the real UI process as a child.
// ---------------------------------------------------------------------------
typedef BOOL (WINAPI *pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                       BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *pCreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
                                       BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
static pCreateProcessW orig_CreateProcessW = NULL;
static pCreateProcessA orig_CreateProcessA = NULL;

typedef BOOL (WINAPI *pCreateProcessInternalW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
                                               LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
                                               LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE);
static pCreateProcessInternalW orig_CreateProcessInternalW = NULL;

BOOL WINAPI hook_CreateProcessInternalW(HANDLE token, LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                        LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
                                        LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi, PHANDLE newToken) {
    DWORD f = flags;
    BOOL we_suspended = FALSE;
    if (!(f & CREATE_SUSPENDED)) { f |= CREATE_SUSPENDED; we_suspended = TRUE; }
    BOOL ok = orig_CreateProcessInternalW(token, app, cmd, pa, ta, inherit, f, env, dir, si, pi, newToken);
    if (g_verbose) {
        static int n = 0;
        if (n < 12) {
            char b[300];
            // Log the image name only. The full command line can carry per-session
            // tokens (e.g. PARSEC_IPC_<token>) and must not be written to disk.
            _snprintf(b, sizeof(b), "CPIW[%d] ok=%d app=%ls", n, ok, app ? app : L"(null)");
            report(b);
            n++;
        }
    }
    if (ok && pi && pi->hProcess) {
        wchar_t path[MAX_PATH] = {0};
        const wchar_t* p = app;
        const wchar_t* q = cmd;
        if (!p && q) {
            while (*q == L' ' || *q == L'\t') q++;
            int n = 0;
            if (*q == L'"') { q++; while (*q && *q != L'"' && n < MAX_PATH - 1) path[n++] = *q++; }
            else { while (*q && *q != L' ' && n < MAX_PATH - 1) path[n++] = *q++; }
            path[n] = 0;
            p = path;
        } else if (p) {
            DWORD c = (DWORD)wcslen(p);
            if (c < MAX_PATH) wcscpy(path, p);
        }
        if (path[0]) {
            size_t L = wcslen(path);
            const wchar_t* tail = L >= 11 ? path + L - 11 : path;
            if (_wcsicmp(tail, L"parsecd.exe") == 0 && g_dllpath[0] && contains_ci_w(path, L"parsec")) {
                DWORD cpid = GetProcessId(pi->hProcess);
                if (!mark_injecting(cpid)) {
                    inject_into(pi->hProcess, g_dllpath);
                    report("parsec-zh: injected UI child via CreateProcessInternalW");
                }
            }
        }
    }
    if (ok && we_suspended) ResumeThread(pi->hThread);
    return ok;
}

// Ultimate fallback: hook the kernel-level process creation entry in ntdll so
// every child Parsec spawns (whatever API the loader used) gets injected.
typedef NTSTATUS (WINAPI *pNtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
                                                void*, void*, ULONG, ULONG, void*, void*, void*);
static pNtCreateUserProcess orig_NtCreateUserProcess = NULL;

static NTSTATUS WINAPI hook_NtCreateUserProcess(PHANDLE ph, PHANDLE th, ACCESS_MASK pa, ACCESS_MASK ta,
                                                void* poa, void* toa, ULONG pf, ULONG tf, void* pp,
                                                void* ci, void* al) {
    // Force the child to be created suspended so we can inject our DLL *before*
    // it starts running its own main(). The UI child builds its ImGui font atlas
    // during startup; if we lose that race the atlas has no CJK glyphs.
    int we_suspended = 0;
    ULONG tf2 = tf;
    if (!(tf & 0x1) && !dev_flag("nosuspend.flag")) {
        tf2 = tf | 0x1;   // THREAD_CREATE_FLAGS_CREATE_SUSPENDED
        we_suspended = 1;
    }
    NTSTATUS st = orig_NtCreateUserProcess(ph, th, pa, ta, poa, toa, pf, tf2, pp, ci, al);
    if (st >= 0 && ph && *ph) {
        wchar_t path[MAX_PATH] = {0};
        DWORD len = MAX_PATH;
        if (QueryFullProcessImageNameW(*ph, 0, path, &len)) {
            size_t L = wcslen(path);
            const wchar_t* tail = L >= 11 ? path + L - 11 : path;
            if (_wcsicmp(tail, L"parsecd.exe") == 0 && g_dllpath[0] && contains_ci_w(path, L"parsec")) {
                char b[300];
                _snprintf(b, sizeof(b), "parsec-zh: child via NtCreateUserProcess -> %ls suspended=%d t=%u",
                          path, we_suspended, (unsigned)GetTickCount());
                report(b);
                DWORD cpid = GetProcessId(*ph);
                if (!mark_injecting(cpid)) inject_into(*ph, g_dllpath);
            }
        }
    }
    if (we_suspended && st >= 0 && th && *th) ResumeThread(*th);
    return st;
}

BOOL WINAPI hook_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
                                LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi) {
    DWORD f = flags;
    BOOL we_suspended = FALSE;
    if (!(f & CREATE_SUSPENDED)) { f |= CREATE_SUSPENDED; we_suspended = TRUE; }
    BOOL ok = orig_CreateProcessW(app, cmd, pa, ta, inherit, f, env, dir, si, pi);
    if (ok && pi && pi->hProcess) {
        wchar_t path[MAX_PATH] = {0};
        const wchar_t* p = app;
        wchar_t cmd0[MAX_PATH] = {0};
        if (!p && cmd) {
            // first token of the command line
            while (*cmd == L' ' || *cmd == L'\t') cmd++;
            int n = 0;
            if (*cmd == L'"') { cmd++; while (*cmd && *cmd != L'"' && n < MAX_PATH - 1) cmd0[n++] = *cmd++; }
            else { while (*cmd && *cmd != L' ' && n < MAX_PATH - 1) cmd0[n++] = *cmd++; }
            cmd0[n] = 0;
            p = cmd0;
        }
        if (p) { DWORD c = (DWORD)wcslen(p); if (c < MAX_PATH) wcscpy(path, p); }
        if (path[0]) {
            // ends with parsecd.exe ?
            size_t L = wcslen(path);
            const wchar_t* tail = L >= 11 ? path + L - 11 : path;   // "parsecd.exe"
            if (_wcsicmp(tail, L"parsecd.exe") == 0 && g_dllpath[0] && contains_ci_w(path, L"parsec")) {
                DWORD cpid = GetProcessId(pi->hProcess);
                if (!mark_injecting(cpid)) inject_into(pi->hProcess, g_dllpath);
            }
        }
    }
    if (ok && we_suspended) ResumeThread(pi->hThread);
    return ok;
}

BOOL WINAPI hook_CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta,
                                BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
                                LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi) {
    // Call the original A variant DIRECTLY. Routing the A call through the W hook
    // would hand an ANSI environment block (and a partially filled STARTUPINFO) to
    // the wide API, corrupting the child's environment.
    DWORD f = flags;
    BOOL we_suspended = FALSE;
    if (!(f & CREATE_SUSPENDED)) { f |= CREATE_SUSPENDED; we_suspended = TRUE; }
    BOOL ok = orig_CreateProcessA(app, cmd, pa, ta, inherit, f, env, dir, si, pi);
    if (ok && pi && pi->hProcess) {
        char path[MAX_PATH] = {0};
        const char* p = app;
        char cmd0[MAX_PATH] = {0};
        if (!p && cmd) {
            while (*cmd == ' ' || *cmd == '\t') cmd++;
            int n = 0;
            if (*cmd == '"') { cmd++; while (*cmd && *cmd != '"' && n < MAX_PATH - 1) cmd0[n++] = *cmd++; }
            else { while (*cmd && *cmd != ' ' && n < MAX_PATH - 1) cmd0[n++] = *cmd++; }
            cmd0[n] = 0;
            p = cmd0;
        }
        if (p) { size_t c = strlen(p); if (c < MAX_PATH) memcpy(path, p, c + 1); }
        if (path[0]) {
            size_t L = strlen(path);
            const char* tail = L >= 11 ? path + L - 11 : path;   // "parsecd.exe"
            if (_stricmp(tail, "parsecd.exe") == 0 && g_dllpath[0] && contains_ci_a(path, "parsec")) {
                DWORD cpid = GetProcessId(pi->hProcess);
                if (!mark_injecting(cpid)) inject_into(pi->hProcess, g_dllpath);
            }
        }
    }
    if (ok && we_suspended) ResumeThread(pi->hThread);
    return ok;
}


// ---------------------------------------------------------------------------
// CJK font loading
// ---------------------------------------------------------------------------
static const char* k_font_files[] = {
    "msyh.ttc",   // Microsoft YaHei (bolder, easy to read)
    "msyh.ttf",   // Microsoft YaHei (legacy)
    "Deng.ttf",   // DengXian
    "simhei.ttf", // SimHei (fallback)
    "simsun.ttc", // SimSun
};
static char g_cjk_path[MAX_PATH] = {0};

static int try_load_font(const char* full) {
    HANDLE h = CreateFileA(full, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz == 0) { CloseHandle(h); return 0; }
    void* data = VirtualAlloc(NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) { CloseHandle(h); return 0; }
    DWORD rd = 0;
    if (ReadFile(h, data, sz, &rd, NULL) && rd == sz) {
        g_cjk_data = data;
        g_cjk_size = (int)sz;
        strncpy(g_cjk_path, full, sizeof(g_cjk_path) - 1);
        g_cjk_path[sizeof(g_cjk_path) - 1] = 0;
        CloseHandle(h);
        return 1;
    }
    VirtualFree(data, 0, MEM_RELEASE);
    CloseHandle(h);
    return 0;
}

// Search the real Windows font directory (system drive may not be C:) and the
// per-user font directory, so a Chinese UI still works on trimmed images or when
// the font was installed for the current user only.
static void load_cjk_font(void) {
    if (dev_flag("passthru.flag")) return;
    char dirs[2][MAX_PATH];
    int ndir = 0;
    char win[MAX_PATH];
    if (GetWindowsDirectoryA(win, MAX_PATH)) {
        _snprintf(dirs[ndir], MAX_PATH, "%s\\Fonts", win);
        dirs[ndir][MAX_PATH - 1] = 0;
        ndir++;
    }
    { const char* la = getenv("LOCALAPPDATA");
      if (la && la[0]) { _snprintf(dirs[ndir], MAX_PATH, "%s\\Microsoft\\Windows\\Fonts", la); dirs[ndir][MAX_PATH - 1] = 0; ndir++; } }
    for (int d = 0; d < ndir; d++) {
        for (int i = 0; i < (int)(sizeof(k_font_files)/sizeof(k_font_files[0])); i++) {
            char full[MAX_PATH];
            _snprintf(full, sizeof(full), "%s\\%s", dirs[d], k_font_files[i]);
            full[MAX_PATH - 1] = 0;
            if (try_load_font(full)) return;
        }
    }
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------
extern void naked_RenderText(void);
extern void naked_CalcTextSize(void);

#define PARSEC_ZH_LOG_MAX (4u * 1024u * 1024u)
static void report(const char* msg) {
    // write to a log file next to the dll
    HMODULE self = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&report, &self);
    char dll[MAX_PATH];
    if (!GetModuleFileNameA(self, dll, MAX_PATH)) return;
    char* dot = strrchr(dll, '.');
    size_t dl = strlen(dll);
    int log_ok = 0;
    if (dot) { if ((size_t)(dot - dll) + 5 <= sizeof(dll)) { strcpy(dot, ".log"); log_ok = 1; } }
    else if (dl + 4 < sizeof(dll)) { memcpy(dll + dl, ".log", 5); log_ok = 1; }
    if (!log_ok) return;   // never fall back to appending into the DLL itself
    // Read + atomic append (FILE_APPEND_DATA without FILE_WRITE_DATA) so GetFileSize
    // works and concurrent processes never overwrite each other's lines; truncate
    // once, through a separate write handle, when the file grows past the cap.
    HANDLE f = CreateFileA(dll, GENERIC_READ | FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return;
    DWORD sz = GetFileSize(f, NULL);
    if (sz != INVALID_FILE_SIZE && sz > PARSEC_ZH_LOG_MAX) {
        HANDLE ft = CreateFileA(dll, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (ft != INVALID_HANDLE_VALUE) { SetEndOfFile(ft); CloseHandle(ft); }
    }
    DWORD w;
    char line[512];
    _snprintf(line, sizeof(line), "[pid %lu] %s", GetCurrentProcessId(), msg);
    line[sizeof(line) - 1] = 0;                 // clamp: don't trust _snprintf's return
    DWORD len = (DWORD)strlen(line);
    SetFilePointer(f, 0, NULL, FILE_END);
    WriteFile(f, line, len, &w, NULL);
    WriteFile(f, "\r\n", 2, &w, NULL);
    CloseHandle(f);
}

static HMODULE find_target_present(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    HMODULE found = NULL;
    if (Module32First(snap, &me)) {
        do {
            size_t L = strlen(me.szModule);
            if (_strnicmp(me.szModule, "parsecd-", 8) == 0 && L >= 4 &&
                _stricmp(me.szModule + L - 4, ".dll") == 0) {
                found = (HMODULE)me.hModule;
                break;
            }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// Is the mapped image still committed, readable and a valid PE? Used to avoid
// patching a module that is in the middle of being unloaded. NOTE: the PE header
// page is read-only (not executable), so do NOT require execute on the base page.
static int module_stable(HMODULE m) {
    if (!m) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery((LPCVOID)m, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD rd = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
               PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(mbi.Protect & rd)) return 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)m;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((unsigned char*)m + dos->e_lfanew);
    return nt->Signature == IMAGE_NT_SIGNATURE;
}

// Wait until a skel module exists and has stopped moving (Parsec loads it once
// for verification, unloads it, then loads it again to actually run the UI).
static HMODULE find_target_stable(void) {
    for (int i = 0; i < 50; i++) {
        HMODULE m = find_target_present();
        if (m) {
            Sleep(150);
            if (find_target_present() == m && module_stable(m)) return m;
        } else {
            Sleep(150);
        }
    }
    return NULL;
}

static int g_hooks_done = 0;
static volatile int g_install_tries = 0;   // bounded retries for the fallback poll

static void* g_hooked_base = NULL;

// Guards hook installation: the LdrLoadDll hook (loader thread) and the deferred
// fallback poll (install thread) must never patch the same module concurrently.
static volatile LONG g_installing = 0;

static int in_text_blob(unsigned char* p) {
    return g_text_blob.p && p >= g_text_blob.p && p < g_text_blob.p + g_text_blob.n;
}

// Version guard: only accept discoveries we can prove are the real entry points
// with the exact prologues we rely on. Anything else is dropped -> that hook is
// skipped and the UI simply stays English, instead of patching the wrong bytes.
static void validate_discovery(unsigned char* base) {
    (void)base;
    if (g_f_addfont) {
        unsigned char b0 = *(volatile unsigned char*)g_f_addfont;
        if (!in_text_blob(g_f_addfont) || !is_direct_target(g_f_addfont) ||
            b0 == 0xE9 || b0 == 0xC3 || b0 == 0xCC) {
            report("parsec-zh: VERIFY rejected AddFont (bad entry)");
            g_f_addfont = NULL;
        }
    }
    if (g_f_rendertext) {
        static const unsigned char rt_pat[7] = {0x48,0x8B,0xC4,0x48,0x89,0x50,0x10};
        if (!in_text_blob(g_f_rendertext) || memcmp(g_f_rendertext, rt_pat, 7) != 0) {
            report("parsec-zh: VERIFY rejected RenderText (prologue mismatch)");
            g_f_rendertext = NULL;
        }
    }
    if (g_f_calctextsize) {
        static const unsigned char ct_pat[12] = {0x48,0x8B,0xC4,0x53,0x56,0x48,0x81,0xEC,0x98,0x00,0x00,0x00};
        if (!in_text_blob(g_f_calctextsize) || memcmp(g_f_calctextsize, ct_pat, 12) != 0) {
            report("parsec-zh: VERIFY rejected CalcTextSizeA (prologue mismatch)");
            g_f_calctextsize = NULL;
        }
    }
}

static void install_target_hooks_locked(HMODULE mod) {
    if (!mod) return;
    // Only one skel module may be hooked per process: the three text detours share
    // a single set of global trampolines, so a second (different) module would
    // make one module's call jump into the other module's trampoline.
    if (g_hooked_base && g_hooked_base != (void*)mod) {
        if (module_stable((HMODULE)g_hooked_base)) {   // still mapped -> refuse a second one
            char b[200];
            _snprintf(b, sizeof(b), "parsec-zh: skip extra skel module %p (already hooked %p)",
                      (void*)mod, g_hooked_base);
            report(b);
            return;
        }
        g_hooked_base = NULL;   // previous module unloaded: allow switching to this one
    }
    g_install_tries++;
    g_target = mod;
    if (!g_t_target_hook) g_t_target_hook = GetTickCount();
    tr_init();
    discover_functions((unsigned char*)mod);
    validate_discovery((unsigned char*)mod);
    {
        char b[300];
        _snprintf(b, sizeof(b), "parsec-zh: discovered base=%p AddFont=%p RenderText=%p CalcTextSize=%p t=%u",
                  (void*)mod, (void*)g_f_addfont, (void*)g_f_rendertext, (void*)g_f_calctextsize,
                  (unsigned)GetTickCount());
        report(b);
    }
    // The three hooks are each idempotent on their own: validate_discovery()
    // rejects a function whose prologue no longer matches (i.e. one we already
    // patched), so a second pass cannot double-patch. Crucially we do NOT return
    // early when AddFont is already hooked -- otherwise a partial first install
    // (AddFont ok, a text hook failed) could never be completed and the UI would
    // stay English forever.
    g_hooked_base = (void*)mod;
    {
        char b[256];
        _snprintf(b, sizeof(b), "parsec-zh: installing hooks in %p", (void*)mod);
        report(b);
    }

    // NOTE: we deliberately KEEP the process-creation hooks in every process.
    // Removing them as soon as *any* skel is hooked used to break the loader's
    // ability to inject its UI child (the loader maps the skel for verification
    // before it spawns the UI). Keeping them is harmless and makes child
    // injection reliable regardless of which process loads the skel first.
    (void)g_creation_hooks_removed;
    if (dev_flag("discover_only.flag")) {
        report("parsec-zh: discovery-only (flag), not hooking");
        return;
    }
    int af_ok = 0, cts_ok = 0, rt_ok = 0;
    if (!dev_flag("nofont.flag")) {
        if (!dev_flag("passcfg.flag")) g_cfg_enable = 1;
        if (g_f_addfont && MH_CreateHook((LPVOID)g_f_addfont, (LPVOID)&detour_AddFont, (LPVOID*)&g_orig_AddFont) == MH_OK) {
            MH_EnableHook((LPVOID)g_f_addfont);
            af_ok = 1;
            report("parsec-zh: AddFont hooked (merge mode)");
        } else report("parsec-zh: AddFont NOT hooked");
    } else report("parsec-zh: AddFont hook skipped (flag)");

    if (!dev_flag("nocalc.flag")) {
        if (g_f_calctextsize && manual_hook(g_f_calctextsize, (void*)&naked_CalcTextSize, 5, &g_p_trampoline_cts)) {
            cts_ok = 1;
            report("parsec-zh: CalcTextSizeA hooked");
        } else report("parsec-zh: CalcTextSizeA NOT hooked");
    } else report("parsec-zh: CalcTextSizeA hook skipped (flag)");

    if (!dev_flag("norender.flag")) {
        if (g_f_rendertext && manual_hook(g_f_rendertext, (void*)&naked_RenderText, 7, &g_p_trampoline)) {
            rt_ok = 1;
            report("parsec-zh: RenderText hooked");
        } else report("parsec-zh: RenderText NOT hooked");
    } else report("parsec-zh: RenderText hook skipped (flag)");

    // Stop the fallback poll only once the whole localization path is in place:
    // AddFont merged the glyphs AND both text hooks are installed. A partial pass
    // (e.g. AddFont ok but a text hook failed) must stay retryable, otherwise the
    // UI would stay English forever.
    if (af_ok && cts_ok && rt_ok) g_hooks_done = 1;
    report((af_ok || cts_ok || rt_ok) ? "parsec-zh: hooks installed" : "parsec-zh: no hooks installed");
}

// Serialized entry point. If another thread is already installing, we simply
// return: the other install (or a later re-load) will cover this module.
static void install_target_hooks(HMODULE mod) {
    if (!mod) return;
    if (InterlockedCompareExchange(&g_installing, 1, 0) != 0) return;
    install_target_hooks_locked(mod);
    InterlockedExchange(&g_installing, 0);
}

// Hook the loader so the skel's functions are patched the instant it is mapped,
// i.e. before the app can build its font atlas.
typedef NTSTATUS (WINAPI *pLdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PVOID*);
static pLdrLoadDll orig_LdrLoadDll = NULL;

static NTSTATUS WINAPI hook_LdrLoadDll(PWSTR path, PULONG flags, PUNICODE_STRING name, PVOID* handle) {
    NTSTATUS st = orig_LdrLoadDll(path, flags, name, handle);
    if (st >= 0 && handle && *handle) {
        char modname[MAX_PATH];
        if (GetModuleFileNameA((HMODULE)*handle, modname, MAX_PATH)) {
            char* b = strrchr(modname, '\\');
            b = b ? b + 1 : modname;
            if (_strnicmp(b, "parsecd-", 8) == 0) {
                char m[300];
                _snprintf(m, sizeof(m), "parsec-zh: LdrLoadDll loaded %s base=%p t=%u",
                          b, (void*)*handle, (unsigned)GetTickCount());
                report(m);
                install_target_hooks((HMODULE)*handle);
            }
        }
    }
    return st;
}

// Heartbeat: report AddFont activity even when no text is being drawn, so we can
// tell whether the font atlas is (re)built after our hooks are in place.
static DWORD WINAPI reporter_thread(LPVOID p) {
    (void)p;
    int last_hits = -1, last_patched = -1, last_snaps = -1, last_mis = 0;
    for (;;) {
        Sleep(1500);
        // Late safety net: if the skel appeared after our LdrLoadDll hook was in
        // place (or before it), pick it up now -- as long as nothing is hooked yet.
        if (!g_hooks_done && g_install_tries < 5) {
            HMODULE m = find_target_present();
            if (m && module_stable(m)) install_target_hooks(m);
        }
        if (g_verbose && (g_cfg_hits != last_hits || g_cfg_patched != last_patched)) {
            char b[200];
            _snprintf(b, sizeof(b), "HEART hits=%d patched=%d t_target=%u t_af=%u enable=%d",
                      (int)g_cfg_hits, (int)g_cfg_patched, g_t_target_hook, g_t_first_af, (int)g_cfg_enable);
            report(b);
            last_hits = g_cfg_hits; last_patched = g_cfg_patched;
        }
        if (g_verbose && g_snap_n != last_snaps) {
            int n = g_snap_n;
            for (int i = 0; i < n && i < 24; i++) {
                char b[200];
                _snprintf(b, sizeof(b), "CFG[%d] size=%.1f oh=%u ov=%u snap=%u rmult=%.2f",
                          i, g_snaps[i].size, g_snaps[i].oh, g_snaps[i].ov, g_snaps[i].snap, g_snaps[i].rmult);
                report(b);
            }
            last_snaps = n;
        }
        if (g_verbose && g_rt_mismatch != last_mis) {
            char b[200];
            _snprintf(b, sizeof(b), "RTPROBE mismatch=%d size=%.2f fontsize=%.2f diff=%.2f",
                      (int)g_rt_mismatch, g_rt_last_size, g_rt_last_fsize, g_rt_last_diff);
            report(b);
            last_mis = g_rt_mismatch;
        }
    }
    return 0;
}

static DWORD WINAPI install_thread(LPVOID param) {
    (void)param;
    g_t_install_start = GetTickCount();
    { const char* e = getenv("PARSEC_ZH_DEV"); g_dev = (e && e[0] && e[0] != '0') ? 1 : 0; }
    {
        const char* v = getenv("PARSEC_ZH_VERBOSE");
        g_verbose = ((v && v[0] && v[0] != '0') || g_dev) ? 1 : 0;
    }
    char m[160];
    _snprintf(m, sizeof(m), "parsec-zh: install thread start pid=%lu t=%u (attach t=%u)",
              GetCurrentProcessId(), g_t_install_start, g_t_attach);
    report(m);

    if (MH_Initialize() != MH_OK) { report("parsec-zh: MH_Initialize failed"); return 0; }

    // Create the readiness event first so the launcher/parent can always find it.
    // Named per-PID: a shared name would be pre-signalled by any other process
    // that already has us injected, making the wait useless.
    {
        char rn[64];
        _snprintf(rn, sizeof(rn), "Local\\parsec-zh-ready-%lu", (unsigned long)GetCurrentProcessId());
        g_ready_ev = CreateEventA(NULL, TRUE, FALSE, rn);   // handle kept open on purpose
    }

    {
        HMODULE self = NULL;
        GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCSTR)&report, &self);
        GetModuleFileNameA(self, g_dllpath, MAX_PATH);
    }

    tr_init();
    g_osv2 = dev_flag("osv2.flag");

    // child-process injection
    if (!dev_flag("nocp.flag")) {
        HMODULE k32 = GetModuleHandleA("kernel32.dll");
        if (MH_CreateHook((LPVOID)GetProcAddress(k32, "CreateProcessW"), (LPVOID)&hook_CreateProcessW, (LPVOID*)&orig_CreateProcessW) == MH_OK)
            MH_EnableHook((LPVOID)GetProcAddress(k32, "CreateProcessW"));
        if (MH_CreateHook((LPVOID)GetProcAddress(k32, "CreateProcessA"), (LPVOID)&hook_CreateProcessA, (LPVOID*)&orig_CreateProcessA) == MH_OK)
            MH_EnableHook((LPVOID)GetProcAddress(k32, "CreateProcessA"));
        void* cpi = (void*)GetProcAddress(k32, "CreateProcessInternalW");
        if (cpi && MH_CreateHook(cpi, (LPVOID)&hook_CreateProcessInternalW, (LPVOID*)&orig_CreateProcessInternalW) == MH_OK)
            MH_EnableHook(cpi);
        void* ncp = (void*)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateUserProcess");
        if (ncp && MH_CreateHook(ncp, (LPVOID)&hook_NtCreateUserProcess, (LPVOID*)&orig_NtCreateUserProcess) == MH_OK) {
            MH_EnableHook(ncp);
            report("parsec-zh: NtCreateUserProcess hook installed");
        }
        report("parsec-zh: CreateProcess hooks installed");
    } else report("parsec-zh: CreateProcess hooks skipped (flag)");

    // earliest possible target hooking
    if (!dev_flag("noldr.flag")) {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        void* ldr = (void*)GetProcAddress(ntdll, "LdrLoadDll");
        if (ldr && MH_CreateHook(ldr, (LPVOID)&hook_LdrLoadDll, (LPVOID*)&orig_LdrLoadDll) == MH_OK) {
            MH_EnableHook(ldr);
            report("parsec-zh: LdrLoadDll hook installed");
        } else {
            report("parsec-zh: LdrLoadDll hook failed");
        }
    } else {
        report("parsec-zh: LdrLoadDll hook skipped (flag)");
    }

    // Load the CJK font LAST (after the hooks are live), so injection/hooking is
    // not delayed by a ~20 MB file read; the parent only releases the child once
    // this ready event fires, and the font must exist before the atlas is built.
    load_cjk_font();
    if (g_cjk_data) {
        char fb[320];
        _snprintf(fb, sizeof(fb), "parsec-zh: cjk font loaded: %s (%d bytes)", g_cjk_path, g_cjk_size);
        report(fb);
    } else report("parsec-zh: WARNING no cjk font found");

    // Tell the launcher/parent that hooking is in place, so it can release the
    // target process only now (otherwise Parsec may spawn its UI child too early).
    {
        char rn[64];
        _snprintf(rn, sizeof(rn), "Local\\parsec-zh-ready-%lu", (unsigned long)GetCurrentProcessId());
        if (!g_ready_ev) g_ready_ev = CreateEventA(NULL, TRUE, FALSE, rn);
        if (g_ready_ev) { SetEvent(g_ready_ev); report("parsec-zh: ready event set"); }  // handle kept open
    }

    // Fallback for the case where the skel was already mapped before our
    // LdrLoadDll hook was in place. We wait briefly first so that any in-flight
    // verify-load has settled, then require the module to be stable.
    Sleep(600);
    if (!g_hooks_done && g_install_tries < 5) {
        HMODULE mod = find_target_stable();
        if (mod) install_target_hooks(mod);
        else report("parsec-zh: fallback find_target_stable found nothing");
    }
    report("parsec-zh: install thread done");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved) {
    (void)inst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        g_t_attach = GetTickCount();
        HANDLE h = CreateThread(NULL, 0, install_thread, NULL, 0, NULL);
        if (h) CloseHandle(h);
        HANDLE h2 = CreateThread(NULL, 0, reporter_thread, NULL, 0, NULL);
        if (h2) CloseHandle(h2);
    }
    return TRUE;
}
