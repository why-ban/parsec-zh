// parsec-zh-launcher: injects parsec-zh.dll into Parsec as it starts.
//
// Modes:
//   parsec-zh-launcher.exe                 watch + restart Parsec, keep watching
//   parsec-zh-launcher.exe --no-restart    watch only
//   parsec-zh-launcher.exe --inject-now    inject into running Parsec, then exit
//   parsec-zh-launcher.exe <target> [args] (Image File Execution Options style)
//
// Parsec's client is normally started by the "Parsec" service, then re-executes
// itself to produce the process that actually shows the UI. The watcher injects
// the launcher process; the injected DLL hooks CreateProcess so the UI child is
// injected too, race-free.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#define DEFAULT_TARGET "C:\\Program Files\\Parsec\\parsecd.exe"

static void get_self_dir(char* out, DWORD n) {
    GetModuleFileNameA(NULL, out, n);
    char* p = strrchr(out, '\\');
    if (p) *p = 0;
}

static int file_exists(const char* p) {
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void plog(const char* fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    char log[MAX_PATH];
    GetModuleFileNameA(NULL, log, MAX_PATH);
    char* dot = strrchr(log, '.');
    size_t ll = strlen(log);
    if (dot) { if ((size_t)(dot - log) + 5 <= sizeof(log)) strcpy(dot, ".log"); }
    else if (ll + 4 < sizeof(log)) { memcpy(log + ll, ".log", 5); }
    HANDLE f = CreateFileA(log, GENERIC_READ | FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(f, NULL);
        if (sz != INVALID_FILE_SIZE && sz > (4u * 1024u * 1024u)) {
            HANDLE ft = CreateFileA(log, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (ft != INVALID_HANDLE_VALUE) { SetEndOfFile(ft); CloseHandle(ft); }
        }
        DWORD w;
        WriteFile(f, buf, (DWORD)strlen(buf), &w, NULL);
        WriteFile(f, "\r\n", 2, &w, NULL);
        CloseHandle(f);
    }
}

// Parsec's client is started by a SYSTEM service, so injecting into it needs
// SeDebugPrivilege even from an elevated shell.
static void enable_debug_priv(void) {
    HANDLE tok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) return;
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), NULL, NULL)) {
            DWORD e = GetLastError();
            if (e == ERROR_SUCCESS) plog("SeDebugPrivilege enabled");
            else plog("SeDebugPrivilege not held (err=%lu); will only inject same-user processes", e);
        }
    }
    CloseHandle(tok);
}

static int is_parsec_name(const char* n) {
    return _stricmp(n, "parsecd.exe") == 0 || _stricmp(n, "parsecd_zh.exe") == 0;
}

// A process is "the UI" only if it owns a top-level window of Parsec's window
// class (libmatoya: "MTY_Window"). The service-side/host parsecd loads the skel
// but never draws, so it must NOT count as an unlocalized UI and must never be
// killed by the self-heal. (Session number is NOT reliable: the SYSTEM host was
// observed in the user's session.)
typedef struct { DWORD pid; int found; } FindUi;
static BOOL CALLBACK enum_find_ui(HWND h, LPARAM l) {
    FindUi* f = (FindUi*)l;
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    if (pid != f->pid) return TRUE;
    wchar_t cls[64] = {0};
    if (GetClassNameW(h, cls, 63) && _wcsicmp(cls, L"MTY_Window") == 0) { f->found = 1; return FALSE; }
    return TRUE;
}
static int pid_is_ui(DWORD pid) {
    FindUi f = { pid, 0 };
    EnumWindows(enum_find_ui, (LPARAM)&f);
    return f.found;
}

// The real UI process is the one Parsec re-execs: a parsecd whose parent is also
// a parsecd. The service-side host parsecd (parent = pservice) is neither that
// nor owns a Parsec window, so it is never treated as an unlocalized UI nor
// killed. The parent check works even while the UI is silent / tray-hidden (where
// the window check alone would fail).
static int parent_is_parsecd(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD parent = 0;
    if (Process32First(snap, &pe)) {
        do { if (pe.th32ProcessID == pid) { parent = pe.th32ParentProcessID; break; } }
        while (Process32Next(snap, &pe));
    }
    int r = 0;
    if (parent) {
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do { if (pe.th32ProcessID == parent && is_parsec_name(pe.szExeFile)) { r = 1; break; } }
            while (Process32Next(snap, &pe));
        }
    }
    CloseHandle(snap);
    return r;
}
static int is_ui(DWORD pid) {
    return pid_is_ui(pid) || parent_is_parsecd(pid);
}

static int contains_ci(const char* hay, const char* needle) {
    size_t nl = strlen(needle);
    if (!nl) return 0;
    for (; *hay; hay++) if (_strnicmp(hay, needle, nl) == 0) return 1;
    return 0;
}

// Only treat a parsecd.exe that lives under a Parsec install directory as our
// target, so we never touch an unrelated same-named executable. Matching a
// "parsec" substring also handles the \Device\HarddiskVolumeN\... form that
// QueryFullProcessImageName may return for another session's process.
static int is_parsec_install(HANDLE h) {
    char path[MAX_PATH] = {0};
    DWORD n = MAX_PATH;
    if (!QueryFullProcessImageNameA(h, 0, path, &n)) return 0;
    return contains_ci(path, "parsec");
}

// Negative cache: retry a failed PID quickly a couple of times (so a UI that is
// still starting is not missed -> permanently English), then back off.
#define FAILCACHE 64
static DWORD g_fail_pid[FAILCACHE];
static DWORD g_fail_t[FAILCACHE];
static int   g_fail_n[FAILCACHE];
static int fail_recent(DWORD pid) {
    DWORD now = GetTickCount();
    for (int i = 0; i < FAILCACHE; i++)
        if (g_fail_pid[i] == pid) {
            DWORD wait = (g_fail_n[i] < 3) ? 300u : 10000u;
            return (now - g_fail_t[i]) < wait;
        }
    return 0;
}
static void fail_note(DWORD pid) {
    DWORD now = GetTickCount();
    int slot = -1;
    for (int i = 0; i < FAILCACHE; i++) {
        if (g_fail_pid[i] == pid) { slot = i; break; }
        if (slot < 0 && g_fail_pid[i] == 0) slot = i;
        if (slot < 0 && (now - g_fail_t[i]) > 10000u) slot = i;
    }
    if (slot < 0) { int o = 0; for (int i = 1; i < FAILCACHE; i++) if (g_fail_t[i] < g_fail_t[o]) o = i; slot = o; }
    if (g_fail_pid[slot] != pid) g_fail_n[slot] = 0;
    g_fail_pid[slot] = pid;
    g_fail_t[slot] = now;
    if (g_fail_n[slot] < 1000) g_fail_n[slot]++;
}

static int has_our_dll(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    int found = 0;
    if (Module32First(snap, &me)) {
        do {
            if (_stricmp(me.szModule, "parsec-zh.dll") == 0) { found = 1; break; }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

// Diagnostic-friendly injection: a small stub calls LoadLibraryW and stores both
// the result and GetLastError into the target buffer so we can read them back.
static int inject_ex(HANDLE proc, const char* dllpath, DWORD* out_err) {
    wchar_t wpath[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, dllpath, -1, wpath, MAX_PATH) <= 0) { if (out_err) *out_err = 0xDEAD; return 0; }
    SIZE_T pathBytes = (wcslen(wpath) + 1) * sizeof(wchar_t);
    SIZE_T total = 0x1000;
    unsigned char* rem = (unsigned char*)VirtualAllocEx(proc, NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!rem) { if (out_err) *out_err = GetLastError(); return 0; }
    if (!WriteProcessMemory(proc, rem, wpath, pathBytes, NULL)) { if (out_err) *out_err = GetLastError(); VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }

    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    void* llw = (void*)GetProcAddress(k32, "LoadLibraryExW");
    void* gle = (void*)GetProcAddress(k32, "GetLastError");
    void* ext = (void*)GetProcAddress(k32, "ExitThread");

    unsigned char sc[160];
    int n = 0;
    #define EMIT(...) do { unsigned char _b[] = { __VA_ARGS__ }; for (unsigned i=0;i<sizeof(_b);i++) sc[n++]=_b[i]; } while(0)
    EMIT(0x48,0x89,0xCB);                              // mov rbx, rcx        (rbx = rem)
    EMIT(0x48,0x89,0xE5);                              // mov rbp, rsp
    EMIT(0x48,0x83,0xE4,0xF0);                         // and rsp, -16
    EMIT(0x48,0x83,0xEC,0x20);                         // sub rsp, 0x20       (shadow space)
    EMIT(0x48,0x89,0xD9);                              // mov rcx, rbx        (path)
    EMIT(0x31,0xD2);                                   // xor edx, edx        (hFile = NULL)
    EMIT(0x41,0xB8,0x00,0x09,0x00,0x00);               // mov r8d, 0x900 (DLL_LOAD_DIR|SYSTEM32)
    EMIT(0x48,0xB8); *(void**)(sc+n) = llw; n += 8;    // mov rax, LoadLibraryExW
    EMIT(0xFF,0xD0);                                   // call rax
    EMIT(0x48,0x89,0x83,0x00,0x04,0x00,0x00);          // mov [rbx+0x400], rax
    EMIT(0x48,0xB8); *(void**)(sc+n) = gle; n += 8;    // mov rax, GetLastError
    EMIT(0xFF,0xD0);                                   // call rax
    EMIT(0x89,0x83,0x08,0x04,0x00,0x00);               // mov [rbx+0x408], eax
    EMIT(0x31,0xC9);                                   // xor ecx, ecx
    EMIT(0x48,0xB8); *(void**)(sc+n) = ext; n += 8;    // mov rax, ExitThread
    EMIT(0xFF,0xD0);                                   // call rax  (never returns)

    // place the stub after the (variable-length) path, aligned and bounds-checked
    SIZE_T codeOff = (pathBytes + 15) & ~(SIZE_T)15;
    if (codeOff + sizeof(sc) > total) { if (out_err) *out_err = 0xBEEF; VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }
    unsigned char* code = rem + codeOff;
    if (!WriteProcessMemory(proc, code, sc, n, NULL)) { if (out_err) *out_err = GetLastError(); VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }

    HANDLE th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)code, rem, 0, NULL);
    if (!th) { if (out_err) *out_err = GetLastError(); VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }
    DWORD w = WaitForSingleObject(th, 20000);
    CloseHandle(th);
    if (w != WAIT_OBJECT_0) { if (out_err) *out_err = 0xFFFF; return 0; }

    // load result from rem (we stored hmod at rem+0x400 offset by construction)
    void* hmod = NULL; DWORD err = 0;
    SIZE_T got = 0;
    // recompute: result slots are at code+0x40+? -> we wrote to [rbx+0x400]
    ReadProcessMemory(proc, rem + 0x400, &hmod, sizeof(hmod), &got);
    ReadProcessMemory(proc, rem + 0x408, &err, sizeof(err), &got);
    if (out_err) *out_err = err;
    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    return hmod != NULL;
}

static int inject(HANDLE proc, const char* dllpath) {
    wchar_t wpath[MAX_PATH];
    if (MultiByteToWideChar(CP_ACP, 0, dllpath, -1, wpath, MAX_PATH) <= 0) return 0;
    SIZE_T sz = (wcslen(wpath) + 1) * sizeof(wchar_t);
    void* rem = VirtualAllocEx(proc, NULL, sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!rem) { plog("  VirtualAllocEx failed err=%lu", GetLastError()); return 0; }
    if (!WriteProcessMemory(proc, rem, wpath, sz, NULL)) { plog("  WriteProcessMemory failed err=%lu", GetLastError()); VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }
    FARPROC llw = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");
    if (!llw) { plog("  LoadLibraryW addr not found"); VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }
    HANDLE th = CreateRemoteThread(proc, NULL, 0, (LPTHREAD_START_ROUTINE)llw, rem, 0, NULL);
    if (!th) { plog("  CreateRemoteThread failed err=%lu", GetLastError()); VirtualFreeEx(proc, rem, 0, MEM_RELEASE); return 0; }
    DWORD w = WaitForSingleObject(th, 20000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    CloseHandle(th);
    if (w != WAIT_OBJECT_0) { plog("  thread wait timeout/err %lu", w); return 0; }  // leak rem on timeout (safe)
    VirtualFreeEx(proc, rem, 0, MEM_RELEASE);
    if (code == 0) { plog("  LoadLibraryW returned 0"); return 0; }
    return 1;
}

static int already_injected(DWORD pid) {
    char name[64];
    _snprintf(name, sizeof(name), "Local\\parsec-zh-ready-%lu", (unsigned long)pid);
    HANDLE ev = OpenEventA(SYNCHRONIZE, FALSE, name);
    if (ev) { CloseHandle(ev); return 1; }
    return 0;
}

static int inject_all(const char* dll) {
    DWORD now = GetTickCount();

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD self = GetCurrentProcessId();
    int n = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self) continue;
            if (!is_parsec_name(pe.szExeFile)) continue;
            if (fail_recent(pe.th32ProcessID)) continue;
            // Fast "already injected?" test: the injected DLL keeps a per-PID event
            // open for its whole lifetime, so its existence is authoritative and
            // far cheaper than a module snapshot (which used to make us lose the
            // race against the skel load).
            if (already_injected(pe.th32ProcessID)) continue;
            if (has_our_dll(pe.th32ProcessID)) continue;

            HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                                   PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
            if (h) {
                if (!is_parsec_install(h)) {
                    fail_note(pe.th32ProcessID);
                    CloseHandle(h); continue;
                }
                DWORD ierr = 0;
                if (inject_ex(h, dll, &ierr)) { n++; plog("injected pid=%lu (%s)", pe.th32ProcessID, pe.szExeFile); }
                else { fail_note(pe.th32ProcessID); plog("inject FAILED pid=%lu (%s) target_lasterr=%lu", pe.th32ProcessID, pe.szExeFile, ierr); }
                CloseHandle(h);
            } else {
                fail_note(pe.th32ProcessID);
                plog("OpenProcess denied pid=%lu (%s) err=%lu", pe.th32ProcessID, pe.szExeFile, GetLastError());
            }
            (void)now;
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return n;
}

static int has_localized(DWORD pid) {
    char n[64];
    _snprintf(n, sizeof(n), "Local\\parsec-zh-localized-%lu", (unsigned long)pid);
    HANDLE e = OpenEventA(SYNCHRONIZE, FALSE, n);
    if (e) { CloseHandle(e); return 1; }
    return 0;
}
static int proc_has_skel(DWORD pid);

// Process age in ms (0xFFFFFFFF if unknown). Used as a start-up grace period so
// the self-heal does not restart a UI that simply has not finished loading.
static DWORD proc_age_ms(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0xFFFFFFFF;
    FILETIME c, e, k, u;
    DWORD age = 0xFFFFFFFF;
    if (GetProcessTimes(h, &c, &e, &k, &u)) {
        ULARGE_INTEGER t, now;
        t.LowPart = c.dwLowDateTime; t.HighPart = c.dwHighDateTime;
        GetSystemTimeAsFileTime((FILETIME*)&now);
        if (now.QuadPart > t.QuadPart) age = (DWORD)((now.QuadPart - t.QuadPart) / 10000ULL);
    }
    CloseHandle(h);
    return age;
}

static DWORD unlocalized_ui_pid(void) {   // the English UI process, or 0
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD r = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (is_parsec_name(pe.szExeFile) && is_ui(pe.th32ProcessID) &&
                proc_has_skel(pe.th32ProcessID) &&
                !has_localized(pe.th32ProcessID) &&
                proc_age_ms(pe.th32ProcessID) >= 6000) { r = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return r;
}

static void kill_pid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) { TerminateProcess(h, 0); CloseHandle(h); }
}

// kill all client processes (used only by the explicit --start path).
static void kill_parsecd(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe; pe.dwSize = sizeof(pe);
    DWORD self = GetCurrentProcessId();
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == self) continue;
            if (is_parsec_name(pe.szExeFile)) kill_pid(pe.th32ProcessID);
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

// Runs concurrently with the watcher. Whenever an English UI exists it restarts
// JUST that instance. Re-armed for each new PID and bounded per instance, so it
// never spins and never kills the windowless service-side host.
static DWORD WINAPI self_heal_thread(LPVOID p) {
    (void)p;
    DWORD killed[8];
    int nkilled = 0;
    for (;;) {
        DWORD pid = unlocalized_ui_pid();
        if (pid) {
            int seen = 0;
            for (int i = 0; i < nkilled; i++) if (killed[i] == pid) { seen = 1; break; }
            if (!seen && nkilled < 3) {
                plog("self-heal: restarting unlocalized UI pid=%lu (attempt %d)", pid, nkilled);
                killed[nkilled++] = pid;
                kill_pid(pid);
            }
        }
        Sleep(3000);
    }
    return 0;
}

static int proc_has_skel(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    MODULEENTRY32 me; me.dwSize = sizeof(me);
    int found = 0;
    if (Module32First(snap, &me)) {
        do {
            size_t L = strlen(me.szModule);
            if (_strnicmp(me.szModule, "parsecd-", 8) == 0 && L >= 4 &&
                _stricmp(me.szModule + L - 4, ".dll") == 0) { found = 1; break; }
        } while (Module32Next(snap, &me));
    }
    CloseHandle(snap);
    return found;
}

int main(int argc, char** argv) {
    // Never show a console window. Built with -mwindows so there is normally no
    // console at all; hiding it is a belt-and-suspenders for other build configs.
    { HWND cw = GetConsoleWindow(); if (cw) ShowWindow(cw, SW_HIDE); }
    int watch = 1;
    int restart = 1;
    int start_mode = 0;
    DWORD inject_pid = 0;
    const char* inject_dll = NULL;
    const char* target = DEFAULT_TARGET;

    for (int i = 1; i < argc; i++) {
        if (_stricmp(argv[i], "--no-restart") == 0) restart = 0;
        else if (_stricmp(argv[i], "--inject-now") == 0) watch = 0;
        else if (_stricmp(argv[i], "--start") == 0) { start_mode = 1; watch = 0; }
        else if (_stricmp(argv[i], "--inject-pid") == 0 && i + 1 < argc) {
            inject_pid = (DWORD)strtoul(argv[++i], NULL, 10);
        }
        else if (_stricmp(argv[i], "--inject-dll") == 0 && i + 1 < argc) {
            inject_dll = argv[++i];
        }
        else if (file_exists(argv[i])) {
            size_t L = strlen(argv[i]);
            if (L > 4 && _stricmp(argv[i] + L - 4, ".exe") == 0) target = argv[i];
        }
    }

    char selfdir[MAX_PATH], dll[MAX_PATH];
    get_self_dir(selfdir, sizeof(selfdir));
    // Parsec's client sets BlockRemoteImageLoads and restricts the load path, so
    // the runtime DLL must live under C:\Windows. Keep the "-zh" copy there.
    _snprintf(dll, sizeof(dll), "C:\\Windows\\parsec-zh\\parsec-zh.dll");
    if (!file_exists(dll)) {
        _snprintf(dll, sizeof(dll), "%s\\parsec-zh.dll", selfdir);
    }
    if (!file_exists(dll)) {
        char msg[1024];
        _snprintf(msg, sizeof(msg), "parsec-zh.dll not found:\n%s", dll);
        MessageBoxA(NULL, msg, "parsec-zh", MB_ICONERROR);
        return 1;
    }

    if (inject_pid) {
        enable_debug_priv();
        const char* use = inject_dll ? inject_dll : dll;
        HANDLE h = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                               PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, inject_pid);
        if (!h) { plog("inject-pid: OpenProcess(%lu) failed err=%lu", inject_pid, GetLastError()); return 1; }
        DWORD ie = 0;
        int r = inject_ex(h, use, &ie);
        plog("inject-pid %lu dll=%s -> %d (target_lasterr=%lu)", inject_pid, use, r, ie);
        CloseHandle(h);
        return r ? 0 : 1;
    }

    if (!watch) {
        enable_debug_priv();
        if (start_mode) {
            kill_parsecd();
            Sleep(600);
            char cmdline[32768];
            _snprintf(cmdline, sizeof(cmdline), "\"%s\"", target);
            for (int i = 1; i < argc; i++) {
                if (_stricmp(argv[i], "--start") == 0 || _stricmp(argv[i], target) == 0) continue;
                if (argv[i][0] == '-') continue;
                strncat(cmdline, " ", sizeof(cmdline) - strlen(cmdline) - 1);
                strncat(cmdline, argv[i], sizeof(cmdline) - strlen(cmdline) - 1);
            }
            STARTUPINFOA si; PROCESS_INFORMATION pi;
            memset(&si, 0, sizeof(si)); si.cb = sizeof(si);
            memset(&pi, 0, sizeof(pi));
            if (CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, selfdir, &si, &pi)) {
                plog("started pid=%lu cmd=%s", pi.dwProcessId, cmdline);
                if (!inject(pi.hProcess, dll)) plog("start-inject FAILED");
                {
                    char rn[96];
                    _snprintf(rn, sizeof(rn), "Local\\parsec-zh-ready-%lu", (unsigned long)pi.dwProcessId);
                    HANDLE ev = NULL;
                    for (int i = 0; i < 200 && !ev; i++) { ev = OpenEventA(SYNCHRONIZE, FALSE, rn); if (!ev) Sleep(10); }
                    if (ev) { WaitForSingleObject(ev, 8000); CloseHandle(ev); plog("ready event signalled"); }
                    else plog("ready event not open");
                }
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            } else {
                plog("CreateProcess failed err=%lu cmd=%s", GetLastError(), cmdline);
            }
            return 0;
        }
        inject_all(dll);
        return 0;
    }

    // Single instance per session: a second watcher would double-inject and run a
    // second self-heal, restarting the client twice.
    HANDLE one = CreateMutexA(NULL, FALSE, "Local\\parsec-zh-launcher");
    if (one && GetLastError() == ERROR_ALREADY_EXISTS) {
        return 0;   // another instance is running; exit quietly (the 2-min task pokes us often)
    }
    enable_debug_priv();   // only the resident instance logs; task pokes exit silently above

    // Start the watcher immediately; run the self-heal concurrently so it never
    // blocks injection (localization is what makes the heal succeed). --no-restart
    // disables the heal so the caller fully controls when Parsec is restarted.
    if (restart) {
        HANDLE hh = CreateThread(NULL, 0, self_heal_thread, NULL, 0, NULL);
        if (hh) CloseHandle(hh);
    }

    // Stay resident: inject every Parsec process that appears (including the UI
    // child, if the DLL's CreateProcess hook could not run early enough). Poll
    // aggressively for the first minute (start-up race) then relax to save CPU.
    {
        DWORD started = GetTickCount();
        for (;;) {
            inject_all(dll);
            DWORD age = GetTickCount() - started;
            Sleep(age < 60000 ? 2 : 200);
        }
    }
    return 0;
}
