// The upper half's calls into the OS DLLs. Pure-memory state is pulled into the
// arena here; calls that create kernel objects are only detected for now.
//
// TODO:
//   - Fls/Tls emulation keeps one value per slot for the whole process; it
//     must become per thread once the upper half runs more than one thread
//   - FLS callbacks run on FlsFree only, never at thread exit
//   - calls in g_unhandled are reported at load, not logged or replayed

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "boundary.h"
#include "arena.h"
#include "log.h"

static Emu     *g_emu;
static Image  **g_detach;
static int      g_n_detach;
static exit_fn  g_on_exit;

static const char *g_unhandled[] = {
    "CreateFileA", "CreateFileW", "CreateFile2",
    "CreatePipe", "CreateNamedPipeA", "CreateNamedPipeW",
    "CreateEventA", "CreateEventW", "CreateEventExA", "CreateEventExW",
    "CreateMutexA", "CreateMutexW", "CreateSemaphoreA", "CreateSemaphoreW",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "MapViewOfFileEx",
    "VirtualAlloc", "VirtualAllocEx", "HeapCreate",
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
    "GetStdHandle", "EncodePointer",
    "SetCurrentDirectoryA", "SetCurrentDirectoryW",
    "SetEnvironmentVariableA", "SetEnvironmentVariableW", "SetConsoleMode",
};
static const char *g_seen[sizeof g_unhandled / sizeof g_unhandled[0]];
static int         g_n_seen;

static HANDLE g_stale[3];
static int    g_n_stale;

#define STUB_OFF  (EMU_SIZE - PAGE)
#define STUB_SIZE 16

static int  protect_stubs(void);
static void write_stubs(void);
static int  refresh_modules_and_procs(void);

int boundary_init(ULONGLONG emu_at)
{
    if (sizeof(Emu) > STUB_OFF) {
        fprintf(stderr, "boundary: Emu is %zu bytes, room is %llu\n", sizeof(Emu), STUB_OFF);
        return 0;
    }
    if (!VirtualAlloc((LPVOID)emu_at, (SIZE_T)EMU_SIZE, MEM_COMMIT, PAGE_READWRITE)) {
        fprintf(stderr, "boundary: EMU commit at 0x%llX failed, err=%lu\n", emu_at, GetLastError());
        return 0;
    }
    g_emu = (Emu *)emu_at;
    memset(g_emu, 0, sizeof *g_emu);
    write_stubs();
    return protect_stubs();
}

int boundary_adopt(ULONGLONG emu_at)
{
    g_emu = (Emu *)emu_at;
    return protect_stubs() && refresh_modules_and_procs();
}

void boundary_on_exit(Image **detach_order, int n, exit_fn on_exit)
{
    g_detach   = detach_order;
    g_n_detach = n;
    g_on_exit  = on_exit;
}

static void WINAPI hook_ExitProcess(UINT code)
{
    // The CRT copies flush stdout and run their cleanup in DllMain(PROCESS_DETACH),
    // which Windows never calls for images it did not load.
    for (int i = 0; i < g_n_detach; i++)
        loader_dll_main(g_detach[i], DLL_PROCESS_DETACH);
    if (g_on_exit) g_on_exit(code);
    ExitProcess(code);
}

static BOOL WINAPI hook_CloseHandle(HANDLE h)
{
    for (int i = 0; i < g_n_stale; i++)
        if (h == g_stale[i]) return TRUE;
    return CloseHandle(h);
}

static int slot_ok(const int *used, DWORD i)
{
    if (i < EMU_SLOTS && used[i]) return 1;
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
}

static DWORD WINAPI hook_FlsAlloc(PFLS_CALLBACK_FUNCTION cb)
{
    for (DWORD i = 0; i < EMU_SLOTS; i++) {
        if (g_emu->fls_used[i]) continue;
        g_emu->fls_used[i] = 1;
        g_emu->fls_cb[i]   = cb;
        g_emu->fls_val[i]  = NULL;
        return i;
    }
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FLS_OUT_OF_INDEXES;
}

static BOOL WINAPI hook_FlsFree(DWORD i)
{
    if (!slot_ok(g_emu->fls_used, i)) return FALSE;
    if (g_emu->fls_cb[i] && g_emu->fls_val[i]) g_emu->fls_cb[i](g_emu->fls_val[i]);
    g_emu->fls_used[i] = 0;
    return TRUE;
}

static PVOID WINAPI hook_FlsGetValue(DWORD i)
{
    if (!slot_ok(g_emu->fls_used, i)) return NULL;
    SetLastError(ERROR_SUCCESS);
    return g_emu->fls_val[i];
}

static PVOID WINAPI hook_FlsGetValue2(DWORD i)
{
    if (i >= EMU_SLOTS || !g_emu->fls_used[i]) return NULL;
    return g_emu->fls_val[i];
}

static BOOL WINAPI hook_FlsSetValue(DWORD i, PVOID v)
{
    if (!slot_ok(g_emu->fls_used, i)) return FALSE;
    g_emu->fls_val[i] = v;
    return TRUE;
}

static DWORD WINAPI hook_TlsAlloc(void)
{
    for (DWORD i = 0; i < EMU_SLOTS; i++) {
        if (g_emu->tls_used[i]) continue;
        g_emu->tls_used[i] = 1;
        g_emu->tls_val[i]  = NULL;
        return i;
    }
    SetLastError(ERROR_NO_MORE_ITEMS);
    return TLS_OUT_OF_INDEXES;
}

static BOOL WINAPI hook_TlsFree(DWORD i)
{
    if (!slot_ok(g_emu->tls_used, i)) return FALSE;
    g_emu->tls_used[i] = 0;
    return TRUE;
}

static LPVOID WINAPI hook_TlsGetValue(DWORD i)
{
    if (!slot_ok(g_emu->tls_used, i)) return NULL;
    SetLastError(ERROR_SUCCESS);
    return g_emu->tls_val[i];
}

static BOOL WINAPI hook_TlsSetValue(DWORD i, LPVOID v)
{
    if (!slot_ok(g_emu->tls_used, i)) return FALSE;
    g_emu->tls_val[i] = v;
    return TRUE;
}

static LPSTR WINAPI hook_GetCommandLineA(void)
{
    if (!g_emu->cmdline_a) {
        const char *src = GetCommandLineA();
        size_t n = strlen(src) + 1;
        g_emu->cmdline_a = (char *)arena_malloc(n);
        if (g_emu->cmdline_a) memcpy(g_emu->cmdline_a, src, n);
    }
    return g_emu->cmdline_a;
}

static LPWSTR WINAPI hook_GetCommandLineW(void)
{
    if (!g_emu->cmdline_w) {
        const WCHAR *src = GetCommandLineW();
        size_t n = (wcslen(src) + 1) * sizeof(WCHAR);
        g_emu->cmdline_w = (WCHAR *)arena_malloc(n);
        if (g_emu->cmdline_w) memcpy(g_emu->cmdline_w, src, n);
    }
    return g_emu->cmdline_w;
}

static void *find_hook(const char *name);

static BYTE *stub_page(void)
{
    return (BYTE *)g_emu + STUB_OFF;
}

static int protect_stubs(void)
{
    DWORD old = 0;
    if (!VirtualProtect(stub_page(), (SIZE_T)PAGE, PAGE_EXECUTE_READ, &old)) {
        fprintf(stderr, "boundary: stub page protect failed, err=%lu\n", GetLastError());
        return 0;
    }
    return 1;
}

static void write_stubs(void)
{
    for (int i = 0; i < EMU_PROCS; i++) {
        BYTE *s = stub_page() + i * STUB_SIZE;
        LONG disp = (LONG)((BYTE *)&g_emu->proc[i].target - (s + 6));
        s[0] = 0xFF;
        s[1] = 0x25;
        memcpy(s + 2, &disp, sizeof disp);
        memset(s + 6, 0xCC, STUB_SIZE - 6);
    }
}

static int in_arena(HMODULE h)
{
    ULONGLONG a = (ULONGLONG)h;
    ULONGLONG base = (ULONGLONG)g_emu - EMU_OFF;
    return a >= base && a < base + ARENA_SIZE;
}

static int record_module(HMODULE h)
{
    if (!h || in_arena(h)) return -1;
    for (int i = 0; i < g_emu->n_mod; i++)
        if (g_emu->mod[i].saved == h) return i;
    if (g_emu->n_mod == EMU_MODULES) {
        fprintf(stderr, "boundary: module table full, 0x%p not recorded\n", (void *)h);
        return -1;
    }
    EmuModule *m = &g_emu->mod[g_emu->n_mod];
    if (!GetModuleFileNameW(h, m->path, MAX_PATH)) return -1;
    m->saved = h;
    m->now   = h;
    return g_emu->n_mod++;
}

static HMODULE module_now(HMODULE h)
{
    for (int i = 0; i < g_emu->n_mod; i++)
        if (g_emu->mod[i].saved == h) return g_emu->mod[i].now;
    return h;
}

// After a reboot a live handle can equal a value saved for another module;
// GetProcAddress would then be sent to the wrong module.
static HMODULE remember(HMODULE h)
{
    for (int i = 0; i < g_emu->n_mod; i++)
        if (g_emu->mod[i].saved == h && g_emu->mod[i].now != h)
            fprintf(stderr, "boundary: module 0x%p is live, but also saved for %ls\n",
                    (void *)h, g_emu->mod[i].path);
    record_module(h);
    return h;
}

static void *proc_stub(int m, LPCSTR name, void *target)
{
    if (m < 0) return NULL;
    WORD ord = IS_INTRESOURCE(name) ? (WORD)(ULONG_PTR)name : 0;
    for (int i = 0; i < g_emu->n_proc; i++) {
        EmuProc *p = &g_emu->proc[i];
        if (p->module == m && (ord ? p->ordinal == ord : strcmp(p->name, name) == 0))
            return stub_page() + i * STUB_SIZE;
    }
    if (g_emu->n_proc == EMU_PROCS || (!ord && strlen(name) >= sizeof g_emu->proc[0].name)) {
        fprintf(stderr, "boundary: no stub for %s, its address will not survive a reboot\n",
                ord ? "an ordinal" : name);
        return NULL;
    }
    EmuProc *p = &g_emu->proc[g_emu->n_proc];
    p->module  = m;
    p->ordinal = ord;
    if (!ord) strcpy(p->name, name);
    p->target  = (ULONGLONG)target;
    return stub_page() + g_emu->n_proc++ * STUB_SIZE;
}

static int refresh_modules_and_procs(void)
{
    for (int i = 0; i < g_emu->n_mod; i++) {
        EmuModule *m = &g_emu->mod[i];
        m->now = LoadLibraryW(m->path);
        if (!m->now) {
            fprintf(stderr, "boundary: reload of %ls failed, err=%lu\n", m->path, GetLastError());
            return 0;
        }
    }
    for (int i = 0; i < g_emu->n_proc; i++) {
        EmuProc *p = &g_emu->proc[i];
        LPCSTR name = p->ordinal ? (LPCSTR)(ULONG_PTR)p->ordinal : p->name;
        void *ours = p->ordinal ? NULL : find_hook(p->name);
        void *real = (void *)GetProcAddress(g_emu->mod[p->module].now, name);
        if (!real) {
            fprintf(stderr, "boundary: %s not found in %ls\n",
                    p->ordinal ? "an ordinal" : p->name, g_emu->mod[p->module].path);
            return 0;
        }
        p->target = (ULONGLONG)(ours ? ours : real);
    }
    VLOG("boundary: %d module(s), %d GetProcAddress stub(s) re-resolved\n",
         g_emu->n_mod, g_emu->n_proc);
    return 1;
}

static FARPROC WINAPI hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC real = GetProcAddress(module_now(mod), name);
    if (!real) return NULL;
    void *ours   = IS_INTRESOURCE(name) ? NULL : find_hook(name);
    void *target = ours ? ours : (void *)real;
    void *stub   = proc_stub(record_module(mod), name, target);
    return (FARPROC)(stub ? stub : target);
}

static HMODULE WINAPI hook_LoadLibraryA(LPCSTR name)
{
    return remember(LoadLibraryA(name));
}

static HMODULE WINAPI hook_LoadLibraryW(LPCWSTR name)
{
    return remember(LoadLibraryW(name));
}

static HMODULE WINAPI hook_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
    return remember(LoadLibraryExA(name, file, flags));
}

static HMODULE WINAPI hook_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    return remember(LoadLibraryExW(name, file, flags));
}

static HMODULE WINAPI hook_GetModuleHandleA(LPCSTR name)
{
    return remember(GetModuleHandleA(name));
}

static HMODULE WINAPI hook_GetModuleHandleW(LPCWSTR name)
{
    return remember(GetModuleHandleW(name));
}

static BOOL WINAPI hook_GetModuleHandleExA(DWORD flags, LPCSTR name, HMODULE *out)
{
    if (!GetModuleHandleExA(flags, name, out)) return FALSE;
    remember(*out);
    return TRUE;
}

static BOOL WINAPI hook_GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE *out)
{
    if (!GetModuleHandleExW(flags, name, out)) return FALSE;
    remember(*out);
    return TRUE;
}

static BOOL WINAPI hook_FreeLibrary(HMODULE h)
{
    return FreeLibrary(module_now(h));
}

static void WINAPI hook_FreeLibraryAndExitThread(HMODULE h, DWORD code)
{
    FreeLibraryAndExitThread(module_now(h), code);
}

static DWORD WINAPI hook_GetModuleFileNameA(HMODULE h, LPSTR out, DWORD size)
{
    return GetModuleFileNameA(module_now(h), out, size);
}

static DWORD WINAPI hook_GetModuleFileNameW(HMODULE h, LPWSTR out, DWORD size)
{
    return GetModuleFileNameW(module_now(h), out, size);
}

static const struct {
    const char *name;
    void       *fn;
} g_hooks[] = {
    { "GetProcessHeap",           (void *)arena_heap_handle             },
    { "HeapAlloc",                (void *)arena_heap_alloc              },
    { "HeapFree",                 (void *)arena_heap_free               },
    { "HeapReAlloc",              (void *)arena_heap_realloc            },
    { "HeapSize",                 (void *)arena_heap_size               },
    { "ExitProcess",              (void *)hook_ExitProcess              },
    { "CloseHandle",              (void *)hook_CloseHandle              },
    { "FlsAlloc",                 (void *)hook_FlsAlloc                 },
    { "FlsFree",                  (void *)hook_FlsFree                  },
    { "FlsGetValue",              (void *)hook_FlsGetValue              },
    { "FlsGetValue2",             (void *)hook_FlsGetValue2             },
    { "FlsSetValue",              (void *)hook_FlsSetValue              },
    { "TlsAlloc",                 (void *)hook_TlsAlloc                 },
    { "TlsFree",                  (void *)hook_TlsFree                  },
    { "TlsGetValue",              (void *)hook_TlsGetValue              },
    { "TlsSetValue",              (void *)hook_TlsSetValue              },
    { "GetCommandLineA",          (void *)hook_GetCommandLineA          },
    { "GetCommandLineW",          (void *)hook_GetCommandLineW          },
    { "GetProcAddress",           (void *)hook_GetProcAddress           },
    { "LoadLibraryA",             (void *)hook_LoadLibraryA             },
    { "LoadLibraryW",             (void *)hook_LoadLibraryW             },
    { "LoadLibraryExA",           (void *)hook_LoadLibraryExA           },
    { "LoadLibraryExW",           (void *)hook_LoadLibraryExW           },
    { "GetModuleHandleA",         (void *)hook_GetModuleHandleA         },
    { "GetModuleHandleW",         (void *)hook_GetModuleHandleW         },
    { "GetModuleHandleExA",       (void *)hook_GetModuleHandleExA       },
    { "GetModuleHandleExW",       (void *)hook_GetModuleHandleExW       },
    { "FreeLibrary",              (void *)hook_FreeLibrary              },
    { "FreeLibraryAndExitThread", (void *)hook_FreeLibraryAndExitThread },
    { "GetModuleFileNameA",       (void *)hook_GetModuleFileNameA       },
    { "GetModuleFileNameW",       (void *)hook_GetModuleFileNameW       },
};

static void *find_hook(const char *name)
{
    for (int i = 0; i < (int)(sizeof g_hooks / sizeof g_hooks[0]); i++)
        if (strcmp(name, g_hooks[i].name) == 0) return g_hooks[i].fn;
    return NULL;
}

void *boundary_hook(const char *import_name)
{
    for (int i = 0; i < (int)(sizeof g_unhandled / sizeof g_unhandled[0]); i++)
        if (strcmp(import_name, g_unhandled[i]) == 0 &&
            g_n_seen < (int)(sizeof g_seen / sizeof g_seen[0]))
            g_seen[g_n_seen++] = g_unhandled[i];
    return find_hook(import_name);
}

typedef intptr_t (__cdecl *get_osfhandle_fn)(int fd);
typedef int      (__cdecl *close_fn)(int fd);
typedef int      (__cdecl *open_osfhandle_fn)(intptr_t h, int flags);
typedef int      (__cdecl *dup2_fn)(int from, int to);

// fd 0-2 of the CRT copy hold handle values of the process that was checkpointed.
// In this process those values are invalid or name some other object, so the CRT's
// own _close must not reach CloseHandle with them.
int boundary_rebind_std(const Image *ucrt)
{
    get_osfhandle_fn  get_h = (get_osfhandle_fn)loader_export(ucrt, "_get_osfhandle", 0);
    close_fn          close = (close_fn)loader_export(ucrt, "_close", 0);
    open_osfhandle_fn open  = (open_osfhandle_fn)loader_export(ucrt, "_open_osfhandle", 0);
    dup2_fn           dup2  = (dup2_fn)loader_export(ucrt, "_dup2", 0);
    if (!get_h || !close || !open || !dup2) {
        fprintf(stderr, "boundary: %s lacks _get_osfhandle/_close/_open_osfhandle/_dup2\n",
                ucrt->name);
        return 0;
    }

    // The CRT's _close of fd 0-2 also calls SetStdHandle(..., NULL).
    HANDLE std[3];
    for (int fd = 0; fd < 3; fd++)
        std[fd] = GetStdHandle((DWORD)(-10 - fd));

    int was_open[3];
    g_n_stale = 0;
    for (int fd = 0; fd < 3; fd++) {
        intptr_t h = get_h(fd);
        was_open[fd] = h != -1 && h != -2;
        if (was_open[fd]) g_stale[g_n_stale++] = (HANDLE)h;
    }
    for (int fd = 0; fd < 3; fd++)
        if (was_open[fd]) close(fd);
    g_n_stale = 0;

    for (int fd = 0; fd < 3; fd++) {
        if (!was_open[fd]) continue;
        if (std[fd] == NULL || std[fd] == INVALID_HANDLE_VALUE) {
            VLOG("boundary: fd %d left closed, this process has no std handle for it\n", fd);
            continue;
        }
        HANDLE dup = NULL;
        if (!DuplicateHandle(GetCurrentProcess(), std[fd], GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) {
            fprintf(stderr, "boundary: DuplicateHandle for fd %d failed, err=%lu\n", fd, GetLastError());
            return 0;
        }
        int got = open((intptr_t)dup, 0);
        if (got < 0) {
            fprintf(stderr, "boundary: _open_osfhandle for fd %d failed\n", fd);
            CloseHandle(dup);
            return 0;
        }
        if (got != fd) {
            int moved = dup2(got, fd);
            close(got);
            if (moved != 0) {
                fprintf(stderr, "boundary: _dup2(%d, %d) failed\n", got, fd);
                return 0;
            }
        }
        VLOG("boundary: fd %d rebound to handle 0x%p\n", fd, dup);
    }
    return 1;
}

void boundary_report(const char *module)
{
    if (g_n_seen == 0) return;
    printf("boundary: WARNING %s imports %d call(s) whose state does not survive a restart yet:",
           module, g_n_seen);
    for (int i = 0; i < g_n_seen; i++) printf(" %s", g_seen[i]);
    printf("\n");
    g_n_seen = 0;
}
