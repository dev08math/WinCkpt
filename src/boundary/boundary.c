// The upper half's calls into the OS DLLs. Pure-memory state is pulled into the
// arena here; calls that create kernel objects are only detected for now.
//
// TODO: minimal on purpose, with known defects.
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
    "GetProcAddress", "GetStdHandle", "EncodePointer",
    "SetCurrentDirectoryA", "SetCurrentDirectoryW",
    "SetEnvironmentVariableA", "SetEnvironmentVariableW", "SetConsoleMode",
};
static const char *g_seen[sizeof g_unhandled / sizeof g_unhandled[0]];
static int         g_n_seen;

int boundary_init(ULONGLONG emu_at)
{
    if (sizeof(Emu) > EMU_SIZE) {
        fprintf(stderr, "boundary: Emu is %zu bytes, EMU_SIZE is %llu\n", sizeof(Emu), EMU_SIZE);
        return 0;
    }
    if (!VirtualAlloc((LPVOID)emu_at, (SIZE_T)EMU_SIZE, MEM_COMMIT, PAGE_READWRITE)) {
        fprintf(stderr, "boundary: EMU commit at 0x%llX failed, err=%lu\n", emu_at, GetLastError());
        return 0;
    }
    g_emu = (Emu *)emu_at;
    memset(g_emu, 0, sizeof *g_emu);
    return 1;
}

void boundary_adopt(ULONGLONG emu_at)
{
    g_emu = (Emu *)emu_at;
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

static const struct {
    const char *name;
    void       *fn;
} g_hooks[] = {
    { "GetProcessHeap",  (void *)arena_heap_handle    },
    { "HeapAlloc",       (void *)arena_heap_alloc     },
    { "HeapFree",        (void *)arena_heap_free      },
    { "HeapReAlloc",     (void *)arena_heap_realloc   },
    { "HeapSize",        (void *)arena_heap_size      },
    { "ExitProcess",     (void *)hook_ExitProcess     },
    { "FlsAlloc",        (void *)hook_FlsAlloc        },
    { "FlsFree",         (void *)hook_FlsFree         },
    { "FlsGetValue",     (void *)hook_FlsGetValue     },
    { "FlsSetValue",     (void *)hook_FlsSetValue     },
    { "TlsAlloc",        (void *)hook_TlsAlloc        },
    { "TlsFree",         (void *)hook_TlsFree         },
    { "TlsGetValue",     (void *)hook_TlsGetValue     },
    { "TlsSetValue",     (void *)hook_TlsSetValue     },
    { "GetCommandLineA", (void *)hook_GetCommandLineA },
    { "GetCommandLineW", (void *)hook_GetCommandLineW },
};

void *boundary_hook(const char *import_name)
{
    for (int i = 0; i < (int)(sizeof g_hooks / sizeof g_hooks[0]); i++)
        if (strcmp(import_name, g_hooks[i].name) == 0) return g_hooks[i].fn;

    for (int i = 0; i < (int)(sizeof g_unhandled / sizeof g_unhandled[0]); i++)
        if (strcmp(import_name, g_unhandled[i]) == 0 &&
            g_n_seen < (int)(sizeof g_seen / sizeof g_seen[0]))
            g_seen[g_n_seen++] = g_unhandled[i];
    return NULL;
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
