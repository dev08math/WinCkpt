#include <windows.h>

#include "arena.h"

static HANDLE WINAPI hook_GetProcessHeap(void)
{
    return arena_heap();
}

static LPVOID WINAPI hook_HeapAlloc(HANDLE heap, DWORD flags, SIZE_T n)
{
    if (heap != arena_heap()) return HeapAlloc(heap, flags, n);
    return arena_heap_alloc(flags, n);
}

static BOOL WINAPI hook_HeapFree(HANDLE heap, DWORD flags, LPVOID p)
{
    if (heap != arena_heap()) return HeapFree(heap, flags, p);
    arena_free(p);
    return TRUE;
}

static LPVOID WINAPI hook_HeapReAlloc(HANDLE heap, DWORD flags, LPVOID p, SIZE_T n)
{
    if (heap != arena_heap()) return HeapReAlloc(heap, flags, p, n);
    return arena_heap_realloc(flags, p, n);
}

static SIZE_T WINAPI hook_HeapSize(HANDLE heap, DWORD flags, LPCVOID p)
{
    if (heap != arena_heap()) return HeapSize(heap, flags, p);
    if (!p) return (SIZE_T)-1;
    return arena_size(p);
}

static int is_self(HANDLE process)
{
    return process == NULL || GetProcessId(process) == GetCurrentProcessId();
}

static LPVOID WINAPI hook_VirtualAlloc(LPVOID at, SIZE_T n, DWORD type, DWORD prot)
{
    LPVOID p = VirtualAlloc(at, n, type, prot);
    if (p && (type & MEM_RESERVE || !at)) arena_outside_record(p, "VirtualAlloc");
    return p;
}

static LPVOID WINAPI hook_VirtualAllocEx(HANDLE process, LPVOID at, SIZE_T n, DWORD type, DWORD prot)
{
    LPVOID p = VirtualAllocEx(process, at, n, type, prot);
    if (p && is_self(process) && (type & MEM_RESERVE || !at)) arena_outside_record(p, "VirtualAllocEx");
    return p;
}

typedef PVOID (WINAPI *virtual_alloc2_fn)(HANDLE, PVOID, SIZE_T, ULONG, ULONG,
                                          MEM_EXTENDED_PARAMETER *, ULONG);

// Looked up, not imported: older Windows has no VirtualAlloc2.
static PVOID WINAPI hook_VirtualAlloc2(HANDLE process, PVOID at, SIZE_T n, ULONG type, ULONG prot,
                                       MEM_EXTENDED_PARAMETER *ext, ULONG n_ext)
{
    virtual_alloc2_fn real = (virtual_alloc2_fn)GetProcAddress(
        GetModuleHandleW(L"kernelbase.dll"), "VirtualAlloc2");
    PVOID p = real(process, at, n, type, prot, ext, n_ext);
    if (p && is_self(process) && (type & MEM_RESERVE || !at)) arena_outside_record(p, "VirtualAlloc2");
    return p;
}

static BOOL WINAPI hook_VirtualFree(LPVOID at, SIZE_T n, DWORD type)
{
    if (!VirtualFree(at, n, type)) return FALSE;
    if (type & MEM_RELEASE) arena_outside_forget(at);
    return TRUE;
}

static BOOL WINAPI hook_VirtualFreeEx(HANDLE process, LPVOID at, SIZE_T n, DWORD type)
{
    if (!VirtualFreeEx(process, at, n, type)) return FALSE;
    if (is_self(process) && type & MEM_RELEASE) arena_outside_forget(at);
    return TRUE;
}

static HANDLE WINAPI hook_HeapCreate(DWORD flags, SIZE_T initial, SIZE_T max)
{
    HANDLE h = HeapCreate(flags, initial, max);
    arena_outside_record(h, "HeapCreate");
    return h;
}

static BOOL WINAPI hook_HeapDestroy(HANDLE h)
{
    if (!HeapDestroy(h)) return FALSE;
    arena_outside_forget(h);
    return TRUE;
}

static HLOCAL WINAPI hook_LocalAlloc(UINT flags, SIZE_T n)
{
    HLOCAL h = LocalAlloc(flags, n);
    arena_outside_record(h, "LocalAlloc");
    return h;
}

static HLOCAL WINAPI hook_LocalReAlloc(HLOCAL old, SIZE_T n, UINT flags)
{
    HLOCAL h = LocalReAlloc(old, n, flags);
    if (h && h != old) {
        arena_outside_forget(old);
        arena_outside_record(h, "LocalReAlloc");
    }
    return h;
}

static HLOCAL WINAPI hook_LocalFree(HLOCAL h)
{
    if (h && arena_contains((ULONGLONG)h)) {
        arena_free(h);
        return NULL;
    }
    HLOCAL r = LocalFree(h);
    if (!r) arena_outside_forget(h);
    return r;
}

static HGLOBAL WINAPI hook_GlobalAlloc(UINT flags, SIZE_T n)
{
    HGLOBAL h = GlobalAlloc(flags, n);
    arena_outside_record(h, "GlobalAlloc");
    return h;
}

static HGLOBAL WINAPI hook_GlobalReAlloc(HGLOBAL old, SIZE_T n, UINT flags)
{
    HGLOBAL h = GlobalReAlloc(old, n, flags);
    if (h && h != old) {
        arena_outside_forget(old);
        arena_outside_record(h, "GlobalReAlloc");
    }
    return h;
}

static HGLOBAL WINAPI hook_GlobalFree(HGLOBAL h)
{
    HGLOBAL r = GlobalFree(h);
    if (!r) arena_outside_forget(h);
    return r;
}

static FARPROC real_fn(const WCHAR *dll, const char *name)
{
    HMODULE m = GetModuleHandleW(dll);
    if (!m) m = LoadLibraryW(dll);
    return m ? GetProcAddress(m, name) : NULL;
}

static void *swap_in(void *real, size_t n)
{
    void *copy = arena_copy(real, n);
    if (!copy) SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return copy;
}

static size_t env_bytes(const void *env, size_t unit)
{
    const BYTE *p = (const BYTE *)env;
    size_t n = 0;
    for (;;) {
        int end1 = 1, end2 = 1;
        for (size_t k = 0; k < unit; k++) {
            if (p[n + k])        end1 = 0;
            if (p[n + unit + k]) end2 = 0;
        }
        if (end1 && end2) return n + 2 * unit;
        n += unit;
    }
}

static LPWCH WINAPI hook_GetEnvironmentStringsW(void)
{
    LPWCH env = GetEnvironmentStringsW();
    if (!env) return NULL;
    LPWCH copy = (LPWCH)swap_in(env, env_bytes(env, sizeof(WCHAR)));
    FreeEnvironmentStringsW(env);
    return copy;
}

static LPCH WINAPI hook_GetEnvironmentStringsA(void)
{
    LPCH env = GetEnvironmentStrings();
    if (!env) return NULL;
    LPCH copy = (LPCH)swap_in(env, env_bytes(env, 1));
    FreeEnvironmentStringsA(env);
    return copy;
}

static BOOL WINAPI hook_FreeEnvironmentStringsW(LPWCH env)
{
    if (!arena_contains((ULONGLONG)env)) return FreeEnvironmentStringsW(env);
    arena_free(env);
    return TRUE;
}

static BOOL WINAPI hook_FreeEnvironmentStringsA(LPCH env)
{
    if (!arena_contains((ULONGLONG)env)) return FreeEnvironmentStringsA(env);
    arena_free(env);
    return TRUE;
}

static DWORD WINAPI hook_FormatMessageW(DWORD flags, LPCVOID src, DWORD id, DWORD lang,
                                        LPWSTR buf, DWORD size, va_list *args)
{
    DWORD n = FormatMessageW(flags, src, id, lang, buf, size, args);
    if (!n || !(flags & FORMAT_MESSAGE_ALLOCATE_BUFFER)) return n;
    LPWSTR *out = (LPWSTR *)buf;
    LPWSTR copy = (LPWSTR)swap_in(*out, ((size_t)n + 1) * sizeof(WCHAR));
    LocalFree(*out);
    *out = copy;
    return copy ? n : 0;
}

static DWORD WINAPI hook_FormatMessageA(DWORD flags, LPCVOID src, DWORD id, DWORD lang,
                                        LPSTR buf, DWORD size, va_list *args)
{
    DWORD n = FormatMessageA(flags, src, id, lang, buf, size, args);
    if (!n || !(flags & FORMAT_MESSAGE_ALLOCATE_BUFFER)) return n;
    LPSTR *out = (LPSTR *)buf;
    LPSTR copy = (LPSTR)swap_in(*out, (size_t)n + 1);
    LocalFree(*out);
    *out = copy;
    return copy ? n : 0;
}

typedef LPWSTR *(WINAPI *argv_fn)(LPCWSTR, int *);

static LPWSTR *WINAPI hook_CommandLineToArgvW(LPCWSTR cmd, int *argc)
{
    argv_fn real = (argv_fn)real_fn(L"shell32.dll", "CommandLineToArgvW");
    LPWSTR *argv = real ? real(cmd, argc) : NULL;
    if (!argv) return NULL;
    LPWSTR *copy = (LPWSTR *)swap_in(argv, LocalSize(argv));
    for (int i = 0; copy && i < *argc; i++)
        copy[i] = (LPWSTR)((BYTE *)copy + ((BYTE *)argv[i] - (BYTE *)argv));
    LocalFree(argv);
    return copy;
}

typedef BOOL (WINAPI *alloc_sid_fn)(PSID_IDENTIFIER_AUTHORITY, BYTE, DWORD, DWORD, DWORD, DWORD,
                                    DWORD, DWORD, DWORD, DWORD, PSID *);
typedef PVOID (WINAPI *free_sid_fn)(PSID);

static BOOL WINAPI hook_AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY auth, BYTE count,
                                                 DWORD s0, DWORD s1, DWORD s2, DWORD s3,
                                                 DWORD s4, DWORD s5, DWORD s6, DWORD s7, PSID *sid)
{
    alloc_sid_fn real = (alloc_sid_fn)real_fn(L"advapi32.dll", "AllocateAndInitializeSid");
    free_sid_fn  free = (free_sid_fn)real_fn(L"advapi32.dll", "FreeSid");
    if (!real || !free || !real(auth, count, s0, s1, s2, s3, s4, s5, s6, s7, sid)) return FALSE;
    PSID copy = swap_in(*sid, 8 + 4 * (size_t)((BYTE *)*sid)[1]);
    free(*sid);
    *sid = copy;
    return copy != NULL;
}

static PVOID WINAPI hook_FreeSid(PSID sid)
{
    if (arena_contains((ULONGLONG)sid)) {
        arena_free(sid);
        return NULL;
    }
    free_sid_fn real = (free_sid_fn)real_fn(L"advapi32.dll", "FreeSid");
    return real ? real(sid) : sid;
}

typedef BOOL (WINAPI *sddl_w_fn)(LPCWSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);
typedef BOOL (WINAPI *sddl_a_fn)(LPCSTR, DWORD, PSECURITY_DESCRIPTOR *, PULONG);

static BOOL WINAPI hook_ConvertStringSecurityDescriptorToSecurityDescriptorW(
    LPCWSTR s, DWORD rev, PSECURITY_DESCRIPTOR *sd, PULONG size)
{
    sddl_w_fn real = (sddl_w_fn)real_fn(L"advapi32.dll",
                                        "ConvertStringSecurityDescriptorToSecurityDescriptorW");
    if (!real || !real(s, rev, sd, size)) return FALSE;
    PSECURITY_DESCRIPTOR copy = swap_in(*sd, LocalSize(*sd));
    LocalFree(*sd);
    *sd = copy;
    return copy != NULL;
}

static BOOL WINAPI hook_ConvertStringSecurityDescriptorToSecurityDescriptorA(
    LPCSTR s, DWORD rev, PSECURITY_DESCRIPTOR *sd, PULONG size)
{
    sddl_a_fn real = (sddl_a_fn)real_fn(L"advapi32.dll",
                                        "ConvertStringSecurityDescriptorToSecurityDescriptorA");
    if (!real || !real(s, rev, sd, size)) return FALSE;
    PSECURITY_DESCRIPTOR copy = swap_in(*sd, LocalSize(*sd));
    LocalFree(*sd);
    *sd = copy;
    return copy != NULL;
}

const Hook arena_hooks[] = {
    { "GetProcessHeap", (void *)hook_GetProcessHeap },
    { "HeapAlloc",      (void *)hook_HeapAlloc      },
    { "HeapFree",       (void *)hook_HeapFree       },
    { "HeapReAlloc",    (void *)hook_HeapReAlloc    },
    { "HeapSize",       (void *)hook_HeapSize       },
    { "HeapCreate",     (void *)hook_HeapCreate     },
    { "HeapDestroy",    (void *)hook_HeapDestroy    },
    { "VirtualAlloc",   (void *)hook_VirtualAlloc   },
    { "VirtualAllocEx", (void *)hook_VirtualAllocEx },
    { "VirtualAlloc2",  (void *)hook_VirtualAlloc2  },
    { "VirtualFree",    (void *)hook_VirtualFree    },
    { "VirtualFreeEx",  (void *)hook_VirtualFreeEx  },
    { "LocalAlloc",     (void *)hook_LocalAlloc     },
    { "LocalReAlloc",   (void *)hook_LocalReAlloc   },
    { "LocalFree",      (void *)hook_LocalFree      },
    { "GlobalAlloc",    (void *)hook_GlobalAlloc    },
    { "GlobalReAlloc",  (void *)hook_GlobalReAlloc  },
    { "GlobalFree",     (void *)hook_GlobalFree     },

    { "GetEnvironmentStringsW",  (void *)hook_GetEnvironmentStringsW  },
    { "GetEnvironmentStrings",   (void *)hook_GetEnvironmentStringsA  },
    { "GetEnvironmentStringsA",  (void *)hook_GetEnvironmentStringsA  },
    { "FreeEnvironmentStringsW", (void *)hook_FreeEnvironmentStringsW },
    { "FreeEnvironmentStringsA", (void *)hook_FreeEnvironmentStringsA },
    { "FormatMessageW",          (void *)hook_FormatMessageW          },
    { "FormatMessageA",          (void *)hook_FormatMessageA          },
    { "CommandLineToArgvW",      (void *)hook_CommandLineToArgvW      },
    { "AllocateAndInitializeSid", (void *)hook_AllocateAndInitializeSid },
    { "FreeSid",                  (void *)hook_FreeSid                  },
    { "ConvertStringSecurityDescriptorToSecurityDescriptorW",
      (void *)hook_ConvertStringSecurityDescriptorToSecurityDescriptorW },
    { "ConvertStringSecurityDescriptorToSecurityDescriptorA",
      (void *)hook_ConvertStringSecurityDescriptorToSecurityDescriptorA },
};
const int arena_n_hooks = sizeof arena_hooks / sizeof arena_hooks[0];
