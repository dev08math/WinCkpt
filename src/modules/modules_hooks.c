#include <windows.h>

#include "modules.h"

static FARPROC WINAPI hook_GetProcAddress(HMODULE mod, LPCSTR name)
{
    FARPROC real = GetProcAddress(modules_now(mod), name);
    if (!real) return NULL;
    return modules_proc(mod, name, real);
}

static HMODULE WINAPI hook_LoadLibraryA(LPCSTR name)
{
    return modules_remember(LoadLibraryA(name), 0, 1);
}

static HMODULE WINAPI hook_LoadLibraryW(LPCWSTR name)
{
    return modules_remember(LoadLibraryW(name), 0, 1);
}

static HMODULE WINAPI hook_LoadLibraryExA(LPCSTR name, HANDLE file, DWORD flags)
{
    return modules_remember(LoadLibraryExA(name, file, flags), flags, 1);
}

static HMODULE WINAPI hook_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags)
{
    return modules_remember(LoadLibraryExW(name, file, flags), flags, 1);
}

static HMODULE WINAPI hook_GetModuleHandleA(LPCSTR name)
{
    return modules_remember(GetModuleHandleA(name), 0, 0);
}

static HMODULE WINAPI hook_GetModuleHandleW(LPCWSTR name)
{
    return modules_remember(GetModuleHandleW(name), 0, 0);
}

static BOOL WINAPI hook_GetModuleHandleExA(DWORD flags, LPCSTR name, HMODULE *out)
{
    if (!GetModuleHandleExA(flags, name, out)) return FALSE;
    modules_remember(*out, 0, !(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT));
    return TRUE;
}

static BOOL WINAPI hook_GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE *out)
{
    if (!GetModuleHandleExW(flags, name, out)) return FALSE;
    modules_remember(*out, 0, !(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT));
    return TRUE;
}

static BOOL WINAPI hook_FreeLibrary(HMODULE h)
{
    return modules_free(h);
}

static void WINAPI hook_FreeLibraryAndExitThread(HMODULE h, DWORD code)
{
    FreeLibraryAndExitThread(modules_now(h), code);
}

static DWORD WINAPI hook_GetModuleFileNameA(HMODULE h, LPSTR out, DWORD size)
{
    return GetModuleFileNameA(modules_now(h), out, size);
}

static DWORD WINAPI hook_GetModuleFileNameW(HMODULE h, LPWSTR out, DWORD size)
{
    return GetModuleFileNameW(modules_now(h), out, size);
}

const Hook modules_hooks[] = {
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
const int modules_n_hooks = sizeof modules_hooks / sizeof modules_hooks[0];
