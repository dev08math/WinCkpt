#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "handles.h"
#include "arena.h"
#include "log.h"

static int std_index(DWORD n)
{
    DWORD i = STD_INPUT_HANDLE - n;
    return i < 3 ? (int)i : -1;
}

static HANDLE WINAPI hook_GetStdHandle(DWORD n)
{
    int i = std_index(n);
    if (i < 0) return GetStdHandle(n);
    return handles_state()->std[i];
}

static BOOL WINAPI hook_SetStdHandle(DWORD n, HANDLE h)
{
    int i = std_index(n);
    if (i < 0) return SetStdHandle(n, h);
    if (!SetStdHandle(n, handles_real(h))) return FALSE;
    handles_state()->std[i] = h;
    return TRUE;
}

static int reserved2_size(const BYTE *p)
{
    int n = *(const int *)p;
    return (int)sizeof(int) + n + n * (int)sizeof(HANDLE);
}

static BYTE *g_inherited;

static BYTE *wrap_inherited(const BYTE *p, int size)
{
    BYTE *copy = (BYTE *)malloc((size_t)size);
    if (!copy) return NULL;
    memcpy(copy, p, (size_t)size);
    int     n  = *(int *)copy;
    BYTE   *fl = copy + sizeof(int);
    HANDLE *hs = (HANDLE *)(fl + n);
    for (int fd = 0; fd < n; fd++) {
        if (!(fl[fd] & 0x01) || hs[fd] == INVALID_HANDLE_VALUE || hs[fd] == (HANDLE)-2) continue;
        if (fd >= 3) {
            VLOG("handles: inherited fd %d (0x%p) is not in the table yet\n", fd, hs[fd]);
            continue;
        }
        HANDLE fake = handles_wrap_std(STD_INPUT_HANDLE - (DWORD)fd, hs[fd]);
        if (fake) hs[fd] = fake;
    }
    return copy;
}

static VOID WINAPI hook_GetStartupInfoW(LPSTARTUPINFOW si)
{
    GetStartupInfoW(si);
    HandlesEmu *e = handles_state();
    if (si->dwFlags & STARTF_USESTDHANDLES) {
        si->hStdInput  = e->std[0];
        si->hStdOutput = e->std[1];
        si->hStdError  = e->std[2];
    }
    if (si->cbReserved2 < sizeof(int) || !si->lpReserved2) return;
    int size = reserved2_size(si->lpReserved2);
    if (size > si->cbReserved2) return;
    if (!g_inherited) g_inherited = wrap_inherited(si->lpReserved2, size);
    if (g_inherited) si->lpReserved2 = g_inherited;
}

static BOOL WINAPI hook_CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
                                       LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags,
                                       LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si,
                                       LPPROCESS_INFORMATION pi)
{
    STARTUPINFOEXW real_ex = { 0 };
    memcpy(&real_ex, si, (flags & EXTENDED_STARTUPINFO_PRESENT) ? sizeof real_ex : sizeof real_ex.StartupInfo);
    STARTUPINFOW *real_si = &real_ex.StartupInfo;
    BYTE *copy = NULL;
    if (si->dwFlags & STARTF_USESTDHANDLES) {
        real_si->hStdInput  = handles_real(si->hStdInput);
        real_si->hStdOutput = handles_real(si->hStdOutput);
        real_si->hStdError  = handles_real(si->hStdError);
    }
    if (si->cbReserved2 >= sizeof(int) && si->lpReserved2) {
        copy = (BYTE *)malloc(si->cbReserved2);
        if (!copy) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            return FALSE;
        }
        memcpy(copy, si->lpReserved2, si->cbReserved2);
        int     n  = *(int *)copy;
        HANDLE *hs = (HANDLE *)(copy + sizeof(int) + n);
        if (reserved2_size(copy) <= si->cbReserved2)
            for (int fd = 0; fd < n; fd++) hs[fd] = handles_real(hs[fd]);
        real_si->lpReserved2 = copy;
    }
    BOOL ok = CreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, real_si, pi);
    DWORD err = GetLastError();
    free(copy);
    SetLastError(err);
    return ok;
}

static BOOL sa_inherit(LPSECURITY_ATTRIBUTES sa)
{
    return sa ? sa->bInheritHandle : FALSE;
}

static HANDLE wrap_opened(HANDLE h, const WCHAR *name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                          DWORD flags)
{
    if (h == INVALID_HANDLE_VALUE) return h;
    DWORD err = GetLastError();
    HANDLE fake = handles_wrap_file(h, name, access, share, flags, sa_inherit(sa));
    if (!fake) {
        CloseHandle(h);
        SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return INVALID_HANDLE_VALUE;
    }
    SetLastError(err);
    return fake;
}

static HANDLE WINAPI hook_CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                      DWORD disp, DWORD flags, HANDLE tmpl)
{
    HANDLE h = CreateFileW(name, access, share, sa, disp, flags, handles_real(tmpl));
    return wrap_opened(h, name, access, share, sa, flags);
}

static WCHAR *to_wide(LPCSTR s, UINT cp)
{
    int n = MultiByteToWideChar(cp, 0, s, -1, NULL, 0);
    WCHAR *w = n > 0 ? (WCHAR *)malloc((size_t)n * sizeof(WCHAR)) : NULL;
    if (w) MultiByteToWideChar(cp, 0, s, -1, w, n);
    else   SetLastError(ERROR_NOT_ENOUGH_MEMORY);
    return w;
}

static int to_wide_name(LPCSTR name, WCHAR **out)
{
    *out = name ? to_wide(name, CP_ACP) : NULL;
    return !name || *out;
}

static HANDLE free_wide(WCHAR *w, HANDLE h)
{
    DWORD err = GetLastError();
    free(w);
    SetLastError(err);
    return h;
}

static HANDLE WINAPI hook_CreateFileA(LPCSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa,
                                      DWORD disp, DWORD flags, HANDLE tmpl)
{
    WCHAR *w = to_wide(name, AreFileApisANSI() ? CP_ACP : CP_OEMCP);
    if (!w) return INVALID_HANDLE_VALUE;
    return free_wide(w, hook_CreateFileW(w, access, share, sa, disp, flags, tmpl));
}

static HANDLE wrap_sync(HANDLE h, HandleKind kind, LPCWSTR name, DWORD access, BOOL inherit)
{
    if (!h) return NULL;
    DWORD err = GetLastError();
    HANDLE fake = handles_wrap_sync(h, kind, name, access, inherit);
    if (!fake) {
        CloseHandle(h);
        SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return NULL;
    }
    SetLastError(err);
    return fake;
}

static HANDLE WINAPI hook_CreateEventW(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL set, LPCWSTR name)
{
    return wrap_sync(CreateEventW(sa, manual, set, name), HK_EVENT, name, EVENT_ALL_ACCESS, sa_inherit(sa));
}

static HANDLE WINAPI hook_CreateEventA(LPSECURITY_ATTRIBUTES sa, BOOL manual, BOOL set, LPCSTR name)
{
    WCHAR *w;
    if (!to_wide_name(name, &w)) return NULL;
    return free_wide(w, hook_CreateEventW(sa, manual, set, w));
}

static HANDLE WINAPI hook_CreateEventExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{
    return wrap_sync(CreateEventExW(sa, name, flags, access), HK_EVENT, name, access, sa_inherit(sa));
}

static HANDLE WINAPI hook_CreateEventExA(LPSECURITY_ATTRIBUTES sa, LPCSTR name, DWORD flags, DWORD access)
{
    WCHAR *w;
    if (!to_wide_name(name, &w)) return NULL;
    return free_wide(w, hook_CreateEventExW(sa, w, flags, access));
}

static HANDLE WINAPI hook_OpenEventW(DWORD access, BOOL inherit, LPCWSTR name)
{
    return wrap_sync(OpenEventW(access, inherit, name), HK_EVENT, name, access, inherit);
}

static HANDLE WINAPI hook_OpenEventA(DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR *w;
    if (!to_wide_name(name, &w)) return NULL;
    return free_wide(w, hook_OpenEventW(access, inherit, w));
}

static HANDLE WINAPI hook_CreateSemaphoreW(LPSECURITY_ATTRIBUTES sa, LONG count, LONG max, LPCWSTR name)
{
    return wrap_sync(CreateSemaphoreW(sa, count, max, name), HK_SEMAPHORE, name, SEMAPHORE_ALL_ACCESS,
                     sa_inherit(sa));
}

static HANDLE WINAPI hook_CreateSemaphoreA(LPSECURITY_ATTRIBUTES sa, LONG count, LONG max, LPCSTR name)
{
    WCHAR *w;
    if (!to_wide_name(name, &w)) return NULL;
    return free_wide(w, hook_CreateSemaphoreW(sa, count, max, w));
}

static HANDLE WINAPI hook_CreateSemaphoreExW(LPSECURITY_ATTRIBUTES sa, LONG count, LONG max, LPCWSTR name,
                                             DWORD flags, DWORD access)
{
    return wrap_sync(CreateSemaphoreExW(sa, count, max, name, flags, access), HK_SEMAPHORE, name, access,
                     sa_inherit(sa));
}

static HANDLE WINAPI hook_OpenSemaphoreW(DWORD access, BOOL inherit, LPCWSTR name)
{
    return wrap_sync(OpenSemaphoreW(access, inherit, name), HK_SEMAPHORE, name, access, inherit);
}

static HANDLE WINAPI hook_CreateMutexW(LPSECURITY_ATTRIBUTES sa, BOOL owner, LPCWSTR name)
{
    return wrap_sync(CreateMutexW(sa, owner, name), HK_MUTEX, name, MUTEX_ALL_ACCESS, sa_inherit(sa));
}

static HANDLE WINAPI hook_CreateMutexA(LPSECURITY_ATTRIBUTES sa, BOOL owner, LPCSTR name)
{
    WCHAR *w;
    if (!to_wide_name(name, &w)) return NULL;
    return free_wide(w, hook_CreateMutexW(sa, owner, w));
}

static HANDLE WINAPI hook_CreateMutexExW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name, DWORD flags, DWORD access)
{
    return wrap_sync(CreateMutexExW(sa, name, flags, access), HK_MUTEX, name, access, sa_inherit(sa));
}

static HANDLE WINAPI hook_OpenMutexW(DWORD access, BOOL inherit, LPCWSTR name)
{
    return wrap_sync(OpenMutexW(access, inherit, name), HK_MUTEX, name, access, inherit);
}

static HANDLE WINAPI hook_OpenMutexA(DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR *w;
    if (!to_wide_name(name, &w)) return NULL;
    return free_wide(w, hook_OpenMutexW(access, inherit, w));
}

static BOOL WINAPI hook_SetEvent(HANDLE h)
{
    return SetEvent(handles_real(h));
}

static BOOL WINAPI hook_ResetEvent(HANDLE h)
{
    return ResetEvent(handles_real(h));
}

static BOOL WINAPI hook_PulseEvent(HANDLE h)
{
    return PulseEvent(handles_real(h));
}

static BOOL WINAPI hook_ReleaseSemaphore(HANDLE h, LONG n, LPLONG prev)
{
    return ReleaseSemaphore(handles_real(h), n, prev);
}

static BOOL WINAPI hook_ReleaseMutex(HANDLE h)
{
    return ReleaseMutex(handles_real(h));
}

static DWORD WINAPI hook_WaitForSingleObjectEx(HANDLE h, DWORD ms, BOOL alertable)
{
    return WaitForSingleObjectEx(handles_real(h), ms, alertable);
}

static DWORD WINAPI hook_WaitForMultipleObjectsEx(DWORD n, const HANDLE *hs, BOOL all, DWORD ms, BOOL alertable)
{
    if (n > MAXIMUM_WAIT_OBJECTS) return WaitForMultipleObjectsEx(n, hs, all, ms, alertable);
    HANDLE real[MAXIMUM_WAIT_OBJECTS];
    for (DWORD i = 0; i < n; i++) real[i] = handles_real(hs[i]);
    return WaitForMultipleObjectsEx(n, real, all, ms, alertable);
}

static DWORD WINAPI hook_WaitForMultipleObjects(DWORD n, const HANDLE *hs, BOOL all, DWORD ms)
{
    return hook_WaitForMultipleObjectsEx(n, hs, all, ms, FALSE);
}

static DWORD WINAPI hook_SignalObjectAndWait(HANDLE signal, HANDLE wait, DWORD ms, BOOL alertable)
{
    return SignalObjectAndWait(handles_real(signal), handles_real(wait), ms, alertable);
}

static BOOL WINAPI hook_CreatePipe(PHANDLE r, PHANDLE w, LPSECURITY_ATTRIBUTES sa, DWORD size)
{
    HANDLE rr, ww;
    if (!CreatePipe(&rr, &ww, sa, size)) return FALSE;
    if (!handles_wrap_pipe(rr, ww, size, sa_inherit(sa), r, w)) {
        CloseHandle(rr);
        CloseHandle(ww);
        SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return FALSE;
    }
    return TRUE;
}

static HANDLE found(HANDLE h, const char *by)
{
    if (h != INVALID_HANDLE_VALUE) arena_outside_record(h, by);
    return h;
}

static HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR name, FINDEX_INFO_LEVELS level, LPVOID data,
                                           FINDEX_SEARCH_OPS op, LPVOID filter, DWORD flags)
{
    return found(FindFirstFileExW(name, level, data, op, filter, flags), "FindFirstFileExW");
}

static HANDLE WINAPI hook_FindFirstFileExA(LPCSTR name, FINDEX_INFO_LEVELS level, LPVOID data,
                                           FINDEX_SEARCH_OPS op, LPVOID filter, DWORD flags)
{
    return found(FindFirstFileExA(name, level, data, op, filter, flags), "FindFirstFileExA");
}

static HANDLE WINAPI hook_FindFirstFileW(LPCWSTR name, LPWIN32_FIND_DATAW data)
{
    return found(FindFirstFileW(name, data), "FindFirstFileW");
}

static HANDLE WINAPI hook_FindFirstFileA(LPCSTR name, LPWIN32_FIND_DATAA data)
{
    return found(FindFirstFileA(name, data), "FindFirstFileA");
}

static BOOL WINAPI hook_FindClose(HANDLE h)
{
    if (!FindClose(h)) return FALSE;
    arena_outside_forget(h);
    return TRUE;
}

static BOOL WINAPI hook_CloseHandle(HANDLE h)
{
    if (!handles_is_fake(h)) return CloseHandle(h);
    HANDLE real = handles_real(h);
    if (real == h) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    handles_drop(h);
    return CloseHandle(real);
}

static int is_self(HANDLE process)
{
    return process == GetCurrentProcess() || GetProcessId(process) == GetCurrentProcessId();
}

static BOOL WINAPI hook_DuplicateHandle(HANDLE sp, HANDLE s, HANDLE tp, LPHANDLE t,
                                        DWORD access, BOOL inherit, DWORD opts)
{
    int ours = handles_is_fake(s) && is_self(sp);
    if (!ours || !t || !is_self(tp)) {
        BOOL ok = DuplicateHandle(sp, ours ? handles_real(s) : s, tp, t, access, inherit, opts);
        if (ok && ours && (opts & DUPLICATE_CLOSE_SOURCE)) handles_drop(s);
        return ok;
    }
    HANDLE real;
    if (!DuplicateHandle(sp, handles_real(s), tp, &real, access, inherit, opts)) return FALSE;
    HANDLE fake = handles_wrap_dup(s, real, opts, access, inherit);
    if (!fake) {
        CloseHandle(real);
        SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return FALSE;
    }
    if (opts & DUPLICATE_CLOSE_SOURCE) handles_drop(s);
    *t = fake;
    return TRUE;
}

static DWORD WINAPI hook_WaitForSingleObject(HANDLE h, DWORD ms)
{
    return WaitForSingleObject(handles_real(h), ms);
}

static BOOL WINAPI hook_ReadFile(HANDLE h, LPVOID b, DWORD n, LPDWORD got, LPOVERLAPPED ov)
{
    return ReadFile(handles_real(h), b, n, got, ov);
}

static BOOL WINAPI hook_WriteFile(HANDLE h, LPCVOID b, DWORD n, LPDWORD got, LPOVERLAPPED ov)
{
    return WriteFile(handles_real(h), b, n, got, ov);
}

static BOOL WINAPI hook_GetFileSizeEx(HANDLE h, PLARGE_INTEGER size)
{
    return GetFileSizeEx(handles_real(h), size);
}

static BOOL WINAPI hook_SetFilePointerEx(HANDLE h, LARGE_INTEGER d, PLARGE_INTEGER out, DWORD how)
{
    return SetFilePointerEx(handles_real(h), d, out, how);
}

static DWORD WINAPI hook_GetFileType(HANDLE h)
{
    return GetFileType(handles_real(h));
}

static BOOL WINAPI hook_LockFileEx(HANDLE h, DWORD f, DWORD r0, DWORD lo, DWORD hi, LPOVERLAPPED ov)
{
    return LockFileEx(handles_real(h), f, r0, lo, hi, ov);
}

static BOOL WINAPI hook_UnlockFileEx(HANDLE h, DWORD r0, DWORD lo, DWORD hi, LPOVERLAPPED ov)
{
    return UnlockFileEx(handles_real(h), r0, lo, hi, ov);
}

static BOOL WINAPI hook_FlushFileBuffers(HANDLE h)
{
    return FlushFileBuffers(handles_real(h));
}

static BOOL WINAPI hook_SetEndOfFile(HANDLE h)
{
    return SetEndOfFile(handles_real(h));
}

static BOOL WINAPI hook_GetFileInformationByHandle(HANDLE h, LPBY_HANDLE_FILE_INFORMATION info)
{
    return GetFileInformationByHandle(handles_real(h), info);
}

static BOOL WINAPI hook_SetFileTime(HANDLE h, const FILETIME *c, const FILETIME *a, const FILETIME *w)
{
    return SetFileTime(handles_real(h), c, a, w);
}

static BOOL WINAPI hook_GetConsoleMode(HANDLE h, LPDWORD mode)
{
    return GetConsoleMode(handles_real(h), mode);
}

static BOOL WINAPI hook_SetConsoleMode(HANDLE h, DWORD mode)
{
    return SetConsoleMode(handles_real(h), mode);
}

static BOOL WINAPI hook_WriteConsoleW(HANDLE h, const VOID *b, DWORD n, LPDWORD got, LPVOID r0)
{
    return WriteConsoleW(handles_real(h), b, n, got, r0);
}

static BOOL WINAPI hook_ReadConsoleW(HANDLE h, LPVOID b, DWORD n, LPDWORD got, PCONSOLE_READCONSOLE_CONTROL c)
{
    return ReadConsoleW(handles_real(h), b, n, got, c);
}

static BOOL WINAPI hook_ReadConsoleInputW(HANDLE h, PINPUT_RECORD b, DWORD n, LPDWORD got)
{
    return ReadConsoleInputW(handles_real(h), b, n, got);
}

static BOOL WINAPI hook_PeekConsoleInputA(HANDLE h, PINPUT_RECORD b, DWORD n, LPDWORD got)
{
    return PeekConsoleInputA(handles_real(h), b, n, got);
}

static BOOL WINAPI hook_GetNumberOfConsoleInputEvents(HANDLE h, LPDWORD n)
{
    return GetNumberOfConsoleInputEvents(handles_real(h), n);
}

static BOOL WINAPI hook_PeekNamedPipe(HANDLE h, LPVOID b, DWORD n, LPDWORD got, LPDWORD avail, LPDWORD left)
{
    return PeekNamedPipe(handles_real(h), b, n, got, avail, left);
}

const Hook handles_hooks[] = {
    { "GetStdHandle",                  (void *)hook_GetStdHandle                  },
    { "SetStdHandle",                  (void *)hook_SetStdHandle                  },
    { "GetStartupInfoW",               (void *)hook_GetStartupInfoW               },
    { "CreateProcessW",                (void *)hook_CreateProcessW                },
    { "CreateFileW",                   (void *)hook_CreateFileW                   },
    { "CreateFileA",                   (void *)hook_CreateFileA                   },
    { "CreatePipe",                    (void *)hook_CreatePipe                    },
    { "CreateEventW",                  (void *)hook_CreateEventW                  },
    { "CreateEventA",                  (void *)hook_CreateEventA                  },
    { "CreateEventExW",                (void *)hook_CreateEventExW                },
    { "CreateEventExA",                (void *)hook_CreateEventExA                },
    { "OpenEventW",                    (void *)hook_OpenEventW                    },
    { "OpenEventA",                    (void *)hook_OpenEventA                    },
    { "CreateSemaphoreW",              (void *)hook_CreateSemaphoreW              },
    { "CreateSemaphoreA",              (void *)hook_CreateSemaphoreA              },
    { "CreateSemaphoreExW",            (void *)hook_CreateSemaphoreExW            },
    { "OpenSemaphoreW",                (void *)hook_OpenSemaphoreW                },
    { "CreateMutexW",                  (void *)hook_CreateMutexW                  },
    { "CreateMutexA",                  (void *)hook_CreateMutexA                  },
    { "CreateMutexExW",                (void *)hook_CreateMutexExW                },
    { "OpenMutexW",                    (void *)hook_OpenMutexW                    },
    { "OpenMutexA",                    (void *)hook_OpenMutexA                    },
    { "SetEvent",                      (void *)hook_SetEvent                      },
    { "ResetEvent",                    (void *)hook_ResetEvent                    },
    { "PulseEvent",                    (void *)hook_PulseEvent                    },
    { "ReleaseSemaphore",              (void *)hook_ReleaseSemaphore              },
    { "ReleaseMutex",                  (void *)hook_ReleaseMutex                  },
    { "WaitForSingleObjectEx",         (void *)hook_WaitForSingleObjectEx         },
    { "WaitForMultipleObjects",        (void *)hook_WaitForMultipleObjects        },
    { "WaitForMultipleObjectsEx",      (void *)hook_WaitForMultipleObjectsEx      },
    { "SignalObjectAndWait",           (void *)hook_SignalObjectAndWait           },
    { "FindFirstFileExW",              (void *)hook_FindFirstFileExW              },
    { "FindFirstFileExA",              (void *)hook_FindFirstFileExA              },
    { "FindFirstFileW",                (void *)hook_FindFirstFileW                },
    { "FindFirstFileA",                (void *)hook_FindFirstFileA                },
    { "FindClose",                     (void *)hook_FindClose                     },
    { "CloseHandle",                   (void *)hook_CloseHandle                   },
    { "DuplicateHandle",               (void *)hook_DuplicateHandle               },
    { "WaitForSingleObject",           (void *)hook_WaitForSingleObject           },
    { "ReadFile",                      (void *)hook_ReadFile                      },
    { "WriteFile",                     (void *)hook_WriteFile                     },
    { "GetFileSizeEx",                 (void *)hook_GetFileSizeEx                 },
    { "SetFilePointerEx",              (void *)hook_SetFilePointerEx              },
    { "GetFileType",                   (void *)hook_GetFileType                   },
    { "LockFileEx",                    (void *)hook_LockFileEx                    },
    { "UnlockFileEx",                  (void *)hook_UnlockFileEx                  },
    { "FlushFileBuffers",              (void *)hook_FlushFileBuffers              },
    { "SetEndOfFile",                  (void *)hook_SetEndOfFile                  },
    { "GetFileInformationByHandle",    (void *)hook_GetFileInformationByHandle    },
    { "SetFileTime",                   (void *)hook_SetFileTime                   },
    { "GetConsoleMode",                (void *)hook_GetConsoleMode                },
    { "SetConsoleMode",                (void *)hook_SetConsoleMode                },
    { "WriteConsoleW",                 (void *)hook_WriteConsoleW                 },
    { "ReadConsoleW",                  (void *)hook_ReadConsoleW                  },
    { "ReadConsoleInputW",             (void *)hook_ReadConsoleInputW             },
    { "PeekConsoleInputA",             (void *)hook_PeekConsoleInputA             },
    { "GetNumberOfConsoleInputEvents", (void *)hook_GetNumberOfConsoleInputEvents },
    { "PeekNamedPipe",                 (void *)hook_PeekNamedPipe                 },
};
const int handles_n_hooks = sizeof handles_hooks / sizeof handles_hooks[0];

const char *const handles_unhandled[] = {
    "CreateFile2",
    "CreateNamedPipeA", "CreateNamedPipeW",
    "SetConsoleMode",
    "SetFilePointer", "GetFileSize", "LockFile", "UnlockFile", "ReadFileEx", "WriteFileEx",
    "GetFileInformationByHandleEx", "SetFileInformationByHandle", "GetFinalPathNameByHandleW",
    "DeviceIoControl", "GetOverlappedResult", "CancelIo", "CancelIoEx",
    "WriteConsoleA", "ReadConsoleA", "ReadConsoleInputA", "PeekConsoleInputW",
    "FlushConsoleInputBuffer", "GetConsoleScreenBufferInfo", "GetConsoleScreenBufferInfoEx",
    "SetConsoleTextAttribute", "SetConsoleCursorPosition",
    "FillConsoleOutputCharacterW", "FillConsoleOutputAttribute",
};
const int handles_n_unhandled = sizeof handles_unhandled / sizeof handles_unhandled[0];
