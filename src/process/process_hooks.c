#include <windows.h>

#include "process.h"

static void WINAPI hook_ExitProcess(UINT code)
{
    process_detach(code);
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
    ProcessEmu *p = process_state();
    for (DWORD i = 0; i < EMU_SLOTS; i++) {
        if (p->fls_used[i]) continue;
        p->fls_used[i] = 1;
        p->fls_cb[i]   = cb;
        p->fls_val[i]  = NULL;
        return i;
    }
    SetLastError(ERROR_NO_MORE_ITEMS);
    return FLS_OUT_OF_INDEXES;
}

static BOOL WINAPI hook_FlsFree(DWORD i)
{
    ProcessEmu *p = process_state();
    if (!slot_ok(p->fls_used, i)) return FALSE;
    if (p->fls_cb[i] && p->fls_val[i]) p->fls_cb[i](p->fls_val[i]);
    p->fls_used[i] = 0;
    return TRUE;
}

static PVOID WINAPI hook_FlsGetValue(DWORD i)
{
    ProcessEmu *p = process_state();
    if (!slot_ok(p->fls_used, i)) return NULL;
    SetLastError(ERROR_SUCCESS);
    return p->fls_val[i];
}

static PVOID WINAPI hook_FlsGetValue2(DWORD i)
{
    ProcessEmu *p = process_state();
    if (i >= EMU_SLOTS || !p->fls_used[i]) return NULL;
    return p->fls_val[i];
}

static BOOL WINAPI hook_FlsSetValue(DWORD i, PVOID v)
{
    ProcessEmu *p = process_state();
    if (!slot_ok(p->fls_used, i)) return FALSE;
    p->fls_val[i] = v;
    return TRUE;
}

static DWORD WINAPI hook_TlsAlloc(void)
{
    ProcessEmu *p = process_state();
    for (DWORD i = 0; i < EMU_SLOTS; i++) {
        if (p->tls_used[i]) continue;
        p->tls_used[i] = 1;
        p->tls_val[i]  = NULL;
        return i;
    }
    SetLastError(ERROR_NO_MORE_ITEMS);
    return TLS_OUT_OF_INDEXES;
}

static BOOL WINAPI hook_TlsFree(DWORD i)
{
    ProcessEmu *p = process_state();
    if (!slot_ok(p->tls_used, i)) return FALSE;
    p->tls_used[i] = 0;
    return TRUE;
}

static LPVOID WINAPI hook_TlsGetValue(DWORD i)
{
    ProcessEmu *p = process_state();
    if (!slot_ok(p->tls_used, i)) return NULL;
    SetLastError(ERROR_SUCCESS);
    return p->tls_val[i];
}

static BOOL WINAPI hook_TlsSetValue(DWORD i, LPVOID v)
{
    ProcessEmu *p = process_state();
    if (!slot_ok(p->tls_used, i)) return FALSE;
    p->tls_val[i] = v;
    return TRUE;
}

static LPSTR WINAPI hook_GetCommandLineA(void)
{
    return process_state()->cmdline_a;
}

static LPWSTR WINAPI hook_GetCommandLineW(void)
{
    return process_state()->cmdline_w;
}

const Hook process_hooks[] = {
    { "ExitProcess",     (void *)hook_ExitProcess     },
    { "FlsAlloc",        (void *)hook_FlsAlloc        },
    { "FlsFree",         (void *)hook_FlsFree         },
    { "FlsGetValue",     (void *)hook_FlsGetValue     },
    { "FlsGetValue2",    (void *)hook_FlsGetValue2    },
    { "FlsSetValue",     (void *)hook_FlsSetValue     },
    { "TlsAlloc",        (void *)hook_TlsAlloc        },
    { "TlsFree",         (void *)hook_TlsFree         },
    { "TlsGetValue",     (void *)hook_TlsGetValue     },
    { "TlsSetValue",     (void *)hook_TlsSetValue     },
    { "GetCommandLineA", (void *)hook_GetCommandLineA },
    { "GetCommandLineW", (void *)hook_GetCommandLineW },
};
const int process_n_hooks = sizeof process_hooks / sizeof process_hooks[0];
