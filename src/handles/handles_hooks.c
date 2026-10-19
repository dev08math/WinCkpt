#include <windows.h>

#include "handles.h"

static BOOL WINAPI hook_CloseHandle(HANDLE h)
{
    if (handles_is_stale(h)) return TRUE;
    return CloseHandle(h);
}

const Hook handles_hooks[] = {
    { "CloseHandle", (void *)hook_CloseHandle },
};
const int handles_n_hooks = sizeof handles_hooks / sizeof handles_hooks[0];
