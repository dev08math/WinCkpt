#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "boundary.h"
#include "arena.h"
#include "handles.h"

#define STUB_OFF (EMU_SIZE - PAGE)

static const struct {
    const Hook *hooks;
    const int  *n;
} g_registry[] = {
    { arena_hooks,   &arena_n_hooks   },
    { handles_hooks, &handles_n_hooks },
    { process_hooks, &process_n_hooks },
    { modules_hooks, &modules_n_hooks },
};

static const char *g_unhandled[] = {
    "CreateFileA", "CreateFileW", "CreateFile2",
    "CreatePipe", "CreateNamedPipeA", "CreateNamedPipeW",
    "CreateEventA", "CreateEventW", "CreateEventExA", "CreateEventExW",
    "CreateMutexA", "CreateMutexW", "CreateSemaphoreA", "CreateSemaphoreW",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "MapViewOfFileEx",
    "VirtualAlloc", "VirtualAllocEx", "HeapCreate",
    "GetStdHandle", "EncodePointer",
    "SetCurrentDirectoryA", "SetCurrentDirectoryW",
    "SetEnvironmentVariableA", "SetEnvironmentVariableW", "SetConsoleMode",
};
static const char *g_seen[sizeof g_unhandled / sizeof g_unhandled[0]];
static int         g_n_seen;

int boundary_init(ULONGLONG emu_at, const WCHAR *cmdline)
{
    if (sizeof(Emu) > STUB_OFF) {
        fprintf(stderr, "boundary: Emu is %zu bytes, room is %llu\n", sizeof(Emu), STUB_OFF);
        return 0;
    }
    if (!VirtualAlloc((LPVOID)emu_at, (SIZE_T)EMU_SIZE, MEM_COMMIT, PAGE_READWRITE)) {
        fprintf(stderr, "boundary: EMU commit at 0x%llX failed, err=%lu\n", emu_at, GetLastError());
        return 0;
    }
    Emu *emu = (Emu *)emu_at;
    memset(emu, 0, sizeof *emu);
    return process_init(&emu->process, cmdline)
        && modules_init(&emu->modules, (BYTE *)emu + STUB_OFF);
}

int boundary_adopt(ULONGLONG emu_at)
{
    Emu *emu = (Emu *)emu_at;
    process_adopt(&emu->process);
    return modules_adopt(&emu->modules, (BYTE *)emu + STUB_OFF);
}

void *boundary_find(const char *name)
{
    for (int t = 0; t < (int)(sizeof g_registry / sizeof g_registry[0]); t++)
        for (int i = 0; i < *g_registry[t].n; i++)
            if (strcmp(name, g_registry[t].hooks[i].name) == 0) return g_registry[t].hooks[i].fn;
    return NULL;
}

void *boundary_hook(const char *import_name)
{
    for (int i = 0; i < (int)(sizeof g_unhandled / sizeof g_unhandled[0]); i++)
        if (strcmp(import_name, g_unhandled[i]) == 0 &&
            g_n_seen < (int)(sizeof g_seen / sizeof g_seen[0]))
            g_seen[g_n_seen++] = g_unhandled[i];
    return boundary_find(import_name);
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
