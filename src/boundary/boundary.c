#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "boundary.h"
#include "arena.h"
#include "handles.h"

#define STUB_OFF (EMU_SIZE - PAGE)

#define SEEN_MAX 256

static const struct {
    const Hook        *hooks;
    const int         *n;
    const char *const *unhandled;
    const int         *n_unhandled;
} g_registry[] = {
    { arena_hooks,   &arena_n_hooks,   arena_unhandled,   &arena_n_unhandled   },
    { handles_hooks, &handles_n_hooks, handles_unhandled, &handles_n_unhandled },
    { process_hooks, &process_n_hooks, process_unhandled, &process_n_unhandled },
    { modules_hooks, &modules_n_hooks, NULL,              NULL                 },
};
#define N_REGISTRY ((int)(sizeof g_registry / sizeof g_registry[0]))

static const char *g_seen[SEEN_MAX];
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
        && modules_init(&emu->modules, (BYTE *)emu + STUB_OFF)
        && handles_init(&emu->handles);
}

int boundary_adopt(ULONGLONG emu_at)
{
    Emu *emu = (Emu *)emu_at;
    process_adopt(&emu->process);
    return modules_adopt(&emu->modules, (BYTE *)emu + STUB_OFF)
        && handles_adopt(&emu->handles);
}

void *boundary_find(const char *name)
{
    for (int t = 0; t < N_REGISTRY; t++)
        for (int i = 0; i < *g_registry[t].n; i++)
            if (strcmp(name, g_registry[t].hooks[i].name) == 0) return g_registry[t].hooks[i].fn;
    return NULL;
}

void *boundary_hook(const char *import_name)
{
    for (int t = 0; t < N_REGISTRY; t++) {
        if (!g_registry[t].unhandled) continue;
        for (int i = 0; i < *g_registry[t].n_unhandled; i++) {
            if (strcmp(import_name, g_registry[t].unhandled[i]) != 0) continue;
            if (g_n_seen < SEEN_MAX) g_seen[g_n_seen] = g_registry[t].unhandled[i];
            g_n_seen++;
        }
    }
    return boundary_find(import_name);
}

void boundary_report(const char *module)
{
    if (g_n_seen == 0) return;
    printf("boundary: WARNING %s imports %d call(s) WinCkpt does not handle yet:",
           module, g_n_seen);
    for (int i = 0; i < g_n_seen && i < SEEN_MAX; i++) printf(" %s", g_seen[i]);
    if (g_n_seen > SEEN_MAX) printf(" (+%d more)", g_n_seen - SEEN_MAX);
    printf("\n");
    g_n_seen = 0;
}
