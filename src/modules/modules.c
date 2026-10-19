#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "modules.h"
#include "boundary.h"
#include "arena.h"
#include "log.h"

#define STUB_SIZE 16

static ModulesEmu *g_m;
static BYTE       *g_stubs;

static int protect_stubs(void)
{
    DWORD old = 0;
    if (!VirtualProtect(g_stubs, (SIZE_T)PAGE, PAGE_EXECUTE_READ, &old)) {
        fprintf(stderr, "modules: stub page protect failed, err=%lu\n", GetLastError());
        return 0;
    }
    return 1;
}

static void write_stubs(void)
{
    for (int i = 0; i < EMU_PROCS; i++) {
        BYTE *s = g_stubs + i * STUB_SIZE;
        LONG disp = (LONG)((BYTE *)&g_m->proc[i].target - (s + 6));
        s[0] = 0xFF;
        s[1] = 0x25;
        memcpy(s + 2, &disp, sizeof disp);
        memset(s + 6, 0xCC, STUB_SIZE - 6);
    }
}

static int find_module(HMODULE h)
{
    for (int i = 0; i < g_m->n_mod; i++)
        if (g_m->mod[i].saved == h && !g_m->mod[i].gone) return i;
    return -1;
}

static int free_row(void)
{
    for (int i = 0; i < g_m->n_mod; i++) {
        if (!g_m->mod[i].gone) continue;
        int used = 0;
        for (int j = 0; j < g_m->n_proc && !used; j++)
            used = g_m->proc[j].module == i;
        if (!used) return i;
    }
    return g_m->n_mod < EMU_MODULES ? g_m->n_mod : -1;
}

static int record_module(HMODULE h, DWORD flags)
{
    if (!h || arena_contains((ULONGLONG)h)) return -1;
    int i = find_module(h);
    if (i >= 0) return i;
    i = free_row();
    if (i < 0) {
        fprintf(stderr, "modules: module table full, 0x%p not recorded\n", (void *)h);
        return -1;
    }
    EmuModule *m = &g_m->mod[i];
    if (!GetModuleFileNameW(h, m->path, MAX_PATH)) return -1;
    m->saved = h;
    m->now   = h;
    m->flags = flags;
    m->refs  = 0;
    m->gone  = 0;
    if (i == g_m->n_mod) g_m->n_mod++;
    return i;
}

HMODULE modules_now(HMODULE h)
{
    int i = find_module(h);
    return i >= 0 ? g_m->mod[i].now : h;
}

static int in_windows_dir(const WCHAR *path)
{
    WCHAR dir[MAX_PATH];
    UINT n = GetWindowsDirectoryW(dir, MAX_PATH);
    return n > 0 && n < MAX_PATH && _wcsnicmp(path, dir, n) == 0 && path[n] == L'\\';
}

// After a reboot a live handle can equal one saved for another module.
HMODULE modules_remember(HMODULE h, DWORD flags, int add_ref)
{
    for (int i = 0; i < g_m->n_mod; i++)
        if (g_m->mod[i].saved == h && g_m->mod[i].now != h && !g_m->mod[i].gone)
            fprintf(stderr, "modules: module 0x%p is live, but also saved for %ls\n",
                    (void *)h, g_m->mod[i].path);
    int i = record_module(h, flags);
    if (i < 0 || !add_ref) return h;
    if (++g_m->mod[i].refs == 1 && !in_windows_dir(g_m->mod[i].path))
        printf("modules: WARNING %ls is loaded by Windows outside the arena; "
               "its state does not survive a restart\n", g_m->mod[i].path);
    return h;
}

static int still_loaded(HMODULE now)
{
    HMODULE h;
    return GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              (LPCWSTR)now, &h) && h == now;
}

static void *proc_stub(int m, LPCSTR name, void *target)
{
    if (m < 0) return NULL;
    WORD ord = IS_INTRESOURCE(name) ? (WORD)(ULONG_PTR)name : 0;
    for (int i = 0; i < g_m->n_proc; i++) {
        EmuProc *p = &g_m->proc[i];
        if (p->module == m && (ord ? p->ordinal == ord : strcmp(p->name, name) == 0))
            return g_stubs + i * STUB_SIZE;
    }
    if (g_m->n_proc == EMU_PROCS || (!ord && strlen(name) >= sizeof g_m->proc[0].name)) {
        fprintf(stderr, "modules: no stub for %s, its address will not survive a reboot\n",
                ord ? "an ordinal" : name);
        return NULL;
    }
    EmuProc *p = &g_m->proc[g_m->n_proc];
    p->module  = m;
    p->ordinal = ord;
    if (!ord) strcpy(p->name, name);
    p->target  = (ULONGLONG)target;
    return g_stubs + g_m->n_proc++ * STUB_SIZE;
}

static int refresh_modules_and_procs(void)
{
    for (int i = 0; i < g_m->n_mod; i++) {
        EmuModule *m = &g_m->mod[i];
        if (m->gone) continue;
        for (int r = 0; r < (m->refs > 1 ? m->refs : 1); r++) {
            m->now = LoadLibraryExW(m->path, NULL, m->flags);
            if (!m->now) {
                fprintf(stderr, "modules: reload of %ls failed, err=%lu\n", m->path, GetLastError());
                return 0;
            }
        }
    }
    for (int i = 0; i < g_m->n_proc; i++) {
        EmuProc *p = &g_m->proc[i];
        if (g_m->mod[p->module].gone) continue;
        LPCSTR name = p->ordinal ? (LPCSTR)(ULONG_PTR)p->ordinal : p->name;
        void *ours = p->ordinal ? NULL : boundary_find(p->name);
        void *real = (void *)GetProcAddress(g_m->mod[p->module].now, name);
        if (!real) {
            fprintf(stderr, "modules: %s not found in %ls\n",
                    p->ordinal ? "an ordinal" : p->name, g_m->mod[p->module].path);
            return 0;
        }
        p->target = (ULONGLONG)(ours ? ours : real);
    }
    VLOG("modules: %d module(s), %d GetProcAddress stub(s) re-resolved\n",
         g_m->n_mod, g_m->n_proc);
    return 1;
}

FARPROC modules_proc(HMODULE mod, LPCSTR name, FARPROC real)
{
    void *ours   = IS_INTRESOURCE(name) ? NULL : boundary_find(name);
    void *target = ours ? ours : (void *)real;
    void *stub   = proc_stub(record_module(mod, 0), name, target);
    return (FARPROC)(stub ? stub : target);
}

BOOL modules_free(HMODULE h)
{
    int i = find_module(h);
    HMODULE now = i >= 0 ? g_m->mod[i].now : h;
    if (!FreeLibrary(now)) return FALSE;
    if (i >= 0) {
        if (g_m->mod[i].refs > 0) g_m->mod[i].refs--;
        g_m->mod[i].gone = !still_loaded(now);
    }
    return TRUE;
}

int modules_init(ModulesEmu *m, BYTE *stub_page)
{
    g_m     = m;
    g_stubs = stub_page;
    write_stubs();
    return protect_stubs();
}

int modules_adopt(ModulesEmu *m, BYTE *stub_page)
{
    g_m     = m;
    g_stubs = stub_page;
    return protect_stubs() && refresh_modules_and_procs();
}
