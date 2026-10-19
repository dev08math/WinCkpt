#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "process.h"
#include "arena.h"

static ProcessEmu  *g_p;
static Image      **g_crt;
static int          g_n_crt;
static const Image *g_app;
static exit_fn      g_on_exit;

static int set_cmdline(const WCHAR *w)
{
    size_t nw = (wcslen(w) + 1) * sizeof(WCHAR);
    int na = WideCharToMultiByte(CP_ACP, 0, w, -1, NULL, 0, NULL, NULL);
    g_p->cmdline_w = (WCHAR *)arena_malloc(nw);
    g_p->cmdline_a = na > 0 ? (char *)arena_malloc((size_t)na) : NULL;
    if (!g_p->cmdline_w || !g_p->cmdline_a) {
        fprintf(stderr, "process: command line copy failed, err=%lu\n", GetLastError());
        return 0;
    }
    memcpy(g_p->cmdline_w, w, nw);
    WideCharToMultiByte(CP_ACP, 0, w, -1, g_p->cmdline_a, na, NULL, NULL);
    return 1;
}

int process_init(ProcessEmu *p, const WCHAR *cmdline)
{
    g_p = p;
    return set_cmdline(cmdline);
}

void process_adopt(ProcessEmu *p)
{
    g_p = p;
}

ProcessEmu *process_state(void)
{
    return g_p;
}

void process_on_exit(Image **crt, int n_crt, const Image *app, exit_fn on_exit)
{
    g_crt     = crt;
    g_n_crt   = n_crt;
    g_app     = app;
    g_on_exit = on_exit;
}

void process_detach(UINT code)
{
    // Windows sends no DETACH to images it did not load; the exe's TLS callbacks run last.
    for (int i = g_n_crt - 1; i >= 0; i--)
        loader_dll_main(g_crt[i], DLL_PROCESS_DETACH);
    if (g_app) loader_run_tls(g_app, DLL_PROCESS_DETACH);
    if (g_on_exit) g_on_exit(code);
}
