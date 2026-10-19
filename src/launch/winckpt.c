#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ckpt_format.h"
#include "loader.h"
#include "winckpt_api.h"
#include "log.h"

int g_verbose;
static int g_exit_after_ckpt;

static char   g_app_path[MAX_PATH];
static char   g_ckpt_path[MAX_PATH];
static Image  g_app;
static Image  g_ucrt = { "ucrtbase.dll" };
static Image  g_vcrt = { "vcruntime140.dll" };
static Image *g_crt_copies[2];
static int    g_n_crt;

static void app_returned(void)
{
    fprintf(stderr, "app returned from its entry point -- unexpected\n");
    ExitProcess(2);
}

static void enter_app_on_arena_stack(ULONGLONG entry)
{
    // Entry expects rsp ending in 8 and writes up to 32 bytes above it.
    ULONGLONG top = ARENA_BASE + APP_STACK_OFF + APP_STACK_SIZE - 256;
    ULONGLONG rsp = top - 8;
    *(ULONGLONG *)rsp = (ULONGLONG)app_returned;

    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    ctx.Rip = entry;
    ctx.Rsp = rsp;
    winckpt_enter(&ctx);
}

static int app_dir_path(char *out, DWORD size, const char *name)
{
    size_t dir = (size_t)(g_app.name - g_app_path);
    if (dir + strlen(name) + 1 > size) return 0;
    memcpy(out, g_app_path, dir);
    strcpy(out + dir, name);
    return 1;
}

static void usage(void)
{
    fprintf(stderr, "usage: winckpt.exe [-v] [-k] [--ckptdir DIR] [--] <program> [args...]\n"
                    "  --ckptdir DIR  where to write the checkpoint (env %s, default .)\n",
            CKPT_DIR_ENV);
}

// The CRT's argv rules: 2n backslashes + quote toggle quoting, 2n+1 make the quote
// literal; argv[0] has no escapes.
static const WCHAR *skip_arg(const WCHAR *p, int first)
{
    int quoted = 0;
    while (*p && (quoted || (*p != L' ' && *p != L'\t'))) {
        if (!first && *p == L'\\') {
            int n = 0;
            while (*p == L'\\') { n++; p++; }
            if (*p == L'"' && n % 2) p++;
            continue;
        }
        if (*p == L'"') quoted = !quoted;
        p++;
    }
    while (*p == L' ' || *p == L'\t') p++;
    return p;
}

static const WCHAR *app_cmdline(int prog_index)
{
    const WCHAR *p = GetCommandLineW();
    while (*p == L' ' || *p == L'\t') p++;
    for (int i = 0; i < prog_index; i++)
        p = skip_arg(p, i == 0);
    return p;
}

static int ckpt_path_for(const char *dir)
{
    DWORD attr = GetFileAttributesA(dir);
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        fprintf(stderr, "launch: checkpoint directory %s does not exist\n", dir);
        return 0;
    }
    char stem[MAX_PATH];
    strcpy(stem, g_app.name);
    char *dot = strrchr(stem, '.');
    if (dot && !_stricmp(dot, ".exe")) *dot = 0;

    char rel[MAX_PATH];
    int n = snprintf(rel, sizeof rel, "%s\\ckpt_%s_%lu%s", dir, stem, GetCurrentProcessId(),
                     CKPT_SUFFIX);
    DWORD got = n > 0 && n < (int)sizeof rel
                ? GetFullPathNameA(rel, sizeof g_ckpt_path, g_ckpt_path, NULL) : 0;
    if (got == 0 || got >= sizeof g_ckpt_path) {
        fprintf(stderr, "launch: checkpoint path in %s too long or invalid\n", dir);
        return 0;
    }
    return 1;
}

static int system_dir_path(char *out, DWORD size, const char *name)
{
    UINT n = GetSystemDirectoryA(out, size);
    if (n == 0 || n + strlen(name) + 2 > size) {
        fprintf(stderr, "launch: GetSystemDirectoryA failed, err=%lu\n", GetLastError());
        return 0;
    }
    strcat(out, "\\");
    strcat(out, name);
    return 1;
}

static int map_crt_copy(Image *img, ULONGLONG off, int app_local_first)
{
    char path[MAX_PATH];
    int found = app_local_first && app_dir_path(path, sizeof path, img->name)
                && GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
    if (!found && !system_dir_path(path, sizeof path, img->name)) return 0;
    return loader_map(img, path, ARENA_BASE + off);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *ckpt_dir = getenv(CKPT_DIR_ENV);
    int prog = 1;
    for (; prog < argc && argv[prog][0] == '-'; prog++) {
        if (!strcmp(argv[prog], "--")) { prog++; break; }
        if (!strcmp(argv[prog], "-v")) g_verbose = 1;
        else if (!strcmp(argv[prog], "-k")) g_exit_after_ckpt = 1;
        else if (!strcmp(argv[prog], "--ckptdir") && prog + 1 < argc) ckpt_dir = argv[++prog];
        else { usage(); return 1; }
    }
    if (prog >= argc) { usage(); return 1; }
    char *file = NULL;
    DWORD n = SearchPathA(NULL, argv[prog], ".exe", sizeof g_app_path, g_app_path, &file);
    if (n == 0 || n >= sizeof g_app_path || !file) {
        fprintf(stderr, "launch: %s: program not found, err=%lu\n", argv[prog], GetLastError());
        return 1;
    }
    g_app.name = file;
    if (!ckpt_path_for(ckpt_dir ? ckpt_dir : ".")) return 1;
    const WCHAR *cmdline = app_cmdline(prog);

    BYTE *arena = (BYTE *)VirtualAlloc((LPVOID)ARENA_BASE, (SIZE_T)ARENA_SIZE,
                                       MEM_RESERVE, PAGE_READWRITE);
    if (arena == NULL || (ULONGLONG)arena != ARENA_BASE) {
        fprintf(stderr, "launch: arena reserve failed (got 0x%p), err=%lu\n",
                (void *)arena, GetLastError());
        return 1;
    }
    VLOG("arena   0x%llX-0x%llX  %llu GB reserved\n",
         ARENA_BASE, ARENA_BASE + ARENA_SIZE, ARENA_SIZE >> 30);

    if (!loader_map(&g_app, g_app_path, ARENA_BASE)) return 1;
    if (g_app.nt->OptionalHeader.SizeOfImage > APP_STACK_OFF) {
        fprintf(stderr, "launch: %s is %lu bytes, its slot is %llu\n",
                g_app.name, g_app.nt->OptionalHeader.SizeOfImage, APP_STACK_OFF);
        return 1;
    }
    if (!loader_become_main(&g_app, g_app_path)) return 1;
    if (!map_crt_copy(&g_ucrt, UCRT_OFF, 0)) return 1;
    g_crt_copies[g_n_crt++] = &g_ucrt;
    if (loader_imports(&g_app, g_vcrt.name)) {
        if (!map_crt_copy(&g_vcrt, VCRT_OFF, 1)) return 1;
        g_crt_copies[g_n_crt++] = &g_vcrt;
    }

    if (!VirtualAlloc((LPVOID)(ARENA_BASE + APP_STACK_OFF), (SIZE_T)APP_STACK_SIZE,
                      MEM_COMMIT, PAGE_READWRITE)) {
        fprintf(stderr, "launch: app stack commit failed, err=%lu\n", GetLastError());
        return 1;
    }

    winckpt_args a = { g_verbose, g_exit_after_ckpt, g_crt_copies, g_n_crt, &g_app,
                       g_app_path, g_ckpt_path, cmdline };
    if (!winckpt_init(&a)) {
        fprintf(stderr, "launch: winckpt_init failed\n");
        return 1;
    }

    for (int i = 0; i < g_n_crt; i++)
        if (!loader_dll_main(g_crt_copies[i], DLL_PROCESS_ATTACH)) return 1;
    if (!loader_run_tls(&g_app, DLL_PROCESS_ATTACH)) return 1;

    printf("launch: system ucrtbase loaded: %s\n",
           GetModuleHandleA("ucrtbase.dll") ? "YES -- a second CRT is live" : "no");

    ULONGLONG app_entry = (ULONGLONG)g_app.base + g_app.nt->OptionalHeader.AddressOfEntryPoint;
    VLOG("launch: entering app at 0x%llX on the arena stack\n", app_entry);
    DLOG("\n--- app ---\n");
    enter_app_on_arena_stack(app_entry);

    fprintf(stderr, "launch: winckpt_enter returned -- unreachable\n");
    return 0;
}
