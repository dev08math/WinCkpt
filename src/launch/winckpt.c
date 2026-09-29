#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "loader.h"
#include "winckpt_api.h"
#include "log.h"

int g_verbose;
static ULONGLONG g_arena_base;
static ULONGLONG g_arena_end;
static ULONGLONG g_stack_limit;
static ULONGLONG g_stack_base;

static Image  g_app  = { "app.exe" };
static Image  g_ucrt = { "ucrtbase.dll" };
static Image  g_vcrt = { "vcruntime140.dll" };
static Image *g_crt_copies[2];
static Image *g_detach_order[2];
static int    g_n_crt;

static void app_returned(void)
{
    fprintf(stderr, "app returned from its entry point -- unexpected\n");
    ExitProcess(2);
}

static int setup_app_stack(void)
{
    g_stack_limit = g_arena_base + APP_STACK_OFF;
    g_stack_base  = g_stack_limit + APP_STACK_SIZE;
    if (!VirtualAlloc((LPVOID)g_stack_limit, (SIZE_T)APP_STACK_SIZE,
                      MEM_COMMIT, PAGE_READWRITE))
        return 0;
    return 1;
}

static void enter_app_on_arena_stack(ULONGLONG entry)
{
    // The entry expects rsp = 16n+8, as if a call had just pushed the return
    // address, so the offset must be a multiple of 16. It must also be nonzero:
    // the entry writes shadow space above rsp, which at 0 lands past the stack
    // top. 256 is headroom. Sweep: 0, 8, 40 crash; 16, 32, 48 work.
    ULONGLONG top = g_stack_base - 256;
    ULONGLONG rsp = top - 8;
    *(ULONGLONG *)rsp = (ULONGLONG)app_returned;

    // The TEB still points at this thread's original stack. Repoint it at the
    // arena stack so the CRT's stack checks and exception dispatch look at the
    // right place.
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    tib->StackBase  = (void *)g_stack_base;
    tib->StackLimit = (void *)g_stack_limit;

    CONTEXT ctx;
    RtlCaptureContext(&ctx);
    ctx.Rip = entry;
    ctx.Rsp = rsp;
    RtlRestoreContext(&ctx, NULL);
}

static int app_dir_path(char *out, DWORD size, const char *name)
{
    char *file = NULL;
    DWORD n = GetFullPathNameA(DEFAULT_APP_PATH, size, out, &file);
    if (n == 0 || n >= size || file == NULL) return 0;
    *file = 0;
    if (strlen(out) + strlen(name) + 1 > size) return 0;
    strcat(out, name);
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
    return loader_map(img, path, g_arena_base + off);
}

static int fill(Image *img)
{
    if (!loader_fill_imports(img, g_crt_copies, g_n_crt, winckpt_hook_lookup)) return 0;
    winckpt_hook_report(img->name);
    return loader_protect(img);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-v")) g_verbose = 1;

    // TODO: the base is fixed. Launch may take it from an arg, or choose it by scanning
    // the address spaces of processes on this machine for a range none of them uses,
    // then map app.exe there with relocations like the CRT copies, and record it in
    // arena_start. Only restart must reuse the recorded base.
    BYTE *arena = (BYTE *)VirtualAlloc((LPVOID)ARENA_BASE, (SIZE_T)ARENA_SIZE,
                                       MEM_RESERVE, PAGE_READWRITE);
    if (arena == NULL || (ULONGLONG)arena != ARENA_BASE) {
        fprintf(stderr, "launch: arena reserve failed (got 0x%p), err=%lu\n",
                (void *)arena, GetLastError());
        return 1;
    }
    g_arena_base = ARENA_BASE;
    g_arena_end  = ARENA_BASE + ARENA_SIZE;
    VLOG("arena   0x%llX-0x%llX  %llu GB reserved\n",
         g_arena_base, g_arena_end, ARENA_SIZE >> 30);

    if (!loader_map(&g_app, DEFAULT_APP_PATH, ARENA_BASE)) return 1;
    if (g_app.nt->OptionalHeader.SizeOfImage > APP_STACK_OFF) {
        fprintf(stderr, "launch: app.exe is %lu bytes, its slot is %llu\n",
                g_app.nt->OptionalHeader.SizeOfImage, APP_STACK_OFF);
        return 1;
    }
    // Windows 10+ always loads the System32 ucrtbase and ignores an app-local copy.
    if (!map_crt_copy(&g_ucrt, UCRT_OFF, 0)) return 1;
    g_crt_copies[g_n_crt++] = &g_ucrt;
    if (loader_imports(&g_app, g_vcrt.name)) {
        if (!map_crt_copy(&g_vcrt, VCRT_OFF, 1)) return 1;
        g_crt_copies[g_n_crt++] = &g_vcrt;
    }
    for (int i = 0; i < g_n_crt; i++)
        g_detach_order[i] = g_crt_copies[g_n_crt - 1 - i];

    ULONGLONG app_end = (ULONGLONG)g_app.base + g_app.nt->OptionalHeader.SizeOfImage;
    if (!setup_app_stack()) {
        fprintf(stderr, "launch: setup_app_stack failed, err=%lu\n", GetLastError());
        return 1;
    }

    HANDLE app_thread = NULL;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &app_thread,
                         THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, 0)) {
        fprintf(stderr, "launch: DuplicateHandle failed, err=%lu\n", GetLastError());
        return 1;
    }

    winckpt_arena a;
    memset(&a, 0, sizeof a);
    a.base        = g_arena_base;
    a.end         = g_arena_end;
    a.heap_start  = g_arena_base + HEAP_OFF;
    a.heap_end    = g_arena_end;
    a.stack_limit = g_stack_limit;
    a.stack_base  = g_stack_base;
    a.app_base    = (ULONGLONG)g_app.base;
    a.app_end     = app_end;
    a.emu_at      = g_arena_base + EMU_OFF;
    a.app_thread  = app_thread;
    a.verbose     = g_verbose;
    a.detach      = g_detach_order;
    a.n_detach    = g_n_crt;
    if (!winckpt_init(&a)) {
        fprintf(stderr, "launch: winckpt_init failed\n");
        return 1;
    }

    for (int i = 0; i < g_n_crt; i++)
        if (!fill(g_crt_copies[i])) return 1;
    if (!fill(&g_app)) return 1;

    for (int i = 0; i < g_n_crt; i++)
        if (!loader_dll_main(g_crt_copies[i], DLL_PROCESS_ATTACH)) return 1;
    if (!loader_run_tls(&g_app, DLL_PROCESS_ATTACH)) return 1;

    printf("launch: system ucrtbase loaded: %s\n",
           GetModuleHandleA("ucrtbase.dll") ? "YES -- a second CRT is live" : "no");

    ULONGLONG app_entry = (ULONGLONG)g_app.base + g_app.nt->OptionalHeader.AddressOfEntryPoint;
    VLOG("launch: entering app at 0x%llX on the arena stack\n", app_entry);
    DLOG("\n--- app ---\n");
    enter_app_on_arena_stack(app_entry);

    fprintf(stderr, "launch: RtlRestoreContext returned -- unreachable\n");
    return 0;
}
