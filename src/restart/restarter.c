#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "loader.h"
#include "winckpt_api.h"
#include "log.h"

int g_verbose;
static int    g_exit_after_ckpt;
static LPVOID g_reserve_got;
static DWORD  g_reserve_err;

static char   g_app_path[MAX_PATH];
static char   g_ckpt_path[MAX_PATH];
static Image  g_app;
static Image  g_ucrt = { "ucrtbase.dll" };
static Image  g_vcrt = { "vcruntime140.dll" };
static Image *g_crt_copies[2];
static int    g_n_crt;

// A TLS callback runs before CRT startup, so the CRT cannot take the range first.
static void NTAPI arena_reserve_cb(PVOID inst, DWORD reason, PVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return;
    g_reserve_got = VirtualAlloc((LPVOID)ARENA_BASE, (SIZE_T)ARENA_SIZE,
                                 MEM_RESERVE, PAGE_READWRITE);
    g_reserve_err = g_reserve_got ? 0 : GetLastError();
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_arena_reserve_cb")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK p_arena_reserve_cb = arena_reserve_cb;
#pragma const_seg()

static void report_conflict(void)
{
    for (ULONGLONG a = ARENA_BASE; a < ARENA_BASE + ARENA_SIZE; ) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            fprintf(stderr, "restart: VirtualQuery(0x%llX) failed, err=%lu\n", a, GetLastError());
            return;
        }
        if (mbi.State != MEM_FREE)
            fprintf(stderr, "restart: in the way: 0x%llX+0x%llX state=0x%lX type=0x%lX\n",
                    (ULONGLONG)mbi.BaseAddress, (ULONGLONG)mbi.RegionSize, mbi.State, mbi.Type);
        a = (ULONGLONG)mbi.BaseAddress + mbi.RegionSize;
    }
}

static int check_regions(const Snapshot *s)
{
    for (ULONGLONG i = 0; i < s->count; i++) {
        const RegionRec *r = &s->rg[i];
        if (r->base < ARENA_BASE || r->size > ARENA_BASE + ARENA_SIZE - r->base) {
            fprintf(stderr, "restart: region[%llu] 0x%llX+0x%llX outside the arena\n",
                    i, r->base, r->size);
            return 0;
        }
    }
    return 1;
}

static int paste_regions(const Snapshot *s)
{
    for (ULONGLONG i = 0; i < s->count; i++) {
        const RegionRec *r = &s->rg[i];
        if (!VirtualAlloc((LPVOID)r->base, (SIZE_T)r->size, MEM_COMMIT, PAGE_READWRITE)) {
            fprintf(stderr, "restart: region[%llu] commit at 0x%llX failed, err=%lu\n",
                    i, r->base, GetLastError());
            return 0;
        }
        memcpy((void *)r->base, s->bytes + r->off, (size_t)r->size);
        VLOG("restart: region[%llu] 0x%llX+0x%llX %s pasted\n",
             i, r->base, r->size, r->kind == REGION_STACK ? "STACK" : "PLAIN");
    }
    return 1;
}

static int vcrt_pasted(const Snapshot *s)
{
    for (ULONGLONG i = 0; i < s->count; i++)
        if (s->rg[i].base == ARENA_BASE + VCRT_OFF) return 1;
    return 0;
}

static int adopt(void)
{
    winckpt_arena a;
    memset(&a, 0, sizeof a);
    a.base        = ARENA_BASE;
    a.end         = ARENA_BASE + ARENA_SIZE;
    a.heap_start  = ARENA_BASE + HEAP_OFF;
    a.heap_end    = a.end;
    a.stack_limit = ARENA_BASE + APP_STACK_OFF;
    a.stack_base  = a.stack_limit + APP_STACK_SIZE;
    a.app_base    = (ULONGLONG)g_app.base;
    a.app_end     = a.app_base + g_app.nt->OptionalHeader.SizeOfImage;
    a.emu_at      = ARENA_BASE + EMU_OFF;
    a.verbose     = g_verbose;
    a.exit_after_ckpt = g_exit_after_ckpt;
    a.crt         = g_crt_copies;
    a.n_crt       = g_n_crt;
    a.app         = &g_app;
    a.app_path    = g_app_path;
    a.ckpt_path   = g_ckpt_path;
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(),
                         GetCurrentProcess(), &a.app_thread,
                         THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, 0)) {
        fprintf(stderr, "restart: DuplicateHandle failed, err=%lu\n", GetLastError());
        return 0;
    }
    return winckpt_adopt(&a);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    const char *ckpt = NULL;
    int bad = 0;
    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-v")) g_verbose = 1;
        else if (!strcmp(argv[i], "-k")) g_exit_after_ckpt = 1;
        else if (argv[i][0] != '-' && !ckpt) ckpt = argv[i];
        else bad = 1;
    size_t len = ckpt ? strlen(ckpt) : 0;
    if (bad || len < strlen(CKPT_SUFFIX)
        || _stricmp(ckpt + len - strlen(CKPT_SUFFIX), CKPT_SUFFIX)) {
        fprintf(stderr, "usage: restarter.exe [-v] [-k] <ckpt%s>\n", CKPT_SUFFIX);
        return 1;
    }
    DWORD n = GetFullPathNameA(ckpt, sizeof g_ckpt_path, g_ckpt_path, NULL);
    if (n == 0 || n >= sizeof g_ckpt_path) {
        fprintf(stderr, "restart: %s: path too long or invalid\n", ckpt);
        return 1;
    }

    if (!g_reserve_got) {
        fprintf(stderr, "restart: arena reserve at 0x%llX failed, err=%lu\n",
                ARENA_BASE, g_reserve_err);
        report_conflict();
        return 1;
    }

    Snapshot s;
    if (!ckpt_read(g_ckpt_path, &s)) return 1;
    if (!s.context_present) {
        fprintf(stderr, "restart: %s has no saved context\n", g_ckpt_path);
        snapshot_free(&s);
        return 1;
    }
    strcpy(g_app_path, s.app_path);
    const char *slash = strrchr(g_app_path, '\\');
    g_app.name = slash ? slash + 1 : g_app_path;
    if (!check_regions(&s) || !paste_regions(&s)) {
        snapshot_free(&s);
        return 1;
    }
    CONTEXT ctx = s.ctx;

    loader_attach(&g_app, ARENA_BASE);
    if (!loader_become_main(&g_app, g_app_path)) {
        snapshot_free(&s);
        return 1;
    }
    loader_attach(&g_ucrt, ARENA_BASE + UCRT_OFF);
    g_crt_copies[g_n_crt++] = &g_ucrt;
    if (vcrt_pasted(&s)) {
        loader_attach(&g_vcrt, ARENA_BASE + VCRT_OFF);
        g_crt_copies[g_n_crt++] = &g_vcrt;
    }
    printf("restart: %llu regions, %llu bytes pasted; %d images\n", s.count, s.total, 1 + g_n_crt);
    snapshot_free(&s);

    for (int i = 0; i < g_n_crt; i++)
        if (!winckpt_fill(g_crt_copies[i], g_crt_copies, g_n_crt)) return 1;
    if (!winckpt_fill(&g_app, g_crt_copies, g_n_crt)) return 1;
    if (!adopt()) return 1;
    if (!winckpt_rebind_std(&g_ucrt)) return 1;

    VLOG("restart: resuming at Rip=0x%llX Rsp=0x%llX\n", ctx.Rip, ctx.Rsp);
    winckpt_enter(&ctx);

    fprintf(stderr, "restart: winckpt_enter returned -- unreachable\n");
    return 1;
}
