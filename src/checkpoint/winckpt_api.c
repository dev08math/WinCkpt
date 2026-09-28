#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#include "ckpt_format.h"
#include "arena.h"
#include "boundary.h"
#include "winckpt_api.h"
#include "log.h"

static void snapshot_free(Snapshot *s)
{
    free(s->rg);
    free(s->bytes);
    s->rg = NULL;
    s->bytes = NULL;
}

static int snapshot_arena(Snapshot *s, ULONGLONG start, ULONGLONG stop,
                          ULONGLONG *vq_high)
{
    memset(s, 0, sizeof(*s));
    s->arena_start = start;
    *vq_high = start;

    for (int pass = 0; pass < 2; pass++) {
        ULONGLONG n = 0;
        s->total = 0;
        for (ULONGLONG a = start; a < stop; ) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                fprintf(stderr, "snapshot: VirtualQuery(0x%llX) failed, err=%lu\n",
                        a, GetLastError());
                return 0;
            }
            ULONGLONG rend = (ULONGLONG)mbi.BaseAddress + mbi.RegionSize;
            if (rend > stop) rend = stop;

            if (mbi.State == MEM_COMMIT) {
                if (pass == 1) {
                    RegionRec *r = &s->rg[n];
                    r->base    = a;
                    r->size    = rend - a;
                    r->protect = mbi.Protect;
                    r->kind    = (a >= g_arena.stack_limit && a < g_arena.stack_base)
                                     ? REGION_STACK : REGION_PLAIN;
                    r->off     = s->total;
                }
                s->total += rend - a;
                n++;
                if (rend > *vq_high) *vq_high = rend;
            }
            a = rend;
        }
        if (pass == 0) {
            s->count = n;
            s->rg = (RegionRec *)calloc((size_t)n, sizeof(RegionRec));
            if (!s->rg) { fprintf(stderr, "snapshot: out of memory\n"); return 0; }
        }
    }

    s->bytes = (BYTE *)malloc((size_t)s->total);
    if (!s->bytes) { fprintf(stderr, "snapshot: out of memory\n"); return 0; }
    for (ULONGLONG i = 0; i < s->count; i++)
        memcpy(s->bytes + s->rg[i].off, (const void *)s->rg[i].base,
               (size_t)s->rg[i].size);
    return 1;
}

// TODO: the writer emits one fixed layout and only checks that each WriteFile
// returned the byte count. Needs a version field the reader dispatches on, and
// a write to a temp file renamed on success so a failed write cannot leave a
// half-written checkpoint in place of a good one.
static int write_ckpt(const char *path, const Snapshot *s, ULONGLONG *out_bytes)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "write_ckpt: CreateFileA failed, err=%lu\n", GetLastError());
        return 0;
    }
    ULONGLONG written = 0;
    DWORD got = 0;
    int ok = 1;

    ULONGLONG hdr[5] = { CKPT_MAGIC, s->arena_start, s->count,
                         s->context_present, s->total };
    ok = WriteFile(h, hdr, sizeof(hdr), &got, NULL) && got == sizeof(hdr);
    written += got;

    for (ULONGLONG i = 0; ok && i < s->count; i++) {
        ULONGLONG rec[4] = { s->rg[i].base, s->rg[i].size,
                             s->rg[i].protect, s->rg[i].kind };
        ok = WriteFile(h, rec, sizeof(rec), &got, NULL) && got == sizeof(rec);
        written += got;
        if (!ok) break;
        ok = WriteFile(h, s->bytes + s->rg[i].off, (DWORD)s->rg[i].size, &got, NULL)
             && got == (DWORD)s->rg[i].size;
        written += got;
    }

    if (ok && s->context_present) {
        ULONGLONG tag = TAG_CONTEXT;
        ok = WriteFile(h, &tag, sizeof(tag), &got, NULL) && got == sizeof(tag);
        written += got;
        if (ok) {
            ok = WriteFile(h, &s->ctx, sizeof(s->ctx), &got, NULL)
                 && got == sizeof(s->ctx);
            written += got;
        }
    }
    if (!ok) fprintf(stderr, "write_ckpt: WriteFile failed, err=%lu\n", GetLastError());
    CloseHandle(h);
    *out_bytes = written;
    return ok;
}

static void do_checkpoint(const CONTEXT *ctx)
{
    ULONGLONG vq_high = 0;
    Snapshot snap;

    if (!snapshot_arena(&snap, g_arena.base, g_arena.end, &vq_high)) {
        snapshot_free(&snap);
        return;
    }

    if (ctx) {
        snap.ctx = *ctx;
        snap.context_present = 1;
    }

    for (ULONGLONG i = 0; i < snap.count; i++)
        if (g_verbose
            || snap.rg[i].base < g_arena.base
            || snap.rg[i].base + snap.rg[i].size > g_arena.end)
        printf("ckpt: region[%llu]  [0x%llX .. 0x%llX)  %8llu bytes  %-5s  prot=0x%lX%s\n",
               i, snap.rg[i].base, snap.rg[i].base + snap.rg[i].size,
               snap.rg[i].size,
               snap.rg[i].kind == REGION_STACK ? "STACK" : "PLAIN",
               snap.rg[i].protect,
               (snap.rg[i].base >= g_arena.base
                && snap.rg[i].base + snap.rg[i].size <= g_arena.end)
                   ? "" : "  *** OUTSIDE ARENA ***");

    VLOG("ckpt: heap_ctl.committed=0x%llX, VirtualQuery high-water=0x%llX\n",
         g_ctl->committed, vq_high);

    char sizes[128];
    sizes[0] = 0;
    for (ULONGLONG i = 0; i < snap.count; i++) {
        char one[48];
        sprintf(one, " %s %llu", snap.rg[i].kind == REGION_STACK ? "stack"
                : snap.rg[i].base == g_arena.app_base ? "image" : "heap",
                snap.rg[i].size);
        if (strlen(sizes) + strlen(one) < sizeof sizes) strcat(sizes, one);
    }

    ULONGLONG fsize = 0;
    if (!write_ckpt(DEFAULT_CKPT_PATH, &snap, &fsize)) { snapshot_free(&snap); return; }

    VLOG("mem     %llu regions:%s\n", snap.count, sizes);
    VLOG("file    %s  %llu bytes\n", DEFAULT_CKPT_PATH, fsize);

    snapshot_free(&snap);
}

static void capture_context(CONTEXT *out, int *frames_popped)
{
    CONTEXT ctx;
    RtlCaptureContext(&ctx);

    int n = 0;
    while (!(ctx.Rip >= g_arena.app_base && ctx.Rip < g_arena.app_end) && n < 8) {
        ULONGLONG img = 0;
        PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(ctx.Rip, &img, NULL);
        if (!fn) {
            fprintf(stderr, "capture_context: no function entry for 0x%llX\n", ctx.Rip);
            break;
        }
        PVOID handler_data = NULL;
        ULONG64 establisher = 0;
        RtlVirtualUnwind(UNW_FLAG_NHANDLER, img, ctx.Rip, fn, &ctx,
                         &handler_data, &establisher, NULL);
        n++;
    }
    *frames_popped = n;
    *out = ctx;
}

WINCKPT_API void winckpt_checkpoint(void)
{
    // Rsp is the return-address slot + 8 bytes the ret pops.
    ULONGLONG expect_rsp = (ULONGLONG)_AddressOfReturnAddress() + 8;

    CONTEXT ctx;
    int frames = 0;
    capture_context(&ctx, &frames);

    int rip_ok = ctx.Rip >= g_arena.app_base && ctx.Rip < g_arena.app_end;
    int rsp_ok = ctx.Rsp >= g_arena.stack_limit && ctx.Rsp < g_arena.stack_base;
    int rsp_match = ctx.Rsp == expect_rsp;

    DLOG("\n--- checkpoint ---\n");
    VLOG("regs    Rip 0x%llX %s  Rsp 0x%llX %s%s\n",
           ctx.Rip, rip_ok ? "(app code)" : "(NOT APP CODE)",
           ctx.Rsp, rsp_ok ? "(app stack)" : "(NOT APP STACK)",
           rsp_match ? "" : "  UNWIND MISMATCH");
    if (!rip_ok || !rsp_ok || !rsp_match)
        printf("ckpt: app image [0x%llX..0x%llX) arena stack [0x%llX..0x%llX) "
               "expected Rsp=0x%llX, unwound %d frame(s)\n",
               g_arena.app_base, g_arena.app_end,
               g_arena.stack_limit, g_arena.stack_base,
               expect_rsp, frames);
    else
        VLOG("ckpt: unwound %d frame(s) to reach the app\n", frames);

    do_checkpoint(&ctx);
    DLOG("--- app resumes ---\n");
}

static void on_app_exit(UINT code)
{
    DLOG("\n--- app exit %u ---\n", code);
    VLOG("winckpt: %llu malloc / %llu free / %llu realloc / %llu calloc\n",
         g_n_malloc, g_n_free, g_n_realloc, g_n_calloc);
    if (g_verbose) arena_dump_ctl("at exit");
    if (code == 0 && g_ctl->cur > g_arena.heap_start && g_ctl->cur <= g_ctl->committed)
        printf("PASS    %llu upper-half allocs, all in arena\n", g_n_malloc + g_n_calloc);
    else
        printf("FAIL    exit code %u or arena allocator control block not sane\n", code);
}

WINCKPT_API void *winckpt_hook_lookup(const char *import_name)
{
    return boundary_hook(import_name);
}

WINCKPT_API void winckpt_hook_report(const char *module)
{
    boundary_report(module);
}

WINCKPT_API int winckpt_init(const winckpt_arena *a)
{
    g_verbose = a->verbose;
    setvbuf(stdout, NULL, _IONBF, 0);

    if (!arena_init(a)) {
        fprintf(stderr, "winckpt_init: arena_init failed, err=%lu\n", GetLastError());
        return 0;
    }
    if (!boundary_init(a->emu_at)) return 0;
    boundary_on_exit(a->detach, a->n_detach, on_app_exit);

    VLOG("winckpt: heap at 0x%llX, ctl reserve %llu bytes, emu at 0x%llX\n",
         g_arena.heap_start, (ULONGLONG)HEAP_CTL_RESERVE, a->emu_at);
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reason; (void)reserved;
    return TRUE;
}
