#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <intrin.h>

#include "ckpt_format.h"
#include "arena.h"
#include "boundary.h"
#include "handles.h"
#include "winckpt_api.h"
#include "log.h"

static winckpt_args g_args;

WINCKPT_API void snapshot_free(Snapshot *s)
{
    free(s->rg);
    free(s->bytes);
    s->rg = NULL;
    s->bytes = NULL;
}

static int snapshot_arena(Snapshot *s)
{
    memset(s, 0, sizeof(*s));
    s->arena_start = g_arena.base;

    for (int pass = 0; pass < 2; pass++) {
        ULONGLONG n = 0;
        s->total = 0;
        for (ULONGLONG a = g_arena.base; a < g_arena.end; ) {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                fprintf(stderr, "snapshot: VirtualQuery(0x%llX) failed, err=%lu\n",
                        a, GetLastError());
                return 0;
            }
            ULONGLONG rend = (ULONGLONG)mbi.BaseAddress + mbi.RegionSize;
            if (rend > g_arena.end) rend = g_arena.end;

            if (mbi.State == MEM_COMMIT) {
                if (pass == 1) {
                    RegionRec *r = &s->rg[n];
                    r->base = a;
                    r->size = rend - a;
                    r->kind = (a >= g_arena.stack_limit && a < g_arena.stack_base)
                                  ? REGION_STACK : REGION_PLAIN;
                    r->off  = s->total;
                }
                s->total += rend - a;
                n++;
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

    ULONGLONG hdr[4] = { CKPT_MAGIC, s->arena_start, s->count, s->total };
    ok = WriteFile(h, hdr, sizeof(hdr), &got, NULL) && got == sizeof(hdr);
    written += got;
    if (ok) {
        ok = WriteFile(h, s->app_path, sizeof(s->app_path), &got, NULL)
             && got == sizeof(s->app_path);
        written += got;
    }

    for (ULONGLONG i = 0; ok && i < s->count; i++) {
        ULONGLONG rec[3] = { s->rg[i].base, s->rg[i].size, s->rg[i].kind };
        ok = WriteFile(h, rec, sizeof(rec), &got, NULL) && got == sizeof(rec);
        written += got;
        if (!ok) break;
        ok = WriteFile(h, s->bytes + s->rg[i].off, (DWORD)s->rg[i].size, &got, NULL)
             && got == (DWORD)s->rg[i].size;
        written += got;
    }

    if (ok) {
        ok = WriteFile(h, &s->ctx, sizeof(s->ctx), &got, NULL) && got == sizeof(s->ctx);
        written += got;
    }
    if (!ok) fprintf(stderr, "write_ckpt: WriteFile failed, err=%lu\n", GetLastError());
    CloseHandle(h);
    *out_bytes = written;
    return ok;
}

static int parse_ckpt(const BYTE *p, const BYTE *end, Snapshot *s)
{
    ULONGLONG hdr[4];
    if ((ULONGLONG)(end - p) < sizeof(hdr)) {
        fprintf(stderr, "ckpt_read: truncated header\n");
        return 0;
    }
    memcpy(hdr, p, sizeof(hdr));
    p += sizeof(hdr);
    if (hdr[0] != CKPT_MAGIC) {
        fprintf(stderr, "ckpt_read: bad magic 0x%llX\n", hdr[0]);
        return 0;
    }
    s->arena_start = hdr[1];
    s->count       = hdr[2];
    s->total       = hdr[3];

    if ((ULONGLONG)(end - p) < sizeof(s->app_path)) {
        fprintf(stderr, "ckpt_read: truncated app path\n");
        return 0;
    }
    memcpy(s->app_path, p, sizeof(s->app_path));
    p += sizeof(s->app_path);
    if (!memchr(s->app_path, 0, sizeof(s->app_path))) {
        fprintf(stderr, "ckpt_read: app path not terminated\n");
        return 0;
    }

    ULONGLONG rec[3];
    if (s->count > (ULONGLONG)(end - p) / sizeof(rec) || s->total > (ULONGLONG)(end - p)) {
        fprintf(stderr, "ckpt_read: %llu regions, %llu bytes: larger than the file\n",
                s->count, s->total);
        return 0;
    }
    s->rg    = (RegionRec *)calloc((size_t)s->count, sizeof(RegionRec));
    s->bytes = (BYTE *)malloc((size_t)s->total);
    if (!s->rg || !s->bytes) {
        fprintf(stderr, "ckpt_read: out of memory\n");
        return 0;
    }

    ULONGLONG off = 0;
    for (ULONGLONG i = 0; i < s->count; i++) {
        if ((ULONGLONG)(end - p) < sizeof(rec)) {
            fprintf(stderr, "ckpt_read: truncated region record %llu\n", i);
            return 0;
        }
        memcpy(rec, p, sizeof(rec));
        p += sizeof(rec);
        RegionRec *r = &s->rg[i];
        r->base = rec[0];
        r->size = rec[1];
        r->kind = rec[2];
        r->off  = off;
        if (r->base < ARENA_BASE || r->size > ARENA_BASE + ARENA_SIZE - r->base) {
            fprintf(stderr, "ckpt_read: region %llu 0x%llX+0x%llX outside the arena\n",
                    i, r->base, r->size);
            return 0;
        }
        if (r->size > (ULONGLONG)(end - p) || r->size > s->total - off) {
            fprintf(stderr, "ckpt_read: truncated payload of region %llu\n", i);
            return 0;
        }
        memcpy(s->bytes + off, p, (size_t)r->size);
        p += r->size;
        off += r->size;
    }
    if (off != s->total) {
        fprintf(stderr, "ckpt_read: payload %llu bytes, header says %llu\n", off, s->total);
        return 0;
    }

    if ((ULONGLONG)(end - p) != sizeof(CONTEXT)) {
        fprintf(stderr, "ckpt_read: %llu bytes after the regions, a context is %zu\n",
                (ULONGLONG)(end - p), sizeof(CONTEXT));
        return 0;
    }
    memcpy(&s->ctx, p, sizeof(CONTEXT));
    return 1;
}

WINCKPT_API int ckpt_read(const char *path, Snapshot *s)
{
    memset(s, 0, sizeof(*s));
    DWORD fsize = 0;
    BYTE *file = loader_read_file(path, &fsize);
    if (!file) return 0;
    int ok = parse_ckpt(file, file + fsize, s);
    free(file);
    if (!ok) snapshot_free(s);
    return ok;
}

static int do_checkpoint(const CONTEXT *ctx)
{
    Snapshot snap;

    if (!arena_outside_ok()) return 0;
    if (!snapshot_arena(&snap)) {
        snapshot_free(&snap);
        return 0;
    }
    strcpy(snap.app_path, g_args.app_path);
    snap.ctx = *ctx;

    for (ULONGLONG i = 0; g_verbose && i < snap.count; i++)
        printf("ckpt: region[%llu]  [0x%llX .. 0x%llX)  %8llu bytes  %s\n",
               i, snap.rg[i].base, snap.rg[i].base + snap.rg[i].size, snap.rg[i].size,
               snap.rg[i].kind == REGION_STACK ? "STACK" : "PLAIN");

    ULONGLONG fsize = 0;
    int ok = write_ckpt(g_args.ckpt_path, &snap, &fsize);
    if (ok) VLOG("file    %s  %llu bytes\n", g_args.ckpt_path, fsize);
    snapshot_free(&snap);
    return ok;
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
    int written = 0;
    if (!rip_ok || !rsp_ok || !rsp_match) {
        printf("ckpt: refused, caller is not app code: Rip=0x%llX Rsp=0x%llX, "
               "app image [0x%llX..0x%llX) arena stack [0x%llX..0x%llX) "
               "expected Rsp=0x%llX, unwound %d frame(s)\n",
               ctx.Rip, ctx.Rsp, g_arena.app_base, g_arena.app_end,
               g_arena.stack_limit, g_arena.stack_base,
               expect_rsp, frames);
    } else {
        VLOG("ckpt: unwound %d frame(s) to reach the app\n", frames);
        written = do_checkpoint(&ctx);
    }
    if (g_args.exit_after_ckpt) {
        printf("ckpt: %s %s, exiting (-k)\n", g_args.ckpt_path, written ? "written" : "NOT written");
        TerminateProcess(GetCurrentProcess(), written ? 0 : 1);
    }
    DLOG("--- app resumes ---\n");
}

static void on_app_exit(UINT code)
{
    DLOG("\n--- app exit %u ---\n", code);
    VLOG("winckpt: %llu malloc / %llu free / %llu realloc / %llu calloc\n",
         g_ctl->n_malloc, g_ctl->n_free, g_ctl->n_realloc, g_ctl->n_calloc);
    if (g_verbose) arena_dump_ctl("at exit");
    if (code == 0 && g_ctl->cur > g_arena.heap_start && g_ctl->cur <= g_ctl->committed)
        printf("PASS    %llu upper-half allocs, all in arena\n", g_ctl->n_malloc + g_ctl->n_calloc);
    else
        printf("FAIL    exit code %u or arena allocator control block not sane\n", code);
}

static int fill(Image *img)
{
    if (!loader_fill_imports(img, g_args.crt, g_args.n_crt, boundary_hook)) return 0;
    boundary_report(img->name);
    return loader_protect(img);
}

static int fill_all(void)
{
    for (int i = 0; i < g_args.n_crt; i++)
        if (!fill(g_args.crt[i])) return 0;
    return fill(g_args.app);
}

static void begin(const winckpt_args *a, winckpt_arena *layout)
{
    g_args    = *a;
    g_verbose = a->verbose;
    setvbuf(stdout, NULL, _IONBF, 0);

    layout->base        = ARENA_BASE;
    layout->end         = ARENA_BASE + ARENA_SIZE;
    layout->heap_start  = ARENA_BASE + HEAP_OFF;
    layout->stack_limit = ARENA_BASE + APP_STACK_OFF;
    layout->stack_base  = layout->stack_limit + APP_STACK_SIZE;
    layout->app_base    = (ULONGLONG)a->app->base;
    layout->app_end     = layout->app_base + a->app->nt->OptionalHeader.SizeOfImage;
    layout->emu_at      = ARENA_BASE + EMU_OFF;
    process_on_exit(a->crt, a->n_crt, a->app, on_app_exit);
}

WINCKPT_API int winckpt_init(const winckpt_args *a)
{
    winckpt_arena layout;
    begin(a, &layout);
    if (!arena_init(&layout)) {
        fprintf(stderr, "winckpt_init: arena_init failed, err=%lu\n", GetLastError());
        return 0;
    }
    if (!boundary_init(layout.emu_at, a->cmdline)) return 0;
    VLOG("winckpt: heap at 0x%llX, ctl reserve %llu bytes, emu at 0x%llX\n",
         layout.heap_start, (ULONGLONG)HEAP_CTL_RESERVE, layout.emu_at);
    return fill_all();
}

WINCKPT_API int winckpt_adopt(const winckpt_args *a)
{
    winckpt_arena layout;
    begin(a, &layout);
    arena_adopt(&layout);
    if (!boundary_adopt(layout.emu_at)) return 0;
    VLOG("winckpt: adopted heap at 0x%llX (cur=0x%llX), emu at 0x%llX\n",
         layout.heap_start, g_ctl->cur, layout.emu_at);
    return fill_all() && handles_rebind_std(g_args.crt[0]);
}

WINCKPT_API void winckpt_enter(CONTEXT *ctx)
{
    // __chkstk and exception dispatch read the stack bounds from the TEB.
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    tib->StackBase  = (void *)g_arena.stack_base;
    tib->StackLimit = (void *)g_arena.stack_limit;
    RtlRestoreContext(ctx, NULL);
}
