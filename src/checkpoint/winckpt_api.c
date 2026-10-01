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

WINCKPT_API void snapshot_free(Snapshot *s)
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

static BYTE *read_file(const char *path, DWORD *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "ckpt_read: CreateFileA(%s) failed, err=%lu\n", path, GetLastError());
        return NULL;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart > MAXDWORD) {
        fprintf(stderr, "ckpt_read: %s: size unreadable or over 4 GB\n", path);
        CloseHandle(h);
        return NULL;
    }
    BYTE *buf = (BYTE *)malloc((size_t)size.QuadPart);
    DWORD got = 0;
    if (!buf || !ReadFile(h, buf, size.LowPart, &got, NULL) || got != size.LowPart) {
        fprintf(stderr, "ckpt_read: ReadFile(%s) failed, err=%lu\n", path, GetLastError());
        CloseHandle(h);
        free(buf);
        return NULL;
    }
    CloseHandle(h);
    *out_size = size.LowPart;
    return buf;
}

static int parse_ckpt(const BYTE *p, const BYTE *end, Snapshot *s)
{
    ULONGLONG hdr[5];
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
    s->arena_start     = hdr[1];
    s->count           = hdr[2];
    s->context_present = hdr[3];
    s->total           = hdr[4];

    ULONGLONG rec[4];
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
        r->base    = rec[0];
        r->size    = rec[1];
        r->protect = (DWORD)rec[2];
        r->kind    = (DWORD)rec[3];
        r->off     = off;
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

    if (s->context_present) {
        ULONGLONG tag;
        if ((ULONGLONG)(end - p) < sizeof(tag) + sizeof(CONTEXT)) {
            fprintf(stderr, "ckpt_read: truncated context\n");
            return 0;
        }
        memcpy(&tag, p, sizeof(tag));
        p += sizeof(tag);
        if (tag != TAG_CONTEXT) {
            fprintf(stderr, "ckpt_read: bad context tag 0x%llX\n", tag);
            return 0;
        }
        memcpy(&s->ctx, p, sizeof(CONTEXT));
        p += sizeof(CONTEXT);
    }
    if (p != end) {
        fprintf(stderr, "ckpt_read: %llu trailing bytes\n", (ULONGLONG)(end - p));
        return 0;
    }
    return 1;
}

WINCKPT_API int ckpt_read(const char *path, Snapshot *s)
{
    memset(s, 0, sizeof(*s));
    DWORD fsize = 0;
    BYTE *file = read_file(path, &fsize);
    if (!file) return 0;
    int ok = parse_ckpt(file, file + fsize, s);
    free(file);
    if (!ok) snapshot_free(s);
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
    if (g_arena.exit_after_ckpt) {
        printf("ckpt: %s written, exiting (-k)\n", DEFAULT_CKPT_PATH);
        TerminateProcess(GetCurrentProcess(), 0);
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

WINCKPT_API void *winckpt_hook_lookup(const char *import_name)
{
    return boundary_hook(import_name);
}

WINCKPT_API void winckpt_hook_report(const char *module)
{
    boundary_report(module);
}

WINCKPT_API int winckpt_rebind_std(const Image *ucrt)
{
    return boundary_rebind_std(ucrt);
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

WINCKPT_API int winckpt_adopt(const winckpt_arena *a)
{
    g_verbose = a->verbose;
    setvbuf(stdout, NULL, _IONBF, 0);

    arena_adopt(a);
    if (!boundary_adopt(a->emu_at)) return 0;
    boundary_on_exit(a->detach, a->n_detach, on_app_exit);

    VLOG("winckpt: adopted heap at 0x%llX (cur=0x%llX), emu at 0x%llX\n",
         g_arena.heap_start, g_ctl->cur, a->emu_at);
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reason; (void)reserved;
    return TRUE;
}
