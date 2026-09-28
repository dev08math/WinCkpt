#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Standalone reader for the M4a checkpoint (WCKPT002). Parses the file front
// to back and applies the verification the milestone is judged by. It derives
// the app image range from app.exe's own headers rather than hardcoding it, so
// it stays honest if the preferred base ever changes.

#define CKPT_PATH  "arena.ckpt"
#define APP_PATH   "app.exe"
#define CKPT_MAGIC 0x32303054504B4357ULL   // "WCKPT002"
#define OLD_MAGIC  0x31303054504B4357ULL   // "WCKPT001"
#define TAG_CONTEXT 0x584B4354ULL          // "TCKX"

#define REGION_PLAIN 0u
#define REGION_STACK 1u

#define ARENA_BASE 0x2A0000000ULL
#define ARENA_SIZE 0x40000000ULL
#define PAGE       0x1000ULL

static BYTE *read_whole(const char *path, DWORD *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "dumpckpt: cannot open %s, err=%lu\n", path, GetLastError());
        return NULL;
    }
    DWORD size = GetFileSize(h, NULL);
    BYTE *buf = (BYTE *)malloc(size);
    DWORD got = 0;
    if (!buf || !ReadFile(h, buf, size, &got, NULL) || got != size) {
        fprintf(stderr, "dumpckpt: read failed on %s, err=%lu\n", path, GetLastError());
        CloseHandle(h); free(buf); return NULL;
    }
    CloseHandle(h);
    *out_size = size;
    return buf;
}

static int app_image_range(ULONGLONG *lo, ULONGLONG *hi)
{
    DWORD size = 0;
    BYTE *f = read_whole(APP_PATH, &size);
    if (!f) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)f;
    if (size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) { free(f); return 0; }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(f + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { free(f); return 0; }
    *lo = nt->OptionalHeader.ImageBase;
    *hi = *lo + nt->OptionalHeader.SizeOfImage;
    free(f);
    return 1;
}

// TODO: this parser is duplicated in restarter.c. Both should call one shared
// reader built on ckpt_format.h.
int main(void)
{
    DWORD fsize = 0;
    BYTE *file = read_whole(CKPT_PATH, &fsize);
    if (!file) return 1;

    BYTE *p = file, *end = file + fsize;
    if ((ULONGLONG)(end - p) < 40) { fprintf(stderr, "dumpckpt: truncated header\n"); return 1; }

    ULONGLONG magic, arena_start, count, ctx_present, total;
    memcpy(&magic, p, 8);        p += 8;
    memcpy(&arena_start, p, 8);  p += 8;
    memcpy(&count, p, 8);        p += 8;
    memcpy(&ctx_present, p, 8);  p += 8;
    memcpy(&total, p, 8);        p += 8;

    if (magic == OLD_MAGIC) {
        fprintf(stderr, "dumpckpt: WCKPT001 file -- format superseded, refusing\n");
        return 1;
    }
    if (magic != CKPT_MAGIC) { fprintf(stderr, "dumpckpt: bad magic 0x%llX\n", magic); return 1; }

    printf("header: magic=WCKPT002 arena_start=0x%llX regions=%llu "
           "context_present=%llu total_bytes=%llu\n",
           arena_start, count, ctx_present, total);

    ULONGLONG stack_base = 0, stack_size = 0;
    int stack_regions = 0;
    ULONGLONG seen = 0;

    for (ULONGLONG i = 0; i < count; i++) {
        if ((ULONGLONG)(end - p) < 32) { fprintf(stderr, "dumpckpt: truncated rec %llu\n", i); return 1; }
        ULONGLONG rec[4];
        memcpy(rec, p, 32); p += 32;
        ULONGLONG base = rec[0], size = rec[1];
        DWORD prot = (DWORD)rec[2], kind = (DWORD)rec[3];

        if ((ULONGLONG)(end - p) < size) { fprintf(stderr, "dumpckpt: truncated payload %llu\n", i); return 1; }
        p += size;
        seen += size;

        printf("region[%llu] base=0x%011llX size=0x%08llX protect=0x%-3lX kind=%s\n",
               i, base, size, prot, kind == REGION_STACK ? "STACK" : "PLAIN");

        if (kind == REGION_STACK) { stack_base = base; stack_size = size; stack_regions++; }
    }

    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    if (ctx_present) {
        if ((ULONGLONG)(end - p) < 8 + sizeof(CONTEXT)) {
            fprintf(stderr, "dumpckpt: truncated context\n"); return 1;
        }
        ULONGLONG tag;
        memcpy(&tag, p, 8); p += 8;
        if (tag != TAG_CONTEXT) { fprintf(stderr, "dumpckpt: bad context tag\n"); return 1; }
        memcpy(&ctx, p, sizeof(ctx)); p += sizeof(ctx);
    }

    printf("\n");
    if (stack_regions == 1)
        printf("stack region: base=0x%llX size=0x%llX (%llu KB)\n",
               stack_base, stack_size, stack_size / 1024);
    else
        printf("stack region: %d found (expected exactly 1)\n", stack_regions);

    if (ctx_present) {
        printf("context: Rip=0x%llX Rsp=0x%llX Rbp=0x%llX Rbx=0x%llX\n",
               ctx.Rip, ctx.Rsp, ctx.Rbp, ctx.Rbx);
        ULONGLONG live_lo = ctx.Rsp & ~(PAGE - 1);
        printf("live stack extent: [0x%llX .. 0x%llX) = %llu bytes of the %llu captured\n",
               live_lo, stack_base + stack_size,
               (stack_base + stack_size) - live_lo, stack_size);
    } else {
        printf("context: none\n");
    }

    ULONGLONG app_lo = 0, app_hi = 0;
    int have_app = app_image_range(&app_lo, &app_hi);

    printf("\nVERIFY\n");
    int ok = 1;

    if (have_app) {
        int a = ctx_present && ctx.Rip >= app_lo && ctx.Rip < app_hi;
        printf("  [A] Rip inside app image [0x%llX..0x%llX): %s\n",
               app_lo, app_hi, a ? "PASS" : "FAIL");
        ok &= a;
    } else {
        printf("  [A] app image range unavailable (app.exe not readable): SKIP\n");
        ok = 0;
    }

    int b = ctx_present && stack_regions == 1
            && ctx.Rsp >= stack_base && ctx.Rsp < stack_base + stack_size;
    printf("  [B] Rsp inside captured stack region: %s\n", b ? "PASS" : "FAIL");
    ok &= b;

    int c = stack_regions == 1
            && stack_base >= ARENA_BASE
            && stack_base + stack_size <= ARENA_BASE + ARENA_SIZE;
    printf("  [C] stack region inside arena (upper-half pure): %s\n", c ? "PASS" : "FAIL");
    ok &= c;

    int d = (p == end) && (seen == total);
    printf("  [D] bytes consumed == file size: %s (%llu/%lu, payload %llu/%llu)\n",
           d ? "PASS" : "FAIL", (ULONGLONG)(p - file), fsize, seen, total);
    ok &= d;

    printf("\n%s\n", ok ? "dumpckpt: ALL CHECKS PASS" : "dumpckpt: CHECKS FAILED");
    free(file);
    return ok ? 0 : 1;
}
