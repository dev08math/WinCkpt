#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ckpt_format.h"
#include "winckpt_api.h"

#define CKPT_PATH  DEFAULT_CKPT_PATH
#define APP_PATH   DEFAULT_APP_PATH

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

int main(void)
{
    Snapshot s;
    if (!ckpt_read(CKPT_PATH, &s)) return 1;

    printf("header: magic=WCKPT002 arena_start=0x%llX regions=%llu "
           "context_present=%llu total_bytes=%llu\n",
           s.arena_start, s.count, s.context_present, s.total);

    ULONGLONG stack_base = 0, stack_size = 0;
    int stack_regions = 0;

    for (ULONGLONG i = 0; i < s.count; i++) {
        const RegionRec *r = &s.rg[i];
        printf("region[%llu] base=0x%011llX size=0x%08llX protect=0x%-3lX kind=%s\n",
               i, r->base, r->size, r->protect, r->kind == REGION_STACK ? "STACK" : "PLAIN");
        if (r->kind == REGION_STACK) { stack_base = r->base; stack_size = r->size; stack_regions++; }
    }

    printf("\n");
    if (stack_regions == 1)
        printf("stack region: base=0x%llX size=0x%llX (%llu KB)\n",
               stack_base, stack_size, stack_size / 1024);
    else
        printf("stack region: %d found (expected exactly 1)\n", stack_regions);

    const CONTEXT *ctx = &s.ctx;
    if (s.context_present) {
        printf("context: Rip=0x%llX Rsp=0x%llX Rbp=0x%llX Rbx=0x%llX\n",
               ctx->Rip, ctx->Rsp, ctx->Rbp, ctx->Rbx);
        ULONGLONG live_lo = ctx->Rsp & ~(PAGE - 1);
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
        int a = s.context_present && ctx->Rip >= app_lo && ctx->Rip < app_hi;
        printf("  [A] Rip inside app image [0x%llX..0x%llX): %s\n",
               app_lo, app_hi, a ? "PASS" : "FAIL");
        ok &= a;
    } else {
        printf("  [A] app image range unavailable (app.exe not readable): SKIP\n");
        ok = 0;
    }

    int b = s.context_present && stack_regions == 1
            && ctx->Rsp >= stack_base && ctx->Rsp < stack_base + stack_size;
    printf("  [B] Rsp inside captured stack region: %s\n", b ? "PASS" : "FAIL");
    ok &= b;

    int c = stack_regions == 1
            && stack_base >= ARENA_BASE
            && stack_base + stack_size <= ARENA_BASE + ARENA_SIZE;
    printf("  [C] stack region inside arena (upper-half pure): %s\n", c ? "PASS" : "FAIL");
    ok &= c;

    printf("\n%s\n", ok ? "dumpckpt: ALL CHECKS PASS" : "dumpckpt: CHECKS FAILED");
    snapshot_free(&s);
    return ok ? 0 : 1;
}
