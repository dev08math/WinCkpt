#include <windows.h>
#include <stdio.h>

#include "ckpt_format.h"
#include "loader.h"
#include "winckpt_api.h"

int g_verbose;

static int app_image_size(const Snapshot *s, ULONGLONG *size_image)
{
    for (ULONGLONG i = 0; i < s->count; i++) {
        const RegionRec *r = &s->rg[i];
        if (r->base != s->arena_start) continue;
        Image img = { "app" };
        if (!loader_attach(&img, (ULONGLONG)(s->bytes + r->off), r->size)) return 0;
        *size_image = img.nt->OptionalHeader.SizeOfImage;
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: dumpckpt.exe <ckpt%s>\n", CKPT_SUFFIX);
        return 1;
    }
    Snapshot s;
    if (!ckpt_read(argv[1], &s)) return 1;

    printf("header: magic=WCKPT005 arena_start=0x%llX regions=%llu total_bytes=%llu\n",
           s.arena_start, s.count, s.total);
    printf("app:    %s\n", s.app_path);

    ULONGLONG stack_base = 0, stack_size = 0;
    int stack_regions = 0;

    for (ULONGLONG i = 0; i < s.count; i++) {
        const RegionRec *r = &s.rg[i];
        printf("region[%llu] base=0x%011llX size=0x%08llX kind=%s\n",
               i, r->base, r->size, r->kind == REGION_STACK ? "STACK" : "PLAIN");
        if (r->kind == REGION_STACK) { stack_base = r->base; stack_size = r->size; stack_regions++; }
    }

    printf("\n");
    if (stack_regions == 1)
        printf("stack region: base=0x%llX size=0x%llX (%llu KB)\n",
               stack_base, stack_size, stack_size / 1024);
    else
        printf("stack region: %d found (expected exactly 1)\n", stack_regions);

    const CONTEXT *ctx = &s.ctx;
    printf("context: Rip=0x%llX Rsp=0x%llX Rbp=0x%llX Rbx=0x%llX\n",
           ctx->Rip, ctx->Rsp, ctx->Rbp, ctx->Rbx);
    ULONGLONG live_lo = ctx->Rsp & ~(PAGE - 1);
    printf("live stack extent: [0x%llX .. 0x%llX) = %llu bytes of the %llu captured\n",
           live_lo, stack_base + stack_size, (stack_base + stack_size) - live_lo, stack_size);

    ULONGLONG size_image = 0;
    int have_app = app_image_size(&s, &size_image);
    ULONGLONG app_lo = s.arena_start, app_hi = s.arena_start + size_image;

    printf("\nVERIFY\n");
    int ok = 1;

    if (have_app) {
        int a = ctx->Rip >= app_lo && ctx->Rip < app_hi;
        printf("  [A] Rip inside app image [0x%llX..0x%llX): %s\n",
               app_lo, app_hi, a ? "PASS" : "FAIL");
        ok &= a;
    } else {
        printf("  [A] no valid app header at the arena base: FAIL\n");
        ok = 0;
    }

    int b = stack_regions == 1
            && ctx->Rsp >= stack_base && ctx->Rsp < stack_base + stack_size;
    printf("  [B] Rsp inside captured stack region: %s\n", b ? "PASS" : "FAIL");
    ok &= b;

    printf("\n%s\n", ok ? "dumpckpt: ALL CHECKS PASS" : "dumpckpt: CHECKS FAILED");
    snapshot_free(&s);
    return ok ? 0 : 1;
}
