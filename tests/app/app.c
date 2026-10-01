#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

__declspec(dllimport) void winckpt_checkpoint(void);

#define LOOP_ITERS  10
#define CKPT_AT_1    4
#define CKPT_AT_2    7

static int fill_check(unsigned char *p, size_t n, unsigned char seed)
{
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(seed + i);
    for (size_t i = 0; i < n; i++)
        if (p[i] != (unsigned char)(seed + i)) return 0;
    return 1;
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    int stack_probe = 0;
    printf("app: start (a local lives at %p)\n", (void *)&stack_probe);

    unsigned char *a = (unsigned char *)malloc(100);
    unsigned char *b = (unsigned char *)malloc(4096);
    unsigned char *c = (unsigned char *)malloc(37);
    printf("app: a=%p b=%p c=%p\n", (void *)a, (void *)b, (void *)c);
    if (!fill_check(a, 100, 0x10) || !fill_check(b, 4096, 0x20)
        || !fill_check(c, 37, 0x30)) {
        printf("app: VERIFY FAIL (initial)\n"); return 1;
    }

    a = (unsigned char *)realloc(a, 500);
    printf("app: a realloc -> %p\n", (void *)a);
    for (size_t i = 0; i < 100; i++)
        if (a[i] != (unsigned char)(0x10 + i)) {
            printf("app: VERIFY FAIL (realloc lost data)\n"); return 1;
        }
    if (!fill_check(a, 500, 0x40)) {
        printf("app: VERIFY FAIL (realloc)\n"); return 1;
    }

    unsigned char *d = (unsigned char *)calloc(64, 8);
    printf("app: d(calloc)=%p\n", (void *)d);
    for (size_t i = 0; i < 512; i++)
        if (d[i] != 0) { printf("app: VERIFY FAIL\n"); return 1; }
    if (!fill_check(d, 512, 0x50)) {
        printf("app: VERIFY FAIL\n"); return 1;
    }

    free(b);
    free(c);
    unsigned char *e = (unsigned char *)malloc(30);
    unsigned char *f = (unsigned char *)malloc(4096);
    printf("app: e=%p f=%p (after frees)\n", (void *)e, (void *)f);
    if (!fill_check(e, 30, 0x60) || !fill_check(f, 4096, 0x70)) {
        printf("app: VERIFY FAIL (reuse)\n"); return 1;
    }

    free(a);
    free(d);
    free(e);
    free(f);

    printf("app: all allocations verified\n");

    unsigned char *live = (unsigned char *)malloc(256);
    printf("app: live buffer at %p\n", (void *)live);

    static char words[] = "w0 w1 w2 w3 w4 w5 w6 w7 w8 w9";
    srand(42);
    char *tok = strtok(words, " ");

    for (int i = 0; i < LOOP_ITERS; i++) {
        live[i] = (unsigned char)(0xA0 + i);
        printf("app: iteration %d (live[%d]=0x%02X) rand=%d tok=%s\n",
               i, i, live[i], rand(), tok);
        if (i == CKPT_AT_1 || i == CKPT_AT_2) {
            printf("app: --- calling winckpt_checkpoint() ---\n");
            errno = 1000 + i;
            winckpt_checkpoint();
            printf("app: --- returned from winckpt_checkpoint() --- errno=%d\n", errno);
        }
        tok = strtok(NULL, " ");
    }

    printf("app: loop done\n");
    free(live);
    return 0;
}
