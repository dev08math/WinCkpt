#include <windows.h>
#include <stdio.h>

#include "arena.h"

#define MAX_OUTSIDE 1024

static struct {
    ULONGLONG   at;
    const char *by;
} g_out[MAX_OUTSIDE];
static int g_n_out;
static int g_out_lost;

void arena_outside_record(void *at, const char *by)
{
    if (!at || arena_contains((ULONGLONG)at)) return;
    if (g_n_out == MAX_OUTSIDE) {
        g_out_lost = 1;
        return;
    }
    g_out[g_n_out].at = (ULONGLONG)at;
    g_out[g_n_out].by = by;
    g_n_out++;
}

void arena_outside_forget(void *at)
{
    for (int i = 0; i < g_n_out; i++)
        if (g_out[i].at == (ULONGLONG)at) {
            g_out[i] = g_out[--g_n_out];
            return;
        }
}

int arena_outside_ok(void)
{
    if (g_out_lost) {
        printf("ckpt: refused, more than %d outside-arena allocations by the app to track\n", MAX_OUTSIDE);
        return 0;
    }
    for (int i = 0; i < g_n_out && i < 8; i++)
        printf("ckpt: the app holds memory outside the arena: %s -> 0x%llX\n",
               g_out[i].by, g_out[i].at);
    if (g_n_out)
        printf("ckpt: refused, %d app allocation(s) outside the arena would be lost\n", g_n_out);
    return g_n_out == 0;
}
