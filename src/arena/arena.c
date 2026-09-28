// Bump allocator with a LIFO free list. It backs the Windows heap calls of the
// upper half: the hooked GetProcessHeap hands out arena_heap_handle(), and any
// other heap handle is passed through to the OS heap.
//
// TODO: minimal on purpose, with known defects.
//   - not thread safe: g_ctl and the free list are unlocked, which breaks as
//     soon as the checkpoint listener thread exists
//   - no coalescing: adjacent free blocks never merge, so external
//     fragmentation grows without bound
//   - no splitting: a free block is reused whole, so malloc(16) can consume a
//     4 KB block permanently
//   - arena_free does not check the pointer belongs to the arena; a stray or
//     double free corrupts the list
//   - realloc never shrinks
//   - 16 bytes of header per allocation, O(n) free-list scan, no decommit

#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "ckpt_format.h"
#include "arena.h"
#include "log.h"

int           g_verbose;
winckpt_arena g_arena;
heap_ctl     *g_ctl;
ULONGLONG     g_n_malloc, g_n_free, g_n_realloc, g_n_calloc;

static int ensure_committed(ULONGLONG upto)
{
    if (upto <= g_ctl->committed) return 1;
    ULONGLONG want = (upto + (PAGE - 1)) & ~(PAGE - 1);
    if (want > g_arena.heap_end) return 0;
    if (!VirtualAlloc((LPVOID)g_ctl->committed, (SIZE_T)(want - g_ctl->committed),
                      MEM_COMMIT, PAGE_READWRITE))
        return 0;
    g_ctl->committed = want;
    return 1;
}

int arena_init(const winckpt_arena *a)
{
    g_arena = *a;

    if (!VirtualAlloc((LPVOID)g_arena.heap_start, (SIZE_T)PAGE,
                      MEM_COMMIT, PAGE_READWRITE))
        return 0;

    g_ctl = (heap_ctl *)g_arena.heap_start;
    g_ctl->cur       = g_arena.heap_start + HEAP_CTL_RESERVE;
    g_ctl->committed = g_arena.heap_start + PAGE;
    g_ctl->free_head = 0;
    return 1;
}

void arena_dump_ctl(const char *when)
{
    printf("arena: heap_ctl %s -- cur=0x%llX committed=0x%llX free_head=0x%llX\n",
           when, g_ctl->cur, g_ctl->committed, g_ctl->free_head);
}

void *arena_malloc(size_t n)
{
    // Round up to 16 so the returned pointer is 16-aligned, which is what
    // malloc must guarantee on x64.
    size_t need = (n + 15) & ~(size_t)15;
    if (need == 0) need = 16;

    Block *prev = NULL;
    for (Block *cur = (Block *)g_ctl->free_head; cur; prev = cur, cur = cur->next) {
        if (cur->size >= need) {
            if (prev) prev->next = cur->next;
            else      g_ctl->free_head = (ULONGLONG)cur->next;
            cur->used = n;
            void *p = (char *)cur + HDR;
            g_n_malloc++;
            VLOG("  [heap] malloc(%zu) reuse -> 0x%p\n", n, p);
            return p;
        }
    }

    ULONGLONG at = g_ctl->cur;
    if (!ensure_committed(at + HDR + need)) {
        printf("arena: heap OOM on malloc(%zu)\n", n);
        return NULL;
    }
    Block *b = (Block *)at;
    b->size = need;
    b->used = n;
    g_ctl->cur = at + HDR + need;
    void *p = (char *)b + HDR;
    g_n_malloc++;
    VLOG("  [heap] malloc(%zu) -> 0x%p\n", n, p);
    return p;
}

void arena_free(void *p)
{
    if (!p) return;
    Block *b = (Block *)((char *)p - HDR);
    b->next = (Block *)g_ctl->free_head;
    g_ctl->free_head = (ULONGLONG)b;
    g_n_free++;
    VLOG("  [heap] free(0x%p)\n", p);
}

void *arena_realloc(void *p, size_t n)
{
    if (!p) return arena_malloc(n);
    if (n == 0) { arena_free(p); return NULL; }
    Block *b = (Block *)((char *)p - HDR);
    if (b->size >= n) {
        b->used = n;
        g_n_realloc++;
        VLOG("  [heap] realloc(0x%p,%zu) in-place\n", p, n);
        return p;
    }
    void *q = arena_malloc(n);
    if (!q) return NULL;
    memcpy(q, p, b->used);
    arena_free(p);
    g_n_realloc++;
    VLOG("  [heap] realloc(0x%p,%zu) moved -> 0x%p\n", p, n, q);
    return q;
}

void *arena_calloc(size_t count, size_t sz)
{
    size_t total = count * sz;
    if (count != 0 && total / count != sz) return NULL;
    void *p = arena_malloc(total);
    if (p) memset(p, 0, total);
    g_n_calloc++;
    VLOG("  [heap] calloc(%zu,%zu) -> 0x%p\n", count, sz, p);
    return p;
}

HANDLE WINAPI arena_heap_handle(void)
{
    return (HANDLE)g_ctl;
}

LPVOID WINAPI arena_heap_alloc(HANDLE heap, DWORD flags, SIZE_T n)
{
    if (heap != arena_heap_handle()) return HeapAlloc(heap, flags, n);
    void *p = arena_malloc(n);
    if (p && (flags & HEAP_ZERO_MEMORY))
        memset(p, 0, ((Block *)((char *)p - HDR))->size);
    return p;
}

BOOL WINAPI arena_heap_free(HANDLE heap, DWORD flags, LPVOID p)
{
    if (heap != arena_heap_handle()) return HeapFree(heap, flags, p);
    arena_free(p);
    return TRUE;
}

LPVOID WINAPI arena_heap_realloc(HANDLE heap, DWORD flags, LPVOID p, SIZE_T n)
{
    if (heap != arena_heap_handle()) return HeapReAlloc(heap, flags, p, n);
    if (!p) return NULL;

    Block *b = (Block *)((char *)p - HDR);
    size_t old = b->used;
    void *q = p;
    if (b->size >= n) {
        b->used = n;
    } else {
        if (flags & HEAP_REALLOC_IN_PLACE_ONLY) return NULL;
        q = arena_malloc(n);
        if (!q) return NULL;
        memcpy(q, p, old);
        arena_free(p);
    }
    if ((flags & HEAP_ZERO_MEMORY) && n > old)
        memset((char *)q + old, 0, n - old);
    g_n_realloc++;
    VLOG("  [heap] HeapReAlloc(0x%p,%zu) -> 0x%p\n", p, n, q);
    return q;
}

SIZE_T WINAPI arena_heap_size(HANDLE heap, DWORD flags, LPCVOID p)
{
    if (heap != arena_heap_handle()) return HeapSize(heap, flags, p);
    if (!p) return (SIZE_T)-1;
    return ((const Block *)((const char *)p - HDR))->used;
}
