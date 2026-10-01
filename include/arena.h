#ifndef WINCKPT_ARENA_H
#define WINCKPT_ARENA_H

#include <windows.h>

#include "winckpt_api.h"

// Heap metadata, stored in the arena.
// Addresses are absolute and may need to become relative.
typedef struct heap_ctl {
    ULONGLONG cur;
    ULONGLONG committed;
    ULONGLONG free_head;
    ULONGLONG n_malloc, n_free, n_realloc, n_calloc;
} heap_ctl;

// Bytes the heap gives up to heap_ctl before the first allocation.
#define HEAP_CTL_RESERVE ((sizeof(heap_ctl) + 15ULL) & ~15ULL)

// `next` links a free block; `used` is the requested size of an allocated one.
typedef struct Block {
    size_t size;
    union {
        struct Block *next;
        size_t        used;
    };
} Block;

#define HDR ((ULONGLONG)sizeof(Block))   // 16 on x64, keeps payloads 16-aligned

extern winckpt_arena g_arena;
extern heap_ctl     *g_ctl;

int   arena_init(const winckpt_arena *a);
void  arena_adopt(const winckpt_arena *a);
void *arena_malloc(size_t n);
void  arena_free(void *p);
void *arena_realloc(void *p, size_t n);
void *arena_calloc(size_t count, size_t sz);
void  arena_dump_ctl(const char *when);

HANDLE WINAPI arena_heap_handle(void);
LPVOID WINAPI arena_heap_alloc(HANDLE heap, DWORD flags, SIZE_T n);
BOOL   WINAPI arena_heap_free(HANDLE heap, DWORD flags, LPVOID p);
LPVOID WINAPI arena_heap_realloc(HANDLE heap, DWORD flags, LPVOID p, SIZE_T n);
SIZE_T WINAPI arena_heap_size(HANDLE heap, DWORD flags, LPCVOID p);

#endif
