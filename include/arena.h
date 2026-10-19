#ifndef WINCKPT_ARENA_H
#define WINCKPT_ARENA_H

#include <windows.h>

#include "hook.h"

typedef struct winckpt_arena {
    ULONGLONG base;
    ULONGLONG end;
    ULONGLONG heap_start;
    ULONGLONG stack_limit;
    ULONGLONG stack_base;
    ULONGLONG app_base;
    ULONGLONG app_end;
    ULONGLONG emu_at;
} winckpt_arena;

typedef struct heap_ctl {
    ULONGLONG cur;
    ULONGLONG committed;
    ULONGLONG free_head;
    ULONGLONG n_malloc, n_free, n_realloc, n_calloc;
} heap_ctl;

#define HEAP_CTL_RESERVE ((sizeof(heap_ctl) + 15ULL) & ~15ULL)

typedef struct Block {
    size_t size;
    union {
        struct Block *next;
        size_t        used;
    };
} Block;

#define HDR ((ULONGLONG)sizeof(Block))

extern winckpt_arena g_arena;
extern heap_ctl     *g_ctl;

int    arena_init(const winckpt_arena *a);
void   arena_adopt(const winckpt_arena *a);
int    arena_contains(ULONGLONG a);
void  *arena_malloc(size_t n);
void   arena_free(void *p);
void  *arena_realloc(void *p, size_t n);
void  *arena_calloc(size_t count, size_t sz);
void  *arena_copy(const void *src, size_t n);
void   arena_dump_ctl(const char *when);

HANDLE arena_heap(void);
void  *arena_heap_alloc(DWORD flags, size_t n);
void  *arena_heap_realloc(DWORD flags, void *p, size_t n);
size_t arena_size(const void *p);

void   arena_outside_record(void *at, const char *by);
void   arena_outside_forget(void *at);
int    arena_outside_ok(void);

extern const Hook arena_hooks[];
extern const int  arena_n_hooks;

#endif
