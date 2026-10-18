#ifndef WINCKPT_CKPT_FORMAT_H
#define WINCKPT_CKPT_FORMAT_H

#include <windows.h>

#define CKPT_SUFFIX     ".wckpt"
#define CKPT_DIR_ENV    "WINCKPT_CHECKPOINT_DIR"

#define CKPT_MAGIC 0x33303054504B4357ULL   // "WCKPT003"

// Marks the start of the CONTEXT record, after the variable-length regions.
#define TAG_CONTEXT 0x584B4354ULL          // "TCKX"

#define REGION_PLAIN 0u
#define REGION_STACK 1u

// 300 fresh processes put early stacks and heaps below ~3 TB and nothing at 16 TB.
// TODO: launch picks the base and records it in arena_start; restart reads it.
#define ARENA_BASE 0x100000000000ULL

// Reserving costs no RAM; the heap takes everything past HEAP_OFF.
#define ARENA_SIZE 0x1000000000ULL
#define PAGE       0x1000ULL

// Offsets from the base address of the arena. The app's image must end before APP_STACK_OFF.
#define APP_STACK_OFF  0x10000000ULL
#define APP_STACK_SIZE 0x00100000ULL
#define UCRT_OFF       0x11000000ULL
#define VCRT_OFF       0x12000000ULL
#define EMU_OFF        0x13000000ULL
#define EMU_SIZE       0x00010000ULL
#define HEAP_OFF       0x14000000ULL

typedef struct RegionRec {
    ULONGLONG base;
    ULONGLONG size;
    DWORD     protect;
    DWORD     kind;
    ULONGLONG off;
} RegionRec;

typedef struct Snapshot {
    char       app_path[MAX_PATH];
    ULONGLONG  arena_start;
    ULONGLONG  count;
    ULONGLONG  total;
    ULONGLONG  context_present;
    CONTEXT    ctx;
    RegionRec *rg;
    BYTE      *bytes;
} Snapshot;

#endif
