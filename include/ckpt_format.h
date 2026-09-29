#ifndef WINCKPT_CKPT_FORMAT_H
#define WINCKPT_CKPT_FORMAT_H

#include <windows.h>

// TODO: checkpoint paths are fixed and the reader accepts exactly one layout.
// Needs argv-supplied paths and a versioned reader that dispatches on the magic
// so older checkpoints stay readable as the format changes.
#define DEFAULT_CKPT_PATH  "arena.ckpt"
#define DEFAULT_APP_PATH   "app.exe"

// Rejects a stale or non-checkpoint file before its bytes are mapped and run.
#define CKPT_MAGIC 0x32303054504B4357ULL   // "WCKPT002"

// Marks the start of the CONTEXT record, after the variable-length regions.
#define TAG_CONTEXT 0x584B4354ULL          // "TCKX"

#define REGION_PLAIN 0u
#define REGION_STACK 1u

// Early stacks and heaps of a new process are placed at random below ~3 TB; in 300
// fresh processes nothing was ever mapped between 16 TB and 32 TB. Below 16 TB even
// a 1 GB range collided in 2 of 300. app.exe is linked at this address, which the
// loader requires since it does not relocate the app.
// TODO: once the loader applies .reloc to the app, launch can pick a free base and
// record it in arena_start. The restarter then reads that from the header in its
// TLS callback instead of using this constant.
#define ARENA_BASE 0x100000000000ULL

// 64 GB of addresses. Reserving costs no RAM; the heap takes everything past HEAP_OFF.
#define ARENA_SIZE 0x1000000000ULL
#define PAGE       0x1000ULL

// Offsets from the base address of the arena. app.exe must end before APP_STACK_OFF.
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
    ULONGLONG  arena_start;
    ULONGLONG  count;
    ULONGLONG  total;
    ULONGLONG  context_present;
    CONTEXT    ctx;
    RegionRec *rg;
    BYTE      *bytes;
} Snapshot;

#endif
