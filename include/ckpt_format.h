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

// This range was observed unmapped across many processes and multiple boots, so
// it was chosen to host the arena. app.exe is linked at the same address, which
// the loader requires since it cannot relocate the image.
// TODO: once the loader applies .reloc at load, it can pick a free base and
// record it in arena_start. The restarter then reads that from the header in
// its TLS callback instead of using this constant.
#define ARENA_BASE 0x2A0000000ULL

// 1 GB, spanning 0x2A0000000 to 0x2E0000000, which holds the mapped image, the
// heap, the app stack, the app's private CRT copies and the emulation page.
#define ARENA_SIZE 0x40000000ULL
#define PAGE       0x1000ULL

// Offsets from the base address of the arena.
#define HEAP_WINDOW    0x20000000ULL
#define APP_STACK_OFF  0x30000000ULL
#define APP_STACK_SIZE 0x00100000ULL
#define UCRT_OFF       0x31000000ULL
#define VCRT_OFF       0x32000000ULL
#define EMU_OFF        0x33000000ULL
#define EMU_SIZE       0x00010000ULL

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
