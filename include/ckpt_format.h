#ifndef WINCKPT_CKPT_FORMAT_H
#define WINCKPT_CKPT_FORMAT_H

#include <windows.h>

#define CKPT_SUFFIX     ".wckpt"
#define CKPT_DIR_ENV    "WINCKPT_CHECKPOINT_DIR"

#define CKPT_MAGIC 0x36303054504B4357ULL   // "WCKPT006"

#define REGION_PLAIN 0u
#define REGION_STACK 1u

#define ARENA_BASE 0x100000000000ULL

#define ARENA_SIZE 0x1000000000ULL
#define PAGE       0x1000ULL

// The app's image must end before APP_STACK_OFF.
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
    ULONGLONG kind;
    ULONGLONG off;
} RegionRec;

typedef struct Snapshot {
    char       app_path[MAX_PATH];
    ULONGLONG  arena_start;
    ULONGLONG  count;
    ULONGLONG  total;
    CONTEXT    ctx;
    RegionRec *rg;
    BYTE      *bytes;
} Snapshot;

#endif
