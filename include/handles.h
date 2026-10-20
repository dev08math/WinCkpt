#ifndef WINCKPT_HANDLES_H
#define WINCKPT_HANDLES_H

#include <windows.h>

#include "hook.h"

#define HANDLE_FAKE_BASE 0x10000000ULL
#define HANDLE_SLOTS     1024
#define TEMP_FILE_MAX    (64ULL * 1024 * 1024)

typedef enum HandleKind {
    HK_FREE,
    HK_STD,
    HK_FILE,
    HK_DEVICE,
    HK_PIPE_READ,
    HK_PIPE_WRITE,
    HK_EVENT,
    HK_SEMAPHORE,
    HK_MUTEX,
    HK_OPAQUE,
} HandleKind;

typedef struct HandleEntry {
    HandleKind kind;
    int        group;
    int        peer;
    DWORD      pipe_size;
    DWORD      std_n;
    HANDLE     real;
    WCHAR     *path;
    DWORD      access;
    DWORD      share;
    DWORD      flags;
    BOOL       inherit;
    BOOL       is_dir;
    LONGLONG   offset;
    DWORD      volume;
    ULONGLONG  index;
    BYTE      *data;
    LONGLONG   data_size;
    LONG       sync_type;
    LONG       sync_count;
    LONG       sync_max;
} HandleEntry;

typedef struct HandlesEmu {
    HandleEntry *slot;
    HANDLE       std[3];
    int          next_group;
} HandlesEmu;

int         handles_init(HandlesEmu *e);
int         handles_adopt(HandlesEmu *e);
int         handles_save(void);
HandlesEmu *handles_state(void);
int         handles_is_fake(HANDLE h);
HANDLE      handles_real(HANDLE h);
HANDLE      handles_wrap_std(DWORD std_n, HANDLE real);
HANDLE      handles_wrap_file(HANDLE real, const WCHAR *name, DWORD access, DWORD share, DWORD flags,
                              BOOL inherit);
HANDLE      handles_wrap_sync(HANDLE real, HandleKind kind, const WCHAR *name, DWORD access, BOOL inherit);
int         handles_wrap_pipe(HANDLE r, HANDLE w, DWORD size, BOOL inherit, HANDLE *fake_r, HANDLE *fake_w);
HANDLE      handles_wrap_dup(HANDLE src, HANDLE real, DWORD opts, DWORD access, BOOL inherit);
void        handles_drop(HANDLE fake);

extern const Hook handles_hooks[];
extern const int  handles_n_hooks;
extern const char *const handles_unhandled[];
extern const int         handles_n_unhandled;

#endif
