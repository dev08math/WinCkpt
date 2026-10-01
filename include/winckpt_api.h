#ifndef WINCKPT_API_H
#define WINCKPT_API_H

#include <windows.h>

#include "ckpt_format.h"
#include "loader.h"

#ifdef WINCKPT_API_BUILD
#define WINCKPT_API __declspec(dllexport)
#else
#define WINCKPT_API __declspec(dllimport)
#endif

typedef struct winckpt_arena {
    ULONGLONG base;
    ULONGLONG end;
    ULONGLONG heap_start;
    ULONGLONG heap_end;
    ULONGLONG stack_limit;
    ULONGLONG stack_base;
    ULONGLONG app_base;
    ULONGLONG app_end;
    ULONGLONG emu_at;
    HANDLE    app_thread;   // duplicated, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
    int       verbose;
    int       exit_after_ckpt;
    Image   **detach;       // CRT copies, in the order their DllMain(DETACH) must run
    int       n_detach;
} winckpt_arena;

WINCKPT_API int winckpt_init(const winckpt_arena *a);

WINCKPT_API int winckpt_adopt(const winckpt_arena *a);

WINCKPT_API void *winckpt_hook_lookup(const char *import_name);

WINCKPT_API void winckpt_hook_report(const char *module);

WINCKPT_API int winckpt_rebind_std(const Image *ucrt);

WINCKPT_API void winckpt_checkpoint(void);

WINCKPT_API int  ckpt_read(const char *path, Snapshot *s);

WINCKPT_API void snapshot_free(Snapshot *s);

#endif
