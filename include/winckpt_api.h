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

typedef struct winckpt_args {
    int          verbose;
    int          exit_after_ckpt;
    Image      **crt;           // CRT copies, in DllMain(ATTACH) order
    int          n_crt;
    Image       *app;
    const char  *app_path;
    const char  *ckpt_path;
    const WCHAR *cmdline;
} winckpt_args;

WINCKPT_API int  winckpt_init(const winckpt_args *a);
WINCKPT_API int  winckpt_adopt(const winckpt_args *a);
WINCKPT_API void winckpt_enter(CONTEXT *ctx);
WINCKPT_API void winckpt_checkpoint(void);
WINCKPT_API int  ckpt_read(const char *path, Snapshot *s);
WINCKPT_API void snapshot_free(Snapshot *s);

#endif
