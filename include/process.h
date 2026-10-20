#ifndef WINCKPT_PROCESS_H
#define WINCKPT_PROCESS_H

#include <windows.h>

#include "hook.h"
#include "loader.h"

#define EMU_SLOTS 64

typedef struct ProcessEmu {
    int                    fls_used[EMU_SLOTS];
    PFLS_CALLBACK_FUNCTION fls_cb[EMU_SLOTS];
    void                  *fls_val[EMU_SLOTS];
    int                    tls_used[EMU_SLOTS];
    void                  *tls_val[EMU_SLOTS];
    char                  *cmdline_a;
    WCHAR                 *cmdline_w;
} ProcessEmu;

typedef void (*exit_fn)(UINT code);

int         process_init(ProcessEmu *p, const WCHAR *cmdline);
void        process_adopt(ProcessEmu *p);
ProcessEmu *process_state(void);
void        process_on_exit(Image **crt, int n_crt, const Image *app, exit_fn on_exit);
void        process_detach(UINT code);

extern const Hook process_hooks[];
extern const int  process_n_hooks;
extern const char *const process_unhandled[];
extern const int         process_n_unhandled;

#endif
