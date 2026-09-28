#ifndef WINCKPT_BOUNDARY_H
#define WINCKPT_BOUNDARY_H

#include <windows.h>

#include "loader.h"

#define EMU_SLOTS 64

// Lower-half state the upper half would otherwise hold only by index or pointer,
// emulated here so it lives in the arena and comes back with a checkpoint.
typedef struct Emu {
    int                    fls_used[EMU_SLOTS];
    PFLS_CALLBACK_FUNCTION fls_cb[EMU_SLOTS];
    void                  *fls_val[EMU_SLOTS];
    int                    tls_used[EMU_SLOTS];
    void                  *tls_val[EMU_SLOTS];
    char                  *cmdline_a;
    WCHAR                 *cmdline_w;
} Emu;

typedef void (*exit_fn)(UINT code);

int   boundary_init(ULONGLONG emu_at);
void  boundary_adopt(ULONGLONG emu_at);
void  boundary_on_exit(Image **detach_order, int n, exit_fn on_exit);
void *boundary_hook(const char *import_name);
void  boundary_report(const char *module);

#endif
