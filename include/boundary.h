#ifndef WINCKPT_BOUNDARY_H
#define WINCKPT_BOUNDARY_H

#include <windows.h>

#include "loader.h"

#define EMU_SLOTS   64
#define EMU_PROCS   64
#define EMU_MODULES 32

// A module handle the upper half holds, and the same module in this process.
typedef struct EmuModule {
    HMODULE saved;
    HMODULE now;
    WCHAR   path[MAX_PATH];
} EmuModule;

// A GetProcAddress result. The upper half holds the address of a stub that
// jumps through target; restart re-resolves target for this boot.
typedef struct EmuProc {
    int       module;
    WORD      ordinal;
    char      name[128];
    ULONGLONG target;
} EmuProc;

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
    int                    n_mod;
    EmuModule              mod[EMU_MODULES];
    int                    n_proc;
    EmuProc                proc[EMU_PROCS];
} Emu;

typedef void (*exit_fn)(UINT code);

int   boundary_init(ULONGLONG emu_at, const WCHAR *cmdline);
int   boundary_adopt(ULONGLONG emu_at);
void  boundary_on_exit(Image **crt, int n_crt, const Image *app, exit_fn on_exit);
void *boundary_hook(const char *import_name);
void  boundary_report(const char *module);
int   boundary_rebind_std(const Image *ucrt);

#endif
