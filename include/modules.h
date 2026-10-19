#ifndef WINCKPT_MODULES_H
#define WINCKPT_MODULES_H

#include <windows.h>

#include "hook.h"

#define EMU_PROCS   64
#define EMU_MODULES 32

typedef struct EmuModule {
    HMODULE saved;
    HMODULE now;
    DWORD   flags;
    int     refs;
    int     gone;
    WCHAR   path[MAX_PATH];
} EmuModule;

typedef struct EmuProc {
    int       module;
    WORD      ordinal;
    char      name[128];
    ULONGLONG target;
} EmuProc;

typedef struct ModulesEmu {
    int       n_mod;
    EmuModule mod[EMU_MODULES];
    int       n_proc;
    EmuProc   proc[EMU_PROCS];
} ModulesEmu;

int     modules_init(ModulesEmu *m, BYTE *stub_page);
int     modules_adopt(ModulesEmu *m, BYTE *stub_page);
HMODULE modules_now(HMODULE h);
HMODULE modules_remember(HMODULE h, DWORD flags, int add_ref);
FARPROC modules_proc(HMODULE mod, LPCSTR name, FARPROC real);
BOOL    modules_free(HMODULE h);

extern const Hook modules_hooks[];
extern const int  modules_n_hooks;

#endif
