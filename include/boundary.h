#ifndef WINCKPT_BOUNDARY_H
#define WINCKPT_BOUNDARY_H

#include <windows.h>

#include "process.h"
#include "modules.h"
#include "handles.h"

typedef struct Emu {
    ProcessEmu process;
    ModulesEmu modules;
    HandlesEmu handles;
} Emu;

int   boundary_init(ULONGLONG emu_at, const WCHAR *cmdline);
int   boundary_adopt(ULONGLONG emu_at);
void *boundary_hook(const char *import_name);
void *boundary_find(const char *name);
void  boundary_report(const char *module);

#endif
