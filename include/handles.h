#ifndef WINCKPT_HANDLES_H
#define WINCKPT_HANDLES_H

#include <windows.h>

#include "hook.h"
#include "loader.h"

int handles_rebind_std(const Image *ucrt);
int handles_is_stale(HANDLE h);

extern const Hook handles_hooks[];
extern const int  handles_n_hooks;

#endif
