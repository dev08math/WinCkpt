#ifndef WINCKPT_LOG_H
#define WINCKPT_LOG_H

#include <stdio.h>

// Defined by each binary; the DLL's copy is set from winckpt_arena.verbose.
extern int g_verbose;

#define VLOG(...) if (g_verbose) printf(__VA_ARGS__)

#ifdef _DEBUG
#define DLOG(...) printf(__VA_ARGS__)
#else
#define DLOG(...)
#endif

#endif
