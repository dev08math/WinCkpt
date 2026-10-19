#ifndef WINCKPT_LOG_H
#define WINCKPT_LOG_H

#include <stdio.h>

extern int g_verbose;

#define VLOG(...) if (g_verbose) printf(__VA_ARGS__)

#ifdef _DEBUG
#define DLOG(...) printf(__VA_ARGS__)
#else
#define DLOG(...)
#endif

#endif
