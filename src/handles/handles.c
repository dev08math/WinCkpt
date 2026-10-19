#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include "handles.h"
#include "log.h"

static HANDLE g_stale[3];
static int    g_n_stale;

int handles_is_stale(HANDLE h)
{
    for (int i = 0; i < g_n_stale; i++)
        if (h == g_stale[i]) return 1;
    return 0;
}

typedef intptr_t (__cdecl *get_osfhandle_fn)(int fd);
typedef int      (__cdecl *close_fn)(int fd);
typedef int      (__cdecl *open_osfhandle_fn)(intptr_t h, int flags);
typedef int      (__cdecl *dup2_fn)(int from, int to);

int handles_rebind_std(const Image *ucrt)
{
    get_osfhandle_fn  get_h = (get_osfhandle_fn)loader_export(ucrt, "_get_osfhandle", 0);
    close_fn          close = (close_fn)loader_export(ucrt, "_close", 0);
    open_osfhandle_fn open  = (open_osfhandle_fn)loader_export(ucrt, "_open_osfhandle", 0);
    dup2_fn           dup2  = (dup2_fn)loader_export(ucrt, "_dup2", 0);
    if (!get_h || !close || !open || !dup2) {
        fprintf(stderr, "handles: %s lacks _get_osfhandle/_close/_open_osfhandle/_dup2\n",
                ucrt->name);
        return 0;
    }

    // The CRT's _close of fd 0-2 also calls SetStdHandle(..., NULL).
    HANDLE std[3];
    for (int fd = 0; fd < 3; fd++)
        std[fd] = GetStdHandle((DWORD)(-10 - fd));

    int was_open[3];
    g_n_stale = 0;
    for (int fd = 0; fd < 3; fd++) {
        intptr_t h = get_h(fd);
        was_open[fd] = h != -1 && h != -2;
        if (was_open[fd]) g_stale[g_n_stale++] = (HANDLE)h;
    }
    for (int fd = 0; fd < 3; fd++)
        if (was_open[fd]) close(fd);
    g_n_stale = 0;

    for (int fd = 0; fd < 3; fd++) {
        if (!was_open[fd]) continue;
        if (std[fd] == NULL || std[fd] == INVALID_HANDLE_VALUE) {
            VLOG("handles: fd %d left closed, this process has no std handle for it\n", fd);
            continue;
        }
        HANDLE dup = NULL;
        if (!DuplicateHandle(GetCurrentProcess(), std[fd], GetCurrentProcess(), &dup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) {
            fprintf(stderr, "handles: DuplicateHandle for fd %d failed, err=%lu\n", fd, GetLastError());
            return 0;
        }
        int got = open((intptr_t)dup, 0);
        if (got < 0) {
            fprintf(stderr, "handles: _open_osfhandle for fd %d failed\n", fd);
            CloseHandle(dup);
            return 0;
        }
        if (got != fd) {
            int moved = dup2(got, fd);
            close(got);
            if (moved != 0) {
                fprintf(stderr, "handles: _dup2(%d, %d) failed\n", got, fd);
                return 0;
            }
        }
        VLOG("handles: fd %d rebound to handle 0x%p\n", fd, dup);
    }
    return 1;
}
