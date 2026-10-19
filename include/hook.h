#ifndef WINCKPT_HOOK_H
#define WINCKPT_HOOK_H

typedef struct Hook {
    const char *name;
    void       *fn;
} Hook;

#endif
