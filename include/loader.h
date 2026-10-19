#ifndef WINCKPT_LOADER_H
#define WINCKPT_LOADER_H

#include <windows.h>

typedef struct Image {
    const char         *name;
    BYTE               *base;
    IMAGE_NT_HEADERS64 *nt;
} Image;

typedef void *(*hook_lookup_fn)(const char *import_name);

BYTE *loader_read_file(const char *path, DWORD *out_size);
int   loader_map(Image *img, const char *path, ULONGLONG at);
int   loader_attach(Image *img, ULONGLONG at, ULONGLONG size);
int   loader_imports(const Image *img, const char *dll);
int   loader_fill_imports(Image *img, Image **mapped, int n_mapped, hook_lookup_fn hook);
int   loader_protect(Image *img);
void *loader_export(const Image *img, const char *name, WORD ordinal);
int   loader_become_main(const Image *img, const char *path);
int   loader_run_tls(const Image *img, DWORD reason);
int   loader_dll_main(const Image *img, DWORD reason);

#endif
