#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "loader.h"
#include "log.h"

// Undocumented x64 layouts, cut down to the fields loader_become_main writes.
typedef struct UStr {
    USHORT len;
    USHORT max;
    PWSTR  buf;
} UStr;

typedef struct Peb {
    BYTE  flags[8];
    void *mutant;
    BYTE *image_base;
    BYTE *ldr;
    BYTE *params;
} Peb;

typedef struct LdrData {
    ULONG      length;
    ULONG      initialized;
    void      *ss_handle;
    LIST_ENTRY load_order;
} LdrData;

typedef struct LdrEntry {
    LIST_ENTRY load_links;
    LIST_ENTRY memory_links;
    LIST_ENTRY init_links;
    BYTE      *base;
    BYTE      *entry;
    ULONG      size;
    UStr       full_name;
    UStr       base_name;
} LdrEntry;

typedef struct ProcParams {
    BYTE before_image_path[0x60];
    UStr image_path;
} ProcParams;

static WCHAR g_main_path[MAX_PATH];

BYTE *loader_read_file(const char *path, DWORD *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "read: CreateFileA(%s) failed, err=%lu\n", path, GetLastError());
        return NULL;
    }
    LARGE_INTEGER size;
    if (!GetFileSizeEx(h, &size) || size.QuadPart > MAXDWORD) {
        fprintf(stderr, "read: %s: size unreadable or over 4 GB\n", path);
        CloseHandle(h);
        return NULL;
    }
    BYTE *buf = (BYTE *)malloc(size.QuadPart ? (size_t)size.QuadPart : 1);
    DWORD got = 0;
    if (!buf || !ReadFile(h, buf, size.LowPart, &got, NULL) || got != size.LowPart) {
        fprintf(stderr, "read: ReadFile(%s) failed, err=%lu\n", path, GetLastError());
        CloseHandle(h);
        free(buf);
        return NULL;
    }
    CloseHandle(h);
    *out_size = size.LowPart;
    return buf;
}

static IMAGE_NT_HEADERS64 *pe_headers(const BYTE *file, DWORD size)
{
    if (size < sizeof(IMAGE_DOS_HEADER)) return NULL;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0 ||
        (ULONGLONG)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > size)
        return NULL;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return NULL;
    ULONGLONG sec_end = (ULONGLONG)((BYTE *)IMAGE_FIRST_SECTION(nt) - file)
                      + (ULONGLONG)nt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (sec_end > size || nt->OptionalHeader.SizeOfHeaders > size ||
        nt->OptionalHeader.SizeOfHeaders > nt->OptionalHeader.SizeOfImage)
        return NULL;
    return nt;
}

static int apply_relocations(Image *img, ULONGLONG delta)
{
    IMAGE_DATA_DIRECTORY dir =
        img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (dir.VirtualAddress == 0 || dir.Size == 0) {
        fprintf(stderr, "loader: %s has no .reloc and is not at its preferred base\n", img->name);
        return 0;
    }

    ULONGLONG size_image = img->nt->OptionalHeader.SizeOfImage;
    if ((ULONGLONG)dir.VirtualAddress + dir.Size > size_image) {
        fprintf(stderr, "loader: %s: .reloc runs past the image\n", img->name);
        return 0;
    }
    BYTE *ptr = img->base + dir.VirtualAddress;
    BYTE *end = ptr + dir.Size;
    ULONGLONG n = 0;
    while (ptr + sizeof(IMAGE_BASE_RELOCATION) <= end) {
        IMAGE_BASE_RELOCATION *blk = (IMAGE_BASE_RELOCATION *)ptr;
        if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || blk->SizeOfBlock > (ULONGLONG)(end - ptr)) {
            fprintf(stderr, "loader: %s: bad reloc block size %lu\n", img->name, blk->SizeOfBlock);
            return 0;
        }
        ULONGLONG count = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *entry = (WORD *)(blk + 1);
        for (ULONGLONG i = 0; i < count; i++) {
            WORD type = entry[i] >> 12;
            WORD off  = entry[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
            if (type != IMAGE_REL_BASED_DIR64) {
                fprintf(stderr, "loader: %s: unhandled reloc type %u\n", img->name, type);
                return 0;
            }
            if ((ULONGLONG)blk->VirtualAddress + off + sizeof(ULONGLONG) > size_image) {
                fprintf(stderr, "loader: %s: reloc at 0x%lX past the image\n",
                        img->name, blk->VirtualAddress + off);
                return 0;
            }
            *(ULONGLONG *)(img->base + blk->VirtualAddress + off) += delta;
            n++;
        }
        ptr += blk->SizeOfBlock;
    }
    VLOG("loader: %-16s %llu relocation(s) applied\n", img->name, n);
    return 1;
}

int loader_attach(Image *img, ULONGLONG at, ULONGLONG size)
{
    IMAGE_NT_HEADERS64 *nt = pe_headers((BYTE *)at, size > MAXDWORD ? MAXDWORD : (DWORD)size);
    if (!nt) return 0;
    img->base = (BYTE *)at;
    img->nt   = nt;
    return 1;
}

int loader_map(Image *img, const char *path, ULONGLONG at)
{
    DWORD size = 0;
    BYTE *file = loader_read_file(path, &size);
    if (!file) return 0;

    IMAGE_NT_HEADERS64 *nt = pe_headers(file, size);
    if (!nt) {
        fprintf(stderr, "loader: %s is not a valid PE32+ image\n", path);
        free(file);
        return 0;
    }

    DWORD size_image = nt->OptionalHeader.SizeOfImage;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if ((ULONGLONG)sec[i].PointerToRawData + sec[i].SizeOfRawData > size ||
            (ULONGLONG)sec[i].VirtualAddress + sec[i].SizeOfRawData > size_image) {
            fprintf(stderr, "loader: %s: section %.8s runs past the file or the image\n",
                    path, sec[i].Name);
            free(file);
            return 0;
        }
    }

    BYTE *base = (BYTE *)VirtualAlloc((LPVOID)at, size_image, MEM_COMMIT, PAGE_READWRITE);
    if (base == NULL || (ULONGLONG)base != at) {
        fprintf(stderr, "loader: %s: commit at 0x%llX failed, err=%lu\n", path, at, GetLastError());
        free(file);
        return 0;
    }

    memcpy(base, file, nt->OptionalHeader.SizeOfHeaders);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++)
        memcpy(base + sec[i].VirtualAddress, file + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    free(file);

    loader_attach(img, at, size_image);
    ULONGLONG delta = at - img->nt->OptionalHeader.ImageBase;
    if (delta != 0 && !apply_relocations(img, delta)) return 0;
    img->nt->OptionalHeader.ImageBase = at;

    VLOG("loader: %-16s 0x%llX-0x%llX  %s\n", img->name, at, at + size_image, path);
    return 1;
}

static const char *dll_alias(const char *dll)
{
    return _strnicmp(dll, "api-ms-win-crt-", 15) == 0 ? "ucrtbase.dll" : dll;
}

static Image *mapped_for(const char *dll, Image **mapped, int n_mapped)
{
    const char *want = dll_alias(dll);
    for (int i = 0; i < n_mapped; i++)
        if (_stricmp(mapped[i]->name, want) == 0) return mapped[i];
    return NULL;
}

static void *resolve(const char *dll, const char *name, WORD ordinal, Image **mapped, int n_mapped);

static void *export_of(const Image *img, const char *name, WORD ordinal,
                       Image **mapped, int n_mapped)
{
    IMAGE_DATA_DIRECTORY dir = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dir.VirtualAddress == 0) return NULL;
    IMAGE_EXPORT_DIRECTORY *ex = (IMAGE_EXPORT_DIRECTORY *)(img->base + dir.VirtualAddress);
    DWORD *funcs = (DWORD *)(img->base + ex->AddressOfFunctions);
    DWORD *names = (DWORD *)(img->base + ex->AddressOfNames);
    WORD  *ords  = (WORD *)(img->base + ex->AddressOfNameOrdinals);

    DWORD idx = (DWORD)-1;
    if (name) {
        for (DWORD i = 0; i < ex->NumberOfNames; i++)
            if (strcmp((const char *)(img->base + names[i]), name) == 0) { idx = ords[i]; break; }
    } else {
        idx = ordinal - ex->Base;
    }
    if (idx >= ex->NumberOfFunctions || funcs[idx] == 0) return NULL;

    DWORD rva = funcs[idx];
    if (rva < dir.VirtualAddress || rva >= dir.VirtualAddress + dir.Size)
        return img->base + rva;

    const char *fwd = (const char *)(img->base + rva);
    const char *dot = strchr(fwd, '.');
    if (!dot) return NULL;
    char mod[MAX_PATH];
    _snprintf_s(mod, sizeof mod, _TRUNCATE, "%.*s.dll", (int)(dot - fwd), fwd);
    if (dot[1] == '#') return resolve(mod, NULL, (WORD)atoi(dot + 2), mapped, n_mapped);
    return resolve(mod, dot + 1, 0, mapped, n_mapped);
}

static void *resolve(const char *dll, const char *name, WORD ordinal, Image **mapped, int n_mapped)
{
    Image *m = mapped_for(dll, mapped, n_mapped);
    if (m) return export_of(m, name, ordinal, mapped, n_mapped);
    HMODULE h = LoadLibraryA(dll);
    if (!h) return NULL;
    return (void *)GetProcAddress(h, name ? name : (LPCSTR)(uintptr_t)ordinal);
}

void *loader_export(const Image *img, const char *name, WORD ordinal)
{
    return export_of(img, name, ordinal, NULL, 0);
}

int loader_imports(const Image *img, const char *dll)
{
    IMAGE_DATA_DIRECTORY dir = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return 0;
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(img->base + dir.VirtualAddress);
    for (; desc->Name != 0; desc++)
        if (_stricmp(dll_alias((const char *)(img->base + desc->Name)), dll) == 0) return 1;
    return 0;
}

int loader_fill_imports(Image *img, Image **mapped, int n_mapped, hook_lookup_fn hook)
{
    IMAGE_DATA_DIRECTORY dir = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (dir.VirtualAddress == 0) return 1;

    int to_mapped = 0, to_os = 0, hooked = 0;
    IMAGE_IMPORT_DESCRIPTOR *desc = (IMAGE_IMPORT_DESCRIPTOR *)(img->base + dir.VirtualAddress);
    for (; desc->Name != 0; desc++) {
        const char *dll = (const char *)(img->base + desc->Name);
        Image *m = mapped_for(dll, mapped, n_mapped);
        DWORD names_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        IMAGE_THUNK_DATA64 *name_thunk = (IMAGE_THUNK_DATA64 *)(img->base + names_rva);
        IMAGE_THUNK_DATA64 *iat_thunk  = (IMAGE_THUNK_DATA64 *)(img->base + desc->FirstThunk);

        for (; name_thunk->u1.AddressOfData != 0; name_thunk++, iat_thunk++) {
            const char *name = NULL;
            WORD ordinal = 0;
            if (name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                ordinal = (WORD)IMAGE_ORDINAL64(name_thunk->u1.Ordinal);
            else
                name = ((IMAGE_IMPORT_BY_NAME *)(img->base + name_thunk->u1.AddressOfData))->Name;

            void *p = NULL;
            if (m) {
                p = export_of(m, name, ordinal, mapped, n_mapped);
                to_mapped++;
            } else {
                if (name && hook) p = hook(name);
                if (p) hooked++;
                else p = resolve(dll, name, ordinal, mapped, n_mapped);
                to_os++;
            }
            if (!p) {
                if (name) fprintf(stderr, "loader: %s: unresolved %s!%s\n", img->name, dll, name);
                else      fprintf(stderr, "loader: %s: unresolved %s!#%u\n", img->name, dll, ordinal);
                return 0;
            }
            iat_thunk->u1.Function = (ULONGLONG)p;
        }
    }
    VLOG("loader: %-16s imports %3d -> mapped, %3d -> OS, %d hooked\n",
         img->name, to_mapped, to_os, hooked);
    return 1;
}

static DWORD section_protect(DWORD characteristics)
{
    int x = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    int w = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x)      return PAGE_EXECUTE_READ;
    if (w)      return PAGE_READWRITE;
    return PAGE_READONLY;
}

int loader_protect(Image *img)
{
    DWORD old = 0;
    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(img->nt);
    for (WORD i = 0; i < img->nt->FileHeader.NumberOfSections; i++) {
        SIZE_T vsize = ((SIZE_T)sec[i].Misc.VirtualSize + 0xFFF) & ~(SIZE_T)0xFFF;
        if (vsize == 0) continue;
        if (!VirtualProtect(img->base + sec[i].VirtualAddress, vsize,
                            section_protect(sec[i].Characteristics), &old)) {
            fprintf(stderr, "loader: %s: VirtualProtect(%.8s) failed, err=%lu\n",
                    img->name, sec[i].Name, GetLastError());
            return 0;
        }
    }

    // Exception dispatch finds .pdata only for images Windows itself loaded.
    IMAGE_DATA_DIRECTORY pdata = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (pdata.Size != 0 &&
        !RtlAddFunctionTable((PRUNTIME_FUNCTION)(img->base + pdata.VirtualAddress),
                             pdata.Size / sizeof(RUNTIME_FUNCTION), (DWORD64)img->base)) {
        fprintf(stderr, "loader: %s: RtlAddFunctionTable failed\n", img->name);
        return 0;
    }

    SIZE_T hdr = ((SIZE_T)img->nt->OptionalHeader.SizeOfHeaders + 0xFFF) & ~(SIZE_T)0xFFF;
    if (!VirtualProtect(img->base, hdr, PAGE_READONLY, &old)) {
        fprintf(stderr, "loader: %s: VirtualProtect(headers) failed, err=%lu\n",
                img->name, GetLastError());
        return 0;
    }
    return 1;
}

int loader_become_main(const Image *img, const char *path)
{
    WCHAR wide[MAX_PATH];
    WCHAR *file = NULL;
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, wide, MAX_PATH) ||
        !GetFullPathNameW(wide, MAX_PATH, g_main_path, &file) || !file) {
        fprintf(stderr, "loader: %s: full path failed, err=%lu\n", path, GetLastError());
        return 0;
    }

    Peb      *peb    = (Peb *)__readgsqword(0x60);
    LdrEntry *main   = (LdrEntry *)((LdrData *)peb->ldr)->load_order.Flink;
    UStr      full   = { (USHORT)(wcslen(g_main_path) * sizeof(WCHAR)), (USHORT)sizeof g_main_path,
                         g_main_path };
    UStr      name   = { (USHORT)(wcslen(file) * sizeof(WCHAR)),
                         (USHORT)((g_main_path + MAX_PATH - file) * sizeof(WCHAR)), file };

    peb->image_base = img->base;
    main->base      = img->base;
    main->entry     = img->base + img->nt->OptionalHeader.AddressOfEntryPoint;
    main->size      = img->nt->OptionalHeader.SizeOfImage;
    main->full_name = full;
    main->base_name = name;
    ((ProcParams *)peb->params)->image_path = full;

    VLOG("loader: %-16s is the main module: %ls\n", img->name, g_main_path);
    return 1;
}

int loader_run_tls(const Image *img, DWORD reason)
{
    IMAGE_DATA_DIRECTORY dir = img->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (dir.VirtualAddress == 0 || dir.Size == 0) return 1;

    IMAGE_TLS_DIRECTORY64 *tls = (IMAGE_TLS_DIRECTORY64 *)(img->base + dir.VirtualAddress);
    // tlssup.cpp always defines char _tls_start: TLS callbacks alone give 1 byte of TLS data.
    ULONGLONG tls_bytes = tls->EndAddressOfRawData - tls->StartAddressOfRawData
                        + tls->SizeOfZeroFill;
    if (tls_bytes > sizeof(char)) {
        fprintf(stderr, "loader: %s uses static TLS (__declspec(thread)), not supported\n",
                img->name);
        return 0;
    }
    if (tls->AddressOfCallBacks == 0) return 1;

    int n = 0;
    for (PIMAGE_TLS_CALLBACK *cb = (PIMAGE_TLS_CALLBACK *)tls->AddressOfCallBacks; *cb; cb++, n++)
        (*cb)((PVOID)img->base, reason, NULL);
    VLOG("loader: %-16s %d TLS callback(s) run\n", img->name, n);
    return 1;
}

int loader_dll_main(const Image *img, DWORD reason)
{
    DWORD rva = img->nt->OptionalHeader.AddressOfEntryPoint;
    if (rva == 0) return 1;
    BOOL (WINAPI *entry)(HINSTANCE, DWORD, LPVOID) =
        (BOOL (WINAPI *)(HINSTANCE, DWORD, LPVOID))(img->base + rva);
    if (!entry((HINSTANCE)img->base, reason, NULL)) {
        fprintf(stderr, "loader: %s: DllMain(%lu) returned FALSE\n", img->name, reason);
        return 0;
    }
    VLOG("loader: %-16s DllMain(%lu) ok\n", img->name, reason);
    return 1;
}
