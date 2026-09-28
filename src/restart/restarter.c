#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ckpt_format.h"
#include "arena.h"
#include "log.h"

// Reads the checkpoint and rebuilds the upper half INTO THIS PROCESS: reserve
// the arena, commit each saved region at its original address, paste the
// bytes, apply the saved protections, verify, then RESUME: repoint the app's
// IAT at this process's DLLs and allocator, register the pasted image's
// .pdata, and restore the saved CONTEXT. This process keeps its own fresh
// ntdll/kernel32/CRT as the lower half.

// The allocator is arena.lib, the same code that served the app before the
// checkpoint, so the Block layout cannot drift from what the heap holds. It is
// ADOPTED, never arena_init'd: the control block and every Block header came
// back from the checkpoint, and free_head / Block.next are absolute VAs that
// are valid again because the arena is back at ARENA_BASE. arena_init would
// write a fresh control block and discard the restored heap.
static void adopt_arena(ULONGLONG app_base, ULONGLONG app_end,
                        ULONGLONG heap_start, ULONGLONG stack_base,
                        ULONGLONG stack_size)
{
    g_arena.base        = ARENA_BASE;
    g_arena.end         = ARENA_BASE + ARENA_SIZE;
    g_arena.app_base    = app_base;
    g_arena.app_end     = app_end;
    g_arena.heap_start  = heap_start;
    g_arena.heap_end    = ARENA_BASE + HEAP_WINDOW;
    g_arena.stack_limit = stack_base;
    g_arena.stack_base  = stack_base + stack_size;
    g_ctl = (heap_ctl *)heap_start;
}

// A second checkpoint from a restored process is not part of M4c. Say so
// rather than leaving the slot pointing into the dead loader.
static void restarter_checkpoint_stub(void)
{
    printf("ckpt    second checkpoint from a restored process: not implemented\n");
}

// The loader owned the app's exit slot too, so it is exactly as stale as the
// allocator slots. Taking it back is what turns a clean app exit into the
// resume verdict.
static void __cdecl restarter_exit_hook(int code)
{
    printf("\n--- app exit %d ---\n", code);
    VLOG("heap_ctl  cur=0x%llX committed=0x%llX free_head=0x%llX\n",
         g_ctl->cur, g_ctl->committed, g_ctl->free_head);
    printf("%s\n", code == 0
           ? "PASS    app ran from the checkpoint to its exit"
           : "FAIL    app resumed but exited nonzero");
    g_arena.real_exit(code);
}

// ---------------------------------------------------------------------
// The arena reserve must win the race against this process's own CRT and
// loader allocations. A TLS callback runs at DLL_PROCESS_ATTACH, before the
// EXE entry point and therefore before CRT startup allocates anything, which
// is the earliest point reachable from C. No CRT calls in here: the CRT is
// not initialized yet. The outcome is recorded and reported from main().
// ---------------------------------------------------------------------
static LPVOID g_reserve_got;
static DWORD  g_reserve_err;

static void NTAPI arena_reserve_cb(PVOID inst, DWORD reason, PVOID reserved)
{
    (void)inst; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return;
    g_reserve_got = VirtualAlloc((LPVOID)ARENA_BASE, (SIZE_T)ARENA_SIZE,
                                 MEM_RESERVE, PAGE_NOACCESS);
    g_reserve_err = g_reserve_got ? 0 : GetLastError();
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_arena_reserve_cb")
#pragma const_seg(".CRT$XLB")
EXTERN_C const PIMAGE_TLS_CALLBACK p_arena_reserve_cb = arena_reserve_cb;
#pragma const_seg()

static BYTE *read_file(const char *path, DWORD *out_size)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "read_file: CreateFileA(%s) failed, err=%lu\n",
                path, GetLastError());
        return NULL;
    }
    DWORD size = GetFileSize(h, NULL);
    BYTE *buf = (BYTE *)malloc(size);
    DWORD got = 0;
    if (!buf || !ReadFile(h, buf, size, &got, NULL) || got != size) {
        fprintf(stderr, "read_file: ReadFile(%s) failed, err=%lu\n",
                path, GetLastError());
        CloseHandle(h);
        free(buf);
        return NULL;
    }
    CloseHandle(h);
    *out_size = size;
    return buf;
}

// TODO: this parser is duplicated in dumpckpt.c. Both should call one shared
// reader built on ckpt_format.h.
static int read_ckpt(const char *path, Snapshot *s)
{
    DWORD fsize = 0;
    BYTE *file = read_file(path, &fsize);
    if (!file) return 0;

    memset(s, 0, sizeof(*s));
    BYTE *p = file, *end = file + fsize;
    if ((ULONGLONG)(end - p) < 40) { fprintf(stderr, "read_ckpt: truncated header\n"); goto fail; }

    ULONGLONG magic;
    memcpy(&magic, p, 8);              p += 8;
    memcpy(&s->arena_start, p, 8);     p += 8;
    memcpy(&s->count, p, 8);           p += 8;
    memcpy(&s->context_present, p, 8); p += 8;
    memcpy(&s->total, p, 8);           p += 8;

    if (magic != CKPT_MAGIC) {
        fprintf(stderr, "read_ckpt: bad magic 0x%llX\n", magic);
        goto fail;
    }
    if (s->count * 32 > (ULONGLONG)(end - p)) {
        fprintf(stderr, "read_ckpt: region count %llu exceeds the file\n", s->count);
        goto fail;
    }

    s->rg = (RegionRec *)malloc((size_t)s->count * sizeof(*s->rg));
    if (!s->rg) { fprintf(stderr, "read_ckpt: out of memory\n"); goto fail; }

    s->bytes = (BYTE *)malloc((size_t)s->total);
    if (!s->bytes) { fprintf(stderr, "read_ckpt: out of memory\n"); goto fail; }

    ULONGLONG off = 0;
    for (ULONGLONG i = 0; i < s->count; i++) {
        if ((ULONGLONG)(end - p) < 32) { fprintf(stderr, "read_ckpt: truncated rec %llu\n", i); goto fail; }
        ULONGLONG rec[4];
        memcpy(rec, p, 32); p += 32;
        s->rg[i].base    = rec[0];
        s->rg[i].size    = rec[1];
        s->rg[i].protect = (DWORD)rec[2];
        s->rg[i].kind    = (DWORD)rec[3];
        s->rg[i].off     = off;
        if ((ULONGLONG)(end - p) < s->rg[i].size || off + s->rg[i].size > s->total) {
            fprintf(stderr, "read_ckpt: truncated payload %llu\n", i);
            goto fail;
        }
        memcpy(s->bytes + off, p, (size_t)s->rg[i].size);
        p += s->rg[i].size;
        off += s->rg[i].size;
    }
    if (off != s->total) { fprintf(stderr, "read_ckpt: size mismatch\n"); goto fail; }

    if (s->context_present) {
        if ((ULONGLONG)(end - p) < 8 + sizeof(CONTEXT)) {
            fprintf(stderr, "read_ckpt: truncated context\n"); goto fail;
        }
        ULONGLONG tag;
        memcpy(&tag, p, 8); p += 8;
        if (tag != TAG_CONTEXT) { fprintf(stderr, "read_ckpt: bad context tag\n"); goto fail; }
        memcpy(&s->ctx, p, sizeof(CONTEXT)); p += sizeof(CONTEXT);
    }
    if (p != end) { fprintf(stderr, "read_ckpt: trailing bytes\n"); goto fail; }

    free(file);
    return 1;
fail:
    free(file);
    free(s->bytes);
    free(s->rg);
    s->bytes = NULL;
    s->rg = NULL;
    return 0;
}

// The heap control block sits at the start of the heap region, which the
// loader placed at the first page above the mapped image. Derive it from
// app.exe's headers rather than hardcoding, so this stays honest if the
// image size changes.
static int heap_ctl_addr(ULONGLONG *lo, ULONGLONG *hi, ULONGLONG *ctl)
{
    DWORD size = 0;
    BYTE *f = read_file(DEFAULT_APP_PATH, &size);
    if (!f) return 0;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)f;
    if (size < sizeof(*dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) { free(f); return 0; }
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(f + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { free(f); return 0; }
    *lo  = nt->OptionalHeader.ImageBase;
    *hi  = *lo + nt->OptionalHeader.SizeOfImage;
    *ctl = (*hi + (PAGE - 1)) & ~(PAGE - 1);
    free(f);
    return 1;
}

static int readable(DWORD prot)
{
    DWORD p = prot & 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY
        || p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE
        || p == PAGE_EXECUTE_WRITECOPY;
}

static void report_conflict(void)
{
    for (ULONGLONG a = ARENA_BASE; a < ARENA_BASE + ARENA_SIZE; ) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)a, &mbi, sizeof(mbi)) != sizeof(mbi)) {
            printf("  VirtualQuery(0x%llX) failed, err=%lu\n", a, GetLastError());
            return;
        }
        if (mbi.State != MEM_FREE)
            printf("  in the way: base=0x%llX size=0x%llX state=0x%lX protect=0x%lX type=0x%lX\n",
                   (ULONGLONG)mbi.BaseAddress, (ULONGLONG)mbi.RegionSize,
                   mbi.State, mbi.Protect, mbi.Type);
        a = (ULONGLONG)mbi.BaseAddress + mbi.RegionSize;
    }
}

// ---------------------------------------------------------------------
// STEP 1 -- the core fixup. The pasted IAT holds CHECKPOINT-time addresses of
// ntdll/kernel32/ucrtbase; those DLLs are wherever THIS process has them. The
// names are still readable because the loader only ever wrote FirstThunk,
// leaving OriginalFirstThunk intact, so the loader's own walk works unchanged
// on the pasted image. STEP 1b -- the slots the loader owned (allocator,
// checkpoint, exit) are taken over again, because the old loader's code is not
// in this process at all.
// ---------------------------------------------------------------------
static int fix_iat(ULONGLONG base)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY imp =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp.VirtualAddress == 0) {
        fprintf(stderr, "pasted image has no import directory\n");
        return 0;
    }

    // The launcher applies per-section W^X, so the pasted IAT came back
    // read-only inside .rdata. Unlock exactly the IAT for the fixup and put
    // the saved protection back before the app runs.
    IMAGE_DATA_DIRECTORY iat =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    LPVOID iat_va = NULL;
    DWORD  iat_old = 0;
    if (iat.VirtualAddress == 0 || iat.Size == 0) {
        fprintf(stderr, "pasted image has no IAT directory\n");
        return 0;
    }
    iat_va = (LPVOID)(base + iat.VirtualAddress);
    if (!VirtualProtect(iat_va, iat.Size, PAGE_READWRITE, &iat_old)) {
        fprintf(stderr, "iat     VirtualProtect(0x%llX+0x%lX) failed, err=%lu\n",
                (ULONGLONG)iat_va, iat.Size, GetLastError());
        return 0;
    }
    VLOG("iat     unlocked 0x%llX+0x%lX, was protect=0x%lX\n",
         (ULONGLONG)iat_va, iat.Size, iat_old);

    ULONGLONG slots = 0, changed = 0, overrides = 0;
    IMAGE_IMPORT_DESCRIPTOR *desc =
        (IMAGE_IMPORT_DESCRIPTOR *)(base + imp.VirtualAddress);
    for (; desc->Name != 0; desc++) {
        const char *dll_name = (const char *)(base + desc->Name);
        HMODULE dll = GetModuleHandleA(dll_name);
        if (!dll) dll = LoadLibraryA(dll_name);
        if (!dll) {
            fprintf(stderr, "LoadLibraryA(%s) failed, err=%lu\n",
                    dll_name, GetLastError());
            return 0;
        }
        VLOG("iat     %s -> module 0x%p\n", dll_name, (void *)dll);

        DWORD names_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                   : desc->FirstThunk;
        IMAGE_THUNK_DATA64 *name_thunk = (IMAGE_THUNK_DATA64 *)(base + names_rva);
        IMAGE_THUNK_DATA64 *iat_thunk  = (IMAGE_THUNK_DATA64 *)(base + desc->FirstThunk);

        for (; name_thunk->u1.AddressOfData != 0; name_thunk++, iat_thunk++) {
            ULONGLONG old = iat_thunk->u1.Function;
            slots++;

            if (name_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                WORD ord = (WORD)IMAGE_ORDINAL64(name_thunk->u1.Ordinal);
                FARPROC proc = GetProcAddress(dll, (LPCSTR)(uintptr_t)ord);
                if (!proc) {
                    fprintf(stderr, "GetProcAddress(%s #%u) failed\n", dll_name, ord);
                    return 0;
                }
                iat_thunk->u1.Function = (ULONGLONG)proc;
                if (old != (ULONGLONG)proc) {
                    changed++;
                    VLOG("  %s!#%u: old=0x%llX new=0x%llX\n",
                         dll_name, ord, old, (ULONGLONG)proc);
                }
                continue;
            }

            IMAGE_IMPORT_BY_NAME *ibn =
                (IMAGE_IMPORT_BY_NAME *)(base + name_thunk->u1.AddressOfData);
            const char *fn = ibn->Name;

            void *repl = NULL;
            if      (!strcmp(fn, "malloc"))  repl = (void *)arena_malloc;
            else if (!strcmp(fn, "free"))    repl = (void *)arena_free;
            else if (!strcmp(fn, "realloc")) repl = (void *)arena_realloc;
            else if (!strcmp(fn, "calloc"))  repl = (void *)arena_calloc;
            else if (!strcmp(fn, "winckpt_checkpoint"))
                repl = (void *)restarter_checkpoint_stub;
            else if (!strcmp(fn, "exit")) {
                FARPROC real = GetProcAddress(dll, fn);
                if (!real) {
                    fprintf(stderr, "GetProcAddress(exit) failed\n");
                    return 0;
                }
                g_arena.real_exit = (void (__cdecl *)(int))real;
                repl = (void *)restarter_exit_hook;
            }

            if (repl) {
                iat_thunk->u1.Function = (ULONGLONG)repl;
                overrides++;
                VLOG("  OVERRIDE %s!%s: old=0x%llX new=0x%p (restarter)\n",
                     dll_name, fn, old, repl);
                continue;
            }

            FARPROC proc = GetProcAddress(dll, fn);
            if (!proc) {
                fprintf(stderr, "GetProcAddress(%s!%s) failed\n", dll_name, fn);
                return 0;
            }
            iat_thunk->u1.Function = (ULONGLONG)proc;
            if (old != (ULONGLONG)proc) {
                changed++;
                VLOG("  %s!%s: old=0x%llX new=0x%llX\n",
                     dll_name, fn, old, (ULONGLONG)proc);
            }
        }
    }
    DWORD tmp = 0;
    if (!VirtualProtect(iat_va, iat.Size, iat_old, &tmp)) {
        fprintf(stderr, "iat     restoring protect=0x%lX failed, err=%lu\n",
                iat_old, GetLastError());
        return 0;
    }

    printf("iat     %llu slots: %llu repointed to this process's DLLs, "
           "%llu taken over%s\n", slots, changed, overrides,
           changed == 0 ? "  (0 = same boot, DLLs at unchanged addresses)" : "");
    return 1;
}

// ---------------------------------------------------------------------
// STEP 2 -- the pasted image is not in the PEB loader list, so the unwinder
// cannot find its exception tables on its own. Without this, any SEH dispatch
// or stack unwind after resume finds no function entry and terminates the
// process. Open gap since M2; closed here.
// ---------------------------------------------------------------------
static int register_pdata(ULONGLONG base)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY exc =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exc.VirtualAddress == 0 || exc.Size == 0) {
        fprintf(stderr, "pasted image has no exception directory\n");
        return 0;
    }
    PRUNTIME_FUNCTION fns = (PRUNTIME_FUNCTION)(base + exc.VirtualAddress);
    DWORD count = exc.Size / (DWORD)sizeof(RUNTIME_FUNCTION);
    if (!RtlAddFunctionTable(fns, count, base)) {
        fprintf(stderr, "RtlAddFunctionTable failed\n");
        return 0;
    }
    VLOG("pdata   rva=0x%lX size=0x%lX at 0x%p\n",
         exc.VirtualAddress, exc.Size, (void *)fns);

    ULONGLONG img = 0;
    PRUNTIME_FUNCTION probe =
        RtlLookupFunctionEntry(base + fns[0].BeginAddress, &img, NULL);
    printf("pdata   %lu entries registered, unwinder %s\n",
           count, probe ? "finds them" : "CANNOT FIND THEM");
    return probe != NULL;
}

// ---------------------------------------------------------------------
// STEP 3 -- the same transfer the loader used to enter the app, fed the SAVED
// context instead of a fresh entry point. The TEB still describes the
// restarter's stack; the app is about to run on the pasted arena stack, so the
// CRT's stack probes and SEH dispatch have to be told where that is. Does not
// return.
// ---------------------------------------------------------------------
static void resume_app(const CONTEXT *saved)
{
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    VLOG("resume  TEB stack [0x%llX..0x%llX) -> [0x%llX..0x%llX)\n",
         (ULONGLONG)tib->StackLimit, (ULONGLONG)tib->StackBase,
         g_arena.stack_limit, g_arena.stack_base);
    tib->StackBase  = (void *)g_arena.stack_base;
    tib->StackLimit = (void *)g_arena.stack_limit;

    CONTEXT ctx = *saved;
    printf("resume  Rip 0x%llX  Rsp 0x%llX\n\n--- app ---\n",
           ctx.Rip, ctx.Rsp);
    fflush(stdout);
    RtlRestoreContext(&ctx, NULL);

    fprintf(stderr, "RtlRestoreContext returned -- unreachable\n");
    ExitProcess(3);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    int ok = 1;

    for (int i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-v")) g_verbose = 1;

    // STEP 1 -- the arena reserve, already attempted in the TLS callback.
    if (!g_reserve_got) {
        printf("arena   0x%llX RESERVE FAILED err=%lu\n", ARENA_BASE, g_reserve_err);
        report_conflict();
        return 1;
    }
    if ((ULONGLONG)g_reserve_got != ARENA_BASE) {
        printf("arena   WRONG BASE 0x%llX, wanted 0x%llX\n",
               (ULONGLONG)g_reserve_got, ARENA_BASE);
        report_conflict();
        return 1;
    }
    printf("arena   0x%llX-0x%llX  reserved at exact base\n",
           ARENA_BASE, ARENA_BASE + ARENA_SIZE);

    // STEP 2 -- read the checkpoint.
    Snapshot s;
    if (!read_ckpt(DEFAULT_CKPT_PATH, &s)) return 1;
    printf("file    %s  %llu regions, %llu bytes, registers %s\n",
           DEFAULT_CKPT_PATH, s.count, s.total, s.context_present ? "present" : "ABSENT");

    if (s.arena_start != ARENA_BASE) {
        fprintf(stderr, "file    arena_start 0x%llX != reserved base 0x%llX\n",
                s.arena_start, ARENA_BASE);
        return 1;
    }
    for (ULONGLONG i = 0; i < s.count; i++) {
        if (s.rg[i].base < ARENA_BASE
            || s.rg[i].base + s.rg[i].size > ARENA_BASE + ARENA_SIZE) {
            fprintf(stderr, "file    region[%llu] 0x%llX+0x%llX outside the reserve\n",
                    i, s.rg[i].base, s.rg[i].size);
            return 1;
        }
    }

    char pasted[128];
    pasted[0] = 0;

    // STEP 3 -- commit and paste. Writable first; the saved protections come
    // afterwards so a read-only region is still fillable here.
    for (ULONGLONG i = 0; i < s.count; i++) {
        RegionRec *r = &s.rg[i];
        LPVOID got = VirtualAlloc((LPVOID)r->base, (SIZE_T)r->size,
                                  MEM_COMMIT, PAGE_READWRITE);
        if (!got || (ULONGLONG)got != r->base) {
            printf("paste   region[%llu] 0x%llX+0x%llX COMMIT FAILED "
                   "(got 0x%llX, err=%lu)\n",
                   i, r->base, r->size, (ULONGLONG)got, GetLastError());
            ok = 0;
            continue;
        }
        memcpy((void *)r->base, s.bytes + r->off, (size_t)r->size);
        VLOG("paste   region[%llu] 0x%llX+0x%08llX %s\n",
             i, r->base, r->size, r->kind == REGION_STACK ? "STACK" : "PLAIN");
        {
            char one[48];
            sprintf(one, " %s %llu",
                    r->kind == REGION_STACK ? "stack" : i == 0 ? "image" : "heap",
                    r->size);
            if (strlen(pasted) + strlen(one) < sizeof pasted) strcat(pasted, one);
        }
    }
    printf("paste  %s  -> committed at saved addresses\n", pasted);

    // STEP 4 -- protection pass, after every write.
    for (ULONGLONG i = 0; i < s.count; i++) {
        RegionRec *r = &s.rg[i];
        DWORD old = 0;
        if (!VirtualProtect((LPVOID)r->base, (SIZE_T)r->size, r->protect, &old)) {
            printf("paste   region[%llu] VirtualProtect(0x%lX) FAILED err=%lu\n",
                   i, r->protect, GetLastError());
            ok = 0;
            continue;
        }
        VLOG("paste   region[%llu] protect 0x%lX -> 0x%lX\n", i, old, r->protect);
    }

    // STEP 5 -- peek. Compare what is now in memory against the file bytes.
    int bytes_ok = 1;
    for (ULONGLONG i = 0; i < s.count; i++) {
        RegionRec *r = &s.rg[i];
        if (!readable(r->protect)) {
            printf("verify  region[%llu] 0x%llX protect=0x%lX NOT READABLE\n",
                   i, r->base, r->protect);
            ok = 0; bytes_ok = 0;
            continue;
        }
        const BYTE *mem = (const BYTE *)r->base;
        const BYTE *fil = s.bytes + r->off;
        if (memcmp(mem, fil, (size_t)r->size) == 0) {
            VLOG("verify  region[%llu] 0x%llX+0x%08llX memcmp MATCH\n",
                 i, r->base, r->size);
            continue;
        }
        bytes_ok = 0;
        ULONGLONG k = 0;
        while (k < r->size && mem[k] == fil[k]) k++;
        printf("verify  region[%llu] 0x%llX MEMCMP MISMATCH at +0x%llX (VA 0x%llX)\n",
               i, r->base, k, r->base + k);
        printf("        memory:");
        for (ULONGLONG j = k; j < k + 8 && j < r->size; j++) printf(" %02X", mem[j]);
        printf("\n        file  :");
        for (ULONGLONG j = k; j < k + 8 && j < r->size; j++) printf(" %02X", fil[j]);
        printf("\n");
        ok = 0;
    }

    ULONGLONG app_lo = 0, app_hi = 0, ctl_va = 0;
    int heap_sane = 0;
    if (heap_ctl_addr(&app_lo, &app_hi, &ctl_va)) {
        const heap_ctl *c = (const heap_ctl *)ctl_va;
        heap_sane = c->cur >= ctl_va + HEAP_CTL_RESERVE
                    && c->cur <= c->committed
                    && c->committed <= ARENA_BASE + HEAP_WINDOW
                    && (c->free_head == 0
                        || (c->free_head >= ctl_va && c->free_head < c->cur));
        VLOG("verify  heap_ctl @0x%llX cur=0x%llX committed=0x%llX "
             "free_head=0x%llX\n", ctl_va,
             c->cur, c->committed, c->free_head);
    } else {
        printf("verify  app.exe unreadable, cannot locate heap_ctl\n");
    }
    ok &= heap_sane;

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)ARENA_BASE;
    int mz = dos->e_magic == IMAGE_DOS_SIGNATURE;
    ok &= mz;

    ULONGLONG stack_base = 0, stack_size = 0;
    int stack_regions = 0;
    for (ULONGLONG i = 0; i < s.count; i++)
        if (s.rg[i].kind == REGION_STACK) {
            stack_base = s.rg[i].base; stack_size = s.rg[i].size; stack_regions++;
        }

    int rip_ok = 0, rsp_ok = 0;
    if (s.context_present) {
        rip_ok = app_hi && s.ctx.Rip >= app_lo && s.ctx.Rip < app_hi;
        rsp_ok = stack_regions == 1 && s.ctx.Rsp >= stack_base
                 && s.ctx.Rsp < stack_base + stack_size;
        VLOG("verify  context Rip=0x%llX Rsp=0x%llX Rbp=0x%llX Rbx=0x%llX\n",
             s.ctx.Rip, s.ctx.Rsp, s.ctx.Rbp, s.ctx.Rbx);
    }
    ok &= rip_ok & rsp_ok;

    printf("verify  bytes %s, heap %s, MZ %s, Rip in image %s, Rsp in stack %s\n",
           bytes_ok ? "match" : "DIFFER", heap_sane ? "OK" : "BAD",
           mz ? "OK" : "BAD", rip_ok ? "OK" : "NO", rsp_ok ? "OK" : "NO");

    if (!ok) {
        printf("FAIL    refusing to resume\n");
        free(s.bytes);
        return 1;
    }

    adopt_arena(app_lo, app_hi, ctl_va, stack_base, stack_size);

    CONTEXT resume_ctx = s.ctx;
    free(s.bytes);

    if (!fix_iat(g_arena.app_base)) return 1;
    if (!register_pdata(g_arena.app_base)) return 1;
    resume_app(&resume_ctx);
    return 1;
}
