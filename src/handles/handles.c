#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "handles.h"
#include "arena.h"
#include "log.h"

static HandlesEmu *g_e;

static HANDLE fake_of(int i)
{
    return (HANDLE)(HANDLE_FAKE_BASE + 4ULL * (ULONGLONG)(i + 1));
}

static int slot_of(HANDLE h)
{
    ULONGLONG v = (ULONGLONG)h;
    if (v < HANDLE_FAKE_BASE + 4 || v > HANDLE_FAKE_BASE + 4ULL * HANDLE_SLOTS || (v & 3)) return -1;
    return (int)((v - HANDLE_FAKE_BASE) / 4) - 1;
}

int handles_is_fake(HANDLE h)
{
    return slot_of(h) >= 0;
}

HANDLE handles_real(HANDLE h)
{
    int i = slot_of(h);
    if (i < 0 || g_e->slot[i].kind == HK_FREE) return h;
    return g_e->slot[i].real;
}

void handles_drop(HANDLE fake)
{
    int i = slot_of(fake);
    if (i < 0) return;
    arena_free(g_e->slot[i].path);
    arena_free(g_e->slot[i].data);
    memset(&g_e->slot[i], 0, sizeof g_e->slot[i]);
}

static int first_of_group(int i)
{
    for (int j = 0; j < i; j++)
        if (g_e->slot[j].kind != HK_FREE && g_e->slot[j].group == g_e->slot[i].group) return j;
    return -1;
}

static WCHAR *copy_name(const WCHAR *name)
{
    return (WCHAR *)arena_copy(name, (wcslen(name) + 1) * sizeof(WCHAR));
}

static int free_slot(void)
{
    for (int i = 0; i < HANDLE_SLOTS; i++) {
        if (g_e->slot[i].kind != HK_FREE) continue;
        g_e->slot[i].group = ++g_e->next_group;
        return i;
    }
    fprintf(stderr, "handles: all %d slots in use\n", HANDLE_SLOTS);
    return -1;
}

HANDLE handles_wrap_dup(HANDLE src, HANDLE real, DWORD opts, DWORD access, BOOL inherit)
{
    int j = slot_of(src);
    if (j < 0 || g_e->slot[j].kind == HK_FREE) return NULL;
    int i = free_slot();
    if (i < 0) return NULL;
    HandleEntry *s = &g_e->slot[i];
    *s = g_e->slot[j];
    s->data      = NULL;
    s->data_size = 0;
    if (!(opts & DUPLICATE_SAME_ACCESS)) s->access = access;
    if (s->path) {
        s->path = copy_name(g_e->slot[j].path);
        if (!s->path) {
            memset(s, 0, sizeof *s);
            return NULL;
        }
    }
    s->real    = real;
    s->inherit = inherit;
    VLOG("handles: 0x%p is a dup of 0x%p (group %d)\n", fake_of(i), src, s->group);
    return fake_of(i);
}

HANDLE handles_wrap_std(DWORD std_n, HANDLE real)
{
    int i = free_slot();
    if (i < 0) return NULL;
    g_e->slot[i].kind  = HK_STD;
    g_e->slot[i].std_n = std_n;
    g_e->slot[i].real  = real;
    return fake_of(i);
}

HANDLE handles_wrap_sync(HANDLE real, HandleKind kind, const WCHAR *name, DWORD access, BOOL inherit)
{
    int i = free_slot();
    if (i < 0) return NULL;
    HandleEntry *s = &g_e->slot[i];
    if (name && !(s->path = copy_name(name))) {
        fprintf(stderr, "handles: no arena room to record %ls\n", name);
        return NULL;
    }
    s->kind    = kind;
    s->real    = real;
    s->access  = access;
    s->inherit = inherit;
    VLOG("handles: 0x%p kind %d real 0x%p %ls\n", fake_of(i), kind, real, name ? name : L"(unnamed)");
    return fake_of(i);
}

int handles_wrap_pipe(HANDLE r, HANDLE w, DWORD size, BOOL inherit, HANDLE *fake_r, HANDLE *fake_w)
{
    int i = free_slot();
    if (i < 0) return 0;
    g_e->slot[i].kind = HK_PIPE_READ;
    int j = free_slot();
    if (j < 0) {
        g_e->slot[i].kind = HK_FREE;
        return 0;
    }
    HandleEntry *rs = &g_e->slot[i], *ws = &g_e->slot[j];
    ws->kind      = HK_PIPE_WRITE;
    rs->real      = r;
    ws->real      = w;
    rs->peer      = ws->group;
    ws->peer      = rs->group;
    rs->pipe_size = ws->pipe_size = size;
    rs->inherit   = ws->inherit   = inherit;
    *fake_r = fake_of(i);
    *fake_w = fake_of(j);
    VLOG("handles: pipe read 0x%p (real 0x%p) write 0x%p (real 0x%p)\n", *fake_r, r, *fake_w, w);
    return 1;
}

static WCHAR *full_path(HANDLE h)
{
    DWORD n = GetFinalPathNameByHandleW(h, NULL, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (n == 0) return NULL;
    WCHAR *p = (WCHAR *)arena_malloc(n * sizeof(WCHAR));
    if (!p) return NULL;
    if (GetFinalPathNameByHandleW(h, p, n, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS) >= n) {
        arena_free(p);
        return NULL;
    }
    return p;
}

static int file_id(HANDLE h, DWORD *volume, ULONGLONG *index, LONGLONG *size, BOOL *is_dir)
{
    BY_HANDLE_FILE_INFORMATION fi;
    if (!GetFileInformationByHandle(h, &fi)) return 0;
    *is_dir = (fi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
    *volume = fi.dwVolumeSerialNumber;
    *index  = ((ULONGLONG)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;
    *size   = (LONGLONG)(((ULONGLONG)fi.nFileSizeHigh << 32) | fi.nFileSizeLow);
    return 1;
}

HANDLE handles_wrap_file(HANDLE real, const WCHAR *name, DWORD access, DWORD share, DWORD flags,
                         BOOL inherit)
{
    int i = free_slot();
    if (i < 0) return NULL;
    HandleEntry *s = &g_e->slot[i];
    LONGLONG size;
    DWORD type = GetFileType(real);
    HandleKind kind = HK_OPAQUE;
    if (type == FILE_TYPE_DISK) {
        s->path = full_path(real);
        if (s->path && file_id(real, &s->volume, &s->index, &size, &s->is_dir)) {
            kind = HK_FILE;
        } else {
            arena_free(s->path);
            s->path = NULL;
        }
    } else if (type == FILE_TYPE_CHAR) {
        kind = HK_DEVICE;
    }
    if (!s->path) s->path = copy_name(name);
    if (!s->path) {
        fprintf(stderr, "handles: no arena room to record %ls\n", name);
        return NULL;
    }
    s->kind    = kind;
    s->real    = real;
    s->access  = access;
    s->share   = share;
    s->flags   = flags;
    s->inherit = inherit;
    VLOG("handles: 0x%p kind %d real 0x%p %ls\n", fake_of(i), s->kind, real, s->path);
    return fake_of(i);
}

HandlesEmu *handles_state(void)
{
    return g_e;
}

static int seek_to(HANDLE h, LONGLONG at)
{
    LARGE_INTEGER to;
    to.QuadPart = at;
    return SetFilePointerEx(h, to, NULL, FILE_BEGIN);
}

static int save_contents(HandleEntry *s)
{
    LARGE_INTEGER size;
    if (!GetFileSizeEx(s->real, &size) || (ULONGLONG)size.QuadPart > TEMP_FILE_MAX) {
        printf("ckpt: refused, %ls is deleted when the app dies and its %lld bytes cannot be copied\n",
               s->path, size.QuadPart);
        return 0;
    }
    arena_free(s->data);
    s->data      = (BYTE *)arena_malloc((size_t)size.QuadPart + 1);
    s->data_size = 0;
    if (!s->data || !seek_to(s->real, 0)) {
        printf("ckpt: refused, cannot copy %ls, err=%lu\n", s->path, GetLastError());
        return 0;
    }
    while (s->data_size < size.QuadPart) {
        DWORD want = (DWORD)min(size.QuadPart - s->data_size, 1 << 20), got = 0;
        if (!ReadFile(s->real, s->data + s->data_size, want, &got, NULL) || got == 0) break;
        s->data_size += got;
    }
    int ok = s->data_size == size.QuadPart;
    if (!seek_to(s->real, s->offset) || !ok) {
        printf("ckpt: refused, copied %lld of %lld bytes of %ls, err=%lu\n", s->data_size, size.QuadPart,
               s->path, GetLastError());
        return 0;
    }
    return 1;
}

static int save_pipe(int i)
{
    HandleEntry *s = &g_e->slot[i];
    DWORD avail = 0;
    arena_free(s->data);
    s->data      = NULL;
    s->data_size = 0;
    if (!PeekNamedPipe(s->real, NULL, 0, NULL, &avail, NULL)) {
        if (GetLastError() == ERROR_BROKEN_PIPE) return 1;
        printf("ckpt: refused, cannot look into pipe 0x%p, err=%lu\n", fake_of(i), GetLastError());
        return 0;
    }
    if (avail == 0) return 1;
    s->data = (BYTE *)arena_malloc(avail);
    DWORD got = 0;
    if (!s->data || !PeekNamedPipe(s->real, s->data, avail, &got, NULL, NULL) || got != avail) {
        printf("ckpt: refused, cannot copy %lu bytes waiting in pipe 0x%p, err=%lu\n", avail, fake_of(i),
               GetLastError());
        return 0;
    }
    s->data_size = got;
    VLOG("handles: pipe 0x%p holds %lu bytes\n", fake_of(i), got);
    return 1;
}

typedef LONG (NTAPI *nt_query_fn)(HANDLE h, int info_class, PVOID info, ULONG size, PULONG got);

typedef struct EventInfo {
    LONG type;
    LONG state;
} EventInfo;

typedef struct SemaphoreInfo {
    LONG count;
    LONG max;
} SemaphoreInfo;

typedef struct MutantInfo {
    LONG    count;
    BOOLEAN owned_by_caller;
    BOOLEAN abandoned;
} MutantInfo;

static int save_sync(int i)
{
    static const char *const fn_name[] = { "NtQueryEvent", "NtQuerySemaphore", "NtQueryMutant" };
    HandleEntry *s = &g_e->slot[i];
    int which = s->kind - HK_EVENT;
    nt_query_fn query = (nt_query_fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), fn_name[which]);
    union {
        EventInfo     event;
        SemaphoreInfo semaphore;
        MutantInfo    mutant;
    } info = { 0 };
    LONG st = query ? query(s->real, 0, &info, sizeof info, NULL) : -1;
    if (st < 0) {
        printf("ckpt: refused, %s on handle 0x%p failed, status 0x%lX\n", fn_name[which], fake_of(i), st);
        return 0;
    }
    if (s->kind == HK_EVENT) {
        s->sync_type  = info.event.type;
        s->sync_count = info.event.state;
    } else if (s->kind == HK_SEMAPHORE) {
        s->sync_count = info.semaphore.count;
        s->sync_max   = info.semaphore.max;
    } else {
        s->sync_count = info.mutant.count;
        if (s->sync_count <= 0 && !info.mutant.owned_by_caller) {
            printf("ckpt: refused, mutex 0x%p is owned by another thread\n", fake_of(i));
            return 0;
        }
    }
    VLOG("handles: 0x%p kind %d type %ld count %ld max %ld\n", fake_of(i), s->kind, s->sync_type,
         s->sync_count, s->sync_max);
    return 1;
}

int handles_save(void)
{
    for (int i = 0; i < HANDLE_SLOTS; i++) {
        HandleEntry *s = &g_e->slot[i];
        if (s->kind == HK_OPAQUE) {
            printf("ckpt: refused, %ls (handle 0x%p) cannot be reopened at restart\n", s->path, fake_of(i));
            return 0;
        }
        if (s->kind == HK_PIPE_READ && first_of_group(i) < 0 && !save_pipe(i)) return 0;
        if (s->kind >= HK_EVENT && s->kind <= HK_MUTEX && first_of_group(i) < 0 && !save_sync(i)) return 0;
        if (s->kind != HK_FILE || s->is_dir) continue;
        LARGE_INTEGER zero = { 0 }, pos;
        if (!SetFilePointerEx(s->real, zero, &pos, FILE_CURRENT)) {
            printf("ckpt: refused, cannot read the offset of %ls, err=%lu\n", s->path, GetLastError());
            return 0;
        }
        s->offset = pos.QuadPart;
        if ((s->flags & FILE_FLAG_DELETE_ON_CLOSE) && first_of_group(i) < 0 && !save_contents(s)) return 0;
        VLOG("handles: 0x%p %ls offset %lld\n", fake_of(i), s->path, s->offset);
    }
    return 1;
}

static int recreate(int i)
{
    HandleEntry *s = &g_e->slot[i];
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, s->inherit };
    DWORD access = s->access | GENERIC_WRITE;
    HANDLE h = CreateFileW(s->path, access, s->share, &sa, CREATE_NEW, s->flags, NULL);
    if (h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_FILE_EXISTS) {
        WCHAR suffix[32];
        swprintf(suffix, 32, L".restart%lu", GetCurrentProcessId());
        size_t n = wcslen(s->path) + wcslen(suffix) + 1;
        WCHAR *other = (WCHAR *)arena_malloc(n * sizeof(WCHAR));
        if (!other) {
            fprintf(stderr, "restart: no arena room to rename %ls\n", s->path);
            return 0;
        }
        swprintf(other, n, L"%ls%ls", s->path, suffix);
        arena_free(s->path);
        s->path = other;
        h = CreateFileW(s->path, access, s->share, &sa, CREATE_NEW, s->flags, NULL);
    }
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "restart: cannot recreate %ls, err=%lu\n", s->path, GetLastError());
        return 0;
    }
    LONGLONG done = 0;
    while (done < s->data_size) {
        DWORD want = (DWORD)min(s->data_size - done, 1 << 20), put = 0;
        if (!WriteFile(h, s->data + done, want, &put, NULL) || put == 0) break;
        done += put;
    }
    LONGLONG size;
    if (done != s->data_size || !seek_to(h, s->offset) ||
        !file_id(h, &s->volume, &s->index, &size, &s->is_dir)) {
        fprintf(stderr, "restart: cannot refill %ls (%lld of %lld bytes), err=%lu\n", s->path, done,
                s->data_size, GetLastError());
        CloseHandle(h);
        return 0;
    }
    arena_free(s->data);
    s->data      = NULL;
    s->data_size = 0;
    s->real      = h;
    VLOG("handles: recreated %ls with %lld bytes\n", s->path, done);
    return 1;
}

static int reopen(int i)
{
    HandleEntry *s = &g_e->slot[i];
    if (s->kind == HK_FILE && (s->flags & FILE_FLAG_DELETE_ON_CLOSE)) return recreate(i);
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, s->inherit };
    HANDLE h = CreateFileW(s->path, s->access, s->share, &sa, OPEN_EXISTING, s->flags, NULL);
    if (s->kind == HK_DEVICE) {
        if (h == INVALID_HANDLE_VALUE) VLOG("handles: %ls not available here, err=%lu\n", s->path, GetLastError());
        s->real = h == INVALID_HANDLE_VALUE ? NULL : h;
        return 1;
    }
    if (h == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "restart: cannot reopen %ls, err=%lu\n", s->path, GetLastError());
        return 0;
    }
    DWORD     volume;
    ULONGLONG index;
    LONGLONG  size;
    BOOL      is_dir;
    if (!file_id(h, &volume, &index, &size, &is_dir) || volume != s->volume || index != s->index) {
        fprintf(stderr, "restart: %ls is not the file that was open at the checkpoint\n", s->path);
        CloseHandle(h);
        return 0;
    }
    if (s->is_dir) {
        s->real = h;
        return 1;
    }
    if (size < s->offset) {
        fprintf(stderr, "restart: %ls is %lld bytes, the app was at offset %lld\n", s->path, size, s->offset);
        CloseHandle(h);
        return 0;
    }
    if (!seek_to(h, s->offset)) {
        fprintf(stderr, "restart: cannot seek %ls to %lld, err=%lu\n", s->path, s->offset, GetLastError());
        CloseHandle(h);
        return 0;
    }
    s->real = h;
    return 1;
}

int handles_init(HandlesEmu *e)
{
    g_e = e;
    e->slot = (HandleEntry *)arena_calloc(HANDLE_SLOTS, sizeof(HandleEntry));
    if (!e->slot) {
        fprintf(stderr, "handles: no room for %d slots in the arena\n", HANDLE_SLOTS);
        return 0;
    }
    for (int i = 0; i < 3; i++) {
        DWORD  n    = STD_INPUT_HANDLE - (DWORD)i;
        HANDLE real = GetStdHandle(n);
        if (real == NULL || real == INVALID_HANDLE_VALUE) {
            e->std[i] = real;
            continue;
        }
        e->std[i] = handles_wrap_std(n, real);
        if (!e->std[i]) return 0;
        VLOG("handles: std %d is 0x%p, real 0x%p\n", i, e->std[i], real);
    }
    return 1;
}

static int dup_from(int i, int j)
{
    HandleEntry *s = &g_e->slot[i], *first = &g_e->slot[j];
    if (!first->real) {
        s->real = NULL;
        return 1;
    }
    DWORD opts = s->access == first->access ? DUPLICATE_SAME_ACCESS : 0;
    HANDLE h;
    if (!DuplicateHandle(GetCurrentProcess(), first->real, GetCurrentProcess(), &h, s->access, s->inherit, opts)) {
        fprintf(stderr, "restart: cannot duplicate handle 0x%p (%ls), err=%lu\n", fake_of(i),
                s->path ? s->path : L"unnamed", GetLastError());
        return 0;
    }
    s->real = h;
    return 1;
}

static int is_pipe(HandleKind k)
{
    return k == HK_PIPE_READ || k == HK_PIPE_WRITE;
}

static int first_with_group(int group)
{
    for (int j = 0; j < HANDLE_SLOTS; j++)
        if (g_e->slot[j].kind != HK_FREE && g_e->slot[j].group == group) return j;
    return -1;
}

static int recreate_pipe(int i)
{
    HandleEntry *s = &g_e->slot[i];
    int peer = first_with_group(s->peer);
    if (peer >= 0 && peer < i) return 1;
    int rd = s->kind == HK_PIPE_READ ? i : peer;
    int wr = s->kind == HK_PIPE_WRITE ? i : peer;
    LONGLONG queued = rd >= 0 ? g_e->slot[rd].data_size : 0;
    DWORD size = (DWORD)max((LONGLONG)s->pipe_size, queued);
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, s->inherit };
    HANDLE r, w;
    if (!CreatePipe(&r, &w, &sa, size)) {
        fprintf(stderr, "restart: cannot recreate pipe 0x%p, err=%lu\n", fake_of(i), GetLastError());
        return 0;
    }
    DWORD put = 0;
    if (queued && (!WriteFile(w, g_e->slot[rd].data, (DWORD)queued, &put, NULL) || put != queued)) {
        fprintf(stderr, "restart: cannot refill pipe 0x%p (%lu of %lld bytes), err=%lu\n", fake_of(i), put,
                queued, GetLastError());
        CloseHandle(r);
        CloseHandle(w);
        return 0;
    }
    if (rd >= 0) {
        g_e->slot[rd].real = r;
        arena_free(g_e->slot[rd].data);
        g_e->slot[rd].data      = NULL;
        g_e->slot[rd].data_size = 0;
    } else {
        CloseHandle(r);
    }
    if (wr >= 0) g_e->slot[wr].real = w;
    else         CloseHandle(w);
    VLOG("handles: pipe recreated, %lld bytes back in, read end %s, write end %s\n", queued,
         rd >= 0 ? "kept" : "closed", wr >= 0 ? "kept" : "closed");
    return 1;
}

static int recreate_sync(int i)
{
    HandleEntry *s = &g_e->slot[i];
    SECURITY_ATTRIBUTES sa = { sizeof sa, NULL, s->inherit };
    HANDLE h = NULL;
    int owned = 0;
    if (s->kind == HK_EVENT) {
        DWORD flags = (s->sync_type == 0 ? CREATE_EVENT_MANUAL_RESET : 0) | (s->sync_count ? CREATE_EVENT_INITIAL_SET : 0);
        SetLastError(0);
        h = CreateEventExW(&sa, s->path, flags, s->access);
    } else if (s->kind == HK_SEMAPHORE) {
        SetLastError(0);
        h = CreateSemaphoreExW(&sa, s->sync_count, s->sync_max, s->path, 0, s->access);
    } else {
        owned = s->sync_count <= 0 ? 1 - s->sync_count : 0;
        SetLastError(0);
        h = CreateMutexExW(&sa, s->path, owned ? CREATE_MUTEX_INITIAL_OWNER : 0, s->access);
    }
    if (!h) {
        fprintf(stderr, "restart: cannot recreate %s %ls, err=%lu\n",
                s->kind == HK_EVENT ? "event" : s->kind == HK_SEMAPHORE ? "semaphore" : "mutex",
                s->path ? s->path : L"(unnamed)", GetLastError());
        return 0;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        VLOG("handles: %ls already exists, its current state is kept\n", s->path);
    } else {
        for (int k = 1; k < owned; k++) WaitForSingleObject(h, 0);
    }
    s->real = h;
    return 1;
}

int handles_adopt(HandlesEmu *e)
{
    g_e = e;
    for (int i = 0; i < HANDLE_SLOTS; i++) {
        HandleEntry *s = &e->slot[i];
        if (s->kind == HK_FREE || s->kind == HK_OPAQUE) continue;
        int j = first_of_group(i);
        if (j < 0 && is_pipe(s->kind)) {
            if (!recreate_pipe(i)) return 0;
        } else if (j < 0 && s->kind >= HK_EVENT && s->kind <= HK_MUTEX) {
            if (!recreate_sync(i)) return 0;
        } else if (j >= 0) {
            if (!dup_from(i, j)) return 0;
        } else if (s->kind == HK_STD) {
            s->real = GetStdHandle(s->std_n);
            if (s->real == INVALID_HANDLE_VALUE) s->real = NULL;
        } else if (!reopen(i)) {
            return 0;
        }
        VLOG("handles: 0x%p now real 0x%p\n", fake_of(i), s->real);
    }
    return 1;
}
