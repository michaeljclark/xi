/*
 * xi_nub - atomically create child process hosting static function.
 *
 * Copyright (c) 2020 Michael Clark <michaeljclark@mac.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <cstdio>
#include <cstddef>
#include <cerrno>

#include <string>

#ifdef _WIN32
#define OS_WINDOWS
#endif

#ifdef __APPLE__
#define OS_MACOS
#define OS_POSIX
#endif

#ifdef __linux__
#define OS_LINUX
#define OS_POSIX
#endif

#if defined OS_WINDOWS
#include <windows.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#if defined OS_POSIX
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <semaphore.h>
#include <time.h>
#endif

#include "xi_nub.h"

#if !defined MAXPATHLEN && defined MAX_PATH
#define MAXPATHLEN MAX_PATH
#endif

#if defined OS_WINDOWS
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

/*
 * nub globals
 */

static bool debug = false;


/*
 * nub private structures
 */

enum share_mode {
    file_create_always,
    file_create_new,
    file_open_existing,
    file_open_always,
    file_truncate_existing
};

enum file_perms {
    file_read = 0x1,
    file_write = 0x2,
    file_read_write = 0x3,
    file_append = 0x4
};

struct xi_nub_result {
    xi_nub_error error;
    intptr_t bytes;
};

struct xi_nub_file
{
    virtual const char* identity() = 0;
    virtual bool has_error() = 0;
    virtual int os_error() = 0;
    virtual xi_nub_error error_code() = 0;
    virtual ~xi_nub_file() = 0;
};

inline xi_nub_file::~xi_nub_file() {}

typedef xi_nub_file xi_nub_sock;

/*
 * platform error mapping
 */

#if defined OS_WINDOWS
static xi_nub_error os_error_code(DWORD error) {
    switch (error) {
    case 0:                    return xi_nub_success;
    case ERROR_INVALID_HANDLE: return xi_nub_einval;
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PIPE_BUSY:
    case ERROR_PIPE_NOT_CONNECTED:
                               return xi_nub_econnrefused;
    case ERROR_ALREADY_EXISTS: return xi_nub_eexist;
    case ERROR_ACCESS_DENIED:  return xi_nub_eacces;
    default:                   return xi_nub_egeneric;
    }
}
#endif

#if defined OS_POSIX
static xi_nub_error os_error_code(int error) {
    switch (error) {
    case 0:             return xi_nub_success;
    case EINVAL:        return xi_nub_einval;
    case ECONNREFUSED:  return xi_nub_econnrefused;
    case EEXIST:        return xi_nub_eexist;
    case EACCES:        return xi_nub_eacces;
    default:            return xi_nub_egeneric;
    }
}
#endif

/*
 * windows file descriptor
 */

#if defined OS_WINDOWS
struct xi_nub_win32_file : xi_nub_file
{
    HANDLE h;
    DWORD error;
    char ident[32];

    xi_nub_win32_file() = default;
    xi_nub_win32_file(HANDLE h, DWORD error = GetLastError())
        : h(h), error(error) {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "handle(%lld)", (long long)h);
        return ident;
    }

    virtual bool has_error() { return h == INVALID_HANDLE_VALUE; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_WINDOWS
typedef xi_nub_win32_file xi_nub_win32_sock;
#endif


/*
 * posix file descriptor
 */

#if defined OS_POSIX
struct xi_nub_unix_file : xi_nub_file
{
    int fd;
    int error;
    char ident[32];

    xi_nub_unix_file() = default;
    xi_nub_unix_file(int fd, int error = errno)
        : fd(fd), error(error) {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "fd(%d)", fd);
        return ident;
    }

    virtual bool has_error() { return fd < 0; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_POSIX
typedef xi_nub_unix_file xi_nub_unix_sock;
#endif


/*
 * utf8 <-> utf16 string conversion
 */

using string = std::string;
using wstring = std::wstring;

#if defined OS_WINDOWS
static string utf16_to_utf8(const wstring w)
{
    int l = WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), NULL, 0, NULL, NULL);
    string s(l, 0);
    WideCharToMultiByte(CP_UTF8, 0, &w[0], (int)w.size(), &s[0], l, NULL, NULL);
    return s;
}
#endif

#if defined OS_WINDOWS
static wstring utf8_to_utf16(const string s)
{
    int l = MultiByteToWideChar(CP_UTF8, 0, &s[0], (int)s.size(), NULL, 0);
    wstring w(l, 0);
    MultiByteToWideChar(CP_UTF8, 0, &s[0], (int)s.size(), &w[0], l);
    return w;
}
#endif


/*
 * Windows time
 */

#if defined OS_WINDOWS
static uint64_t _clock_time_ns()
{
    static LARGE_INTEGER f;

    LARGE_INTEGER t;
    if (!f.QuadPart) {
        QueryPerformanceFrequency(&f);
    }
    QueryPerformanceCounter(&t);

    return t.QuadPart * 1000000000ull / f.QuadPart;
}
#endif


/*
 * POSIX time
 */

#if defined OS_POSIX
static uint64_t _clock_time_ns()
{
    struct timespec res;
    clock_gettime(CLOCK_REALTIME, &res);
    return (uint64_t)res.tv_nsec + (uint64_t)res.tv_sec * 1000000000ll;
}
#endif


/*
 * windows named semaphore
 */

#if defined OS_WINDOWS
struct xi_nub_win32_semaphore : xi_nub_file
{
    HANDLE h;
    DWORD error;
    char ident[32];

    xi_nub_win32_semaphore() = default;
    xi_nub_win32_semaphore(HANDLE h, DWORD error = GetLastError())
        : h(h), error(error) {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "handle(%lld)", (long long)h);
        return ident;
    }

    virtual bool has_error() { return h == INVALID_HANDLE_VALUE; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_WINDOWS
typedef xi_nub_win32_semaphore xi_nub_platform_semaphore;
#endif

#if defined OS_WINDOWS
static xi_nub_win32_semaphore _semaphore_create(const char *name)
{
    HANDLE h = CreateSemaphoreW(NULL, /* initial */0, /* maximal */ 1,
                                utf8_to_utf16(name).c_str());
    return xi_nub_win32_semaphore(h, GetLastError());
}
#endif

#if defined OS_WINDOWS
static xi_nub_win32_semaphore _semaphore_open(const char *name)
{
    HANDLE h = OpenSemaphoreW(SEMAPHORE_MODIFY_STATE, 0,
                              utf8_to_utf16(name).c_str());
    return xi_nub_win32_semaphore(h, GetLastError());
}
#endif

#if defined OS_WINDOWS
static bool _semaphore_close(xi_nub_win32_semaphore *s)
{
    return CloseHandle(s->h);
}
#endif

#if defined OS_WINDOWS
static bool _semaphore_unlink(const char *name)
{
    return true; /* windows reference counts semaphores */
}
#endif

#if defined OS_WINDOWS
static bool _semaphore_wait(xi_nub_win32_semaphore *s, int milliseonds)
{
    /* error cases: WAIT_TIMEOUT, WAIT_FAILED, WAIT_ABANDONED */
    DWORD ret = WaitForSingleObject(s->h, milliseonds);
    return (ret == WAIT_OBJECT_0);
}
#endif

#if defined OS_WINDOWS
static bool _semaphore_signal(xi_nub_win32_semaphore *s)
{
    LONG prev = 0;
    bool ret = ReleaseSemaphore(s->h, 1, &prev);
    return (ret && prev == 0);
}
#endif


/*
 * posix named semaphore
 */

#if defined OS_POSIX
struct xi_nub_unix_semaphore : xi_nub_file
{
    //int fd;
    sem_t *sem;
    int error;
    char ident[32];

    xi_nub_unix_semaphore() = default;
    xi_nub_unix_semaphore(sem_t *sem, int error = errno)
        : sem(sem), error(error) {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "sem(%p)", sem);
        return ident;
    }

    virtual bool has_error() { return sem == SEM_FAILED; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_POSIX
typedef xi_nub_unix_semaphore xi_nub_platform_semaphore;
#endif

#if defined OS_POSIX
static xi_nub_unix_semaphore _semaphore_create(const char *name)
{
    sem_t *sem = sem_open(name, O_CREAT | O_EXCL, 0644, 0);
    return xi_nub_unix_semaphore(sem, errno);
}
#endif

#if defined OS_POSIX
static xi_nub_unix_semaphore _semaphore_open(const char *name)
{
    sem_t *sem = sem_open(name, 0);
    return xi_nub_unix_semaphore(sem, errno);
}
#endif

#if defined OS_POSIX
static bool _semaphore_close(xi_nub_unix_semaphore *s)
{
    int ret = sem_close(s->sem);
    return (ret == 0);
}
#endif

#if defined OS_POSIX
static bool _semaphore_unlink(const char *name)
{
    int ret = sem_unlink(name);
    return (ret == 0);
}
#endif

#if defined OS_POSIX
static bool _semaphore_wait(xi_nub_unix_semaphore *s, int millis)
{
    struct timespec ta, t1, t2 = { millis / 1000, (millis % 1000) * 1000000 };
    clock_gettime(CLOCK_REALTIME, &t1);
    ta.tv_sec = t1.tv_sec+t2.tv_sec + (t1.tv_nsec+t2.tv_nsec) / 1000000000ul;
    ta.tv_nsec = (t1.tv_nsec+t2.tv_nsec) % 1000000000ul;
    int ret = sem_timedwait(s->sem, &ta);
    return !(ret < 0 && errno == ETIMEDOUT);
}
#endif

#if defined OS_POSIX
static bool _semaphore_signal(xi_nub_unix_semaphore *s)
{
    int ret = sem_post(s->sem);
    return (ret == 0);
}
#endif

/*
 * filesystem helpers
 */

#if defined OS_WINDOWS
static bool _directory_exists(const char *path)
{
    DWORD dwAttrib = GetFileAttributesW(utf8_to_utf16(path).c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
           (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
#endif

#if defined OS_WINDOWS
static bool _make_directory(const char *path)
{
    return CreateDirectoryW(utf8_to_utf16(path).c_str(), NULL) != 0;
}
#endif

#if defined OS_POSIX
static bool _directory_exists(const char *path)
{
    struct stat sb;
    int ret = stat(path, &sb);
    return ret == 0 && ((sb.st_mode & S_IFMT) == S_IFDIR);
}
#endif

#if defined OS_POSIX
static bool _make_directory(const char *path)
{
    return mkdir(path, 0777) == 0;
}
#endif

#if defined OS_WINDOWS
static std::string windows_getenv(const char *name)
{
    size_t len;
    std::string s;
    getenv_s(&len, NULL, 0, name);
    s.resize(len);
    getenv_s(&len, s.data(), len, name);
    return s;
}
#endif


/*
 * windows memory mapped files
 */

#if defined OS_WINDOWS
struct xi_nub_mm
{
    HANDLE h;
    HANDLE hmap;
    void *map;
};
#endif

#if defined OS_WINDOWS
static xi_nub_mm _map_file(const char *fname, share_mode smode, int access,
    size_t length)
{
    DWORD omode = 0;
    switch (smode) {
    case file_create_always:     omode = CREATE_ALWAYS;     break;
    case file_create_new:        omode = CREATE_NEW;        break;
    case file_open_existing:     omode = OPEN_EXISTING;     break;
    case file_open_always:       omode = OPEN_ALWAYS;       break;
    case file_truncate_existing: omode = TRUNCATE_EXISTING; break;
    }
    DWORD oaccess = 0;
    if (access & file_read) oaccess |= FILE_GENERIC_READ;
    if (access & file_write) oaccess |= FILE_GENERIC_WRITE;
    if (access & file_append) oaccess |= FILE_APPEND_DATA;
    HANDLE h = CreateFileW(utf8_to_utf16(fname).c_str(), oaccess, 0, NULL,
                           omode, FILE_FLAG_RANDOM_ACCESS, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: CreateFile(\"%s\"): ret=0x%08x\n",
            fname, GetLastError());
        return xi_nub_mm { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, NULL };
    }

    if (length) {
        SetFileValidData(h, length);
        if (!SetEndOfFile(h)) {
            fprintf(stderr, "error: SetEndOfFile(): ret=0x%08x\n", GetLastError());
            CloseHandle(h);
            return xi_nub_mm { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, NULL };
        }
    } else {
        _BY_HANDLE_FILE_INFORMATION file_info;
        GetFileInformationByHandle(h, &file_info);
        length = (size_t)file_info.nFileSizeLow |
            ((size_t)file_info.nFileSizeHigh << 32);
    }

    DWORD mprot = SEC_COMMIT;
    if ((access & file_read_write) == file_read_write) mprot |= PAGE_READWRITE;
    else if (access & file_read ) mprot |= PAGE_READONLY;
    HANDLE hmap = CreateFileMapping(h, NULL, mprot, 0, 0, 0);
    if (hmap == NULL) {
        fprintf(stderr, "error: CreateFileMapping(): ret=0x%08x\n",
            GetLastError());
        CloseHandle(h);
        return xi_nub_mm { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, NULL };
    }

    DWORD maccess = 0;
    if (access & file_read) maccess |= FILE_MAP_WRITE;
    if (access & file_write) maccess |= FILE_MAP_READ;
    HANDLE map = MapViewOfFile(hmap, maccess, 0, 0, 0);
    if (map == NULL) {
        fprintf(stderr, "error: MapViewOfFile(): ret=0x%08x\n",
            GetLastError());
        CloseHandle(hmap);
        CloseHandle(h);
        return xi_nub_mm { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE, NULL };
    }

    return xi_nub_mm { h, hmap, map };
}
#endif


/*
 * posix memory mapped files
 */

#if defined OS_POSIX
struct xi_nub_mm
{
    int fd;
    void *map;
};
#endif

#if defined OS_POSIX
static xi_nub_mm _map_file(const char *fname, share_mode smode, int access,
    size_t length)
{
    int oflags = 0;
    switch (smode) {
    case file_create_always:     oflags = O_CREAT | O_TRUNC; break;
    case file_create_new:        oflags = O_CREAT | O_EXCL;  break;
    case file_open_existing:     oflags = 0;                 break;
    case file_open_always:       oflags = O_CREAT;           break;
    case file_truncate_existing: oflags = O_TRUNC;           break;
    }
    if ((access & file_read_write) == file_read_write) oflags |= O_RDWR;
    else if (access & file_read) oflags |= O_RDONLY;
    else if (access & file_write) oflags |= O_WRONLY;

    int fd = open(fname, oflags, 0644);
    if (fd < 0) {
        fprintf(stderr, "error: open(\"%s\"): %s\n",fname, strerror(errno));
            return xi_nub_mm{ -1, NULL };
    }

    if (length) {
        int ret = ftruncate(fd, length);
        if (ret < 0) {
            fprintf(stderr, "error: ftruncate(): %s\n", strerror(errno));
            close(fd);
            return xi_nub_mm{ -1, NULL };
        }
    } else {
        struct stat s;
        if (fstat(fd, &s) < 0) {
            fprintf(stderr, "error: fstat(): %s\n", strerror(errno));
            close(fd);
            return xi_nub_mm{ -1, NULL };
        }
        length = s.st_size;
    }

    off_t offset = 0;
    void *map = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED, fd, offset);
    if (map == NULL) {
        fprintf(stderr, "error: mmap(): %s\n", strerror(errno));
        close(fd);
            return xi_nub_mm{ -1, NULL };
    }

    return xi_nub_mm{ fd, map };
}
#endif


/*
 * windows file io
 */

#if defined OS_WINDOWS
static xi_nub_win32_file _open_file(const char *fname, share_mode smode, int access)
{
    DWORD omode = 0;
    switch (smode) {
    case file_create_always:     omode = CREATE_ALWAYS;     break;
    case file_create_new:        omode = CREATE_NEW;        break;
    case file_open_existing:     omode = OPEN_EXISTING;     break;
    case file_open_always:       omode = OPEN_ALWAYS;       break;
    case file_truncate_existing: omode = TRUNCATE_EXISTING; break;
    }
    DWORD oaccess = 0;
    if (access & file_read) oaccess |= FILE_GENERIC_READ;
    if (access & file_write) oaccess |= FILE_GENERIC_WRITE;
    if (access & file_append) oaccess |= FILE_APPEND_DATA;
    HANDLE h = CreateFileW(utf8_to_utf16(fname).c_str(), oaccess, 0, NULL,
                       omode, FILE_FLAG_RANDOM_ACCESS, NULL);
    return xi_nub_win32_file(h, GetLastError());
}
#endif

#if defined OS_WINDOWS
static xi_nub_result _read(xi_nub_win32_file *file, void *buf, size_t len)
{
    DWORD nbytes;
    BOOL ret = ReadFile(file->h, buf, (DWORD)len, &nbytes, NULL);
    return xi_nub_result{ os_error_code(GetLastError()), ret ? nbytes : -1 };
}

static xi_nub_result _write(xi_nub_win32_file *file, void *buf, size_t len)
{
    DWORD nbytes;
    BOOL ret = WriteFile(file->h, buf, (DWORD)len, &nbytes, NULL);
    return xi_nub_result{ os_error_code(GetLastError()), ret ? nbytes : -1 };
}

static xi_nub_result _disconnect(xi_nub_win32_file *file)
{
    BOOL ret = DisconnectNamedPipe(file->h);
    return xi_nub_result{ os_error_code(GetLastError()), ret ? 0 : -1 };
}

static xi_nub_result _close(xi_nub_win32_file *file)
{
    BOOL ret = CloseHandle(file->h);
    return xi_nub_result{ os_error_code(GetLastError()), ret ? 0 : -1 };
}
#endif


/*
 * posix file io
 */

#if defined OS_POSIX
static xi_nub_unix_file _open_file(const char *fname, share_mode smode, int access)
{
    int oflags = 0;
    switch (smode) {
    case file_create_always:     oflags = O_CREAT | O_TRUNC; break;
    case file_create_new:        oflags = O_CREAT | O_EXCL;  break;
    case file_open_existing:     oflags = 0;                 break;
    case file_open_always:       oflags = O_CREAT;           break;
    case file_truncate_existing: oflags = O_TRUNC;           break;
    }
    if ((access & file_read_write) == file_read_write) oflags |= O_RDWR;
    else if (access & file_read) oflags |= O_RDONLY;
    else if (access & file_write) oflags |= O_WRONLY;
    if (access & file_append) oflags |= O_APPEND|O_WRONLY;
    int fd = open(fname, oflags, 0644);
    return xi_nub_unix_file(fd, errno);
}
#endif

#if defined OS_POSIX
static xi_nub_result _read(xi_nub_unix_file *file, void *buf, size_t len)
{
    intptr_t ret = read(file->fd, buf, len);
    return xi_nub_result{ os_error_code(errno), ret };
}

static xi_nub_result _write(xi_nub_unix_file *file, void *buf, size_t len)
{
    intptr_t ret = write(file->fd, buf, len);
    return xi_nub_result{ os_error_code(errno), ret };
}

static xi_nub_result _disconnect(xi_nub_unix_file *file)
{
    intptr_t ret = close(file->fd);
    return xi_nub_result{ os_error_code(errno), ret };
}

static xi_nub_result _close(xi_nub_unix_file *file)
{
    intptr_t ret = close(file->fd);
    return xi_nub_result{ os_error_code(errno), ret };
}
#endif


/*
 * file position
 */

#if defined OS_WINDOWS
static xi_nub_result _get_file_offset(xi_nub_win32_file *file)
{
    DWORD ret = SetFilePointer(file->h, 0, 0, FILE_CURRENT);
    return xi_nub_result{ os_error_code(GetLastError()),
        ret != INVALID_SET_FILE_POINTER ? ret : -1 };
}
#endif

#if defined OS_POSIX
static xi_nub_result _get_file_offset(xi_nub_unix_file *file)
{
    off_t ret = lseek(file->fd, 0, SEEK_CUR);
    return xi_nub_result{ os_error_code(errno), ret };
}
#endif


/*
 * process management
 */

#if defined OS_WINDOWS
typedef int32_t xi_pid_t;
static xi_pid_t _get_processs_id()
{
    return (xi_pid_t)GetCurrentProcessId();
}
#endif

#if defined OS_POSIX
typedef int32_t xi_pid_t;
static xi_pid_t _get_processs_id()
{
    return (xi_pid_t)getpid();
}
#endif


/*
 * windows sockets
 */

#if defined OS_WINDOWS
typedef xi_nub_win32_sock xi_nub_platform_sock;
#endif

#if defined OS_WINDOWS
static xi_nub_platform_sock listen_socket_create()
{
    DWORD open_mode = PIPE_ACCESS_DUPLEX;
    DWORD pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
    LPWSTR pipe_name = L"\\\\.\\pipe\\Xi";
    DWORD buf_size = 65536;

    HANDLE h = CreateNamedPipeW(pipe_name, open_mode, pipe_mode,
                                    PIPE_UNLIMITED_INSTANCES,
                                    buf_size, buf_size,
                                    NMPWAIT_USE_DEFAULT_WAIT, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: CreateNamedPipe(): ret=0x%08x\n", GetLastError());
        return xi_nub_platform_sock(INVALID_HANDLE_VALUE, GetLastError());
    }

    return xi_nub_platform_sock(h, GetLastError());
}
#endif

#if defined OS_WINDOWS
static xi_nub_platform_sock listen_socket_accept(xi_nub_platform_sock l)
{
    /*
     * we only connect one socket and then must create a new pipe
     * to accept subsequent connections
     */
    int ret = ConnectNamedPipe(l.h, NULL);
    if (ret || (GetLastError() == ERROR_PIPE_CONNECTED)) {
        return xi_nub_platform_sock(l.h, GetLastError());
    } else {
        return xi_nub_platform_sock(INVALID_HANDLE_VALUE, GetLastError());
    }
}
#endif

#if defined OS_WINDOWS
static xi_nub_platform_sock client_socket_connect()
{
    LPWSTR pipe_name = L"\\\\.\\pipe\\Xi";

    DWORD buf_size = 65536;

    HANDLE h = CreateFileW(pipe_name, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: CreateFile(): ret=0x%08x\n", GetLastError());
        return xi_nub_platform_sock(INVALID_HANDLE_VALUE, GetLastError());
    }

    return xi_nub_platform_sock(h, GetLastError());
}
#endif


/*
 * posix sockets
 */

#if defined OS_POSIX
typedef xi_nub_unix_sock xi_nub_platform_sock;
#endif

#if defined OS_POSIX
static xi_nub_platform_sock listen_socket_create()
{
    const char *pipe_path = "Xi";
    sockaddr_un saddr;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;

    size_t saddr_len = offsetof(sockaddr_un,sun_path) + strlen(pipe_path) + 1;
    strncpy(saddr.sun_path + 1, pipe_path, strlen(pipe_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error: socket(): %s\n", strerror(errno));
        return xi_nub_platform_sock(-1, errno);
    }

    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        fprintf(stderr, "error: setsockopt(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_sock(-1, errno);
    }

    if (bind(fd, (sockaddr*)(&saddr), saddr_len) < 0) {
        fprintf(stderr, "error: bind(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_sock(-1, errno);
    }

    if (listen(fd, 256) < 0) {
        fprintf(stderr, "error: listen(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_sock(-1, errno);
    }

    return xi_nub_platform_sock(fd, 0);
}
#endif

#if defined OS_POSIX
static xi_nub_platform_sock listen_socket_accept(xi_nub_platform_sock l)
{
    struct sockaddr saddr;
    socklen_t saddrlen = sizeof(saddr);

    int fd = accept(l.fd, &saddr, &saddrlen);
    if (fd < 0) {
        fprintf(stderr, "error: accept failed: %s\n", strerror(errno));
        return xi_nub_platform_sock(-1, errno);
    }

    return xi_nub_platform_sock(fd, 0);
}
#endif

#if defined OS_POSIX
static xi_nub_platform_sock client_socket_connect()
{
    const char *pipe_path = "Xi";
    sockaddr_un saddr;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;

    size_t saddr_len = offsetof(sockaddr_un,sun_path) + strlen(pipe_path) + 1;
    strncpy(saddr.sun_path + 1, pipe_path, strlen(pipe_path));

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error: socket(): %s\n", strerror(errno));
        return xi_nub_platform_sock(-1, errno);
    }

    if (connect(fd, (sockaddr*)(&saddr), saddr_len) < 0) {
        fprintf(stderr, "error: bind(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_sock(-1, errno);
    }
    return xi_nub_platform_sock(fd, 0);
}
#endif
