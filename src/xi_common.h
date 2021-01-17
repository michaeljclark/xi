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
#include <csignal>
#include <cerrno>

#include <string>
#include <vector>

#ifdef _WIN32
#define OS_WINDOWS
#endif

#ifdef __APPLE__
#define OS_MACOS
#define OS_POSIX
#endif

#ifdef __FreeBSD__
#define OS_FREEBSD
#define OS_POSIX
#endif

#ifdef __linux__
#define OS_LINUX
#define OS_POSIX
#endif

#if defined OS_MACOS
#include <mach-o/dyld.h>
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
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <semaphore.h>
#include <time.h>
#endif

#include "xi_nub.h"

using string = std::string;
using wstring = std::wstring;
template <typename T> using vector = std::vector<T>;

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

enum share_mode
{
    file_create_always,
    file_create_new,
    file_open_existing,
    file_open_always,
    file_truncate_existing
};

enum file_perms
{
    file_read = 0x1,
    file_write = 0x2,
    file_read_write = 0x3,
    file_append = 0x4
};

enum xi_nub_desc_type
{
    xi_nub_desc_type_none,
    xi_nub_desc_type_file,
    xi_nub_desc_type_semaphore,
    xi_nub_desc_type_pipe_listen,
    xi_nub_desc_type_pipe_accepted,
    xi_nub_desc_type_pipe_connected
};

struct xi_nub_result
{
    xi_nub_error error;
    intptr_t bytes;
};

struct xi_nub_desc
{
    virtual const char* identity() = 0;
    virtual bool has_error() = 0;
    virtual int os_error() = 0;
    virtual xi_nub_error error_code() = 0;
    virtual xi_nub_desc_type desc_type() = 0;
    virtual ~xi_nub_desc() = 0;
};

inline xi_nub_desc::~xi_nub_desc() {}


/*
 * platform error mapping
 */

#if defined OS_WINDOWS
static xi_nub_error os_error_code(DWORD error) {
    switch (error) {
    case 0:                        return xi_nub_success;
    case ERROR_INVALID_HANDLE:     return xi_nub_einval;
    case ERROR_ALREADY_EXISTS:     return xi_nub_eexist;
    case ERROR_ACCESS_DENIED:      return xi_nub_eacces;
    case ERROR_FILE_NOT_FOUND:     return xi_nub_enoent;
    case ERROR_CONNECTION_REFUSED: return xi_nub_econnrefused;
    case ERROR_PIPE_BUSY:          return xi_nub_eagain;
    case ERROR_NO_DATA:            return xi_nub_enodata;
    case ERROR_PIPE_NOT_CONNECTED: return xi_nub_eio;
    default:                       return xi_nub_egeneric;
    }
}
#endif

#if defined OS_POSIX
static xi_nub_error os_error_code(int error) {
    switch (error) {
    case 0:                        return xi_nub_success;
    case EBADF:
    case EINVAL:                   return xi_nub_einval;
    case EEXIST:                   return xi_nub_eexist;
    case EACCES:                   return xi_nub_eacces;
    case ENOENT:                   return xi_nub_enoent;
    case ECONNREFUSED:             return xi_nub_econnrefused;
    case EAGAIN:                   return xi_nub_eagain;
    case ENODATA:                  return xi_nub_enodata;
    case EIO:                      return xi_nub_eio;
    default:                       return xi_nub_egeneric;
    }
}
#endif

/*
 * windows file descriptor
 */

#if defined OS_WINDOWS
struct xi_nub_win32_desc : xi_nub_desc
{
    HANDLE h;
    DWORD error;
    xi_nub_desc_type dtype;
    char ident[32];

    xi_nub_win32_desc() : h(INVALID_HANDLE_VALUE), error(0),
        dtype(xi_nub_desc_type_none), ident{0} {}
    xi_nub_win32_desc(HANDLE h, DWORD error = GetLastError(),
                      xi_nub_desc_type dtype = xi_nub_desc_type_none)
        : h(h), error(error), dtype(dtype) {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "handle(%lld)", (long long)h);
        return ident;
    }
    virtual xi_nub_desc_type desc_type() { return dtype; }
    virtual bool has_error() { return h == INVALID_HANDLE_VALUE; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif


/*
 * posix file descriptor
 */

#if defined OS_POSIX
struct xi_nub_unix_desc : xi_nub_desc
{
    int fd;
    int error;
    xi_nub_desc_type dtype;
    char ident[32];

    xi_nub_unix_desc() : fd(0), error(0), dtype(xi_nub_desc_type_none),
        ident{0} {}
    xi_nub_unix_desc(int fd, int error = errno,
                     xi_nub_desc_type dtype = xi_nub_desc_type_none)
        : fd(fd), error(error), dtype(dtype), ident{0} {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "fd(%d)", fd);
        return ident;
    }
    virtual xi_nub_desc_type desc_type() { return dtype; }
    virtual bool has_error() { return fd < 0; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif


/*
 * utf8 <-> utf16 string conversion
 */

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
struct xi_nub_win32_semaphore : xi_nub_desc
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
    virtual xi_nub_desc_type desc_type() { return xi_nub_desc_type_semaphore; }
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

#if defined OS_WINDOWS
static bool _thread_sleep(int millis)
{
    Sleep(millis);
    return true;
}
#endif


/*
 * posix named semaphore
 */

#if defined OS_POSIX
struct xi_nub_unix_semaphore : xi_nub_desc
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
    virtual xi_nub_desc_type desc_type() { return xi_nub_desc_type_semaphore; }
    virtual bool has_error() { return sem == SEM_FAILED; }
    virtual int os_error() { return error; }
    virtual xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_POSIX
typedef xi_nub_unix_semaphore xi_nub_platform_semaphore;
#endif

#if defined OS_POSIX && !defined OS_FREEBSD
static xi_nub_unix_semaphore _semaphore_create(const char *name)
{
    sem_t *sem = sem_open(name, O_CREAT | O_EXCL, 0644, 0);
    return xi_nub_unix_semaphore(sem, errno);
}
#endif

#if defined OS_POSIX && !defined OS_FREEBSD
static xi_nub_unix_semaphore _semaphore_open(const char *name)
{
    sem_t *sem = sem_open(name, 0);
    return xi_nub_unix_semaphore(sem, errno);
}
#endif

#if defined OS_POSIX && defined OS_FREEBSD
static xi_nub_unix_semaphore _semaphore_create(const char *name)
{
    size_t namelen = strlen(name);
    char *sem_name = (char*)alloca(namelen + 2);
    snprintf(sem_name, namelen + 2, "%s%s", name[0] != '/' ? "/" : "", name);
    sem_t *sem = sem_open(sem_name, O_CREAT | O_EXCL, 0644, 0);
    return xi_nub_unix_semaphore(sem, errno);
}
#endif

#if defined OS_POSIX && defined OS_FREEBSD
static xi_nub_unix_semaphore _semaphore_open(const char *name)
{
    size_t namelen = strlen(name);
    char *sem_name = (char*)alloca(namelen + 2);
    snprintf(sem_name, namelen + 2, "%s%s", name[0] != '/' ? "/" : "", name);
    sem_t *sem = sem_open(sem_name, 0);
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

#if defined OS_POSIX && defined OS_MACOS
static bool _semaphore_wait(xi_nub_unix_semaphore *s, int millis)
{
    int ret = sem_wait(s->sem);
    return (ret == 0);
}
#endif

#if defined OS_POSIX && !defined OS_MACOS
static bool _semaphore_wait(xi_nub_unix_semaphore *s, int millis)
{    struct timespec ta, t1, t2 = { millis / 1000, (millis % 1000) * 1000000 };
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

#if defined OS_POSIX
static bool _thread_sleep(int millis)
{
    struct timespec ta = { millis / 1000, (millis % 1000) * 1000000 };
    int ret = nanosleep(&ta, NULL);
    return ret == 0;
}
#endif

/*
 * executable path
 */

#if defined OS_WINDOWS
static string _executable_path()
{
    vector<wchar_t> mname, fname;
    DWORD sz;
    HANDLE h;

    /* GetModuleFileNameW returns size written which is equal to the
     * buffer size in which case we double the size until it fits. */
    mname.resize(MAXPATHLEN);
    sz = GetModuleFileNameW(NULL, mname.data(), (DWORD)mname.size());
    while (sz == mname.size()) {
        mname.resize(mname.size() * 2);
        sz = GetModuleFileNameW(NULL, mname.data(), (DWORD)mname.size());
    }

    /* open executable to resolve the canonical path */
    h = CreateFileW(mname.data(), 0, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return utf16_to_utf8(wstring(mname.data(), mname.size()));
    }

    /* GetFinalPathNameByHandleW returns total size so use resize pattern
     * and the size returned includes the null pointer so we must subtract. */
    sz = GetFinalPathNameByHandleW(h, fname.data(), (DWORD)fname.size(),
                                   VOLUME_NAME_DOS);
    fname.resize(sz);
    sz = GetFinalPathNameByHandleW(h, fname.data(), (DWORD)fname.size(),
                                   VOLUME_NAME_DOS);
    CloseHandle(h);
    /* this should not happen */
    if (sz > fname.size()) {
        return utf16_to_utf8(wstring(mname.data(), mname.size()));
    } else {
        return utf16_to_utf8(wstring(fname.data(), fname.size() - 1));
    }
}
#endif

#if defined OS_MACOS
static string _executable_path()
{
    uint32_t sz;
    string path;

    assert(_NSGetExecutablePath(NULL, &sz) == -1);
    path.resize(sz);
    assert(_NSGetExecutablePath(path.data(), &sz) == 0);

    return path;
}
#endif

#if defined OS_LINUX
static string _executable_path()
{
    char *mname = (char*)alloca(MAXPATHLEN);
    ssize_t ret = readlink("/proc/self/exe", mname, MAXPATHLEN);
    return (ret > 0) ? string(mname, ret) : string();
}
#endif

#if defined OS_FREEBSD
static string _executable_path()
{
    char temp[32];
    snprintf(temp, sizeof(temp),"/proc/%d/file", ::getpid());
    char *mname = (char*)alloca(MAXPATHLEN);
    ssize_t ret = readlink(temp, mname, MAXPATHLEN);
    return (ret > 0) ? string(mname, ret) : string();
}
#endif

/*
 * process creation
 */

#if defined OS_WINDOWS
struct xi_nub_os_process
{
    PROCESS_INFORMATION pi;
    DWORD error;

    bool has_error() { return pi.hProcess == INVALID_HANDLE_VALUE; }
    int os_error() { return error; }
    xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_WINDOWS
static xi_nub_os_process _create_process(int argc, const char **argv)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi { INVALID_HANDLE_VALUE };

    if (argc < 1) return xi_nub_os_process{};

    if (debug) {
        for (size_t i = 0; i < argc; i++) {
            printf("exec[%zu]=\"%s\"\n", i, argv[i]);
        }
    }

    wstring cmd_line;
    for (size_t i = 0; i < argc; i++) {
        string s;
        bool has_space = strchr(argv[i], ' ') != NULL;
        if (has_space) s.append("\"");
        s.append(string(argv[i]));
        if (has_space) s.append("\"");
        if (i > 0) cmd_line.append(1, ' ');
        cmd_line.append(utf8_to_utf16(s));
    }

    CreateProcessW(
        NULL, (LPWSTR)cmd_line.data(), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi
    );

    return xi_nub_os_process{ pi, GetLastError() };
}
#endif

#if defined OS_POSIX
struct xi_nub_os_process
{
    int pid;
    int error;

    bool has_error() { return pid == 0; }
    int os_error() { return error; }
    xi_nub_error error_code() { return os_error_code(error); }
};
#endif

#if defined OS_POSIX
static xi_nub_os_process _create_process(int argc, const char **argv)
{
    if (argc < 1) return xi_nub_os_process{};

    if (debug) {
        for (size_t i = 0; i < argc; i++) {
            printf("exec[%zu]=\"%s\"\n", i, argv[i]);
        }
    }

    int status;
    pid_t pid1 = fork();
    if (pid1) {
        /* top-parent */
    } else {
        int stdin_fd = open("/dev/null", O_RDONLY);
        int stdout_fd =open("/dev/null", O_WRONLY);
        int stderr_fd =open("/dev/null", O_WRONLY);
        dup2(stdin_fd, STDIN_FILENO);
        dup2(stdout_fd, STDOUT_FILENO);
        dup2(stderr_fd, STDERR_FILENO);
        close(stdin_fd);
        close(stdout_fd);
        close(stderr_fd);
        setsid();
        pid_t pid2 = fork();
        if (pid2) {
            /* child-parent */
            exit(0);
        } else {
            /* child-child */
            execvp(argv[0], (char* const*)argv);
        }
     }

    return xi_nub_os_process{ pid1, errno };
}
#endif

/*
 * filesystem helpers
 */

#if defined OS_WINDOWS
static bool _delete_file(const char *fname)
{
    return DeleteFileW(utf8_to_utf16(fname).c_str());
}
#endif

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
static bool _delete_file(const char *fname)
{
    return unlink(fname) == 0;
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
static string _windows_getenv(const char *name)
{
    size_t len;
    string s;
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
static xi_nub_win32_desc _open_file(const char *fname, share_mode smode, int access)
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
                       omode, FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_OVERLAPPED, NULL);
    return xi_nub_win32_desc(h, GetLastError(), xi_nub_desc_type_file);
}
#endif

#if defined OS_WINDOWS
static xi_nub_result _read(xi_nub_win32_desc *file, void *buf, size_t len)
{
    DWORD nbytes;
    OVERLAPPED o{0};
    BOOL ret = ReadFile(file->h, buf, (DWORD)len, &nbytes, &o);
    DWORD error = GetLastError();
    if (ret) {
        return xi_nub_result{ os_error_code(error), nbytes };
    }
    switch (error) {
    case ERROR_IO_PENDING:
        if (GetOverlappedResult(file->h, &o, &nbytes, TRUE)) {
            return xi_nub_result{ xi_nub_success, (int)o.InternalHigh };
        }
        break;
    default:
        break;
    }
    return xi_nub_result{ os_error_code(error), -1 };
}

static xi_nub_result _write(xi_nub_win32_desc *file, void *buf, size_t len)
{
    DWORD nbytes;
    OVERLAPPED o{0};
    BOOL ret = WriteFile(file->h, buf, (DWORD)len, &nbytes, &o);
    DWORD error = GetLastError();
    if (ret) {
        return xi_nub_result{ os_error_code(error), nbytes };
    }
    switch (error) {
    case ERROR_IO_PENDING:
        if (GetOverlappedResult(file->h, &o, &nbytes, TRUE)) {
            return xi_nub_result{ xi_nub_success, (int)o.InternalHigh };
        }
        break;
    default:
        break;
    }
    return xi_nub_result{ os_error_code(error), -1 };
}

static xi_nub_result _disconnect(xi_nub_win32_desc *file)
{
    SetLastError(0);
    BOOL ret = DisconnectNamedPipe(file->h);
    return xi_nub_result{ os_error_code(GetLastError()), ret ? 0 : -1 };
}

static xi_nub_result _close(xi_nub_win32_desc *file)
{
    SetLastError(0);
    BOOL ret = CloseHandle(file->h);
    return xi_nub_result{ os_error_code(GetLastError()), ret ? 0 : -1 };
}
#endif


/*
 * posix file io
 */

#if defined OS_POSIX
static xi_nub_unix_desc _open_file(const char *fname, share_mode smode, int access)
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
    return xi_nub_unix_desc(fd, errno, xi_nub_desc_type_file);
}
#endif

#if defined OS_POSIX
static xi_nub_result _read(xi_nub_unix_desc *file, void *buf, size_t len)
{
    intptr_t ret = read(file->fd, buf, len);
    return xi_nub_result{ os_error_code(ret < 0 ? errno : 0), ret };
}

static xi_nub_result _write(xi_nub_unix_desc *file, void *buf, size_t len)
{
    intptr_t ret = write(file->fd, buf, len);
    return xi_nub_result{ os_error_code(ret < 0 ? errno : 0), ret };
}

static xi_nub_result _disconnect(xi_nub_unix_desc *file)
{
    intptr_t ret = close(file->fd);
    return xi_nub_result{ os_error_code(ret < 0 ? errno : 0), ret };
}

static xi_nub_result _close(xi_nub_unix_desc *file)
{
    intptr_t ret = close(file->fd);
    return xi_nub_result{ os_error_code(ret < 0 ? errno : 0), ret };
}
#endif


/*
 * file position
 */

#if defined OS_WINDOWS
static xi_nub_result _get_file_offset(xi_nub_win32_desc *file)
{
    DWORD ret = SetFilePointer(file->h, 0, 0, FILE_CURRENT);
    return xi_nub_result{ os_error_code(GetLastError()),
        ret != INVALID_SET_FILE_POINTER ? ret : -1 };
}
#endif

#if defined OS_POSIX
static xi_nub_result _get_file_offset(xi_nub_unix_desc *file)
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
typedef xi_nub_win32_desc xi_nub_platform_desc;
#endif

#if defined OS_WINDOWS
static xi_nub_platform_desc _listen_socket_create(const char *pipe_path)
{
    DWORD open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    DWORD pipe_mode = PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE | PIPE_WAIT;
    DWORD buf_size = 65536;

    wstring wpipe_path = L"\\\\.\\pipe\\";
    wpipe_path.append(utf8_to_utf16(pipe_path));

    HANDLE h = CreateNamedPipeW(wpipe_path.c_str(), open_mode, pipe_mode,
                                PIPE_UNLIMITED_INSTANCES, buf_size, buf_size,
                                NMPWAIT_USE_DEFAULT_WAIT, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: CreateNamedPipe(): ret=0x%08x\n", GetLastError());
        return xi_nub_platform_desc(INVALID_HANDLE_VALUE, GetLastError());
    }

    return xi_nub_platform_desc(h, GetLastError(), xi_nub_desc_type_pipe_listen);
}
#endif

#if defined OS_WINDOWS
static xi_nub_platform_desc _listen_socket_accept(xi_nub_platform_desc l)
{
    /*
     * we only connect one socket and then must create a new pipe
     * to accept subsequent connections
     */
retry:
    OVERLAPPED o{0};
    int connected = ConnectNamedPipe(l.h, &o);
    int error = GetLastError();
    if (connected) {
        return xi_nub_platform_desc(l.h, error);
    }
    DWORD nbytes;
    switch (error) {
    case ERROR_IO_PENDING:
        connected = GetOverlappedResult(l.h, &o, &nbytes, TRUE);
        if (connected) {
            return xi_nub_platform_desc(l.h, 0, xi_nub_desc_type_pipe_accepted);
        }
        break;
    case ERROR_NO_DATA:
        /* previous connection closed */
        DisconnectNamedPipe(l.h);
        goto retry;
    case ERROR_PIPE_CONNECTED:
        /* previous connection open */
        return xi_nub_platform_desc(l.h, 0, xi_nub_desc_type_pipe_accepted);
        break;
    default:
        break;
    }
    return xi_nub_platform_desc(INVALID_HANDLE_VALUE, error);
}
#endif

#if defined OS_WINDOWS
static xi_nub_platform_desc _client_socket_connect(const char *pipe_path)
{
    wstring wpipe_path = L"\\\\.\\pipe\\";
    wpipe_path.append(utf8_to_utf16(pipe_path));

    DWORD buf_size = 65536;

    HANDLE h = CreateFileW(wpipe_path.c_str(), GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        return xi_nub_platform_desc(
            INVALID_HANDLE_VALUE, GetLastError(), xi_nub_desc_type_pipe_connected
        );
    }

    return xi_nub_platform_desc(h, GetLastError());
}
#endif


/*
 * posix signal handler for deleting files on exit
 */

#if defined OS_POSIX
static vector<string>& _get_unlink_list()
{
    /* static synchronized constructor technique */
    static vector<string> unlink_list; return unlink_list;
}

static void _exit_hook_delete_files()
{
    for (auto file : _get_unlink_list()) {
        _delete_file(file.c_str());
    }
}

static void _delete_file_on_exit(string file) {
    _get_unlink_list().push_back(file);
}

static void _signal_handler(int signum, siginfo_t *info, void *)
{
    switch (signum) {
        case SIGTERM:
        case SIGINT:
            _exit_hook_delete_files();
            _exit(0);
            break;
        default:
            break;
    }
}

static void _install_signal_handler()
{
    struct sigaction sigaction_handler;
    memset(&sigaction_handler, 0, sizeof(sigaction_handler));
    sigaction_handler.sa_sigaction = _signal_handler;
    sigaction_handler.sa_flags = SA_SIGINFO;
    sigaction(SIGTERM, &sigaction_handler, nullptr);
    sigaction(SIGINT, &sigaction_handler, nullptr);
    sigaction(SIGHUP, &sigaction_handler, nullptr);
}
#endif


/*
 * posix sockets
 */

#if defined OS_POSIX
typedef xi_nub_unix_desc xi_nub_platform_desc;
#endif

#if defined OS_MACOS || defined OS_FREEBSD
static size_t _unix_pipe_address(sockaddr_un *saddr, const char *path)
{
    xi_nub_ctx *ctx = xi_nub_ctx_get_initial_context();
    const char *profile = xi_nub_ctx_get_profile_path(ctx);

    memset(saddr, 0, sizeof(*saddr));
    saddr->sun_family = AF_UNIX;

#if defined OS_MACOS
    return snprintf(saddr->sun_path, sizeof(saddr->sun_path),
                    "%s/%s", profile, path);
#else
    snprintf(saddr->sun_path, sizeof(saddr->sun_path),
                    "%s/%s", profile, path);
    return offsetof(sockaddr_un,sun_path) + strlen(saddr->sun_path) + 1;
#endif
}
#elif defined OS_POSIX
static size_t _unix_pipe_address(sockaddr_un *saddr, const char *pipe_path)
{
    memset(saddr, 0, sizeof(*saddr));
    saddr->sun_family = AF_UNIX;
    memcpy(saddr->sun_path + 1, pipe_path, strlen(pipe_path) + 1);

    return offsetof(sockaddr_un,sun_path) + strlen(pipe_path) + 1;
}
#endif

#if defined OS_POSIX
static xi_nub_platform_desc _listen_socket_create(const char *pipe_path)
{
    sockaddr_un saddr;

    size_t saddr_len = _unix_pipe_address(&saddr, pipe_path);

#if defined OS_MACOS || defined OS_FREEBSD
    _delete_file_on_exit(saddr.sun_path);
#endif

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "error: socket(): %s\n", strerror(errno));
        return xi_nub_platform_desc(-1, errno);
    }

    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        fprintf(stderr, "error: setsockopt(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_desc(-1, errno);
    }

    if (bind(fd, (sockaddr*)(&saddr), saddr_len) < 0) {
        fprintf(stderr, "error: bind(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_desc(-1, errno);
    }

    if (listen(fd, 256) < 0) {
        fprintf(stderr, "error: listen(): %s\n", strerror(errno));
        close(fd);
        return xi_nub_platform_desc(-1, errno);
    }

    return xi_nub_platform_desc(fd, 0, xi_nub_desc_type_pipe_listen);
}
#endif

#if defined OS_POSIX
static xi_nub_platform_desc _listen_socket_accept(xi_nub_platform_desc l)
{
    struct sockaddr saddr;
    socklen_t saddrlen = sizeof(saddr);

    int fd = accept(l.fd, &saddr, &saddrlen);
    if (fd < 0) {
        fprintf(stderr, "error: accept failed: %s\n", strerror(errno));
        return xi_nub_platform_desc(-1, errno);
    }

    return xi_nub_platform_desc(fd, 0, xi_nub_desc_type_pipe_accepted);
}
#endif

#if defined OS_POSIX
static xi_nub_platform_desc _client_socket_connect(const char *pipe_path)
{
    sockaddr_un saddr;

    size_t saddr_len = _unix_pipe_address(&saddr, pipe_path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return xi_nub_platform_desc(-1, errno);
    }

    if (connect(fd, (sockaddr*)(&saddr), saddr_len) < 0) {
        close(fd);
        return xi_nub_platform_desc(-1, errno);
    }
    return xi_nub_platform_desc(fd, 0, xi_nub_desc_type_pipe_connected);
}
#endif

