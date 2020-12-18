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
#include <cstdlib>
#include <cstring>
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
#endif

#include "xi_nub.h"

#if !defined MAXPATHLEN && defined MAX_PATH
#define MAXPATHLEN MAX_PATH
#endif


/*
 * nub globals
 */

static bool debug = false;

#if defined OS_WINDOWS
const char *profile_template = "%s\\Xi";
#elif defined OS_MACOS
const char *profile_template = "%s/Library/Application Support/Xi";
#elif defined OS_LINUX
const char *profile_template =  "%s/.config/Xi";
#endif


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

xi_nub_file::~xi_nub_file() {}

typedef xi_nub_file xi_nub_sock;

struct xi_nub_ctx
{
    std::string user_name;
    std::string home_path;
    std::string profile_path;
    void *user_data;
};

struct xi_nub_server
{
    xi_nub_ctx *ctx;
};

struct xi_nub_client
{
    xi_nub_ctx *ctx;
};

struct xi_nub_conn
{
    xi_nub_ctx *ctx;
    xi_nub_server *server;
    xi_nub_client *client;
    xi_nub_sock *sock;
    void *user_data;
};


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

    xi_nub_unix_file(int fd, int error = errno)
        : fd(fd), error(error) {}

    virtual const char* identity() {
        snprintf(ident, sizeof(ident), "fd(%d)", fd);
        return ident;
    }

    virtual bool has_error() { return fd < 0;}
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
 * filesystem helpers
 */

#if defined OS_WINDOWS
static bool directory_exists(const char *path)
{
    DWORD dwAttrib = GetFileAttributesW(utf8_to_utf16(path).c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
           (dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}
#endif

#if defined OS_WINDOWS
static bool make_directory(const char *path)
{
    return CreateDirectoryW(utf8_to_utf16(path).c_str(), NULL) != 0;
}
#endif

#if defined OS_POSIX
static bool directory_exists(const char *path)
{
    struct stat sb;
    int ret = stat(path, &sb);
    return ret == 0 && ((sb.st_mode & S_IFMT) == S_IFDIR);
}
#endif

#if defined OS_POSIX
static bool make_directory(const char *path)
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
 * profile directory
 */

#if defined OS_WINDOWS
static void xi_nub_find_dirs(xi_nub_ctx *ctx)
{
    char profile_path_tmp[MAXPATHLEN];
    ctx->user_name = windows_getenv("USERNAME");
    ctx->home_path = windows_getenv("HOMEPATH");
    std::string appdata =  windows_getenv("APPDATA");
    snprintf(profile_path_tmp, MAX_PATH, profile_template, appdata.c_str());
    ctx->profile_path = profile_path_tmp;
}
#endif

#if defined OS_POSIX
static void xi_nub_find_dirs(xi_nub_ctx *ctx)
{
    char profile_path_tmp[MAXPATHLEN];
    struct passwd *p = getpwuid(getuid());
    ctx->user_name = p->pw_name;
    ctx->home_path = p->pw_dir;
    snprintf(profile_path_tmp, MAXPATHLEN, profile_template, ctx->home_path.c_str());
    ctx->profile_path = profile_path_tmp;
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
static bool _map_file(xi_nub_mm *mm, const char *fname,
    share_mode smode, size_t length)
{
    DWORD omode = 0;
    switch (smode) {
    case file_create_always:     omode = CREATE_ALWAYS;     break;
    case file_create_new:        omode = CREATE_NEW;        break;
    case file_open_existing:     omode = OPEN_EXISTING;     break;
    case file_open_always:       omode = OPEN_ALWAYS;       break;
    case file_truncate_existing: omode = TRUNCATE_EXISTING; break;
    }
    mm->h = CreateFile(fname, GENERIC_READ | GENERIC_WRITE, 0, NULL, omode,
                       FILE_FLAG_RANDOM_ACCESS, NULL);
    if (mm->h == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: CreateFile(\"%s\"): ret=0x%08x\n",
            fname, GetLastError());
        return false;
    }

    /* truncate file */
    if (length) {
        SetFileValidData(mm->h, length);
        if (!SetEndOfFile(mm->h)) {
            fprintf(stderr, "error: SetEndOfFile(): ret=0x%08x\n",
                GetLastError());
            CloseHandle(mm->h);
            return false;
        }
    } else {
        _BY_HANDLE_FILE_INFORMATION file_info;
        GetFileInformationByHandle(mm->h, &file_info);
        length = (size_t)file_info.nFileSizeLow |
            ((size_t)file_info.nFileSizeHigh << 32);
    }

    /* memory map file */
    mm->hmap = CreateFileMapping(mm->h, NULL, PAGE_READWRITE |SEC_RESERVE,
                                 0, 0, 0);
    if (mm->hmap == NULL)
    {
        fprintf(stderr, "error: CreateFileMapping(): ret=0x%08x\n",
            GetLastError());
        CloseHandle(mm->h);
        return false;
    }

    mm->map = MapViewOfFile(mm->hmap, FILE_MAP_WRITE | FILE_MAP_READ,
                            0, 0, 0);
    if(mm->map == NULL)
    {
        fprintf(stderr, "error: MapViewOfFile(): ret=0x%08x\n",
            GetLastError());
        CloseHandle(mm->hmap);
        CloseHandle(mm->h);
        return false;
    }

    return true;
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
static bool _map_file(xi_nub_mm *mm, const char *fname,
    share_mode smode, size_t length)
{
    int oflags = 0;
    switch (smode) {
    case file_create_always:     oflags = O_CREAT | O_TRUNC; break;
    case file_create_new:        oflags = O_CREAT | O_EXCL;  break;
    case file_open_existing:     oflags = 0;                 break;
    case file_open_always:       oflags = O_CREAT;           break;
    case file_truncate_existing: oflags = O_TRUNC;           break;
    }
    mm->fd = open(fname, O_RDWR | oflags, 0644);
    if (mm->fd < 0) {
        fprintf(stderr, "error: open(\"%s\"): %s\n",fname, strerror(errno));
        return false;
    }

    /* truncate file */
    if (length) {
        int ret = ftruncate(mm->fd, length);
        if (ret < 0) {
            fprintf(stderr, "error: ftruncate(): %s\n", strerror(errno));
            close(mm->fd);
            return false;
        }
    } else {
        struct stat s;
        if (fstat(mm->fd, &s) < 0) {
            fprintf(stderr, "error: fstat(): %s\n", strerror(errno));
            close(mm->fd);
            return false;
        }
        length = s.st_size;
    }

    /* memory map file */
    off_t offset = 0;
    mm->map = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_SHARED,
                      mm->fd, offset);
    if (mm->map == NULL) {
        fprintf(stderr, "error: mmap(): %s\n", strerror(errno));
        close(mm->fd);
        return false;
    }

    return true;
}
#endif


/*
 * windows file io
 */

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


/*
 * nub server
 */

xi_nub_server* xi_nub_server_new(xi_nub_ctx *ctx, int argc, const char **argv)
{
    xi_nub_server *s = (xi_nub_server *)calloc(1, sizeof(xi_nub_server));
    s->ctx = xi_nub_ctx_get_root_context();
    if (debug) printf("xi_nub_server_new: server=%p\n", s);
    return s;
}

void xi_nub_server_accept(xi_nub_server *server, int nthreads, xi_nub_accept_cb cb)
{
    xi_nub_platform_sock listen = listen_socket_create();
    if (debug) {
        printf("xi_nub_server_accept: listening sock=%s\n", listen.identity());
    }

    for (;;) {
        xi_nub_platform_sock sock = listen_socket_accept(listen);
        if (debug) {
            printf("xi_nub_server_accept: accepted sock=%s\n", sock.identity());
        }

        xi_nub_conn conn;
        conn.ctx = server->ctx;
        conn.server = server;
        conn.sock = new xi_nub_platform_sock(sock);

        if (sock.has_error()) cb(&conn, sock.error_code());
        else cb(&conn, xi_nub_success);

        /* TODO - implement server shutdown */
    }
}


/*
 * nub client
 */

xi_nub_client* xi_nub_client_new(xi_nub_ctx *ctx, int argc, const char **argv)
{
    xi_nub_client *c = (xi_nub_client *)calloc(1, sizeof(xi_nub_client));
    c->ctx = xi_nub_ctx_get_root_context();
    if (debug) {
        printf("xi_nub_client_new: client=%p\n", c);
    }
    return c;
}

void xi_nub_client_connect(xi_nub_client *client, int nthreads, xi_nub_connect_cb cb)
{
    xi_nub_platform_sock sock = client_socket_connect();
    if (debug) {
        printf("xi_nub_client_connect: sock=%s\n", sock.identity());
    }

    xi_nub_conn conn;
    conn.ctx = client->ctx;
    conn.client = client;
    conn.sock = new xi_nub_platform_sock(sock);

    if (sock.has_error()) cb(&conn, sock.error_code());
    else cb(&conn, xi_nub_success);
}


/*
 * nub connection io
 */

void xi_nub_conn_read(xi_nub_conn *conn, void *buf, size_t len, xi_nub_read_cb cb)
{
    auto file = reinterpret_cast<xi_nub_platform_sock*>(conn->sock);
    xi_nub_result result = _read(file, buf, len);
    if (debug) {
        printf("xi_nub_conn_read: sock=%s, len=%zu: ret=%zd, error=%d\n",
            conn->sock->identity(), len, result.bytes, result.error);
    }
    if (cb) cb(conn, result.error, buf, result.bytes);
}

void xi_nub_conn_write(xi_nub_conn *conn, void *buf, size_t len, xi_nub_write_cb cb)
{
    auto file = reinterpret_cast<xi_nub_platform_sock*>(conn->sock);
    xi_nub_result result = _write(file, buf, len);
    if (debug) {
        printf("xi_nub_conn_write: sock=%s, len=%zu: ret=%zd, error=%d\n",
            conn->sock->identity(), len, result.bytes, result.error);
    }
    if (cb) cb(conn, result.error, buf, result.bytes);
}

void xi_nub_conn_close(xi_nub_conn *conn, xi_nub_close_cb cb)
{
    auto file = reinterpret_cast<xi_nub_platform_sock*>(conn->sock);
    xi_nub_result result = conn->server ? _disconnect(file) : _close(file);
    if (debug) {
        printf("xi_nub_conn_close: sock=%s: ret=%zd, error=%d\n",
            conn->sock->identity(), result.bytes, result.error);
    }
    if (cb) cb(conn, result.error);
}

const char* xi_nub_conn_get_identity(xi_nub_conn *conn)
{
    return conn->sock->identity();
}


/*
 * nub accessors
 */

void xi_nub_conn_set_user_data(xi_nub_conn *conn, void *data) { conn->user_data = data; }
void* xi_nub_conn_get_user_data(xi_nub_conn *conn) { return conn->user_data; }
xi_nub_client* xi_nub_conn_get_client(xi_nub_conn *conn) { return conn->client; }
xi_nub_server* xi_nub_conn_get_server(xi_nub_conn *conn) { return conn->server; }
xi_nub_ctx* xi_nub_conn_get_context(xi_nub_conn *conn) { return conn->ctx; }

void xi_nub_ctx_set_user_data(xi_nub_ctx *ctx, void *data) { ctx->user_data = data; }
void* xi_nub_ctx_get_user_data(xi_nub_ctx *ctx) { return ctx->user_data; }
const char* xi_nub_ctx_get_profile_path(xi_nub_ctx *ctx) { return ctx->profile_path.c_str(); }


/*
 * nub context
 */

void xi_nub_init(xi_nub_ctx *ctx)
{
    /* find user profile directory */
    xi_nub_find_dirs(ctx);

    /* create profile directory if it does not exist */
    if (!directory_exists(ctx->profile_path.c_str())) {
        if(!make_directory(ctx->profile_path.c_str())) {
            fprintf(stderr, "error: make_directory failed: %s\n",
                ctx->profile_path.c_str());
        }
    }
}

xi_nub_ctx* xi_nub_ctx_get_root_context()
{
    static xi_nub_ctx ctx;

    /* TODO - this needs to be atomic */
    if (ctx.profile_path.size() == 0) {
        xi_nub_init(&ctx);
    }

    return &ctx;
}
