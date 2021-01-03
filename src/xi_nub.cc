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

#include "xi_common.h"
#include "sha256.h"

#include <cstdlib>
#include <cinttypes>

#include <vector>
#include <algorithm>

using string = std::string;
template <typename T> using vector = std::vector<T>;

struct xi_nub_ctx
{
    string user_name;
    string home_path;
    string profile_path;
    void *user_data;
};

struct xi_nub_server
{
    xi_nub_ctx *ctx;
    vector<string> args;
};

struct xi_nub_client
{
    xi_nub_ctx *ctx;
    vector<string> args;
};

struct xi_nub_conn
{
    xi_nub_ctx *ctx;
    xi_nub_server *server;
    xi_nub_client *client;
    xi_nub_platform_sock sock;
    void *user_data;
};


/*
 * profile directory
 */

#if defined OS_WINDOWS
const char *profile_template = "%s\\Xi";
#elif defined OS_MACOS
const char *profile_template = "%s/Library/Application Support/Xi";
#elif defined OS_LINUX
const char *profile_template =  "%s/.config/Xi";
#endif

#if defined OS_WINDOWS
static void xi_nub_find_dirs(xi_nub_ctx *ctx)
{
    char profile_path_tmp[MAXPATHLEN];
    ctx->user_name = windows_getenv("USERNAME");
    ctx->home_path = windows_getenv("HOMEPATH");
    string appdata =  windows_getenv("APPDATA");
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
 * convert command-line argument to a vector
 */

static vector<string> _get_args(int argc, const char **argv)
{
    vector<string> args;
    for (size_t i = 0; i < argc; i++) {
        if (i == 0 && strcmp(argv[0], "<self>") == 0) {
            args.push_back(_executable_path());
        } else {
            args.push_back(argv[i]);
        }
    }
    return args;
}

static char** _get_argv(vector<string> vec)
{
    size_t data_size = 0;
    for (auto &s : vec) {
        data_size += s.size() + 1;
    }
    size_t argc = vec.size();
    size_t array_size = (argc + 1) * sizeof(intptr_t);
    char *p = (char*)malloc(array_size + data_size);
    memset(p, 0, array_size + data_size);
    char *data = (char*)p + array_size;
    char **arr = (char **)p;
    for (size_t i = 0; i < argc; i++) {
        arr[i] = data;
        memcpy(data, vec[i].data(), vec[i].size());
        data += vec[i].size() + 1;
    }
    return (char**)p;
}


struct _argument_hash { unsigned char hash[32]; };

_argument_hash _get_args_hash(vector<string> vec)
{
    _argument_hash ah;
    sha256_ctx ctx;

    sha256_init(&ctx);
    for (auto &s : vec) {
        sha256_update(&ctx, s.c_str(), s.size() + 1);
    }
    sha256_final(&ctx, ah.hash);

    return ah;
}

string _to_hex(const unsigned char *in, size_t in_len)
{
    size_t o = 0, l = in_len << 1;
    char *buf = (char*)alloca(l + 1);
    for (size_t i = 0, o = 0; i < in_len; i++) {
        o+= snprintf(buf+o, l + 1 - o, "%02" PRIx8, in[i]);
    }
    return string(buf, l);
}

string _get_arg_addr(vector<string> vec)
{
    _argument_hash ah = _get_args_hash(vec);
    string addr = "Xi-";
    addr.append(_to_hex(ah.hash, sizeof(ah.hash)));
    return addr;
}


/*
 * nub server
 */

xi_nub_server* xi_nub_server_new(xi_nub_ctx *ctx, int argc, const char **argv)
{
    xi_nub_server *s = (xi_nub_server *)calloc(1, sizeof(xi_nub_server));
    s->ctx = xi_nub_ctx_get_root_context();
    s->args = _get_args(argc, argv);
    if (debug) printf("xi_nub_server_new: server=%p\n", s);
    return s;
}

static void xi_nub_wake_all_waiters()
{
    char sem_file[MAXPATHLEN];
    xi_nub_ctx* ctx = xi_nub_ctx_get_root_context();
    const char* profile_path = xi_nub_ctx_get_profile_path(ctx);
    snprintf(sem_file, sizeof(sem_file), "%s%s", profile_path,
        PATH_SEPARATOR "semaphore");

    auto f = _open_file(sem_file, file_open_existing, file_read_write);
    if (f.has_error()) return; /* no lock file */

    char buf[1024];
    xi_nub_result r = _read(&f, buf, sizeof(buf));
    size_t num_waiters = (size_t)(r.bytes >> 2);
    uint32_t *p = (uint32_t*)buf;
    for (size_t i = 0; i < num_waiters; i++) {
        uint32_t pid = *p++;
        char sem_name[16];
        snprintf(sem_name, sizeof(sem_name), "xi-%u", pid);
        xi_nub_platform_semaphore sem = _semaphore_open(sem_name);
        if (sem.has_error()) {
            fprintf(stderr, "error: _semaphore_open: error_code=%d\n",
                    sem.error_code());
            exit(1);
        }
        if (debug) {
            printf("xi_nub_wake_all_waiters: semaphore=%s *** signal ***\n", sem_name);
        }
        _semaphore_signal(&sem);
        _semaphore_unlink(sem_name);
        _semaphore_close(&sem);
    }
    _close(&f);

    _delete_file(sem_file);
}

void xi_nub_server_accept(xi_nub_server *server, int nthreads, xi_nub_accept_cb cb)
{
    string pipe_addr = _get_arg_addr(server->args);
    xi_nub_platform_sock listen = listen_socket_create(pipe_addr.c_str());
    if (debug) {
        printf("xi_nub_server_accept: listening sock=%s\n", listen.identity());
    }

    xi_nub_wake_all_waiters();

    for (;;) {
        xi_nub_conn conn{
            server->ctx, server, NULL, listen_socket_accept(listen)
        };

        if (debug) {
            printf("xi_nub_server_accept: accepted sock=%s\n", conn.sock.identity());
        }

        if (conn.sock.has_error()) {
            cb(&conn, conn.sock.error_code());
        } else {
            cb(&conn, xi_nub_success);
        }

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
    c->args = _get_args(argc, argv);
    if (debug) {
        printf("xi_nub_client_new: client=%p\n", c);
    }
    return c;
}

struct xi_name_object
{
    char name[MAXPATHLEN];
};

struct xi_nub_ticket
{
    uint32_t ticket;
    uint32_t pid;
    bool is_leader;
    xi_name_object obj;
};

static xi_nub_ticket xi_nub_get_ticket(xi_nub_ctx *ctx)
{
    xi_name_object obj;
    const char* profile_path = xi_nub_ctx_get_profile_path(ctx);
    snprintf(obj.name, sizeof(obj.name), "%s%s", profile_path,
        PATH_SEPARATOR "semaphore");

    bool is_leader = false;
    auto f = _open_file(obj.name, file_create_new, file_append);
    if (f.has_error()) {
        f = _open_file(obj.name, file_open_existing, file_append);
    } else {
        is_leader = true;
    }
    uint32_t pid = (uint32_t)_get_processs_id();
    _write(&f, &pid, sizeof(pid));
    xi_nub_result off = _get_file_offset(&f);
    uint32_t ticket = (uint32_t)off.bytes >> 2;
    _close(&f);

    if (debug) {
        printf("%s: ticket=%u, is_leader=%u, pid=%u, file=%s\n",
            __func__, ticket, is_leader, pid, obj.name);
    }

    return xi_nub_ticket{ticket, pid, is_leader, obj };
}

static void xi_nub_sleep_on_ticket(xi_nub_ctx *ctx, xi_nub_ticket ticket)
{
    char sem_name[16];
    snprintf(sem_name, sizeof(sem_name), "xi-%u", ticket.pid);
    xi_nub_platform_semaphore sem = _semaphore_create(sem_name);
    if (sem.has_error()) {
        fprintf(stderr, "error: _semaphore_create: error_code=%d\n", sem.error_code());
        exit(1);
    }
    if (debug) {
        printf("xi_nub_sleep_on_ticket: semaphore=%s *** created ***\n", sem_name);
    }

    _semaphore_wait(&sem, 15000);

#if defined OS_WINDOWS
    /* FIXME - add wait to avoid ERROR_PIPE_CONNECTED */
    _thread_sleep(100);
#endif

    if (debug) {
        printf("xi_nub_sleep_on_ticket: semaphore=%s *** woke up ***\n", sem_name);
    }
}

void xi_nub_client_connect(xi_nub_client *client, int nthreads, xi_nub_connect_cb cb)
{
    string pipe_addr = _get_arg_addr(client->args);

    xi_nub_conn conn{
        client->ctx, NULL, client, client_socket_connect(pipe_addr.c_str())
    };

    if (debug) {
        printf("xi_nub_client_connect: sock=%s\n", conn.sock.identity());
    }

    /* if we get a socket error, we try to launch a new server */
    if (conn.sock.has_error())
    {
        _close(&conn.sock);

        /* get an atomic launch ticket, first caller is the leader */
        xi_nub_ticket ticket = xi_nub_get_ticket(client->ctx);

        /* launch a server if we are the leader */
        if (ticket.is_leader) {
            char **argv = _get_argv(client->args);
            int argc = (int)client->args.size();
            xi_nub_os_process p = _create_process(argc, (const char**)argv);
            free(argv);
        }

        /* wait for server to wake us up */
        xi_nub_sleep_on_ticket(client->ctx, ticket);

        /* attempt to reconnect */
        conn.sock = client_socket_connect(pipe_addr.c_str());
        if (conn.sock.has_error()) {
            cb(&conn, conn.sock.error_code());
        } else {
            cb(&conn, xi_nub_success);
        }
    } else {
        cb(&conn, xi_nub_success);
    }
}


/*
 * nub connection io
 */

void xi_nub_conn_read(xi_nub_conn *conn, void *buf, size_t len, xi_nub_read_cb cb)
{
    xi_nub_result result = _read(&conn->sock, buf, len);
    if (debug) {
        printf("xi_nub_conn_read: sock=%s, len=%zu: ret=%zd, error=%d\n",
            conn->sock.identity(), len, result.bytes, result.error);
    }
    if (cb) cb(conn, result.error, buf, result.bytes);
}

void xi_nub_conn_write(xi_nub_conn *conn, void *buf, size_t len, xi_nub_write_cb cb)
{
    xi_nub_result result = _write(&conn->sock, buf, len);
    if (debug) {
        printf("xi_nub_conn_write: sock=%s, len=%zu: ret=%zd, error=%d\n",
            conn->sock.identity(), len, result.bytes, result.error);
    }
    if (cb) cb(conn, result.error, buf, result.bytes);
}

void xi_nub_conn_close(xi_nub_conn *conn, xi_nub_close_cb cb)
{
    xi_nub_result result = conn->server
        ? _disconnect(&conn->sock) : _close(&conn->sock);
    if (debug) {
        printf("xi_nub_conn_close: sock=%s: ret=%zd, error=%d\n",
            conn->sock.identity(), result.bytes, result.error);
    }
    if (cb) cb(conn, result.error);
}

const char* xi_nub_conn_get_identity(xi_nub_conn *conn)
{
    return conn->sock.identity();
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
    if (!_directory_exists(ctx->profile_path.c_str())) {
        if(!_make_directory(ctx->profile_path.c_str())) {
            fprintf(stderr, "error: _make_directory failed: %s\n",
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
