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

#include <vector>
#include <algorithm>

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
    std::vector<string> args;
};

struct xi_nub_client
{
    xi_nub_ctx *ctx;
    std::vector<string> args;
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
 * convert command-line argument to a vector
 */

static std::vector<string> _get_args(int argc, const char **argv)
{
    std::vector<string> args;
    for (size_t i = 0; i < argc; i++) {
        if (i == 0 && strcmp(argv[0], "<self>") == 0) {
            args.push_back(_executable_path());
        } else {
            args.push_back(argv[i]);
        }
    }
    return args;
}

static char** _get_argv(std::vector<string> vec)
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

void xi_nub_server_accept(xi_nub_server *server, int nthreads, xi_nub_accept_cb cb)
{
    xi_nub_platform_sock listen = listen_socket_create();
    if (debug) {
        printf("xi_nub_server_accept: listening sock=%s\n", listen.identity());
    }

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

void xi_nub_client_connect(xi_nub_client *client, int nthreads, xi_nub_connect_cb cb)
{

    xi_nub_conn conn{
        client->ctx, NULL, client, client_socket_connect()
    };

    if (debug) {
        printf("xi_nub_client_connect: sock=%s\n", conn.sock.identity());
    }

#if 0
    if (sock.has_error()) cb(&conn, sock.error_code());
    else cb(&conn, xi_nub_success);
#else
    /*
     * if we get a socket error, we won't tell client, we are going
     * to attempt to launch a server
     */
    if (conn.sock.has_error())
    {
        _close(&conn.sock);
        /*
         * EXPERIMENTAL - launch atomicity semaphores not implemented
         */
        char **argv = _get_argv(client->args);
        int argc = (int)client->args.size();
        xi_nub_os_process p = _create_process(argc, (const char**)argv);
        free(argv);

        _thread_sleep(100);
        conn.sock = client_socket_connect();
        if (conn.sock.has_error()) {
            cb(&conn, conn.sock.error_code());
        } else {
            cb(&conn, xi_nub_success);
        }
    } else {
        cb(&conn, xi_nub_success);
    }
#endif
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
