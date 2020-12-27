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

void xi_nub_semaphore()
{
    char sem_file[MAXPATHLEN];
    xi_nub_ctx* ctx = xi_nub_ctx_get_root_context();
    const char* profile_path = xi_nub_ctx_get_profile_path(ctx);
    snprintf(sem_file, sizeof(sem_file), "%s%s", profile_path,
        PATH_SEPARATOR "semaphore.bin");

    printf("semaphore file: %s\n", sem_file);

    bool leader = false;
    auto f = _open_file(sem_file, file_create_new, file_append);
    if (f.has_error()) {
        f = _open_file(sem_file, file_open_existing, file_append);
    } else {
        leader = true;
    }
    uint32_t pid = (uint32_t)_get_processs_id();
    _write(&f, &pid, sizeof(pid));
    xi_nub_result off = _get_file_offset(&f);
    uint32_t ticket = (uint32_t)off.bytes >> 2;
    _close(&f);
    printf("leader=%u pid=%u ticket=%u\n", leader, pid, ticket);
}