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

#include <threads.h>

using string = std::string;
template <typename T> using vector = std::vector<T>;

struct xi_nub_ctx
{
    string app_name;
    string user_name;
    string home_path;
    string profile_path;
    void *user_data;
};

struct xi_nub_agent
{
    xi_nub_ctx *ctx;
    vector<string> args;
    xi_nub_platform_desc listen_sock;
    vector<xi_nub_ch> ch;
};

struct xi_nub_ch
{
    xi_nub_ctx *ctx;
    xi_nub_agent *agent;
    xi_nub_platform_desc sock;
    void *user_data;
};


/*
 * profile directory
 */

#if defined OS_WINDOWS
const char *profile_template = "%s\\%s";
#elif defined OS_MACOS
const char *profile_template = "%s/Library/Application Support/%s";
#elif defined OS_LINUX || defined OS_FREEBSD
const char *profile_template =  "%s/.config/%s";
#endif

#if defined OS_WINDOWS
static void xi_nub_find_dirs(xi_nub_ctx *ctx)
{
    char profile_path_tmp[MAXPATHLEN];
    ctx->user_name = _windows_getenv("USERNAME");
    ctx->home_path = _windows_getenv("HOMEPATH");
    string appdata =  _windows_getenv("APPDATA");
    snprintf(profile_path_tmp, MAX_PATH, profile_template,
             appdata.c_str(), ctx->app_name.c_str());
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
    snprintf(profile_path_tmp, MAXPATHLEN, profile_template,
             ctx->home_path.c_str(), ctx->app_name.c_str());
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
    size_t alloc_size = (vec.size() + 1) * sizeof(char*);
    for (auto &s : vec) alloc_size += s.size() + 1;
    char **arr = (char **)malloc(alloc_size);
    char *data = (char*)&arr[vec.size() + 1];
    for (size_t i = 0; i < vec.size(); i++) {
        arr[i] = data;
        memcpy(data, vec[i].data(), vec[i].size());
        data[vec[i].size()] = 0;
        data += vec[i].size() + 1;
    }
    arr[vec.size()] = 0;
    return (char**)arr;
}


struct _argument_hash { unsigned char hash[32]; };

static _argument_hash _get_args_hash(vector<string> vec)
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

static string _to_hex(const unsigned char *in, size_t in_len)
{
    size_t o = 0, l = in_len << 1;
    char *buf = (char*)alloca(l + 1);
    for (size_t i = 0, o = 0; i < in_len; i++) {
        o+= snprintf(buf+o, l + 1 - o, "%02" PRIx8, in[i]);
    }
    return string(buf, l);
}

static string _get_nub_addr(xi_nub_ctx *ctx, vector<string> vec)
{
    _argument_hash ah = _get_args_hash(vec);
    return ctx->app_name + string("-") + _to_hex(ah.hash, sizeof(ah.hash));
}


/*
 * nub agent
 */

xi_nub_agent* xi_nub_agent_new(xi_nub_ctx *ctx, int argc, const char **argv)
{
    xi_nub_agent *agent = new xi_nub_agent();
    agent->ctx = ctx;
    agent->args = _get_args(argc, argv);
    _debug_func("agent=%p\n", agent);
    return agent;
}

void xi_nub_agent_destroy(xi_nub_agent *agent)
{
    delete agent;
}


/*
 * nub server
 */

static void xi_nub_wake_all_waiters(xi_nub_ctx *ctx)
{
    char sem_file[MAXPATHLEN];
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
        snprintf(sem_name, sizeof(sem_name), "%s-%u", ctx->app_name.c_str(), pid);
        xi_nub_platform_semaphore sem = _semaphore_open(sem_name);
        if (sem.has_error()) {
            _panic("error: _semaphore_open: error_code=%d\n", sem.error_code());
        }
        _debug_func("semaphore=%s *** signal ***\n", sem_name);
        _semaphore_signal(&sem);
        _semaphore_unlink(sem_name);
        _semaphore_close(&sem);
    }
    _close(&f);

    _delete_file(sem_file);
}

void xi_nub_agent_accept(xi_nub_agent *agent, int nthreads, xi_nub_accept_cb cb)
{
    string pipe_addr = _get_nub_addr(agent->ctx, agent->args);
    agent->listen_sock = _listen_socket_create(pipe_addr.c_str());

    if (agent->listen_sock.has_error()) {
        _panic("error: listen_socket_create failed: error=%d\n",
            agent->listen_sock.error_code());
    }

    _debug_func("listening sock=%s\n", agent->listen_sock.identity());

    xi_nub_wake_all_waiters(agent->ctx);

    for (;;) {
        xi_nub_ch ch{
            agent->ctx, agent, _listen_socket_accept(agent->listen_sock)
        };

        _debug_func("accepted sock=%s\n", ch.sock.identity());

        if (ch.sock.has_error()) {
            cb(&ch, ch.sock.error_code());
        } else {
            cb(&ch, xi_nub_success);
        }
    }
}

/*
 * nub client
 */

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

    _debug("%s: ticket=%u, is_leader=%u, pid=%u, file=%s\n",
            __func__, ticket, is_leader, pid, obj.name);

    return xi_nub_ticket{ticket, pid, is_leader, obj };
}

static void xi_nub_sleep_on_ticket(xi_nub_ctx *ctx, xi_nub_ticket ticket)
{
    char sem_name[16];
    snprintf(sem_name, sizeof(sem_name), "%s-%u", ctx->app_name.c_str(), ticket.pid);
    xi_nub_platform_semaphore sem = _semaphore_create(sem_name);
    if (sem.has_error()) {
        _panic("error: _semaphore_create: error_code=%d\n", sem.error_code());
    }
    _debug_func("semaphore=%s *** created ***\n", sem_name);

    _semaphore_wait(&sem, 15000);

#if defined OS_WINDOWS
    _thread_sleep(100);
#endif

    _debug_func("semaphore=%s *** woke up ***\n", sem_name);
}

void xi_nub_agent_connect(xi_nub_agent *agent, int nthreads, xi_nub_connect_cb cb)
{
    string pipe_addr = _get_nub_addr(agent->ctx, agent->args);

    xi_nub_ch ch{
        agent->ctx, agent, _client_socket_connect(pipe_addr.c_str())
    };

    _debug_func("sock=%s\n", ch.sock.identity());

    /* if we get a socket error, we try to launch a new server */
    if (ch.sock.has_error())
    {
        _close(&ch.sock);

        /* get an atomic launch ticket, first caller is the leader */
        xi_nub_ticket ticket = xi_nub_get_ticket(agent->ctx);

        /* launch a server if we are the leader */
        if (ticket.is_leader) {
            char **argv = _get_argv(agent->args);
            int argc = (int)agent->args.size();
            xi_nub_os_process p = _create_process(argc, (const char**)argv);
            free(argv);
        }

        /* wait for server to wake us up */
        xi_nub_sleep_on_ticket(agent->ctx, ticket);

        /* attempt to reconnect */
        ch.sock = _client_socket_connect(pipe_addr.c_str());
        if (ch.sock.has_error()) {
            cb(&ch, ch.sock.error_code());
        } else {
            cb(&ch, xi_nub_success);
        }
    } else {
        cb(&ch, xi_nub_success);
    }
}


/*
 * nub channel io
 */

void xi_nub_io_read(xi_nub_ch *ch, void *buf, size_t len, xi_nub_read_cb cb)
{
    xi_nub_result result = _read(&ch->sock, buf, len);
    _debug_func("sock=%s, len=%zu: ret=%zd, error=%d\n",
                ch->sock.identity(), len, result.bytes, result.error);
    if (cb) cb(ch, result.error, buf, result.bytes);
}

void xi_nub_io_write(xi_nub_ch *ch, void *buf, size_t len, xi_nub_write_cb cb)
{
    xi_nub_result result = _write(&ch->sock, buf, len);
    _debug_func("sock=%s, len=%zu: ret=%zd, error=%d\n",
                ch->sock.identity(), len, result.bytes, result.error);
    if (cb) cb(ch, result.error, buf, result.bytes);
}

void xi_nub_io_close(xi_nub_ch *ch, xi_nub_close_cb cb)
{
    bool is_server = ch->agent->listen_sock.desc_type() == xi_nub_desc_type_pipe_listen;
    xi_nub_result result = is_server ? _disconnect(&ch->sock) : _close(&ch->sock);
    _debug_func("sock=%s: ret=%zd, error=%d\n",
                ch->sock.identity(), result.bytes, result.error);
    if (cb) cb(ch, result.error);
}

const char* xi_nub_io_get_identity(xi_nub_ch *ch)
{
    return ch->sock.identity();
}


/*
 * nub accessors
 */

static xi_nub_ctx *global_nub_ctx;

void xi_nub_io_set_user_data(xi_nub_ch *ch, void *data) { ch->user_data = data; }
void* xi_nub_io_get_user_data(xi_nub_ch *ch) { return ch->user_data; }
xi_nub_agent* xi_nub_io_get_agent(xi_nub_ch *ch) { return ch->agent; }
xi_nub_ctx* xi_nub_io_get_context(xi_nub_ch *ch) { return ch->ctx; }

void xi_nub_ctx_set_user_data(xi_nub_ctx *ctx, void *data) { ctx->user_data = data; }
void* xi_nub_ctx_get_user_data(xi_nub_ctx *ctx) { return ctx->user_data; }
const char* xi_nub_ctx_get_profile_path(xi_nub_ctx *ctx) { return ctx->profile_path.c_str(); }
xi_nub_ctx* xi_nub_ctx_get_initial_context() { return global_nub_ctx; }


/*
 * nub context
 */

static void xi_nub_init(xi_nub_ctx *ctx, const char *app_name)
{
    /* find user profile directory */
    ctx->app_name = app_name;
    xi_nub_find_dirs(ctx);

    /* create profile directory if it does not exist */
    if (!_directory_exists(ctx->profile_path.c_str())) {
        if(!_make_directory(ctx->profile_path.c_str())) {
            _panic("error: _make_directory failed: %s\n",
                ctx->profile_path.c_str());
        }
    }

#if defined OS_POSIX
    /* install handler to cleanup on exit */
    _install_signal_handler();
#endif
}

xi_nub_ctx* xi_nub_ctx_create(const char *app_name)
{
    xi_nub_ctx *ctx;

    ctx = new xi_nub_ctx();
    xi_nub_init(ctx, app_name);

    if (!global_nub_ctx) {
        global_nub_ctx = ctx;
    }

    return ctx;
}

void xi_nub_ctx_destroy(xi_nub_ctx *ctx)
{
    delete ctx;
}
