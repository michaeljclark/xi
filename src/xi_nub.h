/*
 * xi (aka ξ), a search tool for the Unicode Character Database.
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

#pragma once

#include <cstddef>

/*
 * const char* argv[] = { "Xi", "nub-server" };
 *
 * xi_nub_server *server = xi_nub_server_new(argc, argv);
 * xi_nub_accept(server, myaccept_cb);
 *
 * xi_nub_client *client = xi_nub_client_new(argc, argv)
 * xi_nub_connect(client, myconnect_cb)
 *
 * xi_nub_conn_read(conn, err, buf, len, myread_cb)
 * xi_nub_conn_write(conn, err, buf, len, mywrite_cb)
 * xi_nub_conn_close(conn, err, myclose_cb)
 */

#ifdef __cplusplus
extern "C" {
#endif

struct xi_nub_ctx;
struct xi_nub_server;
struct xi_nub_client;
struct xi_nub_conn;

typedef enum
{
	xi_nub_success,
	xi_nub_einval,
	xi_nub_eexist,
	xi_nub_eacces,
	xi_nub_econnrefused,
	xi_nub_eagain,
	xi_nub_enodata,
	xi_nub_enoent,
	xi_nub_eio,
	xi_nub_egeneric = 255
} xi_nub_error;

typedef void(*xi_nub_accept_cb)(xi_nub_conn *conn, xi_nub_error err);
typedef void(*xi_nub_connect_cb)(xi_nub_conn *conn, xi_nub_error err);
typedef void(*xi_nub_read_cb)(xi_nub_conn *conn, xi_nub_error err, void *buf, size_t len);
typedef void(*xi_nub_write_cb)(xi_nub_conn *conn, xi_nub_error err, void *buf, size_t len);
typedef void(*xi_nub_close_cb)(xi_nub_conn *conn, xi_nub_error err);

void xi_nub_init(xi_nub_ctx *ctx);

/* nub server */
xi_nub_server* xi_nub_server_new(xi_nub_ctx *ctx, int argc, const char **argv);
void xi_nub_server_accept(xi_nub_server *server, int nthreads, xi_nub_accept_cb cb);

/* nub client */
xi_nub_client* xi_nub_client_new(xi_nub_ctx *ctx, int argc, const char **argv);
void xi_nub_client_connect(xi_nub_client *client, int nthreads, xi_nub_connect_cb cb);

/* nub connection */
void xi_nub_conn_read(xi_nub_conn *conn, void *buf, size_t len, xi_nub_read_cb cb);
void xi_nub_conn_write(xi_nub_conn *conn, void *buf, size_t len, xi_nub_write_cb cb);
void xi_nub_conn_close(xi_nub_conn *conn, xi_nub_close_cb cb);
void xi_nub_conn_set_user_data(xi_nub_conn *conn, void *data);
void* xi_nub_conn_get_user_data(xi_nub_conn *conn);
xi_nub_client* xi_nub_conn_get_client(xi_nub_conn *conn);
xi_nub_server* xi_nub_conn_get_server(xi_nub_conn *conn);
xi_nub_ctx* xi_nub_conn_get_context(xi_nub_conn *conn);
const char* xi_nub_conn_get_identity(xi_nub_conn *conn);

/* nub context */
xi_nub_ctx* xi_nub_ctx_get_root_context();
const char* xi_nub_ctx_get_profile_path(xi_nub_ctx *ctx);
void xi_nub_ctx_set_user_data(xi_nub_ctx *ctx, void *data);
void* xi_nub_ctx_get_user_data(xi_nub_ctx *ctx);

#ifdef __cplusplus
}
#endif
