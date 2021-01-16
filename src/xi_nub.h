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
 * OR IN chECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

struct xi_nub_ctx;
struct xi_nub_agent;
struct xi_nub_ch;

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

typedef void(*xi_nub_accept_cb)(xi_nub_ch *ch, xi_nub_error err);
typedef void(*xi_nub_connect_cb)(xi_nub_ch *ch, xi_nub_error err);
typedef void(*xi_nub_read_cb)(xi_nub_ch *ch, xi_nub_error err, void *buf, size_t len);
typedef void(*xi_nub_write_cb)(xi_nub_ch *ch, xi_nub_error err, void *buf, size_t len);
typedef void(*xi_nub_close_cb)(xi_nub_ch *ch, xi_nub_error err);

/* nub context */
xi_nub_ctx* xi_nub_ctx_create(const char *app_name);
void xi_nub_ctx_destroy(xi_nub_ctx *ctx);
void xi_nub_ctx_set_user_data(xi_nub_ctx *ctx, void *data);
void* xi_nub_ctx_get_user_data(xi_nub_ctx *ctx);

/* nub agent */
xi_nub_agent* xi_nub_agent_new(xi_nub_ctx *ctx, int argc, const char **argv);
void xi_nub_agent_accept(xi_nub_agent *agent, int nthreads, xi_nub_accept_cb cb);
void xi_nub_agent_connect(xi_nub_agent *agent, int nthreads, xi_nub_connect_cb cb);
void xi_nub_agent_destroy(xi_nub_agent *agent);

/* nub channel */
void xi_nub_io_read(xi_nub_ch *ch, void *buf, size_t len, xi_nub_read_cb cb);
void xi_nub_io_write(xi_nub_ch *ch, void *buf, size_t len, xi_nub_write_cb cb);
void xi_nub_io_close(xi_nub_ch *ch, xi_nub_close_cb cb);
void xi_nub_io_set_user_data(xi_nub_ch *ch, void *data);
void* xi_nub_io_get_user_data(xi_nub_ch *ch);
xi_nub_agent* xi_nub_io_get_agent(xi_nub_ch *ch);
xi_nub_ctx* xi_nub_io_get_context(xi_nub_ch *ch);
const char* xi_nub_io_get_identity(xi_nub_ch *ch);

/* nub profile */
xi_nub_ctx* xi_nub_ctx_get_initial_context();
const char* xi_nub_ctx_get_profile_path(xi_nub_ctx *ctx);

#ifdef __cplusplus
}
#endif
