/* RLIB - Convenience library for useful things
 * Copyright (C) 2017 Haakon Sporsheim <haakon.sporsheim@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 * See the COPYING file at the root of the source repository.
 */
#ifndef __R_NET_HTTP_SERVER_H__
#define __R_NET_HTTP_SERVER_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only pelase."
#endif

#include <rlib/rtypes.h>

#include <rlib/net/proto/rhttp.h>
#include <rlib/ev/revloop.h>

#include <rlib/rref.h>
#include <rlib/rsocketaddress.h>

R_BEGIN_DECLS

typedef struct _RHttpServer RHttpServer;
typedef RHttpResponse * (*RHttpRequestHandler) (rpointer data,
    RHttpRequest * req, RHttpServer * server);
typedef void (*RHttpResponseReady) (rpointer data,
    RHttpResponse * res, RHttpServer * server);
typedef void (*RHttpServerStop) (rpointer data, RHttpServer * server);

R_API RHttpServer * r_http_server_new (REvLoop * loop);
#define r_http_server_ref    r_ref_ref
#define r_http_server_unref  r_ref_unref

R_API rboolean r_http_server_set_handler (RHttpServer * server,
  const rchar * pattern, rssize size, RHttpRequestHandler handler,
  rpointer data, RDestroyNotify notify);

R_API rboolean r_http_server_listen (RHttpServer * server, RSocketAddress * addr);
R_API rsize r_http_server_stop (RHttpServer * server, RHttpServerStop func,
    rpointer data, RDestroyNotify notify);

/* May be used to inject requests into the server without using the listening API. */
R_API rboolean r_http_server_process_request (RHttpServer * server, RHttpRequest * req,
    RHttpResponseReady ready, rpointer data, RDestroyNotify notify);

R_END_DECLS

#endif /* __R_NET_HTTP_SERVER_H__ */

