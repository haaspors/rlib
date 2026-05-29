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

/**
 * @file rlib/net/rhttpserver.h
 * @brief Event-loop-driven HTTP server with pattern-routed request
 * handlers.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/net/proto/rhttp.h>
#include <rlib/ev/revloop.h>

#include <rlib/net/rsocketaddress.h>

/**
 * @defgroup r_http_server HTTP server
 * @ingroup r_net
 *
 * @brief Refcounted HTTP server that runs on an @c REvLoop and
 * dispatches requests to pattern-matched handlers.
 *
 * Register one or more handlers with @ref r_http_server_set_handler
 * (each bound to a path pattern), then @ref r_http_server_listen on a
 * socket address. Each request invokes the matching
 * @ref RHttpRequestHandler, which returns the @ref RHttpResponse to
 * send. Requests can also be injected directly via
 * @ref r_http_server_process_request, bypassing the listener.
 *
 * Built on the @ref r_http_proto wire codec.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted HTTP server. */
typedef struct RHttpServer RHttpServer;
/**
 * @brief Request handler; returns the response to send.
 * @param data   User pointer registered with the handler.
 * @param req    The incoming request.
 * @param addr   Peer address.
 * @param server The server dispatching the request.
 */
typedef RHttpResponse * (*RHttpRequestHandler) (rpointer data,
    RHttpRequest * req, RSocketAddress * addr, RHttpServer * server);
/** @brief Callback invoked when an injected request's response is ready. */
typedef void (*RHttpResponseReady) (rpointer data,
    RHttpResponse * res, RHttpServer * server);
/** @brief Callback invoked once the server has fully stopped. */
typedef void (*RHttpServerStop) (rpointer data, RHttpServer * server);

/** @brief Create an HTTP server bound to event loop @p loop. */
R_API RHttpServer * r_http_server_new (REvLoop * loop);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_http_server_ref    r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_http_server_unref  r_ref_unref

/**
 * @brief Route requests whose path matches @p pattern to @p handler.
 * @param server  Target server.
 * @param pattern Path pattern to match.
 * @param size    Length of @p pattern, or @c -1 for @c strlen.
 * @param handler Handler invoked for matching requests.
 * @param data    User pointer passed to @p handler.
 * @param notify  Destructor for @p data; may be @c NULL.
 */
R_API rboolean r_http_server_set_handler (RHttpServer * server,
  const rchar * pattern, rssize size, RHttpRequestHandler handler,
  rpointer data, RDestroyNotify notify);

/** @brief Start accepting connections on @p addr. */
R_API rboolean r_http_server_listen (RHttpServer * server, RSocketAddress * addr);
/**
 * @brief Stop the server; @p func fires once shutdown completes.
 * @return Number of in-flight requests still draining.
 */
R_API rsize r_http_server_stop (RHttpServer * server, RHttpServerStop func,
    rpointer data, RDestroyNotify notify);

/**
 * @brief Inject a request directly, bypassing the listening socket.
 *
 * Useful for testing or for serving requests received out-of-band;
 * @p ready fires with the produced response.
 */
R_API rboolean r_http_server_process_request (RHttpServer * server,
    RHttpRequest * req, RSocketAddress * addr,
    RHttpResponseReady ready, rpointer data, RDestroyNotify notify);

R_END_DECLS

/** @} */

#endif /* __R_NET_HTTP_SERVER_H__ */

