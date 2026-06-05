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
#ifndef __R_NET_HTTP_CLIENT_H__
#define __R_NET_HTTP_CLIENT_H__

#if !defined(__RLIB_H_INCLUDE_GUARD__) && !defined(RLIB_COMPILATION)
#error "#include <rlib.h> only please."
#endif

/**
 * @file rlib/net/rhttpclient.h
 * @brief Event-loop-driven HTTP client: connect, send a request and
 * deliver the parsed response.
 */

#include <rlib/rtypes.h>
#include <rlib/rref.h>

#include <rlib/net/proto/rhttp.h>
#include <rlib/ev/revloop.h>

#include <rlib/net/rsocketaddress.h>

/**
 * @defgroup r_http_client HTTP client
 * @ingroup r_net
 *
 * @brief Refcounted HTTP client that runs on an @c REvLoop: it connects
 * to a peer, sends an @ref RHttpRequest and delivers the parsed
 * @ref RHttpResponse.
 *
 * @ref r_http_client_send is asynchronous: the result arrives via a
 * callback on the loop thread. For blocking use without managing a loop,
 * see @ref RHttpClientSync, which owns a private loop and an @ref RHttpClient.
 *
 * Scope is plaintext HTTP/1.1 to an explicit @ref RSocketAddress, with
 * response bodies framed by @c Content-Length or by connection close.
 * Built on the @ref r_http_proto wire codec and @ref r_evtcp.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted HTTP client. */
typedef struct RHttpClient RHttpClient;

/** @brief Outcome of an HTTP request attempt. */
typedef enum {
  R_HTTP_CLIENT_OK = 0,         /**< Response received and parsed. */
  R_HTTP_CLIENT_CONNECT_FAILED, /**< Could not connect to the peer. */
  R_HTTP_CLIENT_SEND_FAILED,    /**< Could not send the request. */
  R_HTTP_CLIENT_RECV_FAILED,    /**< Transport error, or closed before the body completed. */
  R_HTTP_CLIENT_PARSE_FAILED,   /**< Malformed response, or unsupported framing (chunked / tunnel). */
} RHttpClientResult;

/**
 * @brief Deliver the outcome of @ref r_http_client_send.
 * @param data   User pointer passed to @ref r_http_client_send.
 * @param res    The parsed response, non-@c NULL only when @p result is
 *               @ref R_HTTP_CLIENT_OK. Borrowed; @ref r_http_response_ref to keep it.
 * @param result The request outcome.
 * @param client The client that issued the request.
 */
typedef void (*RHttpClientResponseFunc) (rpointer data,
    RHttpResponse * res, RHttpClientResult result, RHttpClient * client);

/** @brief Create an HTTP client on event loop @p loop (@c NULL for the default loop). */
R_API RHttpClient * r_http_client_new (REvLoop * loop);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_http_client_ref   r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_http_client_unref r_ref_unref

/**
 * @brief Asynchronously send @p req to @p addr and deliver the response.
 * @param client The client.
 * @param req    The request to send.
 * @param addr   Peer address to connect to.
 * @param cb     Invoked with the outcome on the loop thread.
 * @param data   User pointer passed to @p cb.
 * @param notify Destroy notify for @p data.
 * @return @c TRUE if the request was started, in which case @p cb delivers the
 *         outcome and @p notify is called once the request finishes. On
 *         @c FALSE the request could not be started and the caller retains
 *         ownership of @p data (@p notify is not called).
 */
R_API rboolean r_http_client_send (RHttpClient * client, RHttpRequest * req,
    const RSocketAddress * addr,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify);


/**
 * @brief Opaque, refcounted blocking HTTP client.
 *
 * A self-contained synchronous client: it owns a private @ref REvLoop and an
 * @ref RHttpClient, and @ref r_http_client_sync_request runs that loop until
 * the response is in. Callers never deal with an event loop. For overlapping
 * or non-blocking requests, use @ref RHttpClient directly on your own loop.
 */
typedef struct RHttpClientSync RHttpClientSync;

/** @brief Create a blocking HTTP client (owns a private event loop). */
R_API RHttpClientSync * r_http_client_sync_new (void);
/** @brief Take a reference (alias for @ref r_ref_ref). */
#define r_http_client_sync_ref   r_ref_ref
/** @brief Drop a reference (alias for @ref r_ref_unref). */
#define r_http_client_sync_unref r_ref_unref

/**
 * @brief Send @p req to @p addr and block until the response arrives.
 * @param client The blocking client.
 * @param req    The request to send.
 * @param addr   Peer address to connect to.
 * @param result If non-@c NULL, receives the request outcome.
 * @return The response (caller @ref r_http_response_unref's it) on success,
 *         or @c NULL on failure.
 */
R_API RHttpResponse * r_http_client_sync_request (RHttpClientSync * client,
    RHttpRequest * req, const RSocketAddress * addr, RHttpClientResult * result);

R_END_DECLS

/** @} */

#endif /* __R_NET_HTTP_CLIENT_H__ */
