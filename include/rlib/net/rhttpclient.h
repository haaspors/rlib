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
 * @ref r_http_client_request_to_addr is asynchronous: the result arrives via a
 * callback on the loop thread. For blocking use without managing a loop,
 * see @ref RHttpClientSync, which owns a private loop and an @ref RHttpClient.
 *
 * Scope is HTTP/1.1 over plaintext (@c http) or TLS (@c https), either to an
 * explicit @ref RSocketAddress or to the host/port derived from the request URI
 * (@ref r_http_client_request), with response bodies framed by @c Content-Length,
 * chunked transfer-encoding or connection close. Persistent connections are
 * reused via a small per-client pool (@ref r_http_client_set_keepalive). Built
 * on the @ref r_http_proto wire codec and @ref r_evtcp.
 *
 * @warning HTTPS is not yet authenticated: the server certificate is accepted
 * unconditionally (rlib has no certificate trust store or hostname matching),
 * so the connection is encrypted but open to an active man-in-the-middle. Do
 * not use it to carry secrets over an untrusted network.
 *
 * @{
 */

R_BEGIN_DECLS

/** @brief Opaque, refcounted HTTP client. */
typedef struct RHttpClient RHttpClient;

/** @brief Outcome of an HTTP request attempt. */
typedef enum {
  R_HTTP_CLIENT_OK = 0,         /**< Response received and parsed. */
  R_HTTP_CLIENT_RESOLVE_FAILED, /**< Could not resolve the request URI's host. */
  R_HTTP_CLIENT_CONNECT_FAILED, /**< Could not connect to the peer. */
  R_HTTP_CLIENT_SEND_FAILED,    /**< Could not send the request. */
  R_HTTP_CLIENT_RECV_FAILED,    /**< Transport error, or closed before the body completed. */
  R_HTTP_CLIENT_PARSE_FAILED,   /**< Malformed response, or unsupported framing (chunked / tunnel). */
  R_HTTP_CLIENT_TLS_FAILED,     /**< TLS handshake failed or the session was aborted by an alert. */
} RHttpClientResult;

/**
 * @brief Deliver the outcome of @ref r_http_client_request_to_addr.
 * @param data   User pointer passed to @ref r_http_client_request_to_addr.
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
 * @brief Enable or disable HTTP/1.1 keep-alive connection reuse (default on).
 *
 * When enabled, a connection left open by a self-delimited, persistent response
 * is parked in a per-client pool and reused by the next request to the same
 * destination. A caller can still force a single request to close by setting a
 * @c Connection: close header on it.
 */
R_API void r_http_client_set_keepalive (RHttpClient * client, rboolean enabled);
/** @brief Whether keep-alive connection reuse is enabled (see @ref r_http_client_set_keepalive). */
R_API rboolean r_http_client_get_keepalive (RHttpClient * client);
/**
 * @brief Set how long an idle pooled connection is kept before eviction.
 * @param client  The client.
 * @param timeout Idle lifetime (e.g. @c 30 * @c R_SECOND); @c 0 disables the
 *                timer so connections live until the peer closes them or the
 *                client is destroyed. Default is 60 seconds.
 */
R_API void r_http_client_set_idle_timeout (RHttpClient * client, RClockTimeDiff timeout);
/** @brief The idle-connection timeout (see @ref r_http_client_set_idle_timeout). */
R_API RClockTimeDiff r_http_client_get_idle_timeout (RHttpClient * client);

/**
 * @brief Asynchronously send @p req to @p addr and deliver the response.
 *
 * The connection target is @p addr, but TLS is selected by @p req's URI scheme:
 * an @c https request is terminated with TLS (see the group warning on
 * certificate verification), an @c http request is plaintext. @p addr chooses
 * where to connect; the scheme chooses whether to encrypt.
 *
 * @param client The client.
 * @param req    The request to send; its URI scheme selects plaintext vs TLS.
 * @param addr   Peer address to connect to.
 * @param cb     Invoked with the outcome on the loop thread.
 * @param data   User pointer passed to @p cb.
 * @param notify Destroy notify for @p data.
 * @return @c TRUE if the request was started, in which case @p cb delivers the
 *         outcome and @p notify is called once the request finishes. On
 *         @c FALSE the request could not be started and the caller retains
 *         ownership of @p data (@p notify is not called).
 */
R_API rboolean r_http_client_request_to_addr (RHttpClient * client, RHttpRequest * req,
    const RSocketAddress * addr,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify);

/**
 * @brief Asynchronously resolve @p req's URI, send it and deliver the response.
 *
 * Derives the host and port from the request URI (@ref r_http_request_get_uri),
 * resolves them on the loop via the asynchronous resolver (never blocking the
 * loop thread), then connects to the first resolved address. An @c https scheme
 * terminates the connection with TLS (see the group warning on certificate
 * verification). When the URI omits the port it defaults to 80 for @c http and
 * 443 for @c https; a missing host, or a URI with no port and a scheme that is
 * neither @c http nor @c https, is rejected.
 *
 * @param client The client.
 * @param req    The request to send; its URI selects the target.
 * @param cb     Invoked with the outcome on the loop thread.
 * @param data   User pointer passed to @p cb.
 * @param notify Destroy notify for @p data.
 * @return @c TRUE if the request was started, in which case @p cb delivers the
 *         outcome (including @ref R_HTTP_CLIENT_RESOLVE_FAILED) and @p notify is
 *         called once the request finishes. On @c FALSE the request could not
 *         be started -- the URI lacked a usable host/port -- and the caller
 *         retains ownership of @p data (@p notify is not called).
 */
R_API rboolean r_http_client_request (RHttpClient * client, RHttpRequest * req,
    RHttpClientResponseFunc cb, rpointer data, RDestroyNotify notify);


/**
 * @brief Opaque, refcounted blocking HTTP client.
 *
 * A self-contained synchronous client: it owns a private @ref REvLoop and an
 * @ref RHttpClient, and @ref r_http_client_sync_request_to_addr runs that loop until
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

/** @brief @ref r_http_client_set_keepalive on the underlying client. */
R_API void r_http_client_sync_set_keepalive (RHttpClientSync * client, rboolean enabled);
/** @brief @ref r_http_client_get_keepalive on the underlying client. */
R_API rboolean r_http_client_sync_get_keepalive (RHttpClientSync * client);
/** @brief @ref r_http_client_set_idle_timeout on the underlying client. */
R_API void r_http_client_sync_set_idle_timeout (RHttpClientSync * client, RClockTimeDiff timeout);
/** @brief @ref r_http_client_get_idle_timeout on the underlying client. */
R_API RClockTimeDiff r_http_client_sync_get_idle_timeout (RHttpClientSync * client);

/**
 * @brief Send @p req to @p addr and block until the response arrives.
 *
 * As with @ref r_http_client_request_to_addr, @p addr is the connection target
 * while @p req's URI scheme selects plaintext (@c http) vs TLS (@c https).
 *
 * @param client The blocking client.
 * @param req    The request to send; its URI scheme selects plaintext vs TLS.
 * @param addr   Peer address to connect to.
 * @param result If non-@c NULL, receives the request outcome.
 * @return The response (caller @ref r_http_response_unref's it) on success,
 *         or @c NULL on failure.
 */
R_API RHttpResponse * r_http_client_sync_request_to_addr (RHttpClientSync * client,
    RHttpRequest * req, const RSocketAddress * addr, RHttpClientResult * result);

/**
 * @brief Resolve @p req's URI, send it and block until the response arrives.
 *
 * The blocking counterpart of @ref r_http_client_request -- the destination
 * is derived from the request URI, so the caller passes no address.
 *
 * @param client The blocking client.
 * @param req    The request to send; its URI selects the target.
 * @param result If non-@c NULL, receives the request outcome.
 * @return The response (caller @ref r_http_response_unref's it) on success,
 *         or @c NULL on failure.
 */
R_API RHttpResponse * r_http_client_sync_request (RHttpClientSync * client,
    RHttpRequest * req, RHttpClientResult * result);

R_END_DECLS

/** @} */

#endif /* __R_NET_HTTP_CLIENT_H__ */
