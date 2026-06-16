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
#error "#include <rlib.h> only please."
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
#include <rlib/net/rtlsserver.h>
#include <rlib/crypto/rcert.h>
#include <rlib/crypto/rkey.h>
#include <rlib/crypto/rtruststore.h>

/**
 * @defgroup r_http_server HTTP server
 * @ingroup r_net
 *
 * @brief Refcounted HTTP server that runs on an @c REvLoop and
 * dispatches requests to pattern-matched handlers.
 *
 * Register one or more handlers with @ref r_http_server_set_handler
 * (each bound to a path pattern), then @ref r_http_server_add_listen_addr on a
 * socket address. Each request invokes the matching
 * @ref RHttpRequestHandler, which returns the @ref RHttpResponse to
 * send. Requests can also be injected directly via
 * @ref r_http_server_process_request, bypassing the listener.
 *
 * HTTPS listeners (@ref r_http_server_add_tls_listen_addr) can additionally
 * require a client certificate (mutual TLS) via
 * @ref r_http_server_set_client_cert_mode.
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

/** @brief Add a plaintext (HTTP) listening address; may be called repeatedly. */
R_API rboolean r_http_server_add_listen_addr (RHttpServer * server,
    RSocketAddress * addr);
/**
 * @brief Add a TLS (HTTPS) listening address terminated with @p cert / @p privkey.
 *
 * Each accepted connection runs a per-connection TLS handshake before any HTTP
 * is parsed. @p cert and @p privkey are referenced and apply to this listener
 * only, so distinct addresses may serve distinct certificates. May be combined
 * freely with @ref r_http_server_add_listen_addr on one server (e.g. HTTP on
 * port 80 and HTTPS on port 443).
 */
R_API rboolean r_http_server_add_tls_listen_addr (RHttpServer * server,
    RSocketAddress * addr, RCryptoCert * cert, RCryptoKey * privkey);

/**
 * @brief Enable mutual TLS: request (or require) a client certificate on HTTPS
 * connections.
 *
 * Default @ref R_TLS_CLIENT_CERT_MODE_NONE. With @c REQUEST or @c REQUIRE,
 * configure a client trust store via @ref r_http_server_set_client_trust_store;
 * a presented certificate is validated against it (for TLS client use) and an
 * untrusted one aborts the handshake. With no trust store set, every presented
 * certificate is rejected, so @c REQUIRE admits no client until one is
 * configured.
 */
R_API void r_http_server_set_client_cert_mode (RHttpServer * server,
    RTLSClientCertMode mode);
/** @brief The configured client-certificate mode (see
 *  @ref r_http_server_set_client_cert_mode). */
R_API RTLSClientCertMode r_http_server_get_client_cert_mode (RHttpServer * server);
/**
 * @brief Set the trust store used to validate client certificates under mutual
 * TLS (referenced); pass @c NULL to clear it. See
 * @ref r_http_server_set_client_cert_mode.
 */
R_API void r_http_server_set_client_trust_store (RHttpServer * server,
    RTrustStore * store);

/**
 * @brief Add an SNI virtual host: serve @p cert / @p privkey to clients that
 * request @p host in the TLS @c server_name extension.
 *
 * @p host is matched against the SNI name with the same exact / leftmost-label
 * @c * wildcard semantics as @ref r_crypto_x509_host_match_dns (so
 * @c *.example.com serves any single sub-label). Exact hosts win over wildcards;
 * a connection whose SNI matches no vhost (or that sends none) falls back to the
 * listener certificate and the whole-server client-cert policy. A vhost
 * **inherits** the whole-server client-cert mode and trust store until overridden
 * with @ref r_http_server_set_vhost_client_cert_mode /
 * @ref r_http_server_set_vhost_client_trust_store, so adding a vhost never
 * silently weakens a server-wide requirement. @p cert and @p privkey are
 * referenced. Host matching is case-insensitive.
 *
 * @return @c FALSE on bad arguments, if @p host is already registered, or on
 *         allocation failure.
 */
R_API rboolean r_http_server_add_vhost (RHttpServer * server,
    const rchar * host, RCryptoCert * cert, RCryptoKey * privkey);
/**
 * @brief Set the client-certificate (mutual-TLS) policy for the vhost @p host
 * (added via @ref r_http_server_add_vhost); the per-host counterpart of
 * @ref r_http_server_set_client_cert_mode. Overrides the inherited whole-server
 * mode for this host. @return @c FALSE if @p host is unknown.
 */
R_API rboolean r_http_server_set_vhost_client_cert_mode (RHttpServer * server,
    const rchar * host, RTLSClientCertMode mode);
/**
 * @brief Set the trust store validating client certificates for the vhost
 * @p host (referenced; @c NULL clears it); the per-host counterpart of
 * @ref r_http_server_set_client_trust_store. Overrides the inherited whole-server
 * trust store for this host. @return @c FALSE if @p host is unknown.
 */
R_API rboolean r_http_server_set_vhost_client_trust_store (RHttpServer * server,
    const rchar * host, RTrustStore * store);
/**
 * @brief Set the cipher-suite preference (server order) for the vhost @p host,
 * applied when a connection's SNI selects it.
 *
 * @p suites is copied (@p count entries). The negotiated suite is the server's
 * first preference the client also offers and that the vhost's certificate key
 * supports; an empty intersection fails the handshake. Pass @c NULL / @c 0 to
 * clear it and fall back to the library defaults. @return @c FALSE if @p host is
 * unknown (or on allocation failure).
 */
R_API rboolean r_http_server_set_vhost_cipher_suites (RHttpServer * server,
    const rchar * host, const RTLSCipherSuite * suites, rsize count);

/**
 * @brief The verified client certificate for the request currently being
 * handled, or @c NULL.
 *
 * Only meaningful when called from within an @ref RHttpRequestHandler for a
 * request that arrived over a mutual-TLS connection; returns @c NULL otherwise
 * (plaintext, no client certificate, or called outside a handler). The returned
 * reference is borrowed; @ref r_crypto_cert_ref it to outlive the request.
 */
R_API RCryptoCert * r_http_server_get_peer_cert (RHttpServer * server,
    RHttpRequest * req);

/**
 * @brief Local address of the server's first listener.
 *
 * Useful after listening on an ephemeral port (port 0) to learn the port the
 * OS actually assigned.
 *
 * @return A new @ref RSocketAddress the caller must unref, or @c NULL if the
 *         server is not listening.
 */
R_API RSocketAddress * r_http_server_get_local_address (RHttpServer * server);
/**
 * @brief Stop the server; @p func fires once shutdown completes.
 * @return Number of sockets (listeners + client connections) being closed.
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

